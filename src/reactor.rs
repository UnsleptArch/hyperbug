//! A real, event-driven reactor for the host-side async inputs that used
//! to be polled once per vCPU-loop iteration (DEBTS.md's event-loop
//! item): stdin keystrokes and TAP packets. Runs on its own dedicated OS
//! thread, blocking in a genuine `epoll_wait` — zero overhead while idle,
//! and an immediate wakeup the moment real data is available, instead of
//! a latency bounded only by how often the vCPU loop happened to poll
//! (previously up to the ~20ms periodic-wakeup cadence).
//!
//! Delivering the resulting interrupt doesn't need any vCPU thread's
//! cooperation either: each destination's `IrqLine` (see `irq.rs`) is a
//! plain eventfd write, so a keystroke or packet reaches the guest just
//! as promptly whether it's busy or fully idle in `HLT`.
//!
//! Deliberately **not** extended to the control socket or Python
//! spontaneous `raise_irq()` calls — both stay on the per-iteration poll
//! in `vcpu.rs`. The short version of why: a live vCPU's registers can
//! only safely be read from that vCPU's own thread (KVM vCPU fds aren't
//! safe to use concurrently from a different thread), and a Python
//! device's own arbitrary background thread has no fd for `epoll` to wait
//! on in the first place — see DEBTS.md for the full reasoning.
//!
//! Also owns the other half of `KVM_IOEVENTFD` (DEBTS.md's event-loop
//! item): once a virtio device's notify register gets a real KVM
//! ioeventfd binding (`pci.rs`'s `rebind_ioevents`, at BAR-assignment
//! time), the guest's own queue-kick write never reaches this process as
//! a VM exit at all — KVM signals the eventfd in-kernel instead. This
//! reactor is what actually *does* the queue processing that write used
//! to trigger synchronously: it blocks in the same `epoll_wait` as
//! stdin/TAP, and a kick wakes it immediately whether the vCPU thread
//! that would have taken the old exit is busy or idle.
//!
//! And the completion side of virtio-blk's own io_uring backend
//! (`virtio_blk.rs`): each disk's io_uring instance signals a registered
//! eventfd whenever it has a finished request to report, polled here the
//! same way as everything else — see `handle_blk_completion`.

use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use crate::error::{ExitSlot, GuestExit, request_exit};
use crate::irq::IrqRegistry;
use crate::machine::SharedState;
use crate::pci::PciDevice;
use crate::serial;
use crate::tty;
use crate::virtio::{VirtioDeviceOps, VirtioLegacyPci};
use crate::virtio_blk::VirtioBlk;
use crate::virtio_net::{RX_QUEUE, VNET_HDR_LEN, VirtioNet};

/// One `ioevent_entries()` binding this reactor watches: the `EventFd`
/// KVM signals in-kernel on a matching guest write, which device it
/// belongs to (via the `PciDevice` trait object — `handle_ioevent` is
/// enough to process the notify; nothing here needs the `Device` side),
/// which of that device's `ioevent_entries` fired, and which GSI to pulse
/// if processing it produces a completed buffer.
pub struct VirtioNotifyTarget {
    pub eventfd: Arc<EventFd>,
    pub device: Arc<Mutex<dyn PciDevice>>,
    pub datamatch: u16,
    pub gsi: u32,
}

/// Ctrl-] (the same escape byte telnet uses). Raw mode clears `ISIG`, so a
/// plain Ctrl-C no longer reaches hyperbug as `SIGINT` — without an escape
/// hatch the only way out of a stuck guest would be killing the process
/// from another terminal.
const ESCAPE_BYTE: u8 = 0x1d;

const STDIN_FD: RawFd = 0;
const STDIN_TOKEN: u64 = 0;

/// Bounds how long it takes to notice the run has ended once everything
/// has gone quiet. Real events wake `epoll_wait` immediately regardless.
const QUIESCENT_TIMEOUT_MS: i32 = 200;

/// Largest Ethernet frame the TAP fd can hand over (jumbo frames plus
/// slack), and how much stdin is drained per wakeup.
const RX_BUF_LEN: usize = 65536;
const STDIN_BUF_LEN: usize = 256;

type NetDevice = Arc<Mutex<VirtioLegacyPci<VirtioNet>>>;
type BlkDevice = Arc<Mutex<VirtioLegacyPci<VirtioBlk>>>;

/// Whether stdin can still produce bytes. A closed pipe or file reports
/// itself readable to `epoll` forever, so it has to be unwatched rather
/// than re-read on every wakeup.
#[derive(PartialEq, Eq)]
enum StdinState {
    Open,
    Closed,
}

pub fn spawn(
    shared: Arc<Mutex<SharedState>>,
    exit_slot: ExitSlot,
    irqs: Arc<IrqRegistry>,
    net_devices: Vec<NetDevice>,
    virtio_notifies: Vec<VirtioNotifyTarget>,
    blk_devices: Vec<BlkDevice>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        Reactor::new(shared, exit_slot, irqs, net_devices, virtio_notifies, blk_devices).run()
    })
}

/// Owns the epoll fd for its whole lifetime, so every early return closes
/// it (the old code leaked it on the `epoll_create1` error path's siblings).
struct Epoll {
    fd: RawFd,
}

impl Epoll {
    fn create() -> std::io::Result<Self> {
        // SAFETY: no arguments to get wrong; failure is reported via -1.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    fn add(&self, fd: RawFd, token: u64) -> std::io::Result<()> {
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: token };
        // SAFETY: `self.fd` is a live epoll fd and `ev` outlives the call.
        if unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_ADD, fd, &mut ev) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Stops watching `fd`. Used when stdin reaches EOF: a closed pipe
    /// reports itself readable forever, so leaving it registered turns
    /// this thread into a busy loop.
    fn remove(&self, fd: RawFd) {
        // SAFETY: `self.fd` is a live epoll fd; `EPOLL_CTL_DEL` ignores
        // the event argument, and a failure here is not actionable.
        unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
    }

    /// Blocks for up to `timeout_ms`. Returns the ready slice of `events`.
    fn wait<'a>(&self, events: &'a mut [libc::epoll_event], timeout_ms: i32) -> &'a [libc::epoll_event] {
        // SAFETY: `events` is a valid, correctly-sized array; the kernel
        // writes at most `len` entries and returns how many.
        let n = unsafe {
            libc::epoll_wait(self.fd, events.as_mut_ptr(), events.len() as i32, timeout_ms)
        };
        if n <= 0 { &[] } else { &events[..n as usize] }
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is this struct's own fd and isn't used again.
        unsafe { libc::close(self.fd) };
    }
}

struct Reactor {
    shared: Arc<Mutex<SharedState>>,
    exit_slot: ExitSlot,
    irqs: Arc<IrqRegistry>,
    net_devices: Vec<NetDevice>,
    virtio_notifies: Vec<VirtioNotifyTarget>,
    blk_devices: Vec<BlkDevice>,
}

impl Reactor {
    fn new(
        shared: Arc<Mutex<SharedState>>,
        exit_slot: ExitSlot,
        irqs: Arc<IrqRegistry>,
        net_devices: Vec<NetDevice>,
        virtio_notifies: Vec<VirtioNotifyTarget>,
        blk_devices: Vec<BlkDevice>,
    ) -> Self {
        Self { shared, exit_slot, irqs, net_devices, virtio_notifies, blk_devices }
    }

    fn run(&self) {
        let epoll = match Epoll::create() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[hyperbug] reactor: epoll_create1 failed: {e}");
                return;
            }
        };
        // Not fatal: a guest whose stdin is a regular file (epoll refuses
        // those with EPERM) still runs perfectly well, just without
        // console input.
        if let Err(e) = epoll.add(STDIN_FD, STDIN_TOKEN) {
            eprintln!("[hyperbug] reactor: stdin isn't pollable ({e}); console input is disabled");
        }

        // A fixed set decided at launch (no device hot-plug), so
        // registering fds once up front is enough — each token indexes
        // back into `net_devices`, then `virtio_notifies` past that. The
        // `ioevent_entries` `EventFd`s exist (and can be epoll-watched)
        // from the moment `Machine::build` creates them — only the KVM
        // side of the binding (which guest address triggers one) is
        // filled in later, once the guest actually assigns the owning
        // BAR, so registering the fd itself up front here is safe even
        // though nothing may signal it for a while.
        for (i, net) in self.net_devices.iter().enumerate() {
            let fd = net.lock().unwrap().device_mut().tap_mut().as_raw_fd();
            if let Err(e) = epoll.add(fd, i as u64 + 1) {
                eprintln!("[hyperbug] reactor: couldn't watch TAP fd {fd}: {e}");
            }
        }
        let virtio_notify_base = self.net_devices.len() as u64 + 1;
        for (i, target) in self.virtio_notifies.iter().enumerate() {
            let fd = target.eventfd.as_raw_fd();
            if let Err(e) = epoll.add(fd, virtio_notify_base + i as u64) {
                eprintln!("[hyperbug] reactor: couldn't watch virtio ioeventfd {fd}: {e}");
            }
        }
        let blk_completion_base = virtio_notify_base + self.virtio_notifies.len() as u64;
        for (i, blk) in self.blk_devices.iter().enumerate() {
            let fd = blk.lock().unwrap().device_mut().completion_eventfd();
            if let Some(fd) = fd
                && let Err(e) = epoll.add(fd, blk_completion_base + i as u64)
            {
                eprintln!("[hyperbug] reactor: couldn't watch virtio-blk completion fd {fd}: {e}");
            }
        }

        let mut rx_buf = vec![0u8; RX_BUF_LEN];
        // struct virtio_net_hdr with no offloads negotiated: all-zero.
        let rx_header = [0u8; VNET_HDR_LEN];
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];

        while !self.exit_slot.is_requested() {
            for ev in epoll.wait(&mut events, QUIESCENT_TIMEOUT_MS) {
                // Copied out before matching: a match guard reading a
                // packed struct's field directly (`epoll_event` is
                // `#[repr(packed)]`) needs an aligned place to borrow,
                // which the field itself isn't guaranteed to be.
                let token = ev.u64;
                match token {
                    STDIN_TOKEN => {
                        if self.handle_stdin() == StdinState::Closed {
                            epoll.remove(STDIN_FD);
                        }
                    }
                    token if token < virtio_notify_base => {
                        if let Some(net) = self.net_devices.get((token - 1) as usize) {
                            self.handle_tap(net, &mut rx_buf, &rx_header);
                        }
                    }
                    token if token < blk_completion_base => {
                        if let Some(target) = self.virtio_notifies.get((token - virtio_notify_base) as usize) {
                            self.handle_virtio_notify(target);
                        }
                    }
                    token => {
                        if let Some(blk) = self.blk_devices.get((token - blk_completion_base) as usize) {
                            self.handle_blk_completion(blk);
                        }
                    }
                }
            }
        }
    }

    fn handle_stdin(&self) -> StdinState {
        // Drained in bulk, and fully: fast typing or a paste used to cost
        // one `read(2)` *and* one `SharedState` lock acquisition per
        // character. Level-triggered epoll would hand back whatever's left
        // next time anyway, but a burst shouldn't need a wakeup per byte.
        let mut buf = [0u8; STDIN_BUF_LEN];
        loop {
            let Some(n) = tty::read_stdin(&mut buf) else {
                return StdinState::Closed;
            };
            if n == 0 {
                return StdinState::Open; // nothing queued right now
            }
            if let Some(pos) = buf[..n].iter().position(|&b| b == ESCAPE_BYTE) {
                self.push_rx(&buf[..pos]);
                eprintln!("\r\n[hyperbug] Ctrl-] pressed, exiting");
                request_exit(&self.exit_slot, Ok(GuestExit::UserQuit));
                return StdinState::Open;
            }
            self.push_rx(&buf[..n]);
            if n < buf.len() {
                return StdinState::Open; // the read was short: nothing more is queued
            }
        }
    }

    fn push_rx(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut wants_irq = false;
        {
            let mut state = self.shared.lock().unwrap();
            for &byte in bytes {
                wants_irq |= state.serial.push_rx_byte(byte);
            }
        }
        if wants_irq {
            self.irqs.pulse(serial::COM1_IRQ);
        }
    }

    /// A guest write KVM matched against one of `target`'s ioeventfd
    /// bindings — the actual queue-kick processing that write used to
    /// trigger synchronously inside `Device::write` on a vCPU thread, now
    /// happening here instead, off any vCPU thread entirely.
    fn handle_virtio_notify(&self, target: &VirtioNotifyTarget) {
        // Clears the eventfd's counter; level-triggered `epoll` would
        // otherwise report it ready again on the very next `epoll_wait`.
        let _ = target.eventfd.read();
        let wants_irq = target.device.lock().unwrap().handle_ioevent(target.datamatch);
        if wants_irq {
            self.irqs.pulse(target.gsi);
        }
    }

    /// A virtio-blk device's io_uring instance has at least one finished
    /// request to report — the actual disk I/O already happened
    /// asynchronously (`virtio_blk.rs`'s `submit_io`); this is only the
    /// bookkeeping tail (status byte, used ring, interrupt) that a
    /// synchronous `Device::write` used to do all at once.
    fn handle_blk_completion(&self, blk: &BlkDevice) {
        let mut device = blk.lock().unwrap();
        // Clears the io_uring-registered eventfd's counter (a plain Linux
        // eventfd under the hood) — same reasoning as
        // `handle_virtio_notify`'s own read: level-triggered `epoll`
        // would otherwise report it ready again immediately.
        if let Some(fd) = device.device_mut().completion_eventfd() {
            let mut discard = [0u8; 8];
            // SAFETY: `fd` is a valid, open eventfd for as long as this
            // `VirtioBlk` (whose lock we're holding) is alive; reading
            // exactly 8 bytes is the eventfd read protocol.
            unsafe {
                libc::read(fd, discard.as_mut_ptr().cast(), discard.len());
            }
        }
        if let Some(irq) = device.drain_completions() {
            self.irqs.pulse(irq);
        }
    }

    fn handle_tap(&self, net: &NetDevice, rx_buf: &mut [u8], rx_header: &[u8]) {
        let mut net = net.lock().unwrap();
        // Drain every queued packet, not just the first: a burst used to
        // need one `epoll_wait` round trip per frame.
        loop {
            let Some(n) = net.device_mut().tap_mut().try_read(rx_buf) else {
                return;
            };
            match net.try_deliver_rx(RX_QUEUE, rx_header, &rx_buf[..n]) {
                Some(irq) => self.irqs.pulse(irq),
                // The guest hasn't posted an RX buffer; the packet is
                // dropped, exactly as a real NIC would under buffer
                // exhaustion. Stop draining rather than spin reading
                // packets we can't deliver.
                None => return,
            }
        }
    }
}
