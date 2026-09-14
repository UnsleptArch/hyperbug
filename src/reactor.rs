//! A real, event-driven reactor for the host-side async inputs that used
//! to be polled once per vCPU-loop iteration: stdin keystrokes and TAP
//! packets. Runs on its own dedicated OS
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
//! on in the first place.
//!
//! Also owns the other half of `KVM_IOEVENTFD`: once a virtio device's
//! notify register gets a real KVM
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
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use vmm_sys_util::eventfd::EventFd;

use crate::error::{ExitSlot, GuestExit, request_exit};
use crate::irq::IrqRegistry;
use crate::machine::SharedState;
use crate::pci::PciDevice;
use crate::record::{EventKind, Recorder};
use crate::serial;
use crate::tty;
use crate::virtio::{VirtioDeviceOps, VirtioLegacyPci, VirtioModernPci};
use crate::virtio_blk::VirtioBlk;
use crate::virtio_gpio::VirtioGpio;
use crate::virtio_vsock::VirtioVsock;
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

/// How long `ReactorPause::request_and_wait` waits for the reactor thread
/// to actually reach a safe (not mid-critical-section) point before
/// giving up — see `ReactorPause`'s own doc comment for why this exists
/// at all (`fork.rs`).
const PAUSE_ACK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, PartialEq, Eq)]
enum PauseState {
    Running,
    Requested,
    Paused,
}

/// A real, tested rendezvous the reactor thread checks once per loop
/// iteration (before touching any lock), letting another thread — only
/// `fork.rs`, today — know for certain the reactor isn't mid-critical-
/// section before doing something that would otherwise risk it: `fork()`
/// only clones the *calling* thread, so if the reactor thread happened to
/// be holding `SharedState`'s lock (or any other) at the exact instant of
/// a fork, that lock would be permanently stuck in the child with no
/// owning thread ever able to release it. This exists specifically so
/// `fork.rs` can pause the reactor at a genuinely safe point, fork, and
/// resume it — rather than "just fork and hope," which this project's own
/// history (item 9's segfault, item 35's wakeup-ticker regression) has
/// already shown is not a real strategy for a concurrency-adjacent
/// feature.
#[derive(Clone)]
pub struct ReactorPause {
    inner: Arc<(Mutex<PauseState>, Condvar)>,
}

impl ReactorPause {
    pub fn new() -> Self {
        Self { inner: Arc::new((Mutex::new(PauseState::Running), Condvar::new())) }
    }

    /// Called only by the reactor thread itself, once per loop iteration,
    /// before doing anything else. A no-op (returns immediately) unless a
    /// pause has actually been requested.
    fn check_in(&self) {
        let (lock, cvar) = &*self.inner;
        let mut state = lock.lock().unwrap();
        if *state != PauseState::Requested {
            return;
        }
        *state = PauseState::Paused;
        cvar.notify_all();
        while *state == PauseState::Paused {
            state = cvar.wait(state).unwrap();
        }
    }

    /// Requests a pause and blocks until the reactor thread has actually
    /// reached one (or `PAUSE_ACK_TIMEOUT` elapses). Returns `false` on
    /// timeout — the caller (`fork.rs`) must not proceed with `fork()` in
    /// that case, since the reactor's true state is then unknown.
    pub fn request_and_wait(&self) -> bool {
        let (lock, cvar) = &*self.inner;
        let mut state = lock.lock().unwrap();
        *state = PauseState::Requested;
        let (mut state, timed_out) =
            cvar.wait_timeout_while(state, PAUSE_ACK_TIMEOUT, |s| *s != PauseState::Paused).unwrap();
        if timed_out.timed_out() {
            *state = PauseState::Running; // withdraw the request
            cvar.notify_all();
            return false;
        }
        true
    }

    /// Resumes a paused reactor thread. Called by `fork.rs` in the
    /// *parent* only — the child never had a reactor thread of its own
    /// at all (fork only clones the calling thread), and spawns a
    /// completely fresh one instead.
    pub fn resume(&self) {
        let (lock, cvar) = &*self.inner;
        *lock.lock().unwrap() = PauseState::Running;
        cvar.notify_all();
    }
}

impl Default for ReactorPause {
    fn default() -> Self {
        Self::new()
    }
}

type NetDevice = Arc<Mutex<VirtioLegacyPci<VirtioNet>>>;
type BlkDevice = Arc<Mutex<VirtioLegacyPci<VirtioBlk>>>;
type GpioDevice = Arc<Mutex<VirtioModernPci<VirtioGpio>>>;
type VsockDevice = Arc<Mutex<VirtioModernPci<VirtioVsock>>>;

/// Whether stdin can still produce bytes. A closed pipe or file reports
/// itself readable to `epoll` forever, so it has to be unwatched rather
/// than re-read on every wakeup.
#[derive(PartialEq, Eq)]
enum StdinState {
    Open,
    Closed,
}

/// Bundles `spawn`'s parameters — matches `vcpu.rs`'s own `VcpuEnv`
/// convention, needed once `--record`/`--replay` pushed the plain
/// parameter list past clippy's arity lint.
pub struct ReactorConfig {
    pub shared: Arc<Mutex<SharedState>>,
    pub exit_slot: ExitSlot,
    pub irqs: Arc<IrqRegistry>,
    pub net_devices: Vec<NetDevice>,
    pub virtio_notifies: Vec<VirtioNotifyTarget>,
    pub blk_devices: Vec<BlkDevice>,
    /// Every virtio-gpio adapter, for the same reason `blk_devices` is
    /// handed over: the reactor polls each one's completion eventfd to
    /// finish a guest-armed `eventq` buffer once a real interrupt fires
    /// (`VirtioGpio`'s module doc comment) — see `handle_gpio_completion`.
    pub gpio_devices: Vec<GpioDevice>,
    /// The one optional virtio-vsock adapter's bridge-thread eventfd —
    /// see `VirtioVsock`'s module doc comment and
    /// `handle_vsock_bridge`.
    pub vsock_device: Option<VsockDevice>,
    pub recorder: Option<Arc<Recorder>>,
    /// `true` under `--replay` — see `Reactor::suppress_stdin`'s own doc
    /// comment.
    pub suppress_stdin: bool,
    /// The rendezvous `fork.rs` uses to pause this reactor thread at a
    /// safe point before forking — see `ReactorPause`'s own doc comment.
    pub pause: ReactorPause,
}

pub fn spawn(config: ReactorConfig) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || Reactor::new(config).run())
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
    gpio_devices: Vec<GpioDevice>,
    vsock_device: Option<VsockDevice>,
    /// `Some` only when `--record` was given — see `record.rs`. Tagging
    /// every keyboard byte/TAP packet with a branch-count position is
    /// cheap enough (one syscall read on an already-open fd) to do
    /// unconditionally when present, so no separate "is recording on"
    /// check gates the call sites below beyond this being `Some`.
    recorder: Option<Arc<Recorder>>,
    /// `true` under `--replay`: real stdin is never watched, since
    /// keyboard input comes from the recording instead (delivered from
    /// `vcpu.rs`'s own poll loop). TAP is still watched regardless —
    /// network replay isn't implemented yet.
    suppress_stdin: bool,
    pause: ReactorPause,
}

impl Reactor {
    fn new(config: ReactorConfig) -> Self {
        let ReactorConfig {
            shared,
            exit_slot,
            irqs,
            net_devices,
            virtio_notifies,
            blk_devices,
            gpio_devices,
            vsock_device,
            recorder,
            suppress_stdin,
            pause,
        } = config;
        Self {
            shared,
            exit_slot,
            irqs,
            net_devices,
            virtio_notifies,
            blk_devices,
            gpio_devices,
            vsock_device,
            recorder,
            suppress_stdin,
            pause,
        }
    }

    fn run(&self) {
        let epoll = match Epoll::create() {
            Ok(e) => e,
            Err(e) => {
                crate::log_error!("reactor: epoll_create1 failed: {e}");
                return;
            }
        };
        // Not fatal: a guest whose stdin is a regular file (epoll refuses
        // those with EPERM) still runs perfectly well, just without
        // console input. Never watched at all under `--replay` — see
        // `suppress_stdin`'s own doc comment.
        if !self.suppress_stdin
            && let Err(e) = epoll.add(STDIN_FD, STDIN_TOKEN)
        {
            crate::log_warn!("reactor: stdin isn't pollable ({e}); console input is disabled");
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
                crate::log_error!("reactor: couldn't watch TAP fd {fd}: {e}");
            }
        }
        let virtio_notify_base = self.net_devices.len() as u64 + 1;
        for (i, target) in self.virtio_notifies.iter().enumerate() {
            let fd = target.eventfd.as_raw_fd();
            if let Err(e) = epoll.add(fd, virtio_notify_base + i as u64) {
                crate::log_error!("reactor: couldn't watch virtio ioeventfd {fd}: {e}");
            }
        }
        let blk_completion_base = virtio_notify_base + self.virtio_notifies.len() as u64;
        for (i, blk) in self.blk_devices.iter().enumerate() {
            let fd = blk.lock().unwrap().device_mut().completion_eventfd();
            if let Some(fd) = fd
                && let Err(e) = epoll.add(fd, blk_completion_base + i as u64)
            {
                crate::log_error!("reactor: couldn't watch virtio-blk completion fd {fd}: {e}");
            }
        }
        let gpio_completion_base = blk_completion_base + self.blk_devices.len() as u64;
        for (i, gpio) in self.gpio_devices.iter().enumerate() {
            let fd = gpio.lock().unwrap().device_mut().completion_eventfd();
            if let Some(fd) = fd
                && let Err(e) = epoll.add(fd, gpio_completion_base + i as u64)
            {
                crate::log_error!("reactor: couldn't watch virtio-gpio completion fd {fd}: {e}");
            }
        }
        let vsock_token = gpio_completion_base + self.gpio_devices.len() as u64;
        if let Some(vsock) = &self.vsock_device {
            let fd = vsock.lock().unwrap().device_mut().bridge_eventfd();
            if let Err(e) = epoll.add(fd, vsock_token) {
                crate::log_error!("reactor: couldn't watch virtio-vsock bridge fd {fd}: {e}");
            }
        }

        let mut rx_buf = vec![0u8; RX_BUF_LEN];
        // struct virtio_net_hdr with no offloads negotiated: all-zero.
        let rx_header = [0u8; VNET_HDR_LEN];
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];

        while !self.exit_slot.is_requested() {
            // Checked before touching any lock or doing any dispatch —
            // see `ReactorPause`'s own doc comment for why this specific
            // point (not mid-event-handling) is the only safe place to
            // park for a pending `fork()`.
            self.pause.check_in();
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
                    token if token < gpio_completion_base => {
                        if let Some(blk) = self.blk_devices.get((token - blk_completion_base) as usize) {
                            self.handle_blk_completion(blk);
                        }
                    }
                    token if token < vsock_token => {
                        if let Some(gpio) = self.gpio_devices.get((token - gpio_completion_base) as usize) {
                            self.handle_gpio_completion(gpio);
                        }
                    }
                    _ => {
                        if let Some(vsock) = &self.vsock_device {
                            self.handle_vsock_bridge(vsock);
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
                eprint!("\r\n");
                crate::log_info!("Ctrl-] pressed, exiting");
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
        if let Some(recorder) = &self.recorder {
            recorder.record(EventKind::KeyboardRx, bytes);
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

    /// A virtio-gpio bank's Python plugin has called
    /// `self.hyperbug.raise_irq(line)` — completes whichever `eventq`
    /// buffer was armed for that line (if any) and raises the adapter's
    /// interrupt. Same shape as `handle_blk_completion`, driven by the
    /// same `ChainOutcome::Pending`/`poll_completions` machinery, just
    /// triggered by a plugin call instead of an io_uring completion.
    fn handle_gpio_completion(&self, gpio: &GpioDevice) {
        let mut device = gpio.lock().unwrap();
        if let Some(fd) = device.device_mut().completion_eventfd() {
            let mut discard = [0u8; 8];
            // SAFETY: `fd` is a valid, open eventfd for as long as this
            // `VirtioGpio` (whose lock we're holding) is alive; reading
            // exactly 8 bytes is the eventfd read protocol.
            unsafe {
                libc::read(fd, discard.as_mut_ptr().cast(), discard.len());
            }
        }
        if let Some(irq) = device.drain_completions() {
            self.irqs.pulse(irq);
        }
    }

    /// The virtio-vsock bridge thread has real data, a closed connection,
    /// or a freshly-flushed credit-unblocked backlog to report — drains
    /// it into fully-formed packets and delivers each directly via
    /// `try_deliver_async` (not `drain_completions`/`CompletionResult`,
    /// which only ever writes a single status byte — see
    /// `VirtioVsock`'s own module doc comment on its two delivery paths).
    fn handle_vsock_bridge(&self, vsock: &VsockDevice) {
        let mut device = vsock.lock().unwrap();
        let fd = device.device_mut().bridge_eventfd();
        let mut discard = [0u8; 8];
        // SAFETY: `fd` is a valid, open eventfd for as long as this
        // `VirtioVsock` (whose lock we're holding) is alive.
        unsafe {
            libc::read(fd, discard.as_mut_ptr().cast(), discard.len());
        }
        let packets = device.device_mut().drain_bridge_events();
        let mut irq_to_pulse = None;
        for bytes in packets {
            if let Some(irq) = device.try_deliver_async(crate::virtio_vsock::RX_QUEUE, &bytes) {
                irq_to_pulse = Some(irq);
            }
        }
        drop(device);
        if let Some(irq) = irq_to_pulse {
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
                Some(irq) => {
                    // Recorded only on an actual delivery — a packet the
                    // guest never got (no RX buffer posted, the `None`
                    // arm below) never reached it and has nothing to
                    // replay.
                    if let Some(recorder) = &self.recorder {
                        recorder.record(EventKind::NetRx, &rx_buf[..n]);
                    }
                    self.irqs.pulse(irq);
                }
                // The guest hasn't posted an RX buffer; the packet is
                // dropped, exactly as a real NIC would under buffer
                // exhaustion. Stop draining rather than spin reading
                // packets we can't deliver.
                None => return,
            }
        }
    }
}
