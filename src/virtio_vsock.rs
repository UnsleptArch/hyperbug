//! virtio-vsock: a real, standardized virtio device (`VIRTIO_ID_VSOCK` =
//! 19) that a guest's real, unmodified `vmw_vsock_virtio_transport`
//! driver binds to directly. Queue layout (`rx`=0, `tx`=1, `event`=2) and
//! packet framing verified against the real driver source
//! (`net/vmw_vsock/virtio_transport.c`/`virtio_transport_common.c`,
//! fetched from `torvalds/linux`) — see `vsock.rs` for the wire-format
//! and credit-accounting details this module builds on.
//!
//! **Modern-transport only**: no legacy virtio-vsock PCI ID exists in
//! the real registry (checked against `/usr/share/hwdata/pci.ids`,
//! same discipline as virtio-i2c/virtio-gpio) — vsock postdates the
//! legacy numbering scheme entirely.
//!
//! **Bridging model**: every guest-initiated `SOCK_STREAM` connection,
//! regardless of which destination port it names, connects out to the
//! *same* host Unix domain socket (`--vsock-uds <path>`) — see
//! `vsock.rs`'s own module doc comment for why this (not general port
//! forwarding, not host-initiated connections) is the actual scope.
//!
//! **A real background bridge thread**, not the reactor's own epoll
//! loop: each active guest stream maps to a real `UnixStream` this
//! device owns, and reading from potentially several of them
//! concurrently needs its own blocking-`poll(2)` loop independent of the
//! vCPU/reactor threads. Communicates back via a channel plus a real
//! `eventfd` the reactor watches (`bridge_eventfd`/`drain_bridge_events`)
//! — the same "background thread + channel + eventfd" shape
//! `pydevice_proc.rs`'s sandboxed-plugin reader thread already
//! establishes, applied here to sockets instead of a subprocess pipe.
//!
//! **Two delivery paths into the guest's `rx` queue**, because they
//! trigger at genuinely different times: a `RESPONSE`/`RST` reply to a
//! guest request is produced *synchronously*, inside `process_chain`
//! handling the `tx` queue, and delivered via `VirtioDeviceOps::
//! take_outbox` (drained by `VirtioModernPci` right after that same
//! kick, since `process_chain` itself has no way to reach the `rx`
//! queue's own posted buffers — see that trait method's own doc
//! comment). Real inbound data arriving on the bridged Unix socket is
//! asynchronous, with no guest kick to piggyback on at all, so it's
//! delivered directly via `VirtioModernPci::try_deliver_async` from the
//! reactor's own bridge-eventfd handler instead.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use vmm_sys_util::eventfd::EventFd;

use crate::mem::GuestMemory;
use crate::vsock::{self, HOST_CID, Packet, StreamState};
use crate::virtio::{ChainOutcome, DescChain, VirtioDeviceOps, copy_config};

pub const RX_QUEUE: u16 = 0;
pub const TX_QUEUE: u16 = 1;
#[allow(dead_code)] // never drained (see this module's own doc comment), kept for the real queue-count/index space
pub const EVENT_QUEUE: u16 = 2;

/// This device's own fixed guest CID, reported via config space. A real
/// deployment might want this operator-configurable; fixed is enough for
/// a first, real implementation and matches how `--i2c-device`/
/// `--gpio-device`'s own reference devices picked fixed, simple defaults.
const GUEST_CID: u64 = 3;

/// How large a single delivered `RW` packet's payload is allowed to be —
/// comfortably under a real guest's posted `rx` buffer size
/// (`VIRTIO_VSOCK_DEFAULT_RX_BUF_SIZE` is ~4 KiB minus overhead, per the
/// real kernel header), so one packet always fits in one posted buffer
/// without needing multi-buffer chaining on delivery.
const MAX_RW_CHUNK: usize = 3800;

fn stream_key(a_port: u32, b_port: u32) -> u64 {
    (u64::from(a_port) << 32) | u64::from(b_port)
}

fn split_key(key: u64) -> (u32, u32) {
    ((key >> 32) as u32, key as u32)
}

enum BridgeCmd {
    /// A guest `REQUEST` was accepted and the host-side connect already
    /// succeeded (done synchronously in `process_chain` — a local
    /// `AF_UNIX` connect is effectively instant, not worth an async
    /// round trip) — hands the already-connected socket to the bridge
    /// thread to poll from here on.
    AddExisting { key: u64, stream: UnixStream },
    Write { key: u64, data: Vec<u8> },
    Close { key: u64 },
}

enum BridgeEvent {
    Data { key: u64, data: Vec<u8> },
    Closed { key: u64 },
}

/// Owns the background thread bridging active vsock streams to their
/// real host-side `UnixStream`s. See this module's own doc comment.
struct VsockBridge {
    cmd_tx: mpsc::Sender<BridgeCmd>,
    cmd_wake: Arc<EventFd>,
    event_rx: Mutex<mpsc::Receiver<BridgeEvent>>,
    event_fd: Arc<EventFd>,
}

impl VsockBridge {
    fn new() -> std::io::Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let cmd_wake = Arc::new(EventFd::new(0)?);
        let (event_tx, event_rx) = mpsc::channel();
        let event_fd = Arc::new(EventFd::new(0)?);
        let thread_wake = cmd_wake.clone();
        let thread_event_fd = event_fd.clone();
        thread::spawn(move || bridge_thread_main(cmd_rx, thread_wake, event_tx, thread_event_fd));
        Ok(Self { cmd_tx, cmd_wake, event_rx: Mutex::new(event_rx), event_fd })
    }

    fn send(&self, cmd: BridgeCmd) {
        let _ = self.cmd_tx.send(cmd);
        let _ = self.cmd_wake.write(1);
    }

    fn drain_events(&self) -> Vec<BridgeEvent> {
        self.event_rx.lock().unwrap().try_iter().collect()
    }

    fn eventfd(&self) -> RawFd {
        self.event_fd.as_raw_fd()
    }
}

/// The bridge thread's own loop: a plain `poll(2)` over the command-wake
/// fd plus every currently-connected stream's socket fd. `poll(2)`
/// rather than a dedicated `epoll` instance (like `reactor.rs`'s own)
/// since the fd set here is small and rebuilt every iteration anyway
/// (connections come and go); not worth a second `Epoll` wrapper type
/// for that.
fn bridge_thread_main(
    cmd_rx: mpsc::Receiver<BridgeCmd>,
    cmd_wake: Arc<EventFd>,
    event_tx: mpsc::Sender<BridgeEvent>,
    event_fd: Arc<EventFd>,
) {
    let mut conns: HashMap<u64, UnixStream> = HashMap::new();
    let notify = |key, ev: fn(u64) -> BridgeEvent| {
        let _ = event_tx.send(ev(key));
        let _ = event_fd.write(1);
    };

    loop {
        let mut fds = vec![libc::pollfd { fd: cmd_wake.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        let keys: Vec<u64> = conns.keys().copied().collect();
        for &k in &keys {
            fds.push(libc::pollfd { fd: conns[&k].as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        // SAFETY: `fds` is a valid, correctly-sized array of real open fds
        // (or the wake eventfd) for the duration of this call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            continue; // EINTR or similar — just re-poll
        }

        if fds[0].revents & libc::POLLIN != 0 {
            let mut discard = [0u8; 8];
            // SAFETY: `fds[0].fd` is `cmd_wake`'s own real eventfd.
            unsafe {
                libc::read(fds[0].fd, discard.as_mut_ptr().cast(), discard.len());
            }
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    BridgeCmd::AddExisting { key, stream } => {
                        conns.insert(key, stream);
                    }
                    BridgeCmd::Write { key, data } => {
                        if let Some(s) = conns.get_mut(&key)
                            && s.write_all(&data).is_err()
                        {
                            conns.remove(&key);
                            notify(key, |k| BridgeEvent::Closed { key: k });
                        }
                    }
                    BridgeCmd::Close { key } => {
                        conns.remove(&key);
                    }
                }
            }
            continue; // re-poll: the fd set may have just changed
        }

        for (i, &k) in keys.iter().enumerate() {
            if fds[i + 1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
                continue;
            }
            let mut buf = [0u8; 16384];
            let Some(s) = conns.get_mut(&k) else { continue };
            match s.read(&mut buf) {
                Ok(0) => {
                    conns.remove(&k);
                    notify(k, |key| BridgeEvent::Closed { key });
                }
                Ok(n) => {
                    let _ = event_tx.send(BridgeEvent::Data { key: k, data: buf[..n].to_vec() });
                    let _ = event_fd.write(1);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    conns.remove(&k);
                    notify(k, |key| BridgeEvent::Closed { key });
                }
            }
        }
    }
}

pub struct VirtioVsock {
    uds_path: String,
    bridge: VsockBridge,
    streams: HashMap<u64, StreamState>,
    /// Control-packet replies (`RESPONSE`/`RST`/`CREDIT_UPDATE`) produced
    /// synchronously while handling a `tx`-queue kick — see this
    /// module's own doc comment on the two delivery paths.
    outbox: VecDeque<Vec<u8>>,
}

impl VirtioVsock {
    pub fn new(uds_path: String) -> std::io::Result<Self> {
        Ok(Self { uds_path, bridge: VsockBridge::new()?, streams: HashMap::new(), outbox: VecDeque::new() })
    }

    pub fn bridge_eventfd(&self) -> RawFd {
        self.bridge.eventfd()
    }

    fn push_reply(&mut self, op: u16, flags: u32, our_port: u32, peer_cid: u64, peer_port: u32, state: &StreamState) {
        self.outbox.push_back(vsock::control_packet(op, flags, our_port, peer_cid, peer_port, state).to_bytes());
    }

    fn handle_guest_packet(&mut self, pkt: Packet) {
        let key = stream_key(pkt.src_port, pkt.dst_port);
        match pkt.op {
            vsock::OP_REQUEST => {
                let mut state = StreamState::default();
                state.observe_peer_credit(&pkt);
                match UnixStream::connect(&self.uds_path) {
                    Ok(stream) => {
                        let _ = stream.set_nonblocking(true);
                        self.bridge.send(BridgeCmd::AddExisting { key, stream });
                        self.push_reply(vsock::OP_RESPONSE, 0, pkt.dst_port, pkt.src_cid, pkt.src_port, &state);
                        self.streams.insert(key, state);
                    }
                    Err(_) => {
                        self.push_reply(vsock::OP_RST, 0, pkt.dst_port, pkt.src_cid, pkt.src_port, &state);
                    }
                }
            }
            vsock::OP_RW => {
                if let Some(state) = self.streams.get_mut(&key) {
                    state.observe_peer_credit(&pkt);
                    state.fwd_cnt = state.fwd_cnt.wrapping_add(pkt.payload.len() as u32);
                    self.bridge.send(BridgeCmd::Write { key, data: pkt.payload });
                }
                // An RW for an unknown stream (already torn down, or a
                // buggy guest) is silently dropped rather than RSTing —
                // a real transport would RST it; a small, stated gap
                // rather than added complexity for an edge case this
                // scope's single-bridge-target design rarely hits.
            }
            vsock::OP_CREDIT_UPDATE => {
                if let Some(state) = self.streams.get_mut(&key) {
                    state.observe_peer_credit(&pkt);
                }
            }
            vsock::OP_CREDIT_REQUEST => {
                if let Some(state) = self.streams.get(&key) {
                    let state = StreamState {
                        tx_cnt: state.tx_cnt,
                        fwd_cnt: state.fwd_cnt,
                        peer_buf_alloc: state.peer_buf_alloc,
                        peer_fwd_cnt: state.peer_fwd_cnt,
                        pending_send: VecDeque::new(),
                    };
                    self.push_reply(vsock::OP_CREDIT_UPDATE, 0, pkt.dst_port, pkt.src_cid, pkt.src_port, &state);
                }
            }
            vsock::OP_SHUTDOWN => {
                if pkt.flags & (vsock::SHUTDOWN_RCV | vsock::SHUTDOWN_SEND) == (vsock::SHUTDOWN_RCV | vsock::SHUTDOWN_SEND)
                    && let Some(state) = self.streams.remove(&key)
                {
                    self.bridge.send(BridgeCmd::Close { key });
                    self.push_reply(vsock::OP_RST, 0, pkt.dst_port, pkt.src_cid, pkt.src_port, &state);
                }
            }
            vsock::OP_RST if self.streams.remove(&key).is_some() => {
                self.bridge.send(BridgeCmd::Close { key });
            }
            _ => {}
        }
    }

    /// Drains real events from the bridge thread (data arrived, or a
    /// connection closed) into fully-formed outbound packets, updating
    /// each stream's credit bookkeeping honestly as it goes, then tries
    /// to flush any previously credit-blocked backlog now that new
    /// events (which might include a `CREDIT_UPDATE`-worthy change from
    /// the guest side, observed elsewhere) may have freed room. Called
    /// by the reactor when `bridge_eventfd` fires — see this module's
    /// own doc comment on the two delivery paths.
    pub fn drain_bridge_events(&mut self) -> Vec<Vec<u8>> {
        for event in self.bridge.drain_events() {
            match event {
                BridgeEvent::Data { key, data } => {
                    if let Some(state) = self.streams.get_mut(&key) {
                        state.pending_send.extend(data);
                    }
                }
                BridgeEvent::Closed { key } => {
                    if let Some(state) = self.streams.remove(&key) {
                        let (their_port, our_port) = split_key(key);
                        // We no longer know the peer's own cid once its
                        // `StreamState` is gone — real vsock cids are
                        // small, stable, operator-meaningful values, not
                        // secrets, and a real guest driver only checks
                        // src_port/dst_port to match this to its own
                        // socket, so a fixed default here is harmless.
                        let _ = state; // state consumed only for credit context above
                        let placeholder = StreamState::default();
                        self.outbox.push_back(
                            vsock::control_packet(vsock::OP_RST, 0, our_port, GUEST_CID, their_port, &placeholder).to_bytes(),
                        );
                    }
                }
            }
        }

        let mut out: Vec<Vec<u8>> = self.outbox.drain(..).collect();
        for (&key, state) in self.streams.iter_mut() {
            while !state.pending_send.is_empty() {
                let room = state.peer_has_space().min(MAX_RW_CHUNK as u32) as usize;
                if room == 0 {
                    break;
                }
                let chunk: Vec<u8> = state.pending_send.drain(..room.min(state.pending_send.len())).collect();
                state.tx_cnt = state.tx_cnt.wrapping_add(chunk.len() as u32);
                let (their_port, our_port) = split_key(key);
                out.push(
                    Packet {
                        src_cid: HOST_CID,
                        dst_cid: GUEST_CID,
                        src_port: our_port,
                        dst_port: their_port,
                        op: vsock::OP_RW,
                        flags: 0,
                        buf_alloc: vsock::MY_BUF_ALLOC,
                        fwd_cnt: state.fwd_cnt,
                        payload: chunk,
                    }
                    .to_bytes(),
                );
            }
        }
        out
    }
}

impl VirtioDeviceOps for VirtioVsock {
    fn legacy_pci_device_id(&self) -> u16 {
        0 // never used — see this module's own doc comment
    }

    fn virtio_device_type(&self) -> u16 {
        19 // VIRTIO_ID_VSOCK, per <linux/virtio_ids.h>
    }

    fn pci_class_code(&self) -> u32 {
        0x02_00_00 // Network controller — the closest real PCI class for a host<->guest channel
    }

    fn num_queues(&self) -> u16 {
        3 // rx, tx, event — real driver always looks for all three
    }

    fn queue_size(&self, _queue: u16) -> u16 {
        64
    }

    /// `rx` (and `event`, never used here but same reasoning) is a
    /// "guest posts empty buffers for the device to fill later" queue —
    /// exactly virtio-net's own RX queue shape, and `wants_queue_notify`'s
    /// own doc comment already documents why draining it on kick is
    /// wrong: every buffer the guest posts (real driver behavior:
    /// `virtio_vsock_rx_fill` posts a batch, then kicks once) would
    /// otherwise be popped and immediately marked "used" with 0 bytes by
    /// the default synchronous path, before `try_deliver_async` ever got
    /// a chance to actually fill one — a real, live-guest-caught bug
    /// this device hit on its very first manual boot test (every posted
    /// buffer was silently drained to nothing, so no `RESPONSE`/`RW`
    /// packet could ever reach the guest even though the device produced
    /// one correctly).
    fn wants_queue_notify(&self, queue: u16) -> bool {
        queue != RX_QUEUE && queue != EVENT_QUEUE
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(&GUEST_CID.to_le_bytes(), offset, data);
    }

    fn process_chain(&mut self, queue: u16, mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome {
        if queue != TX_QUEUE {
            // rx/event: the guest only ever posts empty buffers here for
            // later, asynchronous delivery (see `try_deliver_async`) —
            // nothing to process synchronously.
            return ChainOutcome::Done(0);
        }
        let mut raw = Vec::new();
        for buf in &chain.buffers {
            if buf.device_writable {
                continue;
            }
            let mut tmp = vec![0u8; buf.len as usize];
            if mem.read_checked(buf.addr, &mut tmp) {
                raw.extend_from_slice(&tmp);
            }
        }
        let len = raw.len() as u32;
        if let Some(pkt) = Packet::parse(&raw) {
            self.handle_guest_packet(pkt);
        }
        ChainOutcome::Done(len)
    }

    fn take_outbox(&mut self) -> Vec<(u16, Vec<u8>)> {
        self.outbox.drain(..).map(|bytes| (RX_QUEUE, bytes)).collect()
    }
}
