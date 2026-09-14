//! Shared legacy-virtio-over-PCI plumbing: the common register file
//! (feature negotiation, per-queue PFN/size/select/notify, status, ISR)
//! and split-virtqueue descriptor-chain walking. A specific device (block,
//! net, ...) only needs to implement `VirtioDeviceOps`.
//!
//! Deliberately the *legacy* (pre-1.0, "transitional") virtio-PCI
//! interface: a single I/O-space BAR0 with a flat register layout, no PCI
//! capability list to parse. Modern virtio 1.0 (memory-mapped BARs via PCI
//! capabilities) would also work but needs capability-list support in
//! `pci.rs` that nothing here requires yet.
//!
//! Vendor ID 0x1AF4 and this register layout are the open virtio
//! standard (originated at Red Hat, but not proprietary hardware) — this
//! is infrastructure any hypervisor needs to speak virtio at all, not a
//! specific real device's identity.
//!
//! **Descriptor validation is centralized here, on purpose.** `try_pop`
//! rejects any chain containing a buffer that doesn't lie entirely within
//! guest RAM, or whose buffers total more bytes than guest RAM even
//! contains. That single check is what bounds every downstream device's
//! host-side buffering: without it, a guest could describe a 4 GiB
//! descriptor (or 256 of them) and make virtio-blk/net/rng allocate that
//! much host memory before the first bounds check ever ran.

use std::sync::{Arc, Mutex};

use crate::device::Device;
use crate::mem::GuestMemory;
use crate::pci::{EXTRA_CAP_OFFSET, NUM_BARS, PciDevice};

pub const VIRTIO_VENDOR_ID: u16 = 0x1af4;

const REG_HOST_FEATURES: u64 = 0x00;
const REG_GUEST_FEATURES: u64 = 0x04;
const REG_QUEUE_ADDRESS: u64 = 0x08;
const REG_QUEUE_SIZE: u64 = 0x0c;
const REG_QUEUE_SELECT: u64 = 0x0e;
const REG_QUEUE_NOTIFY: u64 = 0x10;
const REG_DEVICE_STATUS: u64 = 0x12;
const REG_ISR_STATUS: u64 = 0x13;
const DEVICE_CONFIG_START: u64 = 0x14;

const QUEUE_ALIGN: u64 = 4096;
const DESC_SIZE: u64 = 16;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// ISR bit 0: "the device used some buffers on a virtqueue" — the only
/// ISR reason this transport ever reports.
const ISR_USED_BUFFER: u8 = 1;

/// One buffer in a descriptor chain: guest address, length, and whether
/// it's device-writable (the guest reads from it) vs. device-readable
/// (the guest wrote it for the device to read). Guaranteed by `try_pop`
/// to lie entirely within guest RAM.
#[derive(Debug)]
pub struct DescBuffer {
    pub addr: u64,
    pub len: u32,
    pub device_writable: bool,
}

/// A popped descriptor chain. Reused across pops (see `VirtioLegacyPci`'s
/// `chain` scratch field) rather than reallocated per request — a busy
/// disk or NIC pops one of these for every single I/O.
#[derive(Default)]
pub struct DescChain {
    head_index: u16,
    pub buffers: Vec<DescBuffer>,
}

impl DescChain {
    fn reset(&mut self, head_index: u16) {
        self.head_index = head_index;
        self.buffers.clear();
    }

    /// This chain's head descriptor index — what `push_used`/
    /// `push_used_head` records on the used ring to tell the guest which
    /// request finished. Needed by a device (`virtio_blk.rs`'s io_uring
    /// path) that defers completion (`ChainOutcome::Pending`) past this
    /// `DescChain` itself being reset for the next pop.
    #[inline]
    pub fn head_index(&self) -> u16 {
        self.head_index
    }

    /// Test-only: builds a `DescChain` directly from a buffer list,
    /// bypassing `try_pop`'s own descriptor-table walk entirely. Used by
    /// property tests in sibling device modules (`virtio_rng.rs`) that
    /// want to drive a device's `process_chain` with adversarial buffer
    /// lists without needing a full virtqueue in guest memory to walk.
    #[cfg(test)]
    pub fn for_test(buffers: Vec<DescBuffer>) -> Self {
        Self { head_index: 0, buffers }
    }
}

/// A split virtqueue's location and size. Two unrelated addressing
/// conventions can populate `desc`/`avail`/`used`, one per transport:
/// legacy's single page-frame-number (`set_pfn`, spec-fixed contiguous
/// layout) and modern virtio 1.0's three independent 64-bit addresses
/// (`set_desc`/`set_avail`/`set_used`, plus an explicit `queue_enable`
/// bit — see `VirtioModernPci`). `try_pop`/`push_used` don't care which
/// transport populated them, only that they're live.
struct VirtQueue {
    size: u16,
    /// Legacy read-back only (`VIRTIO_PCI_QUEUE_PFN` is a real/write
    /// register the driver can read back) — modern virtio has no
    /// equivalent single value, so this stays 0 for a modern queue.
    pfn: u32,
    desc: u64,
    avail: u64,
    used: u64,
    enabled: bool,
    last_avail_idx: u16,
}

impl VirtQueue {
    fn new(size: u16) -> Self {
        Self { size, pfn: 0, desc: 0, avail: 0, used: 0, enabled: false, last_avail_idx: 0 }
    }

    /// Whether this queue can be walked at all: enabled (by whichever
    /// transport's own convention for that), and the device declared a
    /// non-zero size (a zero-size queue would make every `% self.size`
    /// below a division by zero).
    #[inline]
    fn is_live(&self) -> bool {
        self.enabled && self.size != 0
    }

    /// Legacy: one physical page number determines `desc`/`avail`/`used`
    /// via the spec's fixed contiguous layout; 0 means "not configured"
    /// (the legacy convention — modern virtio uses `set_enabled` instead).
    fn set_pfn(&mut self, pfn: u32) {
        self.pfn = pfn;
        if pfn == 0 {
            self.enabled = false;
            return;
        }
        self.desc = u64::from(pfn) << 12;
        self.avail = self.desc + DESC_SIZE * u64::from(self.size);
        let avail_size = 4 + 2 * u64::from(self.size) + 2;
        self.used = (self.avail + avail_size).div_ceil(QUEUE_ALIGN) * QUEUE_ALIGN;
        self.enabled = true;
    }

    /// Modern virtio 1.0: the driver programs all three addresses
    /// independently, then sets `queue_enable` — see
    /// `VirtioModernPci::write_common_cfg`'s `Q_ENABLE` case.
    fn set_desc(&mut self, addr: u64) {
        self.desc = addr;
    }
    fn set_avail(&mut self, addr: u64) {
        self.avail = addr;
    }
    fn set_used(&mut self, addr: u64) {
        self.used = addr;
    }
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    #[inline]
    fn desc_addr(&self) -> u64 {
        self.desc
    }

    #[inline]
    fn avail_addr(&self) -> u64 {
        self.avail
    }

    fn used_addr(&self) -> u64 {
        self.used
    }

    /// Pops the next available descriptor chain into `chain`, if the guest
    /// has queued one we haven't processed yet. Returns `false` on an empty
    /// queue *or* on any malformed/out-of-bounds chain — a misbehaving
    /// guest just stops making progress on this queue rather than crashing
    /// (or exhausting the host memory of) the VMM.
    fn try_pop(&mut self, mem: &GuestMemory, chain: &mut DescChain) -> bool {
        if !self.is_live() {
            return false;
        }
        let Some(avail_idx) = mem.read_u16_checked(self.avail_addr() + 2) else {
            return false;
        };
        if self.last_avail_idx == avail_idx {
            return false;
        }
        let ring_slot = self.avail_addr() + 4 + u64::from(self.last_avail_idx % self.size) * 2;
        let Some(head) = mem.read_u16_checked(ring_slot) else {
            return false;
        };
        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);

        chain.reset(head);
        // No legitimate chain describes more bytes than guest RAM even
        // holds; capping the total is what keeps a device's own buffering
        // bounded by configuration rather than by guest input.
        let budget = mem.size() as u64;
        let mut total = 0u64;
        let mut idx = head;
        // A malicious/buggy guest could build a descriptor cycle; bound the
        // walk by queue size (the longest a legitimate chain can be).
        for _ in 0..self.size {
            if idx >= self.size {
                return false; // index outside the descriptor table
            }
            // One 16-byte read rather than four separate bounds-checked
            // field reads: this is the per-request hot path.
            let mut desc = [0u8; DESC_SIZE as usize];
            if !mem.read_checked(self.desc_addr() + u64::from(idx) * DESC_SIZE, &mut desc) {
                return false;
            }
            let addr = u64::from_le_bytes(desc[0..8].try_into().unwrap());
            let len = u32::from_le_bytes(desc[8..12].try_into().unwrap());
            let flags = u16::from_le_bytes(desc[12..14].try_into().unwrap());
            let next = u16::from_le_bytes(desc[14..16].try_into().unwrap());

            if !mem.in_bounds(addr, u64::from(len)) {
                return false;
            }
            total += u64::from(len);
            if total > budget {
                return false;
            }
            chain.buffers.push(DescBuffer {
                addr,
                len,
                device_writable: flags & VIRTQ_DESC_F_WRITE != 0,
            });
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            idx = next;
        }
        true
    }

    fn push_used(&self, mem: &mut GuestMemory, chain: &DescChain, written_len: u32) {
        self.push_used_head(mem, chain.head_index, written_len);
    }

    /// As `push_used`, taking the descriptor chain's head index directly
    /// rather than a live `DescChain` — for completing a chain that was
    /// popped (and whose `DescChain` scratch buffer has long since been
    /// reused for something else) at submission time, not now. The only
    /// caller is `VirtioLegacyPci::drain_completions`.
    fn push_used_head(&self, mem: &mut GuestMemory, head_index: u16, written_len: u32) {
        if !self.is_live() {
            return;
        }
        let used = self.used_addr();
        let idx = mem.read_u16_checked(used + 2).unwrap_or(0);
        let slot = used + 4 + u64::from(idx % self.size) * 8;
        mem.write_u32_checked(slot, u32::from(head_index));
        mem.write_u32_checked(slot + 4, written_len);
        mem.write_u16_checked(used + 2, idx.wrapping_add(1));
    }
}

/// Copies the `[offset, offset + data.len())` window of a device's config
/// space into `data`, zero-filling anything past the end. Every
/// `VirtioDeviceOps::read_config` impl needs exactly this, and each used
/// to open-code it (with its own off-by-one risk on the tail slice).
pub fn copy_config(config: &[u8], offset: u64, data: &mut [u8]) {
    data.fill(0);
    let Ok(offset) = usize::try_from(offset) else { return };
    let Some(window) = config.get(offset..) else { return };
    let n = window.len().min(data.len());
    data[..n].copy_from_slice(&window[..n]);
}

/// What `process_chain` did with one descriptor chain.
pub enum ChainOutcome {
    /// Handled synchronously, same meaning as the old plain `u32` return:
    /// bytes written into device-writable buffers. `drain_queue` pushes
    /// this chain onto the used ring immediately.
    Done(u32),
    /// The device submitted real async I/O for this chain (via io_uring)
    /// and will complete it itself later, via
    /// `VirtioLegacyPci::drain_completions` — `drain_queue` must **not**
    /// push this chain onto the used ring now; pushing it early would
    /// tell the guest data is ready before it actually is.
    Pending,
}

/// One request `poll_completions` reports as finished: what to write into
/// the guest (the status byte, at `status_buf_addr`) and how to push it
/// onto the used ring (`queue_idx`/`head_index`/`written_len`, matching
/// `push_used`'s own parameters for a chain that was popped earlier, at
/// submission time, and is only being finished now).
pub struct CompletionResult {
    pub queue_idx: u16,
    pub head_index: u16,
    pub written_len: u32,
    pub status_byte: u8,
    pub status_buf_addr: u64,
}

/// Device-specific behavior a legacy virtio-PCI device plugs in. Register
/// plumbing, feature negotiation bookkeeping, and virtqueue mechanics all
/// live in `VirtioLegacyPci` and are the same for every device type.
pub trait VirtioDeviceOps: Send {
    /// The real legacy-transitional PCI device ID (vendor is always
    /// `VIRTIO_VENDOR_ID`). *Not* simply `0x1000 + device-type-id` — the
    /// legacy numbering predates that registry and doesn't follow it (e.g.
    /// net is 0x1000, block is 0x1001, but balloon is 0x1002 despite its
    /// device-type id being 5); verified against `/usr/share/hwdata/pci.ids`
    /// rather than assumed.
    fn legacy_pci_device_id(&self) -> u16;
    /// The real virtio device-type id (net=1, block=2, rng=4, ... per
    /// `virtio_ids.h` — verified against this host's own kernel header,
    /// not assumed), served as the PCI Subsystem ID
    /// (`PciDevice::subsystem_device_id`) `VirtioLegacyPci` reports.
    /// **This is what a real legacy virtio driver actually matches
    /// against** (`virtio_pci_legacy_dev.c` reads `vdev.id.device`
    /// straight from the PCI Subsystem ID, not the PCI Device ID above) —
    /// getting this wrong, or leaving it at 0, means no driver ever binds,
    /// with no error visible anywhere short of the guest's own `/sys/bus/
    /// virtio/devices` showing device id 0. Distinct from
    /// `legacy_pci_device_id` on purpose: the two numbering schemes are
    /// unrelated (see that method's own doc comment).
    fn virtio_device_type(&self) -> u16;
    /// Whether a guest "kick" (notify) of `queue` should actually drain and
    /// process it synchronously. **`true` (the default) is correct for
    /// every queue where the guest posts a buffer *containing the work to
    /// do* (a TX frame, a block request, an RNG request) — the queue this
    /// codebase was originally built around.** It is *not* correct for a
    /// queue where the guest instead posts an *empty* buffer for the
    /// device to fill *whenever it later has data* (virtio-net's RX
    /// queue): draining that queue on kick pops the guest's freshly-posted
    /// buffer and immediately marks it "used" with 0 bytes, before the
    /// buffer ever gets a chance to receive a real incoming packet via
    /// `try_deliver_rx` — starving RX delivery of buffers under exactly
    /// the ordinary "guest posts, then kicks" sequence every real
    /// virtio-net driver uses. A real, live-guest-verified bug found via
    /// real `ping` traffic showing majority packet loss and an erratically
    /// advancing avail-ring index — not something any existing unit test
    /// (which never drives a real guest driver's RX-post-then-kick
    /// sequence) could have caught. `VirtioNet` overrides this to exclude
    /// `RX_QUEUE`; every other device's queues keep the default.
    fn wants_queue_notify(&self, _queue: u16) -> bool {
        true
    }
    fn pci_class_code(&self) -> u32;
    fn num_queues(&self) -> u16;
    fn queue_size(&self, queue: u16) -> u16;
    fn host_features(&self) -> u32 {
        0
    }
    fn read_config(&self, offset: u64, data: &mut [u8]);
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
    /// Handle one descriptor chain popped from `queue`. `Done(n)` means
    /// exactly what the old plain `u32` return used to: `n` bytes were
    /// written into device-writable buffers, and the chain is finished
    /// now. `Pending` means the device submitted real async I/O for it
    /// (see `ChainOutcome`) and will report it later via
    /// `poll_completions`.
    fn process_chain(&mut self, queue: u16, mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome;

    /// Drains whatever async-completion mechanism this device uses (e.g.
    /// io_uring's completion queue) for every request that's finished
    /// since the last call. Most devices never return `Pending` from
    /// `process_chain` and use the default (nothing to drain, ever).
    fn poll_completions(&mut self) -> Vec<CompletionResult> {
        Vec::new()
    }

    /// A raw fd that becomes readable when `poll_completions` has
    /// something new to report — so the reactor can block in `epoll`
    /// instead of polling. `None` (the default) for a device that never
    /// returns `Pending`.
    fn completion_eventfd(&self) -> Option<std::os::fd::RawFd> {
        None
    }

    /// Drains whatever variable-length buffers a device produced as a
    /// *side effect* of `process_chain` handling some other queue's
    /// request, each tagged with which queue it belongs on — for a
    /// device (virtio-vsock's control-packet replies) whose reply to a
    /// guest's request on one queue must be delivered as if the guest
    /// had posted a receive buffer on a *different* queue, something
    /// `process_chain` itself has no way to do (it only sees the one
    /// chain it was handed). Checked by `VirtioModernPci` right after
    /// every successful `drain_queue` call (both the synchronous
    /// register-write path and the ioeventfd-driven one), delivering
    /// each via `try_deliver_async`. Most devices never produce one and
    /// use the default (nothing to deliver, ever) — distinct from
    /// `poll_completions`/`ChainOutcome::Pending`, which is for
    /// completing a chain the device *itself* already popped, not for
    /// injecting one it never received.
    fn take_outbox(&mut self) -> Vec<(u16, Vec<u8>)> {
        Vec::new()
    }
}

pub struct VirtioLegacyPci<D: VirtioDeviceOps> {
    dev: D,
    mem: Arc<Mutex<GuestMemory>>,
    irq: u8,
    guest_features: u32,
    queue_select: u16,
    status: u8,
    isr: u8,
    queues: Vec<VirtQueue>,
    /// Scratch reused by every pop, so a busy queue doesn't allocate a
    /// fresh `Vec<DescBuffer>` per request.
    chain: DescChain,
}

impl<D: VirtioDeviceOps> VirtioLegacyPci<D> {
    pub fn new(dev: D, mem: Arc<Mutex<GuestMemory>>, irq: u8) -> Self {
        let queues = (0..dev.num_queues()).map(|q| VirtQueue::new(dev.queue_size(q))).collect();
        Self {
            dev,
            mem,
            irq,
            guest_features: 0,
            queue_select: 0,
            status: 0,
            isr: 0,
            queues,
            chain: DescChain::default(),
        }
    }

    /// Access to the device-specific state (e.g. virtio-net's TAP handle)
    /// for code that needs to drive it from outside the `Device` trait's
    /// guest-triggered read/write path — see `try_deliver_rx`.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// Drains every available descriptor chain on `queue`. Returns true if
    /// anything was *immediately* processed (so the caller knows to raise
    /// the IRQ now) — a chain the device deferred (`ChainOutcome::Pending`)
    /// doesn't count here; its own completion, later, is what raises the
    /// IRQ for it (see `drain_completions`).
    fn drain_queue(&mut self, queue_idx: u16) -> bool {
        // See `VirtioDeviceOps::wants_queue_notify`'s own doc comment: a
        // "guest posts an empty buffer for the device to fill later"
        // queue (virtio-net's RX) must never be drained just because the
        // guest kicked it — that's the ordinary "I posted a fresh buffer"
        // signal, not "please consume this now".
        if !self.dev.wants_queue_notify(queue_idx) {
            return false;
        }
        let mut processed_any = false;
        loop {
            // Re-locked per chain rather than held across the whole drain:
            // a device's `process_chain` can itself want guest memory (and
            // a Python plugin's DMA path definitely does).
            let mut mem = self.mem.lock().unwrap();
            let Some(queue) = self.queues.get_mut(usize::from(queue_idx)) else {
                return processed_any;
            };
            if !queue.try_pop(&mem, &mut self.chain) {
                return processed_any;
            }
            match self.dev.process_chain(queue_idx, &mut mem, &self.chain) {
                ChainOutcome::Done(written) => {
                    self.queues[usize::from(queue_idx)].push_used(&mut mem, &self.chain, written);
                    processed_any = true;
                }
                // Not pushed onto the used ring now — pushing it before
                // the async I/O actually finishes would tell the guest
                // data is ready before it is. Keep draining the rest of
                // the avail ring regardless; one request going async
                // doesn't block the others from being submitted too.
                ChainOutcome::Pending => {}
            }
        }
    }

    /// Finishes every request the device's own async-completion mechanism
    /// (see `VirtioDeviceOps::poll_completions`) has ready — writes each
    /// one's status byte, pushes it onto its queue's used ring, and
    /// reports whether the interrupt should be raised as a result. Called
    /// from the reactor thread (never a vCPU thread) when a device's
    /// `completion_eventfd` fires — see `reactor::handle_blk_completion`,
    /// the only caller.
    pub fn drain_completions(&mut self) -> Option<u32> {
        let completions = self.dev.poll_completions();
        if completions.is_empty() {
            return None;
        }
        let mut mem = self.mem.lock().unwrap();
        for c in &completions {
            mem.write_checked(c.status_buf_addr, &[c.status_byte]);
            let Some(queue) = self.queues.get(usize::from(c.queue_idx)) else { continue };
            queue.push_used_head(&mut mem, c.head_index, c.written_len + 1);
        }
        self.isr |= ISR_USED_BUFFER;
        Some(u32::from(self.irq))
    }

    /// Delivers `header` immediately followed by `frame` into the next
    /// available descriptor chain on `queue` (virtio-net's RX path: a
    /// `struct virtio_net_hdr` followed by the actual Ethernet frame).
    /// Returns the IRQ to pulse if a buffer was available, `None` if the
    /// guest hadn't posted one (the caller drops the packet, same as a
    /// real NIC would under RX buffer exhaustion) or the queue isn't
    /// configured yet.
    ///
    /// Copies each source slice straight into its destination buffer —
    /// no concatenated staging buffer, and no `drain`-shifting the
    /// remainder down after every descriptor, both of which this used to
    /// do once per received packet.
    pub fn try_deliver_rx(&mut self, queue_idx: u16, header: &[u8], frame: &[u8]) -> Option<u32> {
        let mut mem = self.mem.lock().unwrap();
        let queue = self.queues.get_mut(usize::from(queue_idx))?;
        if !queue.try_pop(&mem, &mut self.chain) {
            return None;
        }

        let mut sources: [&[u8]; 2] = [header, frame];
        let mut written = 0u32;
        for buf in &self.chain.buffers {
            // RX buffers the guest posts are device-*writable* by
            // definition; anything else in this chain is malformed and
            // must not be written through.
            if !buf.device_writable {
                break;
            }
            let mut room = buf.len as usize;
            let mut dst = buf.addr;
            for src in &mut sources {
                if room == 0 {
                    break;
                }
                let pending: &[u8] = src;
                let n = pending.len().min(room);
                if n == 0 {
                    continue;
                }
                if !mem.write_checked(dst, &pending[..n]) {
                    break;
                }
                written += n as u32;
                dst += n as u64;
                room -= n;
                *src = &pending[n..];
            }
            if sources.iter().all(|s| s.is_empty()) {
                break;
            }
        }

        self.queues[usize::from(queue_idx)].push_used(&mut mem, &self.chain, written);
        self.isr |= ISR_USED_BUFFER;
        Some(u32::from(self.irq))
    }
}

impl<D: VirtioDeviceOps> crate::snapshot::Snapshot for VirtioLegacyPci<D> {
    /// See `snapshot.rs`'s module doc comment: `D`'s own state isn't
    /// included since `virtio_net`/`virtio_rng` hold none beyond what's
    /// captured here (their backing TAP handle is an external resource
    /// reopened identically from `Args` on restore).
    ///
    /// **Known gap**: `virtio_blk.rs`'s io_uring backend is the one
    /// exception — a request genuinely in flight (submitted, not yet
    /// completed) at the exact moment a snapshot is taken has no
    /// representation here at all. Restoring drops it silently; the
    /// guest's own virtqueue slot for that request would then never see
    /// a completion and hang. Not fixed this pass (would need draining
    /// in-flight requests before a snapshot can proceed, a real design
    /// task of its own) — stated here rather than left implicit, same as
    /// the FLUSH-ordering gap `virtio_blk.rs`'s own module doc comment
    /// already states.
    fn save_state(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.guest_features.to_le_bytes());
        buf.extend_from_slice(&self.queue_select.to_le_bytes());
        buf.push(self.status);
        buf.push(self.isr);
        buf.extend_from_slice(&(self.queues.len() as u32).to_le_bytes());
        for q in &self.queues {
            buf.extend_from_slice(&q.pfn.to_le_bytes());
            buf.extend_from_slice(&q.last_avail_idx.to_le_bytes());
        }
        buf
    }

    fn restore_state(&mut self, data: &[u8]) -> Result<(), String> {
        use crate::snapshot::{take_u8, take_u16, take_u32};
        let mut buf = data;
        self.guest_features = take_u32(&mut buf)?;
        self.queue_select = take_u16(&mut buf)?;
        self.status = take_u8(&mut buf)?;
        self.isr = take_u8(&mut buf)?;
        let n = take_u32(&mut buf)? as usize;
        if n != self.queues.len() {
            return Err(format!("snapshot has {n} queues, device has {}", self.queues.len()));
        }
        for q in &mut self.queues {
            let pfn = take_u32(&mut buf)?;
            q.set_pfn(pfn);
            q.last_avail_idx = take_u16(&mut buf)?;
        }
        Ok(())
    }
}

impl<D: VirtioDeviceOps> PciDevice for VirtioLegacyPci<D> {
    fn vendor_id(&self) -> u16 {
        VIRTIO_VENDOR_ID
    }
    fn device_id(&self) -> u16 {
        self.dev.legacy_pci_device_id()
    }
    /// See `VirtioDeviceOps::virtio_device_type`'s own doc comment — this
    /// is the field a real legacy virtio driver actually matches on.
    fn subsystem_vendor_id(&self) -> u16 {
        VIRTIO_VENDOR_ID
    }
    fn subsystem_device_id(&self) -> u16 {
        self.dev.virtio_device_type()
    }
    fn class_code(&self) -> u32 {
        self.dev.pci_class_code()
    }
    fn bar_sizes(&self) -> [u32; NUM_BARS] {
        [0x40, 0, 0, 0, 0, 0] // 64 bytes: register file + generous device-config room
    }
    fn bar_is_io(&self, index: usize) -> bool {
        index == 0
    }
    fn interrupt_line(&self) -> u8 {
        self.irq
    }

    /// One entry per queue, all on the same BAR0 notify register — a real
    /// driver writes the queue index as the 2-byte value, and legacy's
    /// flat register file has no distinct address per queue the way
    /// modern virtio 1.0's notify region does. `PciBus::register` creates
    /// one `EventFd` per queue and, once BAR0 gets a real address, KVM
    /// matches a 2-byte write of exactly this queue's index at
    /// `base + REG_QUEUE_NOTIFY` — never reaching this process as a VM
    /// exit, let alone `Device::write`. A queue `wants_queue_notify`
    /// refuses (virtio-net's RX) still gets a binding here — harmless,
    /// since `drain_queue` itself no-ops for it — rather than complicating
    /// this list with a filter for what's already a no-op downstream.
    fn ioevent_entries(&self) -> Vec<(u8, u64, u16)> {
        (0..self.dev.num_queues()).map(|q| (0u8, REG_QUEUE_NOTIFY, q)).collect()
    }

    /// Runs (on the reactor thread — see `reactor::handle_virtio_notify`)
    /// exactly the same queue-drain logic the old `REG_QUEUE_NOTIFY`
    /// `Device::write` arm ran synchronously on a vCPU thread; `datamatch`
    /// is the queue index KVM matched.
    fn handle_ioevent(&mut self, datamatch: u16) -> bool {
        if self.drain_queue(datamatch) {
            self.isr |= ISR_USED_BUFFER;
            true
        } else {
            false
        }
    }
}

/// Copies the low `data.len()` bytes of `value` (little-endian) into
/// `data`, for the register file's fixed-width reads.
#[inline]
fn read_le<const N: usize>(bytes: [u8; N], data: &mut [u8]) {
    let n = data.len().min(N);
    data[..n].copy_from_slice(&bytes[..n]);
}

impl<D: VirtioDeviceOps> Device for VirtioLegacyPci<D> {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if offset >= DEVICE_CONFIG_START {
            self.dev.read_config(offset - DEVICE_CONFIG_START, data);
            return;
        }
        data.fill(0);
        let selected = self.queues.get(usize::from(self.queue_select));
        match offset {
            REG_HOST_FEATURES => read_le(self.dev.host_features().to_le_bytes(), data),
            REG_GUEST_FEATURES => read_le(self.guest_features.to_le_bytes(), data),
            REG_QUEUE_ADDRESS => read_le(selected.map_or(0, |q| q.pfn).to_le_bytes(), data),
            REG_QUEUE_SIZE => read_le(selected.map_or(0, |q| q.size).to_le_bytes(), data),
            REG_QUEUE_SELECT => read_le(self.queue_select.to_le_bytes(), data),
            REG_DEVICE_STATUS => read_le([self.status], data),
            REG_ISR_STATUS => {
                read_le([self.isr], data);
                self.isr = 0; // read-to-clear, per spec
            }
            _ => {}
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        if offset >= DEVICE_CONFIG_START {
            self.dev.write_config(offset - DEVICE_CONFIG_START, data);
            return false;
        }
        match offset {
            REG_GUEST_FEATURES if data.len() == 4 => {
                self.guest_features = u32::from_le_bytes(data.try_into().unwrap());
            }
            REG_QUEUE_ADDRESS if data.len() == 4 => {
                let pfn = u32::from_le_bytes(data.try_into().unwrap());
                if let Some(q) = self.queues.get_mut(usize::from(self.queue_select)) {
                    q.set_pfn(pfn);
                }
            }
            REG_QUEUE_SELECT if data.len() == 2 => {
                self.queue_select = u16::from_le_bytes(data.try_into().unwrap());
            }
            REG_QUEUE_NOTIFY if data.len() == 2 => {
                let queue = u16::from_le_bytes(data.try_into().unwrap());
                if self.drain_queue(queue) {
                    self.isr |= ISR_USED_BUFFER;
                    return true;
                }
            }
            REG_DEVICE_STATUS if !data.is_empty() => {
                self.status = data[0];
                if self.status == 0 {
                    // Guest-initiated reset: drop all queue state.
                    for q in &mut self.queues {
                        q.set_pfn(0);
                        q.last_avail_idx = 0;
                    }
                    self.isr = 0;
                }
            }
            _ => {}
        }
        false
    }
}

// --- Modern virtio 1.0 PCI transport --------------------------------------
//
// Memory-mapped BARs discovered via a PCI capability list, instead of
// legacy's single flat I/O-space register file. Struct layouts and offsets
// below are taken verbatim from this host's own kernel header
// (`include/uapi/linux/virtio_pci.h`), the same "verify against a real
// source of truth" discipline `acpi.rs` and the legacy PCI ID numbering
// above already follow.
//
// Scoped as **modern-only** (not "transitional" — no legacy I/O-BAR
// fallback on the same device): `revision_id() = 1` and a PCI Device ID in
// the modern range (`0x1040 + virtio device type`), per the spec's own
// rule that revision 0 is reserved for a transitional device supporting
// both layouts. A transitional device would need `VirtioLegacyPci` and
// `VirtioModernPci` merged into one `PciDevice`; not attempted here since
// nothing in this codebase's device set actually needs a guest with a
// legacy-only driver to also see this transport.
//
// **MSI-X is deliberately not implemented** (`pci.rs`'s own doc comment,
// checked against the real Linux virtio driver source, already establishes
// why): `vp_find_vqs` only ever requests MSI-X or falls straight back to
// legacy INTx. Both `msix_config`/`queue_msix_vector` here always read back
// `VIRTIO_MSI_NO_VECTOR` (0xffff) and no MSI-X PCI capability is ever
// advertised, so a real driver cleanly takes the INTx path — the existing
// `interrupt_line`/irqfd mechanism every other PCI device in this codebase
// already uses. Real MSI-X support (a second capability, per-vector masking
// via a BAR-mapped table) is a distinct, larger follow-up, not required for
// a guest driver to bind and use this transport correctly today.

/// `struct virtio_pci_cap` (16 bytes) — real layout, not guessed: `cap_vndr`,
/// `cap_next`, `cap_len`, `cfg_type`, `bar`, 3 bytes padding, `offset` (u32
/// LE), `length` (u32 LE).
const VIRTIO_PCI_CAP_LEN: usize = 16;
/// `struct virtio_pci_notify_cap` (20 bytes): a `virtio_pci_cap` plus a
/// trailing `notify_off_multiplier` (u32 LE).
const VIRTIO_PCI_NOTIFY_CAP_LEN: usize = 20;

const CAP_ID_VENDOR_SPECIFIC: u8 = 0x09;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// `VIRTIO_MSI_NO_VECTOR` — what `msix_config`/`queue_msix_vector` report
/// given no MSI-X capability exists (see the module note above).
const NO_VECTOR: u16 = 0xffff;

/// `struct virtio_pci_common_cfg` field offsets, real values from the
/// kernel header (not spec-page-guessed): every field up to and including
/// `queue_used_hi` at 52, for a 56-byte struct.
const CFG_DFSELECT: u64 = 0;
const CFG_DF: u64 = 4;
const CFG_GFSELECT: u64 = 8;
const CFG_GF: u64 = 12;
const CFG_MSIX: u64 = 16;
const CFG_NUMQ: u64 = 18;
const CFG_STATUS: u64 = 20;
const CFG_CFGGEN: u64 = 21;
const CFG_QSELECT: u64 = 22;
const CFG_QSIZE: u64 = 24;
const CFG_QMSIX: u64 = 26;
const CFG_QENABLE: u64 = 28;
const CFG_QNOFF: u64 = 30;
const CFG_QDESCLO: u64 = 32;
const CFG_QDESCHI: u64 = 36;
const CFG_QAVAILLO: u64 = 40;
const CFG_QAVAILHI: u64 = 44;
const CFG_QUSEDLO: u64 = 48;
const CFG_QUSEDHI: u64 = 52;
const COMMON_CFG_LEN: u64 = 56;

/// Bytes per queue in the notify region (`notify_off_multiplier`): each
/// queue's `queue_notify_off` (== its own queue index here) times this
/// gives its byte offset within the region.
const NOTIFY_MULTIPLIER: u32 = 4;
/// Real ISR-status only needs 1 byte; rounded to a dword so the following
/// region stays dword-aligned like every other virtio 1.0 structure.
const ISR_REGION_LEN: u64 = 4;

/// `VIRTIO_F_VERSION_1` (feature bit 32): every driver checks this before
/// accepting the modern layout at all — without it, a spec-compliant
/// driver must assume legacy and this transport wouldn't be recognized.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

fn set_addr_lo(cur: u64, val: u32) -> u64 {
    (cur & !0xffff_ffffu64) | u64::from(val)
}
fn set_addr_hi(cur: u64, val: u32) -> u64 {
    (cur & 0xffff_ffff) | (u64::from(val) << 32)
}
fn lo32(addr: u64) -> u32 {
    addr as u32
}
fn hi32(addr: u64) -> u32 {
    (addr >> 32) as u32
}

/// Builds one `virtio_pci_cap`-family structure's bytes, chained to the
/// next one at `next_offset` within the buffer (`0` for the last).
fn build_cap(cfg_type: u8, bar: u8, offset: u32, length: u32, next_offset: u8) -> [u8; VIRTIO_PCI_CAP_LEN] {
    let mut c = [0u8; VIRTIO_PCI_CAP_LEN];
    c[0] = CAP_ID_VENDOR_SPECIFIC;
    c[1] = next_offset;
    c[2] = VIRTIO_PCI_CAP_LEN as u8;
    c[3] = cfg_type;
    c[4] = bar;
    c[8..12].copy_from_slice(&offset.to_le_bytes());
    c[12..16].copy_from_slice(&length.to_le_bytes());
    c
}

/// A modern virtio 1.0 PCI device: one memory BAR0 holding, back to back,
/// the common-config struct, the per-queue notify region, the 1-byte ISR,
/// and the device-specific config space — laid out and advertised via a
/// real PCI capability list, per the spec, rather than legacy's fixed I/O
/// register file. Generic over the same `VirtioDeviceOps` a device
/// implements for `VirtioLegacyPci`, so `virtio_blk.rs`/`virtio_net.rs`/
/// `virtio_rng.rs` need no changes to be used through either transport.
pub struct VirtioModernPci<D: VirtioDeviceOps> {
    dev: D,
    mem: Arc<Mutex<GuestMemory>>,
    irq: u8,
    /// The spec's device-type ID (1=network, 2=block, 4=entropy, ...) —
    /// used only to compute the modern PCI Device ID (`0x1040 + type`).
    /// Not derived from `legacy_pci_device_id()`: that ID's own doc
    /// comment already establishes it doesn't follow any formula.
    device_type: u16,
    device_feature_select: u32,
    guest_feature_select: u32,
    guest_features: u64,
    status: u8,
    config_generation: u8,
    queue_select: u16,
    queues: Vec<VirtQueue>,
    isr: u8,
    chain: DescChain,
    notify_base: u64,
    isr_base: u64,
    device_base: u64,
    bar_len: u32,
}

impl<D: VirtioDeviceOps> VirtioModernPci<D> {
    /// `device_config_len` is the size in bytes of `dev.read_config`'s
    /// device-specific config space (0 for a device with none, like
    /// virtio-rng) — needed up front to lay out BAR0.
    pub fn new(dev: D, mem: Arc<Mutex<GuestMemory>>, irq: u8, device_type: u16, device_config_len: u32) -> Self {
        let queues = (0..dev.num_queues()).map(|q| VirtQueue::new(dev.queue_size(q))).collect();
        let notify_base = COMMON_CFG_LEN;
        let notify_len = u64::from(dev.num_queues()) * u64::from(NOTIFY_MULTIPLIER);
        let isr_base = notify_base + notify_len;
        let device_base = isr_base + ISR_REGION_LEN;
        let device_end = device_base + u64::from(device_config_len);
        let bar_len = (device_end as u32).next_power_of_two().max(4096);
        Self {
            dev,
            mem,
            irq,
            device_type,
            device_feature_select: 0,
            guest_feature_select: 0,
            guest_features: 0,
            status: 0,
            config_generation: 0,
            queue_select: 0,
            queues,
            isr: 0,
            chain: DescChain::default(),
            notify_base,
            isr_base,
            device_base,
            bar_len,
        }
    }

    /// Access to the device-specific state (e.g. virtio-gpio's wrapped
    /// `GpioBank`) for code that needs to drive it from outside the
    /// `Device` trait's guest-triggered read/write path — mirrors
    /// `VirtioLegacyPci::device_mut`.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.dev
    }

    /// As `VirtioLegacyPci::try_deliver_rx`, generalized to a flat byte
    /// buffer instead of a header+frame split (virtio-vsock's own
    /// packets are already one contiguous blob — see `vsock.rs`): pops
    /// the next available buffer on `queue_idx` (if the guest has posted
    /// one) and writes `data` into it, truncated to whatever room the
    /// guest's own buffer actually has. Returns the IRQ to pulse if a
    /// buffer was available, `None` if the guest hadn't posted one yet
    /// (the caller is responsible for retrying later — virtio-vsock
    /// simply drops it, matching a real NIC's own RX-buffer-exhaustion
    /// behavior, see that module's own doc comment) or the queue isn't
    /// configured.
    pub fn try_deliver_async(&mut self, queue_idx: u16, data: &[u8]) -> Option<u32> {
        let mut mem = self.mem.lock().unwrap();
        let queue = self.queues.get_mut(usize::from(queue_idx))?;
        if !queue.try_pop(&mem, &mut self.chain) {
            return None;
        }
        let mut written = 0usize;
        for buf in &self.chain.buffers {
            if !buf.device_writable {
                break;
            }
            let room = (buf.len as usize).min(data.len() - written);
            if room == 0 {
                break;
            }
            if !mem.write_checked(buf.addr, &data[written..written + room]) {
                break;
            }
            written += room;
            if written >= data.len() {
                break;
            }
        }
        self.queues[usize::from(queue_idx)].push_used(&mut mem, &self.chain, written as u32);
        self.isr |= ISR_USED_BUFFER;
        Some(u32::from(self.irq))
    }

    /// Drains `dev.take_outbox()` after a queue kick was just handled —
    /// see that trait method's own doc comment for why this can't just
    /// happen inside `process_chain` itself. Returns whether *any*
    /// delivery succeeded, for the caller to fold into its own "should I
    /// raise the IRQ" decision.
    fn deliver_outbox(&mut self) -> bool {
        let outbox = self.dev.take_outbox();
        let mut delivered = false;
        for (queue_idx, bytes) in outbox {
            delivered |= self.try_deliver_async(queue_idx, &bytes).is_some();
        }
        delivered
    }

    /// As `VirtioLegacyPci::drain_completions` — finishes every request
    /// the device's own async-completion mechanism has ready. Added here
    /// (rather than only on the legacy transport, where it originated for
    /// virtio-blk's io_uring backend) for virtio-gpio's event queue,
    /// which needs the identical `ChainOutcome::Pending`/`poll_completions`
    /// shape to defer a guest-armed interrupt buffer's completion until a
    /// real event fires, potentially much later than the kick that armed
    /// it.
    pub fn drain_completions(&mut self) -> Option<u32> {
        let completions = self.dev.poll_completions();
        if completions.is_empty() {
            return None;
        }
        let mut mem = self.mem.lock().unwrap();
        for c in &completions {
            mem.write_checked(c.status_buf_addr, &[c.status_byte]);
            let Some(queue) = self.queues.get(usize::from(c.queue_idx)) else { continue };
            queue.push_used_head(&mut mem, c.head_index, c.written_len + 1);
        }
        self.isr |= ISR_USED_BUFFER;
        Some(u32::from(self.irq))
    }

    /// Same draining logic as `VirtioLegacyPci::drain_queue` — kept as its
    /// own copy rather than shared, since the two transports' internal
    /// state (register file vs. common-cfg struct) differs enough that a
    /// shared helper would need its own indirection layer for no real
    /// benefit at this codebase's size. See
    /// `VirtioDeviceOps::wants_queue_notify`'s own doc comment for why the
    /// check below is here — no device uses this transport for a
    /// "guest-fills-later" queue today, but a future one might.
    fn drain_queue(&mut self, queue_idx: u16) -> bool {
        if !self.dev.wants_queue_notify(queue_idx) {
            return false;
        }
        let mut processed_any = false;
        loop {
            let mut mem = self.mem.lock().unwrap();
            let Some(queue) = self.queues.get_mut(usize::from(queue_idx)) else {
                return processed_any;
            };
            if !queue.try_pop(&mem, &mut self.chain) {
                return processed_any;
            }
            match self.dev.process_chain(queue_idx, &mut mem, &self.chain) {
                ChainOutcome::Done(written) => {
                    self.queues[usize::from(queue_idx)].push_used(&mut mem, &self.chain, written);
                    processed_any = true;
                }
                // See `VirtioLegacyPci::drain_queue`'s identical comment —
                // no device on this transport returns `Pending` today, but
                // the transport itself is agnostic to it.
                ChainOutcome::Pending => {}
            }
        }
    }

    fn host_features64(&self) -> u64 {
        u64::from(self.dev.host_features()) | VIRTIO_F_VERSION_1
    }

    fn read_common_cfg(&self, offset: u64, data: &mut [u8]) {
        let selected = self.queues.get(usize::from(self.queue_select));
        match offset {
            CFG_DFSELECT => read_le(self.device_feature_select.to_le_bytes(), data),
            CFG_DF => {
                let features = self.host_features64();
                let word = if self.device_feature_select == 1 { (features >> 32) as u32 } else { features as u32 };
                read_le(word.to_le_bytes(), data);
            }
            CFG_GFSELECT => read_le(self.guest_feature_select.to_le_bytes(), data),
            CFG_GF => {
                let word =
                    if self.guest_feature_select == 1 { (self.guest_features >> 32) as u32 } else { self.guest_features as u32 };
                read_le(word.to_le_bytes(), data);
            }
            CFG_MSIX => read_le(NO_VECTOR.to_le_bytes(), data),
            CFG_NUMQ => read_le((self.queues.len() as u16).to_le_bytes(), data),
            CFG_STATUS => read_le([self.status], data),
            CFG_CFGGEN => read_le([self.config_generation], data),
            CFG_QSELECT => read_le(self.queue_select.to_le_bytes(), data),
            CFG_QSIZE => read_le(selected.map_or(0, |q| q.size).to_le_bytes(), data),
            CFG_QMSIX => read_le(NO_VECTOR.to_le_bytes(), data),
            CFG_QENABLE => {
                let enabled: u16 = selected.is_some_and(VirtQueue::is_live).into();
                read_le(enabled.to_le_bytes(), data);
            }
            CFG_QNOFF => read_le(self.queue_select.to_le_bytes(), data),
            CFG_QDESCLO => read_le(lo32(selected.map_or(0, VirtQueue::desc_addr)).to_le_bytes(), data),
            CFG_QDESCHI => read_le(hi32(selected.map_or(0, VirtQueue::desc_addr)).to_le_bytes(), data),
            CFG_QAVAILLO => read_le(lo32(selected.map_or(0, VirtQueue::avail_addr)).to_le_bytes(), data),
            CFG_QAVAILHI => read_le(hi32(selected.map_or(0, VirtQueue::avail_addr)).to_le_bytes(), data),
            CFG_QUSEDLO => read_le(lo32(selected.map_or(0, VirtQueue::used_addr)).to_le_bytes(), data),
            CFG_QUSEDHI => read_le(hi32(selected.map_or(0, VirtQueue::used_addr)).to_le_bytes(), data),
            _ => {}
        }
    }

    fn write_common_cfg(&mut self, offset: u64, data: &[u8]) {
        match offset {
            CFG_DFSELECT if data.len() == 4 => {
                self.device_feature_select = u32::from_le_bytes(data.try_into().unwrap());
            }
            CFG_GFSELECT if data.len() == 4 => {
                self.guest_feature_select = u32::from_le_bytes(data.try_into().unwrap());
            }
            CFG_GF if data.len() == 4 => {
                let word = u32::from_le_bytes(data.try_into().unwrap());
                self.guest_features = if self.guest_feature_select == 1 {
                    set_addr_hi(self.guest_features, word)
                } else {
                    set_addr_lo(self.guest_features, word)
                };
            }
            CFG_STATUS if !data.is_empty() => {
                self.status = data[0];
                if self.status == 0 {
                    for q in &mut self.queues {
                        q.set_enabled(false);
                        q.last_avail_idx = 0;
                    }
                    self.isr = 0;
                    self.config_generation = self.config_generation.wrapping_add(1);
                }
            }
            CFG_QSELECT if data.len() == 2 => {
                self.queue_select = u16::from_le_bytes(data.try_into().unwrap());
            }
            CFG_QENABLE if data.len() >= 2 => {
                let val = u16::from_le_bytes(data[..2].try_into().unwrap());
                if let Some(q) = self.queues.get_mut(usize::from(self.queue_select)) {
                    q.set_enabled(val & 1 != 0);
                }
            }
            CFG_QDESCLO | CFG_QDESCHI | CFG_QAVAILLO | CFG_QAVAILHI | CFG_QUSEDLO | CFG_QUSEDHI if data.len() == 4 => {
                let val = u32::from_le_bytes(data.try_into().unwrap());
                if let Some(q) = self.queues.get_mut(usize::from(self.queue_select)) {
                    match offset {
                        CFG_QDESCLO => q.set_desc(set_addr_lo(q.desc_addr(), val)),
                        CFG_QDESCHI => q.set_desc(set_addr_hi(q.desc_addr(), val)),
                        CFG_QAVAILLO => q.set_avail(set_addr_lo(q.avail_addr(), val)),
                        CFG_QAVAILHI => q.set_avail(set_addr_hi(q.avail_addr(), val)),
                        CFG_QUSEDLO => q.set_used(set_addr_lo(q.used_addr(), val)),
                        CFG_QUSEDHI => q.set_used(set_addr_hi(q.used_addr(), val)),
                        _ => unreachable!(),
                    }
                }
            }
            _ => {}
        }
    }
}

impl<D: VirtioDeviceOps> crate::snapshot::Snapshot for VirtioModernPci<D> {
    fn save_state(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.device_feature_select.to_le_bytes());
        buf.extend_from_slice(&self.guest_feature_select.to_le_bytes());
        buf.extend_from_slice(&self.guest_features.to_le_bytes());
        buf.push(self.status);
        buf.push(self.config_generation);
        buf.extend_from_slice(&self.queue_select.to_le_bytes());
        buf.push(self.isr);
        buf.extend_from_slice(&(self.queues.len() as u32).to_le_bytes());
        for q in &self.queues {
            buf.extend_from_slice(&q.desc.to_le_bytes());
            buf.extend_from_slice(&q.avail.to_le_bytes());
            buf.extend_from_slice(&q.used.to_le_bytes());
            buf.push(u8::from(q.enabled));
            buf.extend_from_slice(&q.last_avail_idx.to_le_bytes());
        }
        buf
    }

    fn restore_state(&mut self, data: &[u8]) -> Result<(), String> {
        use crate::snapshot::{take_u8, take_u16, take_u32, take_u64};
        let mut buf = data;
        self.device_feature_select = take_u32(&mut buf)?;
        self.guest_feature_select = take_u32(&mut buf)?;
        self.guest_features = take_u64(&mut buf)?;
        self.status = take_u8(&mut buf)?;
        self.config_generation = take_u8(&mut buf)?;
        self.queue_select = take_u16(&mut buf)?;
        self.isr = take_u8(&mut buf)?;
        let n = take_u32(&mut buf)? as usize;
        if n != self.queues.len() {
            return Err(format!("snapshot has {n} queues, device has {}", self.queues.len()));
        }
        for q in &mut self.queues {
            q.desc = take_u64(&mut buf)?;
            q.avail = take_u64(&mut buf)?;
            q.used = take_u64(&mut buf)?;
            q.enabled = take_u8(&mut buf)? != 0;
            q.last_avail_idx = take_u16(&mut buf)?;
        }
        Ok(())
    }
}

impl<D: VirtioDeviceOps> PciDevice for VirtioModernPci<D> {
    fn vendor_id(&self) -> u16 {
        VIRTIO_VENDOR_ID
    }
    fn device_id(&self) -> u16 {
        0x1040 + self.device_type
    }
    fn class_code(&self) -> u32 {
        self.dev.pci_class_code()
    }
    fn revision_id(&self) -> u8 {
        1 // modern-only, per spec (0 is reserved for transitional)
    }
    fn bar_sizes(&self) -> [u32; NUM_BARS] {
        [self.bar_len, 0, 0, 0, 0, 0]
    }
    fn bar_is_io(&self, _index: usize) -> bool {
        false // modern transport is memory-mapped, not I/O-space
    }
    fn interrupt_line(&self) -> u8 {
        self.irq
    }
    fn extra_capabilities(&self) -> Vec<u8> {
        // Chained back-to-back within the buffer PciBus places at
        // EXTRA_CAP_OFFSET: common (16) -> notify (20, longer than the
        // others) -> isr (16) -> device (16, last: cap_next = 0).
        let common_off = EXTRA_CAP_OFFSET;
        let notify_off = common_off + VIRTIO_PCI_CAP_LEN as u16;
        let isr_off = notify_off + VIRTIO_PCI_NOTIFY_CAP_LEN as u16;
        let device_off = isr_off + VIRTIO_PCI_CAP_LEN as u16;

        let notify_len = (self.isr_base - self.notify_base) as u32;
        let common = build_cap(VIRTIO_PCI_CAP_COMMON_CFG, 0, 0, COMMON_CFG_LEN as u32, notify_off as u8);
        let isr =
            build_cap(VIRTIO_PCI_CAP_ISR_CFG, 0, self.isr_base as u32, ISR_REGION_LEN as u32, device_off as u8);
        let device = build_cap(
            VIRTIO_PCI_CAP_DEVICE_CFG,
            0,
            self.device_base as u32,
            self.bar_len - self.device_base as u32,
            0,
        );
        let mut notify =
            build_cap(VIRTIO_PCI_CAP_NOTIFY_CFG, 0, self.notify_base as u32, notify_len, isr_off as u8).to_vec();
        notify[2] = VIRTIO_PCI_NOTIFY_CAP_LEN as u8; // cap_len differs from the plain 16-byte structs
        notify.extend_from_slice(&NOTIFY_MULTIPLIER.to_le_bytes());

        let mut buf = Vec::with_capacity(VIRTIO_PCI_CAP_LEN * 3 + VIRTIO_PCI_NOTIFY_CAP_LEN);
        buf.extend_from_slice(&common);
        buf.extend_from_slice(&notify);
        buf.extend_from_slice(&isr);
        buf.extend_from_slice(&device);
        buf
    }
}

impl<D: VirtioDeviceOps> Device for VirtioModernPci<D> {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        if offset < COMMON_CFG_LEN {
            self.read_common_cfg(offset, data);
        } else if offset == self.isr_base {
            data[0] = self.isr;
            self.isr = 0; // read-to-clear, same convention as legacy
        } else if offset >= self.device_base {
            self.dev.read_config(offset - self.device_base, data);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        if offset < COMMON_CFG_LEN {
            self.write_common_cfg(offset, data);
        } else if offset >= self.notify_base && offset < self.isr_base {
            let idx = ((offset - self.notify_base) / u64::from(NOTIFY_MULTIPLIER)) as u16;
            let drained = self.drain_queue(idx);
            let delivered = self.deliver_outbox();
            if drained || delivered {
                self.isr |= ISR_USED_BUFFER;
                return true;
            }
        } else if offset >= self.device_base {
            self.dev.write_config(offset - self.device_base, data);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const QUEUE_SIZE: u16 = 4;
    const PFN: u32 = 0x10; // guest address 0x10000, arbitrary but page-aligned
    const MEM_SIZE: usize = 1024 * 1024;

    // Independently-computed layout offsets (not reusing VirtQueue's own
    // methods, so this is a real cross-check rather than a tautology).
    fn desc_addr() -> u64 {
        u64::from(PFN) << 12
    }
    fn avail_addr() -> u64 {
        desc_addr() + 16 * u64::from(QUEUE_SIZE)
    }
    fn used_addr() -> u64 {
        let avail_size = 4 + 2 * u64::from(QUEUE_SIZE) + 2;
        (avail_addr() + avail_size).div_ceil(4096) * 4096
    }

    fn new_queue_and_mem() -> (VirtQueue, GuestMemory) {
        let mut q = VirtQueue::new(QUEUE_SIZE);
        q.set_pfn(PFN);
        (q, GuestMemory::new(MEM_SIZE).unwrap())
    }

    fn write_desc(mem: &mut GuestMemory, index: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let d = desc_addr() + u64::from(index) * 16;
        mem.write_checked(d, &addr.to_le_bytes());
        mem.write_checked(d + 8, &len.to_le_bytes());
        mem.write_checked(d + 12, &flags.to_le_bytes());
        mem.write_checked(d + 14, &next.to_le_bytes());
    }

    fn post_avail(mem: &mut GuestMemory, ring_pos: u16, head_index: u16, new_avail_idx: u16) {
        let ring_slot = avail_addr() + 4 + u64::from(ring_pos % QUEUE_SIZE) * 2;
        mem.write_checked(ring_slot, &head_index.to_le_bytes());
        mem.write_checked(avail_addr() + 2, &new_avail_idx.to_le_bytes());
    }

    fn pop(q: &mut VirtQueue, mem: &GuestMemory) -> Option<DescChain> {
        let mut chain = DescChain::default();
        q.try_pop(mem, &mut chain).then_some(chain)
    }

    #[test]
    fn walks_a_two_descriptor_chain_correctly() {
        let (mut q, mut mem) = new_queue_and_mem();
        // desc0: readable, 16 bytes, chains to desc1. desc1: writable, 32
        // bytes, end of chain — mirrors a real virtio-blk request shape.
        write_desc(&mut mem, 0, 0x2000, 16, VIRTQ_DESC_F_NEXT, 1);
        write_desc(&mut mem, 1, 0x3000, 32, VIRTQ_DESC_F_WRITE, 0);
        post_avail(&mut mem, 0, 0, 1);

        let chain = pop(&mut q, &mem).expect("a chain was posted");
        assert_eq!(chain.head_index, 0);
        assert_eq!(chain.buffers.len(), 2);
        assert_eq!(chain.buffers[0].addr, 0x2000);
        assert_eq!(chain.buffers[0].len, 16);
        assert!(!chain.buffers[0].device_writable);
        assert_eq!(chain.buffers[1].addr, 0x3000);
        assert_eq!(chain.buffers[1].len, 32);
        assert!(chain.buffers[1].device_writable);
    }

    #[test]
    fn returns_none_when_nothing_new_is_posted() {
        let (mut q, mem) = new_queue_and_mem();
        // avail.idx starts at 0 in freshly-zeroed memory, matching
        // last_avail_idx's own initial value — nothing to pop.
        assert!(pop(&mut q, &mem).is_none());
    }

    #[test]
    fn does_not_repop_the_same_chain_twice() {
        let (mut q, mut mem) = new_queue_and_mem();
        write_desc(&mut mem, 0, 0x2000, 16, 0, 0);
        post_avail(&mut mem, 0, 0, 1);

        assert!(pop(&mut q, &mem).is_some());
        assert!(pop(&mut q, &mem).is_none(), "same avail_idx shouldn't produce a second chain");
    }

    #[test]
    fn a_cyclic_chain_terminates_instead_of_looping_forever() {
        // A buggy or malicious guest could point every descriptor's `next`
        // back at itself. try_pop must still return promptly, bounded by
        // queue size — this is the DoS-prevention property item 23 exists
        // to actually verify, not just assume from reading the loop bound.
        let (mut q, mut mem) = new_queue_and_mem();
        write_desc(&mut mem, 0, 0x2000, 8, VIRTQ_DESC_F_NEXT, 0); // points at itself
        post_avail(&mut mem, 0, 0, 1);

        let chain = pop(&mut q, &mem).expect("still returns a chain, not a hang");
        assert_eq!(chain.buffers.len(), QUEUE_SIZE as usize);
    }

    #[test]
    fn a_descriptor_index_past_the_table_is_rejected() {
        let (mut q, mut mem) = new_queue_and_mem();
        write_desc(&mut mem, 0, 0x2000, 8, VIRTQ_DESC_F_NEXT, QUEUE_SIZE + 5);
        post_avail(&mut mem, 0, 0, 1);
        assert!(pop(&mut q, &mem).is_none(), "next index outside the table must abort the walk");
    }

    #[test]
    fn an_out_of_bounds_buffer_is_rejected_before_any_device_sees_it() {
        // The check that bounds every downstream device's host-side
        // buffering: a 4 GiB descriptor used to reach virtio-blk/net/rng
        // and be `resize`d into a host allocation before anything checked.
        let (mut q, mut mem) = new_queue_and_mem();
        write_desc(&mut mem, 0, 0x2000, u32::MAX, 0, 0);
        post_avail(&mut mem, 0, 0, 1);
        assert!(pop(&mut q, &mem).is_none());
    }

    #[test]
    fn a_chain_totalling_more_than_guest_ram_is_rejected() {
        // Each buffer individually fits, but together they describe more
        // bytes than exist — the case a per-buffer check alone misses.
        let (mut q, mut mem) = new_queue_and_mem();
        let big = (MEM_SIZE / 2) as u32;
        for i in 0..QUEUE_SIZE {
            let last = i == QUEUE_SIZE - 1;
            let flags = if last { 0 } else { VIRTQ_DESC_F_NEXT };
            write_desc(&mut mem, i, 0, big, flags, i + 1);
        }
        post_avail(&mut mem, 0, 0, 1);
        assert!(pop(&mut q, &mem).is_none());
    }

    #[test]
    fn a_zero_sized_queue_is_inert_rather_than_dividing_by_zero() {
        let mut q = VirtQueue::new(0);
        q.set_pfn(PFN);
        let mut mem = GuestMemory::new(MEM_SIZE).unwrap();
        mem.write_checked(avail_addr() + 2, &1u16.to_le_bytes());
        assert!(pop(&mut q, &mem).is_none());
        q.push_used(&mut mem, &DescChain::default(), 0);
    }

    #[test]
    fn push_used_advances_the_ring_correctly() {
        let (q, mut mem) = new_queue_and_mem();
        let mut chain = DescChain::default();
        chain.reset(2);

        q.push_used(&mut mem, &chain, 42);

        let used_idx = mem.read_u16_checked(used_addr() + 2).unwrap();
        assert_eq!(used_idx, 1, "idx should advance by exactly one");
        let entry_id = mem.read_u32_checked(used_addr() + 4).unwrap();
        let entry_len = mem.read_u32_checked(used_addr() + 8).unwrap();
        assert_eq!(entry_id, 2);
        assert_eq!(entry_len, 42);

        // A second push wraps correctly into ring slot 1, not slot 0 again.
        chain.reset(3);
        q.push_used(&mut mem, &chain, 7);
        let second_entry_id = mem.read_u32_checked(used_addr() + 4 + 8).unwrap();
        assert_eq!(second_entry_id, 3);
    }

    #[test]
    fn copy_config_zero_fills_past_the_end_instead_of_reading_out_of_range() {
        let config = [1u8, 2, 3, 4];
        let mut data = [0xffu8; 6];
        copy_config(&config, 2, &mut data);
        assert_eq!(data, [3, 4, 0, 0, 0, 0]);

        let mut past = [0xffu8; 4];
        copy_config(&config, 99, &mut past);
        assert_eq!(past, [0; 4], "an offset past the config must read as zeroes");
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

        /// Generalizes `a_cyclic_chain_terminates_instead_of_looping_forever`,
        /// `a_descriptor_index_past_the_table_is_rejected`,
        /// `an_out_of_bounds_buffer_is_rejected_before_any_device_sees_it`,
        /// and `a_chain_totalling_more_than_guest_ram_is_rejected` into one
        /// property covering every combination at once: an *entire*
        /// descriptor table filled with adversarially-generated entries
        /// (arbitrary addr/len/flags/next per slot, including
        /// self-referential and forward-referential `next` values, and
        /// lengths spanning the full `u32` range). Whatever `try_pop`
        /// produces, it must uphold the two invariants every downstream
        /// device (`virtio_blk`/`virtio_net`/`virtio_rng`) depends on
        /// without re-checking themselves: every returned buffer lies
        /// entirely within guest RAM, and the chain's total length never
        /// exceeds it. The call itself must also simply return — the
        /// `for _ in 0..self.size` bound in `try_pop` guarantees
        /// termination structurally, so this is confirming that guarantee
        /// holds under generated adversarial input, not discovering
        /// whether it does.
        #[test]
        fn try_pop_never_returns_an_out_of_bounds_or_oversized_chain(
            descs in proptest::collection::vec(
                (any::<u64>(), any::<u32>(), any::<u16>(), 0u16..QUEUE_SIZE * 2),
                QUEUE_SIZE as usize..=QUEUE_SIZE as usize,
            ),
            head in 0u16..QUEUE_SIZE,
        ) {
            let (mut q, mut mem) = new_queue_and_mem();
            for (i, (addr, len, flags, next)) in descs.iter().enumerate() {
                write_desc(&mut mem, i as u16, *addr, *len, *flags, *next);
            }
            post_avail(&mut mem, 0, head, 1);

            if let Some(chain) = pop(&mut q, &mem) {
                let mut total = 0u64;
                for b in &chain.buffers {
                    prop_assert!(
                        mem.in_bounds(b.addr, u64::from(b.len)),
                        "try_pop handed back a buffer outside guest RAM: {:#x}+{}",
                        b.addr, b.len
                    );
                    total += u64::from(b.len);
                }
                prop_assert!(total <= mem.size() as u64, "chain total exceeded guest RAM");
                prop_assert!(chain.buffers.len() <= QUEUE_SIZE as usize);
            }
            // Reaching here at all, for every one of `cases` generated
            // inputs, is itself part of what's being checked: a hang would
            // time out the test rather than report a clean failure.
        }

        /// A chain that *is* fully well-formed (every descriptor points
        /// inside guest RAM, indices in range, no cycle) is always
        /// accepted, with every buffer surviving intact and in the right
        /// order — the positive counterpart to the adversarial property
        /// above, so a fix that made `try_pop` *too* strict would also be
        /// caught here, not just a fix that made it too permissive.
        #[test]
        fn a_well_formed_chain_is_always_accepted_with_buffers_intact(
            addrs in proptest::collection::vec(0u64..(MEM_SIZE as u64 - 4096), QUEUE_SIZE as usize),
            lens in proptest::collection::vec(1u32..4096, QUEUE_SIZE as usize),
        ) {
            let (mut q, mut mem) = new_queue_and_mem();
            for i in 0..QUEUE_SIZE {
                let last = i == QUEUE_SIZE - 1;
                let flags = if last { 0 } else { VIRTQ_DESC_F_NEXT };
                write_desc(&mut mem, i, addrs[i as usize], lens[i as usize], flags, i + 1);
            }
            post_avail(&mut mem, 0, 0, 1);

            let chain = pop(&mut q, &mem).expect("a well-formed chain must always be accepted");
            prop_assert_eq!(chain.buffers.len(), QUEUE_SIZE as usize);
            for (i, b) in chain.buffers.iter().enumerate() {
                prop_assert_eq!(b.addr, addrs[i]);
                prop_assert_eq!(b.len, lens[i]);
            }
        }
    }
}

#[cfg(test)]
mod modern_pci_tests {
    use super::*;

    /// A minimal `VirtioDeviceOps` impl for driving `VirtioModernPci`
    /// directly, independent of any real device (block/net/rng) — records
    /// what it's handed rather than doing real I/O, so tests can assert on
    /// it.
    #[derive(Default)]
    struct DummyDev {
        config: Vec<u8>,
        processed_chain_lens: Vec<usize>,
    }

    impl VirtioDeviceOps for DummyDev {
        fn legacy_pci_device_id(&self) -> u16 {
            0 // unused by the modern transport
        }
        fn virtio_device_type(&self) -> u16 {
            0 // unused by the modern transport
        }
        fn pci_class_code(&self) -> u32 {
            0xff_00_00
        }
        fn num_queues(&self) -> u16 {
            1
        }
        fn queue_size(&self, _queue: u16) -> u16 {
            4
        }
        fn host_features(&self) -> u32 {
            0x2a
        }
        fn read_config(&self, offset: u64, data: &mut [u8]) {
            copy_config(&self.config, offset, data);
        }
        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let Ok(offset) = usize::try_from(offset) else { return };
            if let Some(dst) = self.config.get_mut(offset..offset + data.len()) {
                dst.copy_from_slice(data);
            }
        }
        fn process_chain(&mut self, _queue: u16, _mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome {
            self.processed_chain_lens.push(chain.buffers.len());
            ChainOutcome::Done(7) // arbitrary "bytes written" for the used ring
        }
    }

    const DEVICE_TYPE: u16 = 4; // entropy source, arbitrary for these tests
    const MEM_SIZE: usize = 1024 * 1024;

    fn new_modern(config_len: u32) -> (VirtioModernPci<DummyDev>, Arc<Mutex<GuestMemory>>) {
        let mem = Arc::new(Mutex::new(GuestMemory::new(MEM_SIZE).unwrap()));
        let dev = DummyDev { config: vec![0; config_len as usize], ..Default::default() };
        (VirtioModernPci::new(dev, mem.clone(), 11, DEVICE_TYPE, config_len), mem)
    }

    fn r32(dev: &mut VirtioModernPci<DummyDev>, offset: u64) -> u32 {
        let mut buf = [0u8; 4];
        dev.read(offset, &mut buf);
        u32::from_le_bytes(buf)
    }
    fn w32(dev: &mut VirtioModernPci<DummyDev>, offset: u64, val: u32) -> bool {
        dev.write(offset, &val.to_le_bytes())
    }
    fn r16(dev: &mut VirtioModernPci<DummyDev>, offset: u64) -> u16 {
        let mut buf = [0u8; 2];
        dev.read(offset, &mut buf);
        u16::from_le_bytes(buf)
    }
    fn w16(dev: &mut VirtioModernPci<DummyDev>, offset: u64, val: u16) {
        dev.write(offset, &val.to_le_bytes());
    }
    fn r8(dev: &mut VirtioModernPci<DummyDev>, offset: u64) -> u8 {
        let mut buf = [0u8; 1];
        dev.read(offset, &mut buf);
        buf[0]
    }

    #[test]
    fn advertises_the_modern_pci_id_and_revision() {
        let (dev, _mem) = new_modern(0);
        assert_eq!(dev.device_id(), 0x1040 + DEVICE_TYPE, "modern id must be 0x1040 + device type");
        assert_eq!(dev.vendor_id(), VIRTIO_VENDOR_ID);
        assert_eq!(dev.revision_id(), 1, "revision 0 is reserved for the transitional layout");
        assert!(dev.bar_sizes()[0].is_power_of_two(), "a PCI BAR size must be a power of two");
        assert!(!dev.bar_is_io(0), "modern virtio is memory-mapped, not I/O-space");
    }

    #[test]
    fn the_capability_chain_decodes_to_all_four_real_regions_in_order() {
        let (dev, _mem) = new_modern(8);
        let caps = dev.extra_capabilities();

        // Walk the chain the same way a real guest's PCI core would: start
        // at offset 0 of this buffer (== EXTRA_CAP_OFFSET on the bus), and
        // follow each entry's own cap_next byte.
        let mut offset = 0usize;
        let mut seen_types = Vec::new();
        loop {
            let entry = &caps[offset..];
            assert_eq!(entry[0], CAP_ID_VENDOR_SPECIFIC, "every entry must be a vendor-specific cap");
            let cap_len = entry[2] as usize;
            let cfg_type = entry[3];
            seen_types.push(cfg_type);
            let cap_next = entry[1];
            if cap_next == 0 {
                break;
            }
            offset = usize::from(cap_next) - usize::from(EXTRA_CAP_OFFSET);
            let _ = cap_len;
        }
        assert_eq!(
            seen_types,
            vec![
                VIRTIO_PCI_CAP_COMMON_CFG,
                VIRTIO_PCI_CAP_NOTIFY_CFG,
                VIRTIO_PCI_CAP_ISR_CFG,
                VIRTIO_PCI_CAP_DEVICE_CFG
            ]
        );

        // The notify capability carries a trailing notify_off_multiplier
        // the other three don't have.
        let notify_start = VIRTIO_PCI_CAP_LEN;
        let multiplier = u32::from_le_bytes(
            caps[notify_start + VIRTIO_PCI_CAP_LEN..notify_start + VIRTIO_PCI_NOTIFY_CAP_LEN].try_into().unwrap(),
        );
        assert_eq!(multiplier, NOTIFY_MULTIPLIER);
    }

    #[test]
    fn device_feature_select_exposes_version_1_alongside_the_devices_own_bits() {
        let (mut dev, _mem) = new_modern(0);
        w32(&mut dev, CFG_DFSELECT, 0);
        assert_eq!(r32(&mut dev, CFG_DF), 0x2a, "low word must be the device's own host_features()");

        w32(&mut dev, CFG_DFSELECT, 1);
        assert_eq!(r32(&mut dev, CFG_DF), 1, "high word bit 0 is VIRTIO_F_VERSION_1 (feature bit 32)");
    }

    #[test]
    fn queue_msix_and_msix_config_always_report_no_vector() {
        // No MSI-X capability is ever advertised (see the module doc
        // comment) — a driver that somehow still probed these fields must
        // see "no vector assigned", never a bogus real-looking one.
        let (mut dev, _mem) = new_modern(0);
        assert_eq!(r16(&mut dev, CFG_MSIX), NO_VECTOR);
        w16(&mut dev, CFG_QSELECT, 0);
        assert_eq!(r16(&mut dev, CFG_QMSIX), NO_VECTOR);
    }

    #[test]
    fn queue_setup_via_independent_addresses_then_notify_delivers_a_chain() {
        let (mut dev, mem) = new_modern(0);

        // Real guest addresses, deliberately not derived from a single PFN
        // — the entire point of the modern layout under test.
        let desc: u64 = 0x9000;
        let avail: u64 = 0xa000;
        let used: u64 = 0xb000;

        {
            let mut m = mem.lock().unwrap();
            // One descriptor: 16 device-readable bytes, end of chain.
            m.write_checked(desc, &0x2000u64.to_le_bytes());
            m.write_checked(desc + 8, &16u32.to_le_bytes());
            m.write_checked(desc + 12, &0u16.to_le_bytes());
            m.write_checked(desc + 14, &0u16.to_le_bytes());
            // avail ring: idx = 1, ring[0] = 0 (head index 0).
            m.write_checked(avail + 4, &0u16.to_le_bytes());
            m.write_checked(avail + 2, &1u16.to_le_bytes());
        }

        w16(&mut dev, CFG_QSELECT, 0);
        w32(&mut dev, CFG_QDESCLO, desc as u32);
        w32(&mut dev, CFG_QDESCHI, (desc >> 32) as u32);
        w32(&mut dev, CFG_QAVAILLO, avail as u32);
        w32(&mut dev, CFG_QAVAILHI, (avail >> 32) as u32);
        w32(&mut dev, CFG_QUSEDLO, used as u32);
        w32(&mut dev, CFG_QUSEDHI, (used >> 32) as u32);
        w16(&mut dev, CFG_QENABLE, 1);
        assert_eq!(r16(&mut dev, CFG_QENABLE), 1, "queue_enable must read back what was written");

        // Notify offset for queue 0 is queue_notify_off (0) *
        // notify_off_multiplier — the notify region's very first dword.
        let notify_off = dev.notify_base;
        let raised = dev.write(notify_off, &0u16.to_le_bytes());
        assert!(raised, "a live queue with an available chain must request an interrupt");
        assert_eq!(dev.dev.processed_chain_lens, vec![1]);

        // ISR is read-to-clear.
        let isr_base = dev.isr_base;
        assert_eq!(r8(&mut dev, isr_base), 1);
        assert_eq!(r8(&mut dev, isr_base), 0);
    }

    #[test]
    fn setting_device_status_to_zero_disables_every_queue() {
        let (mut dev, _mem) = new_modern(0);
        w16(&mut dev, CFG_QSELECT, 0);
        w32(&mut dev, CFG_QDESCLO, 0x9000);
        w32(&mut dev, CFG_QAVAILLO, 0xa000);
        w32(&mut dev, CFG_QUSEDLO, 0xb000);
        w16(&mut dev, CFG_QENABLE, 1);
        assert_eq!(r16(&mut dev, CFG_QENABLE), 1);

        dev.write(CFG_STATUS, &[0]);
        assert_eq!(r16(&mut dev, CFG_QENABLE), 0, "a guest-initiated reset must disable every queue");
    }

    #[test]
    fn device_config_region_reads_and_writes_pass_straight_through() {
        let (mut dev, _mem) = new_modern(4);
        let base = dev.device_base;
        dev.write(base, &[1, 2, 3, 4]);
        let mut out = [0u8; 4];
        dev.read(base, &mut out);
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(dev.dev.config, vec![1, 2, 3, 4]);
    }

    #[test]
    fn snapshot_round_trip_preserves_feature_negotiation_and_queue_state() {
        use crate::snapshot::Snapshot;
        let (mut dev, _mem) = new_modern(0);
        w32(&mut dev, CFG_DFSELECT, 1);
        w32(&mut dev, CFG_GFSELECT, 1);
        w32(&mut dev, CFG_GF, 1); // VIRTIO_F_VERSION_1
        w16(&mut dev, CFG_QSELECT, 0);
        w32(&mut dev, CFG_QDESCLO, 0x9000);
        w32(&mut dev, CFG_QAVAILLO, 0xa000);
        w32(&mut dev, CFG_QUSEDLO, 0xb000);
        w16(&mut dev, CFG_QENABLE, 1);
        dev.write(CFG_STATUS, &[0x08]); // FEATURES_OK

        let blob = dev.save_state();
        let (mut fresh, _mem2) = new_modern(0);
        fresh.restore_state(&blob).unwrap();

        w16(&mut fresh, CFG_QSELECT, 0);
        assert_eq!(r32(&mut fresh, CFG_QDESCLO), 0x9000);
        assert_eq!(r32(&mut fresh, CFG_QAVAILLO), 0xa000);
        assert_eq!(r32(&mut fresh, CFG_QUSEDLO), 0xb000);
        assert_eq!(r16(&mut fresh, CFG_QENABLE), 1);
        assert_eq!(r8(&mut fresh, CFG_STATUS), 0x08);
        w32(&mut fresh, CFG_GFSELECT, 1);
        assert_eq!(r32(&mut fresh, CFG_GF), 1, "negotiated VIRTIO_F_VERSION_1 must survive the round trip");
    }

    #[test]
    fn restoring_a_queue_count_mismatch_is_a_clean_error() {
        use crate::snapshot::Snapshot;
        let (dev, _mem) = new_modern(0);
        let blob = dev.save_state();
        // A device built for a different `num_queues()` — restoring
        // against it must fail cleanly rather than desync silently or
        // panic out-of-bounds.
        struct OtherDev;
        impl VirtioDeviceOps for OtherDev {
            fn legacy_pci_device_id(&self) -> u16 {
                0
            }
            fn virtio_device_type(&self) -> u16 {
                0
            }
            fn pci_class_code(&self) -> u32 {
                0
            }
            fn num_queues(&self) -> u16 {
                2
            }
            fn queue_size(&self, _queue: u16) -> u16 {
                4
            }
            fn read_config(&self, _offset: u64, data: &mut [u8]) {
                data.fill(0);
            }
            fn process_chain(&mut self, _queue: u16, _mem: &mut GuestMemory, _chain: &DescChain) -> ChainOutcome {
                ChainOutcome::Done(0)
            }
        }
        let mem2 = Arc::new(Mutex::new(GuestMemory::new(MEM_SIZE).unwrap()));
        let mut other = VirtioModernPci::new(OtherDev, mem2, 11, DEVICE_TYPE, 0);
        assert!(other.restore_state(&blob).is_err());
    }
}

#[cfg(test)]
mod legacy_snapshot_tests {
    use super::*;

    #[derive(Default)]
    struct DummyDev;
    impl VirtioDeviceOps for DummyDev {
        fn legacy_pci_device_id(&self) -> u16 {
            0
        }
        fn virtio_device_type(&self) -> u16 {
            0
        }
        fn pci_class_code(&self) -> u32 {
            0xff_00_00
        }
        fn num_queues(&self) -> u16 {
            1
        }
        fn queue_size(&self, _queue: u16) -> u16 {
            4
        }
        fn read_config(&self, _offset: u64, data: &mut [u8]) {
            data.fill(0);
        }
        fn process_chain(&mut self, _queue: u16, _mem: &mut GuestMemory, _chain: &DescChain) -> ChainOutcome {
            ChainOutcome::Done(0)
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_pfn_and_avail_index() {
        use crate::snapshot::Snapshot;
        let mem = Arc::new(Mutex::new(GuestMemory::new(1024 * 1024).unwrap()));
        let mut dev = VirtioLegacyPci::new(DummyDev, mem.clone(), 10);
        dev.write(0x08, &0x10u32.to_le_bytes()); // REG_QUEUE_ADDRESS: pfn=0x10
        dev.write(0x12, &[0x0f]); // REG_DEVICE_STATUS

        let blob = dev.save_state();
        let mut fresh = VirtioLegacyPci::new(DummyDev, mem, 10);
        fresh.restore_state(&blob).unwrap();

        let mut data = [0u8; 4];
        fresh.read(0x08, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0x10, "queue PFN must be restored");
        let mut status = [0u8; 1];
        fresh.read(0x12, &mut status);
        assert_eq!(status[0], 0x0f, "device status must be restored");
    }
}
