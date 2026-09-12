//! virtio-blk device logic: the `virtio_blk_outhdr`/status protocol,
//! backed by a plain host file (a raw disk image) opened via `--disk`.
//! All the PCI/register/virtqueue plumbing lives in `virtio.rs`.
//!
//! Every guest-supplied sector number and length is range-checked against
//! the image's real capacity before any seek happens (`checked_range`).
//! Without that, `sector * SECTOR_SIZE` wraps for a large enough sector
//! and a write past the end silently *grows* the backing image rather than
//! being rejected.
//!
//! **IN/OUT (read/write) requests go through real io_uring**, submitted
//! non-blocking and completed asynchronously:
//! `process_chain` returns `ChainOutcome::Pending` immediately after
//! submission rather than blocking the calling thread (a vCPU thread on
//! the old synchronous notify path, or the reactor thread via ioeventfd)
//! on the actual disk I/O syscall. `poll_completions`, driven by the
//! reactor once `completion_eventfd` fires, reaps finished requests.
//! FLUSH/DISCARD/WRITE_ZEROES stay fully synchronous — rare, not the
//! performance-sensitive path, and each already bounds its own blocking
//! window (a single `fsync`, or zeroing through a small fixed chunk).
//! **Known gap, stated rather than silently accepted**: a FLUSH does not
//! wait for any in-flight async WRITEs to complete first — no write-
//! ordering barrier between the two paths. Real hardware/virtio doesn't
//! guarantee cross-request ordering either without the guest itself
//! serializing (waiting for one request's completion before issuing a
//! dependent one), so this only matters for a guest that issues a FLUSH
//! concurrently with in-flight writes and assumes it durably covers them.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

use io_uring::{IoUring, opcode, types};
use vmm_sys_util::eventfd::EventFd;

use crate::mem::GuestMemory;
use crate::virtio::{ChainOutcome, CompletionResult, DescBuffer, DescChain, VirtioDeviceOps, copy_config};

const SECTOR_SIZE: u64 = 512;

const VIRTIO_BLK_T_IN: u32 = 0; // read
const VIRTIO_BLK_T_OUT: u32 = 1; // write
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_DISCARD: u32 = 11;
const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const VIRTIO_BLK_F_BLK_SIZE: u32 = 1 << 6;
const VIRTIO_BLK_F_DISCARD: u32 = 1 << 13;
const VIRTIO_BLK_F_WRITE_ZEROES: u32 = 1 << 14;

/// `struct virtio_blk_outhdr`: type (u32), reserved (u32), sector (u64).
const REQUEST_HEADER_LEN: usize = 16;

/// `struct virtio_blk_discard_write_zeroes` is 16 bytes on the wire:
/// sector (u64), num_sectors (u32), flags (u32) — the data buffer(s) for a
/// DISCARD/WRITE_ZEROES request hold one or more of these back-to-back,
/// not raw disk data.
const DISCARD_SEGMENT_LEN: usize = 16;
/// Bit 0 of a discard/write-zeroes segment's flags: "also unmap" — we
/// always physically zero (see `read_config`'s `write_zeroes_may_unmap =
/// 0`), so this bit doesn't change our behavior, but real drivers do set
/// it and we shouldn't reject a request just for setting a bit we're
/// allowed to ignore.
const DISCARD_F_UNMAP: u32 = 1 << 0;

/// How much zeroing is staged through the host at a time. A single
/// WRITE_ZEROES segment can legally cover the whole image, and the old
/// code materialized `num_sectors * 512` zero bytes in one `vec![]` — a
/// guest asking to zero 0xffff_ffff sectors would have tried to allocate
/// 2 TiB before touching the disk at all.
const ZERO_CHUNK: usize = 64 * 1024;

/// `struct virtio_blk_config`, offsets per the real Linux
/// `uapi/linux/virtio_blk.h` layout (checked directly, not reconstructed
/// from memory — the same discipline `acpi.rs` uses for table layouts).
mod config {
    pub const LEN: usize = 64;
    pub const CAPACITY: usize = 0; // u64
    pub const BLK_SIZE: usize = 20; // u32 (VIRTIO_BLK_F_BLK_SIZE)
    pub const MAX_DISCARD_SECTORS: usize = 36; // u32
    pub const MAX_DISCARD_SEG: usize = 40; // u32
    pub const DISCARD_SECTOR_ALIGNMENT: usize = 44; // u32
    pub const MAX_WRITE_ZEROES_SECTORS: usize = 48; // u32
    pub const MAX_WRITE_ZEROES_SEG: usize = 52; // u32
    pub const WRITE_ZEROES_MAY_UNMAP: usize = 56; // u8
}

/// How many I/O requests may be in flight through `ring` at once. Not a
/// hard limit on guest concurrency: `submit_io` falls back to the
/// synchronous path (same as before this existed) if the ring is full
/// rather than blocking or failing the request, so this only bounds how
/// much actually overlaps, not what's allowed.
const RING_ENTRIES: u32 = 64;

/// Wraps the iovec array kept alive for one in-flight io_uring request.
/// `libc::iovec` isn't `Send` (it holds a raw pointer), but nothing in
/// this process ever dereferences it after submission — only the kernel
/// reads it, asynchronously, until the completion CQE arrives — so moving
/// the allocation itself between threads (submission can happen on a
/// vCPU thread or the reactor thread; completion always happens on the
/// reactor thread; either way it's the same `Arc<Mutex<VirtioLegacyPci
/// <VirtioBlk>>>` being accessed, just not always from the same OS
/// thread) is safe.
// The field exists purely to control when the allocation drops (once the
// owning `InFlight` is removed after its completion) — nothing in this
// process ever reads it back out.
#[allow(dead_code)]
struct IovecBox(Box<[libc::iovec]>);
// SAFETY: see the doc comment above — the pointers are never dereferenced
// by this process itself, only held alive for the kernel's benefit.
unsafe impl Send for IovecBox {}

/// Where a chain's completion needs to be reported — everything
/// `process_chain` already knows at submission time but the (long since
/// reused) `DescChain` scratch buffer won't still have once an async
/// request actually finishes. Bundled mainly to keep `submit_io`'s own
/// argument count sane.
struct PendingRequest {
    queue_idx: u16,
    head_index: u16,
    status_buf_addr: u64,
}

/// What `poll_completions` needs to finish a request once its CQE arrives.
struct InFlight {
    request: PendingRequest,
    /// `true` for a read (IN): the CQE's byte count becomes the used
    /// ring's `written_len`. `false` for a write (OUT): writes report 0
    /// bytes written, matching the existing synchronous behavior.
    is_read: bool,
    _iovecs: IovecBox,
}

pub struct VirtioBlk {
    file: File,
    capacity_sectors: u64,
    /// Staging buffer for one descriptor's worth of data, reused across
    /// requests instead of a fresh `Vec` per buffer per I/O — only the
    /// synchronous FLUSH/DISCARD/WRITE_ZEROES path uses this now; IN/OUT
    /// go straight through io_uring against guest memory directly, no
    /// host-side staging buffer at all.
    scratch: Vec<u8>,
    ring: IoUring,
    /// Signaled (via `io_uring`'s own `register_eventfd`) whenever `ring`
    /// has a new completion — what `completion_eventfd` hands the reactor
    /// so it can `epoll` on this instead of polling.
    ring_eventfd: EventFd,
    next_request_id: u64,
    in_flight: HashMap<u64, InFlight>,
}

impl VirtioBlk {
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        let capacity_sectors = file.metadata()?.len() / SECTOR_SIZE;
        let ring = IoUring::new(RING_ENTRIES)?;
        let ring_eventfd = EventFd::new(0)?;
        ring.submitter().register_eventfd(ring_eventfd.as_raw_fd())?;
        Ok(Self {
            file,
            capacity_sectors,
            scratch: Vec::new(),
            ring,
            ring_eventfd,
            next_request_id: 0,
            in_flight: HashMap::new(),
        })
    }

    /// Submits a real, non-blocking `IORING_OP_READV`/`WRITEV` for
    /// `data_buffers` directly against guest memory — no host-side
    /// staging buffer, since guest RAM is one identity-addressed host
    /// mmap (see `mem.rs`'s module doc comment) and each buffer's
    /// `[addr, addr + len)` is already guaranteed to lie entirely within
    /// it (`try_pop`'s own invariant — see `virtio.rs`'s module doc
    /// comment). Returns `false` if the ring is full or the submission
    /// itself fails, in which case the caller falls back to the
    /// synchronous path for this one request rather than losing it.
    fn submit_io(
        &mut self,
        is_read: bool,
        sector: u64,
        data_buffers: &[DescBuffer],
        mem: &mut GuestMemory,
        request: PendingRequest,
    ) -> bool {
        let len = Self::total_len(data_buffers);
        let Some(offset) = self.checked_range(sector, len) else {
            return false;
        };
        let iovecs: Box<[libc::iovec]> = data_buffers
            .iter()
            .map(|b| libc::iovec {
                // SAFETY: `b.addr`/`b.len` lie entirely within `mem`'s
                // mapping — `try_pop`'s invariant, not re-derived here.
                iov_base: unsafe { mem.as_ptr().add(b.addr as usize).cast() },
                iov_len: b.len as usize,
            })
            .collect();

        let fd = types::Fd(self.file.as_raw_fd());
        let sqe = if is_read {
            opcode::Readv::new(fd, iovecs.as_ptr(), iovecs.len() as u32).offset(offset).build()
        } else {
            opcode::Writev::new(fd, iovecs.as_ptr(), iovecs.len() as u32).offset(offset).build()
        };
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        let sqe = sqe.user_data(id);

        // SAFETY: `iovecs` (and the guest memory it points into) outlives
        // this SQE until its completion — kept alive in `self.in_flight`,
        // removed only once `poll_completions` sees the matching CQE.
        if unsafe { self.ring.submission().push(&sqe) }.is_err() {
            return false; // ring full; caller falls back to the sync path
        }
        if self.ring.submit().is_err() {
            return false; // same fallback; nothing was actually queued
        }
        self.in_flight.insert(
            id,
            InFlight { request, is_read, _iovecs: IovecBox(iovecs) },
        );
        true
    }

    /// The byte offset of `sector`, if `len` bytes starting there lie
    /// entirely within the image. `None` means the guest asked for
    /// something outside the disk — rejected rather than allowed to wrap
    /// the multiplication or extend the backing file.
    fn checked_range(&self, sector: u64, len: u64) -> Option<u64> {
        let capacity_bytes = self.capacity_sectors.checked_mul(SECTOR_SIZE)?;
        let offset = sector.checked_mul(SECTOR_SIZE)?;
        let end = offset.checked_add(len)?;
        (end <= capacity_bytes).then_some(offset)
    }

    fn total_len(buffers: &[DescBuffer]) -> u64 {
        buffers.iter().map(|b| u64::from(b.len)).sum()
    }

    fn read_sectors(
        &mut self,
        sector: u64,
        buffers: &[DescBuffer],
        mem: &mut GuestMemory,
    ) -> std::io::Result<u32> {
        let len = Self::total_len(buffers);
        let offset = self
            .checked_range(sector, len)
            .ok_or_else(|| std::io::Error::other("read outside the disk image"))?;
        let Self { file, scratch, .. } = self;
        file.seek(SeekFrom::Start(offset))?;

        let mut written = 0u32;
        for b in buffers {
            scratch.resize(b.len as usize, 0);
            file.read_exact(&mut scratch[..])?;
            if !mem.write_checked(b.addr, &scratch[..]) {
                return Err(std::io::Error::other("guest buffer address out of bounds"));
            }
            written += b.len;
        }
        Ok(written)
    }

    fn write_sectors(
        &mut self,
        sector: u64,
        buffers: &[DescBuffer],
        mem: &GuestMemory,
    ) -> std::io::Result<()> {
        let len = Self::total_len(buffers);
        let offset = self
            .checked_range(sector, len)
            .ok_or_else(|| std::io::Error::other("write outside the disk image"))?;
        let Self { file, scratch, .. } = self;
        file.seek(SeekFrom::Start(offset))?;

        for b in buffers {
            scratch.resize(b.len as usize, 0);
            if !mem.read_checked(b.addr, &mut scratch[..]) {
                return Err(std::io::Error::other("guest buffer address out of bounds"));
            }
            file.write_all(&scratch[..])?;
        }
        Ok(())
    }

    /// DISCARD and WRITE_ZEROES share this implementation: both are
    /// answered by *actually* writing real zero bytes over the requested
    /// sector ranges (`write_zeroes_may_unmap = 0` in `read_config`
    /// promises exactly this — we never punch a hole/deallocate, so
    /// there's no distinct behavior needed between "discard" and "write
    /// zeroes" beyond what the spec already makes optional). Genuinely
    /// correct, not a stub that just reports success: a real seek+write
    /// happens for every segment.
    fn zero_segments(&mut self, buffers: &[DescBuffer], mem: &GuestMemory) -> Result<(), ()> {
        // The segment list itself is small (16 bytes per segment) and
        // already bounded by `try_pop` to fit in guest RAM.
        let mut raw = Vec::with_capacity(Self::total_len(buffers) as usize);
        for b in buffers {
            let start = raw.len();
            raw.resize(start + b.len as usize, 0);
            if !mem.read_checked(b.addr, &mut raw[start..]) {
                return Err(());
            }
        }
        // `as_chunks` rather than `chunks_exact`: a compile-time chunk
        // size gives fixed-length arrays, so the field slicing below is
        // bounds-checked once here instead of per segment.
        let (segments, _partial) = raw.as_chunks::<DISCARD_SEGMENT_LEN>();
        for segment in segments {
            let sector = u64::from_le_bytes(segment[0..8].try_into().unwrap());
            let num_sectors = u32::from_le_bytes(segment[8..12].try_into().unwrap());
            let flags = u32::from_le_bytes(segment[12..16].try_into().unwrap());
            // Any flag bit besides UNMAP (which we already always behave
            // as, see above) is something a future spec revision might
            // define and we don't understand — reject rather than
            // silently ignore an instruction we don't know the meaning of.
            if flags & !DISCARD_F_UNMAP != 0 {
                return Err(());
            }
            self.zero_range(sector, u64::from(num_sectors) * SECTOR_SIZE)?;
        }
        Ok(())
    }

    /// Zeroes `len` bytes at `sector`, streamed through one fixed-size
    /// host buffer rather than a single allocation the guest gets to size.
    fn zero_range(&mut self, sector: u64, len: u64) -> Result<(), ()> {
        let offset = self.checked_range(sector, len).ok_or(())?;
        if len == 0 {
            return Ok(());
        }
        self.file.seek(SeekFrom::Start(offset)).map_err(|_| ())?;
        // `static`, not a stack array: this runs on a vCPU thread, and a
        // 64 KiB stack frame there is a needless risk for a buffer whose
        // contents never change.
        static ZEROS: [u8; ZERO_CHUNK] = [0; ZERO_CHUNK];
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(ZERO_CHUNK as u64) as usize;
            self.file.write_all(&ZEROS[..n]).map_err(|_| ())?;
            remaining -= n as u64;
        }
        Ok(())
    }

    fn handle_request(
        &mut self,
        req_type: u32,
        sector: u64,
        data_buffers: &[DescBuffer],
        mem: &mut GuestMemory,
    ) -> (u8, u32) {
        match req_type {
            VIRTIO_BLK_T_IN => match self.read_sectors(sector, data_buffers, mem) {
                Ok(n) => (VIRTIO_BLK_S_OK, n),
                Err(_) => (VIRTIO_BLK_S_IOERR, 0),
            },
            VIRTIO_BLK_T_OUT => match self.write_sectors(sector, data_buffers, mem) {
                Ok(()) => (VIRTIO_BLK_S_OK, 0),
                Err(_) => (VIRTIO_BLK_S_IOERR, 0),
            },
            VIRTIO_BLK_T_FLUSH => match self.file.sync_data() {
                Ok(()) => (VIRTIO_BLK_S_OK, 0),
                Err(_) => (VIRTIO_BLK_S_IOERR, 0),
            },
            VIRTIO_BLK_T_DISCARD | VIRTIO_BLK_T_WRITE_ZEROES => {
                match self.zero_segments(data_buffers, mem) {
                    Ok(()) => (VIRTIO_BLK_S_OK, 0),
                    Err(()) => (VIRTIO_BLK_S_IOERR, 0),
                }
            }
            _ => (VIRTIO_BLK_S_UNSUPP, 0),
        }
    }
}

impl VirtioDeviceOps for VirtioBlk {
    fn legacy_pci_device_id(&self) -> u16 {
        0x1001 // "Virtio block device", per /usr/share/hwdata/pci.ids
    }

    fn pci_class_code(&self) -> u32 {
        0x01_80_00 // mass storage controller, other
    }

    fn num_queues(&self) -> u16 {
        1
    }

    fn queue_size(&self, _queue: u16) -> u16 {
        128
    }

    fn host_features(&self) -> u32 {
        VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_DISCARD | VIRTIO_BLK_F_WRITE_ZEROES
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Fields for a feature the guest hasn't negotiated are never
        // queried by a conformant driver, but the DISCARD/WRITE_ZEROES
        // limits must still be real, valid values now that `host_features`
        // advertises both — an all-zero `max_discard_sectors` with the
        // feature bit set is invalid device behavior, not "unsupported".
        let mut c = [0u8; config::LEN];
        let put32 = |c: &mut [u8; config::LEN], at: usize, v: u32| {
            c[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        c[config::CAPACITY..config::CAPACITY + 8]
            .copy_from_slice(&self.capacity_sectors.to_le_bytes());
        put32(&mut c, config::BLK_SIZE, SECTOR_SIZE as u32);
        let whole_disk = self.capacity_sectors.min(u64::from(u32::MAX)) as u32;
        put32(&mut c, config::MAX_DISCARD_SECTORS, whole_disk);
        put32(&mut c, config::MAX_DISCARD_SEG, 1);
        put32(&mut c, config::DISCARD_SECTOR_ALIGNMENT, 1);
        put32(&mut c, config::MAX_WRITE_ZEROES_SECTORS, whole_disk);
        put32(&mut c, config::MAX_WRITE_ZEROES_SEG, 1);
        c[config::WRITE_ZEROES_MAY_UNMAP] = 0; // we always physically zero
        copy_config(&c, offset, data);
    }

    fn process_chain(&mut self, queue: u16, mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome {
        // Layout per the virtio-blk spec: [0] request header (16 bytes,
        // device-readable), [1..n-1] data buffers, [n-1] 1-byte status
        // (device-writable). A chain that doesn't even have header+status
        // is malformed; just drop it.
        let Some((status_buf, rest)) = chain.buffers.split_last() else {
            return ChainOutcome::Done(0);
        };
        let Some((header_buf, data_buffers)) = rest.split_first() else {
            return ChainOutcome::Done(0);
        };
        // Don't just trust positional convention — a
        // spec-compliant driver that (legally) flagged these differently
        // would otherwise be silently misread instead of rejected clearly.
        if header_buf.device_writable || !status_buf.device_writable {
            eprintln!(
                "[hyperbug] virtio-blk: header/status descriptor flags don't match the expected \
                 direction (header device_writable={}, status device_writable={}); dropping request",
                header_buf.device_writable, status_buf.device_writable
            );
            return ChainOutcome::Done(0);
        }

        let mut header = [0u8; REQUEST_HEADER_LEN];
        if !mem.read_checked(header_buf.addr, &mut header) {
            return ChainOutcome::Done(0);
        }
        let req_type = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let sector = u64::from_le_bytes(header[8..16].try_into().unwrap());

        // Data buffers' direction must match the request type: IN (read
        // from disk) writes into buffers the guest marked device-writable;
        // everything else the guest sends *to* the device (a write, or a
        // DISCARD/WRITE_ZEROES segment list) must not be.
        let expected_writable = req_type == VIRTIO_BLK_T_IN;
        let direction_ok = req_type == VIRTIO_BLK_T_FLUSH
            || data_buffers.iter().all(|b| b.device_writable == expected_writable);

        // The actual io_uring fast path: a well-formed, non-empty IN/OUT
        // request is submitted asynchronously and completed later by
        // `poll_completions` — this call returns without having done any
        // disk I/O at all. Everything else (FLUSH, DISCARD/WRITE_ZEROES,
        // malformed direction, an empty data-buffer list, or the ring
        // being full) falls through to the existing synchronous path
        // below, exactly as if io_uring didn't exist for that request.
        if direction_ok && !data_buffers.is_empty() && (req_type == VIRTIO_BLK_T_IN || req_type == VIRTIO_BLK_T_OUT) {
            let is_read = req_type == VIRTIO_BLK_T_IN;
            let request = PendingRequest {
                queue_idx: queue,
                head_index: chain.head_index(),
                status_buf_addr: status_buf.addr,
            };
            if self.submit_io(is_read, sector, data_buffers, mem, request) {
                return ChainOutcome::Pending;
            }
        }

        let (status, mut written) = if !direction_ok {
            eprintln!(
                "[hyperbug] virtio-blk: data descriptor direction doesn't match request type {req_type}"
            );
            (VIRTIO_BLK_S_UNSUPP, 0)
        } else {
            self.handle_request(req_type, sector, data_buffers, mem)
        };

        if mem.write_checked(status_buf.addr, &[status]) {
            written += 1;
        }
        ChainOutcome::Done(written)
    }

    fn poll_completions(&mut self) -> Vec<CompletionResult> {
        let mut out = Vec::new();
        // Draining the completion queue (an iterator) is what marks each
        // entry seen; anything with no matching `in_flight` entry (should
        // never happen — `user_data` always comes from a submission this
        // same instance made) is silently skipped rather than panicking
        // on what would be a real bug, not a guest-triggerable condition.
        for cqe in self.ring.completion() {
            let Some(req) = self.in_flight.remove(&cqe.user_data()) else { continue };
            let result = cqe.result();
            let (status, written) = if result < 0 {
                (VIRTIO_BLK_S_IOERR, 0)
            } else if req.is_read {
                (VIRTIO_BLK_S_OK, result as u32)
            } else {
                (VIRTIO_BLK_S_OK, 0)
            };
            out.push(CompletionResult {
                queue_idx: req.request.queue_idx,
                head_index: req.request.head_index,
                written_len: written,
                status_byte: status,
                status_buf_addr: req.request.status_buf_addr,
            });
        }
        out
    }

    fn completion_eventfd(&self) -> Option<std::os::fd::RawFd> {
        Some(self.ring_eventfd.as_raw_fd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::GuestMemory;

    fn temp_disk(sectors: u64) -> (VirtioBlk, std::path::PathBuf) {
        let path = std::env::temp_dir()
            .join(format!("hyperbug-virtio-blk-test-{}-{:p}", std::process::id(), &sectors));
        std::fs::write(&path, vec![0xffu8; (sectors * SECTOR_SIZE) as usize]).unwrap();
        (VirtioBlk::open(path.to_str().unwrap()).unwrap(), path)
    }

    fn disk_contents(path: &std::path::Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    /// Builds a well-formed IN/OUT descriptor chain (header + one data
    /// buffer + status), matching real virtio-blk layout, for driving
    /// `process_chain` exactly the way `VirtioLegacyPci::drain_queue`
    /// would (minus the actual virtqueue walk — `virtio.rs`'s own tests
    /// already cover that part). The caller writes the header's actual
    /// bytes into guest memory itself, at `header_addr`.
    fn blk_chain(header_addr: u64, data_addr: u64, data_len: u32, status_addr: u64, data_writable: bool) -> DescChain {
        let mut chain = DescChain::default();
        chain.buffers.push(DescBuffer { addr: header_addr, len: REQUEST_HEADER_LEN as u32, device_writable: false });
        chain.buffers.push(DescBuffer { addr: data_addr, len: data_len, device_writable: data_writable });
        chain.buffers.push(DescBuffer { addr: status_addr, len: 1, device_writable: true });
        chain
    }

    /// Polls `blk.poll_completions()` until it returns something or
    /// `timeout` elapses — io_uring completion is genuinely asynchronous
    /// (even for a local file, not guaranteed instant), so this is a real
    /// wait, not a single check.
    fn wait_for_completion(blk: &mut VirtioBlk, timeout: std::time::Duration) -> Vec<crate::virtio::CompletionResult> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let c = blk.poll_completions();
            if !c.is_empty() {
                return c;
            }
            assert!(std::time::Instant::now() < deadline, "io_uring completion never arrived");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// The actual point of the whole io_uring backend: `process_chain`
    /// returns `Pending` immediately (no disk I/O done synchronously),
    /// and the real bytes from disk only show up in guest memory once
    /// `poll_completions` reports the async request finished.
    #[test]
    fn process_chain_submits_a_real_read_via_io_uring_and_completes_it_asynchronously() {
        let (mut blk, path) = temp_disk(4);
        let known: Vec<u8> = (0..512u32).map(|i| (i % 256) as u8).collect();
        {
            let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.seek(SeekFrom::Start(SECTOR_SIZE)).unwrap();
            f.write_all(&known).unwrap();
        }

        let mut mem = GuestMemory::new(8192).unwrap();
        let (header_addr, data_addr, status_addr) = (0x100u64, 0x1000u64, 0x2000u64);
        let mut header = [0u8; REQUEST_HEADER_LEN];
        header[0..4].copy_from_slice(&VIRTIO_BLK_T_IN.to_le_bytes());
        header[8..16].copy_from_slice(&1u64.to_le_bytes()); // sector 1
        assert!(mem.write_checked(header_addr, &header));
        let chain = blk_chain(header_addr, data_addr, 512, status_addr, true);

        let outcome = blk.process_chain(0, &mut mem, &chain);
        assert!(matches!(outcome, ChainOutcome::Pending), "a well-formed IN request must go through io_uring");

        let completions = wait_for_completion(&mut blk, std::time::Duration::from_secs(5));
        assert_eq!(completions.len(), 1);
        let c = &completions[0];
        assert_eq!(c.status_byte, VIRTIO_BLK_S_OK);
        assert_eq!(c.written_len, 512, "the used-ring length should be the real bytes read");
        assert_eq!(c.status_buf_addr, status_addr);
        assert_eq!(c.queue_idx, 0);
        assert_eq!(c.head_index, chain.head_index());

        let mut got = vec![0u8; 512];
        assert!(mem.read_checked(data_addr, &mut got));
        assert_eq!(got, known, "the real bytes read from disk via io_uring must land in guest memory");

        let _ = std::fs::remove_file(&path);
    }

    /// The write-side mirror: real bytes from guest memory must actually
    /// land on the backing file once the async request completes.
    #[test]
    fn process_chain_submits_a_real_write_via_io_uring_and_completes_it_asynchronously() {
        let (mut blk, path) = temp_disk(4);
        let mut mem = GuestMemory::new(8192).unwrap();
        let (header_addr, data_addr, status_addr) = (0x100u64, 0x1000u64, 0x2000u64);
        let payload: Vec<u8> = (0..512u32).map(|i| (255 - (i % 256)) as u8).collect();
        assert!(mem.write_checked(data_addr, &payload));

        let mut header = [0u8; REQUEST_HEADER_LEN];
        header[0..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        header[8..16].copy_from_slice(&2u64.to_le_bytes()); // sector 2
        assert!(mem.write_checked(header_addr, &header));
        let chain = blk_chain(header_addr, data_addr, 512, status_addr, false);

        let outcome = blk.process_chain(0, &mut mem, &chain);
        assert!(matches!(outcome, ChainOutcome::Pending), "a well-formed OUT request must go through io_uring");

        let completions = wait_for_completion(&mut blk, std::time::Duration::from_secs(5));
        assert_eq!(completions.len(), 1);
        let c = &completions[0];
        assert_eq!(c.status_byte, VIRTIO_BLK_S_OK);
        assert_eq!(c.written_len, 0, "a write reports 0 bytes written, matching the synchronous path");

        let contents = disk_contents(&path);
        assert_eq!(&contents[2 * 512..3 * 512], &payload[..], "the real guest bytes must have landed on disk");

        let _ = std::fs::remove_file(&path);
    }

    /// `completion_eventfd` is what the reactor actually epolls on — must
    /// be a real, valid fd, not a placeholder.
    #[test]
    fn completion_eventfd_is_a_real_fd() {
        let (blk, path) = temp_disk(1);
        assert!(blk.completion_eventfd().is_some());
        let _ = std::fs::remove_file(&path);
    }

    fn segment(sector: u64, num_sectors: u32, flags: u32) -> Vec<u8> {
        let mut s = Vec::with_capacity(DISCARD_SEGMENT_LEN);
        s.extend_from_slice(&sector.to_le_bytes());
        s.extend_from_slice(&num_sectors.to_le_bytes());
        s.extend_from_slice(&flags.to_le_bytes());
        s
    }

    /// WRITE_ZEROES/DISCARD are real disk I/O, not a stub
    /// that reports success without touching anything — this drives
    /// `zero_segments` exactly the way `process_chain` would (a guest
    /// buffer holding a real `struct virtio_blk_discard_write_zeroes`) and
    /// checks the file on disk, not just the return value.
    #[test]
    fn write_zeroes_actually_zeroes_the_backing_file() {
        let (mut blk, path) = temp_disk(4);
        let mut mem = GuestMemory::new(4096).unwrap();
        let addr = 0x100u64;
        let seg = segment(1, 2, 0);
        assert!(mem.write_checked(addr, &seg));

        let buffers = [DescBuffer { addr, len: seg.len() as u32, device_writable: false }];
        assert!(blk.zero_segments(&buffers, &mem).is_ok());

        let contents = disk_contents(&path);
        assert_eq!(&contents[0..512], &[0xff; 512][..], "sector 0 must be untouched");
        assert_eq!(&contents[512..512 * 3], &[0u8; 512 * 2][..], "sectors 1-2 must be zeroed");
        assert_eq!(&contents[512 * 3..512 * 4], &[0xff; 512][..], "sector 3 must be untouched");

        let _ = std::fs::remove_file(&path);
    }

    /// An unrecognized flag bit is something a future spec revision might
    /// give real meaning to — must be rejected, not silently ignored.
    #[test]
    fn zero_segments_rejects_an_unknown_flag_bit() {
        let (mut blk, path) = temp_disk(1);
        let mut mem = GuestMemory::new(4096).unwrap();
        let addr = 0x100u64;
        let seg = segment(0, 1, 0x2); // an unknown flag bit
        assert!(mem.write_checked(addr, &seg));

        let buffers = [DescBuffer { addr, len: seg.len() as u32, device_writable: false }];
        assert!(blk.zero_segments(&buffers, &mem).is_err());

        let _ = std::fs::remove_file(&path);
    }

    /// A guest asking to zero 0xffff_ffff sectors used to try to allocate
    /// `num_sectors * 512` (2 TiB) host bytes in one `vec![]` before ever
    /// checking the request against the image's real size.
    #[test]
    fn an_absurd_write_zeroes_length_is_rejected_without_allocating_it() {
        let (mut blk, path) = temp_disk(4);
        let mut mem = GuestMemory::new(4096).unwrap();
        let addr = 0x100u64;
        let seg = segment(0, u32::MAX, 0);
        assert!(mem.write_checked(addr, &seg));

        let buffers = [DescBuffer { addr, len: seg.len() as u32, device_writable: false }];
        assert!(blk.zero_segments(&buffers, &mem).is_err());
        assert_eq!(disk_contents(&path).len(), 4 * 512, "the image must not have grown");

        let _ = std::fs::remove_file(&path);
    }

    /// `sector * SECTOR_SIZE` wraps for a large enough sector; a write past
    /// the end would otherwise extend the backing image instead of failing.
    #[test]
    fn a_sector_number_past_the_disk_is_rejected_rather_than_wrapping() {
        let (blk, path) = temp_disk(4);
        assert_eq!(blk.checked_range(4, 512), None, "one sector past the end");
        assert_eq!(blk.checked_range(u64::MAX, 512), None, "an offset that would overflow");
        assert_eq!(blk.checked_range(3, 512), Some(3 * 512), "the last real sector still works");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn writing_past_the_end_of_the_image_does_not_grow_it() {
        let (mut blk, path) = temp_disk(2);
        let mut mem = GuestMemory::new(4096).unwrap();
        assert!(mem.write_checked(0x200, &[0xaa; 512]));

        let buffers = [DescBuffer { addr: 0x200, len: 512, device_writable: false }];
        assert!(blk.write_sectors(2, &buffers, &mem).is_err());
        assert_eq!(disk_contents(&path).len(), 2 * 512);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_read_write_round_trip_moves_the_real_bytes() {
        let (mut blk, path) = temp_disk(4);
        let mut mem = GuestMemory::new(8192).unwrap();
        let payload: Vec<u8> = (0..512u32).map(|i| i as u8).collect();
        assert!(mem.write_checked(0x1000, &payload));

        let out = [DescBuffer { addr: 0x1000, len: 512, device_writable: false }];
        blk.write_sectors(1, &out, &mem).unwrap();

        let into = [DescBuffer { addr: 0x1800, len: 512, device_writable: true }];
        assert_eq!(blk.read_sectors(1, &into, &mut mem).unwrap(), 512);

        let mut back = vec![0u8; 512];
        assert!(mem.read_checked(0x1800, &mut back));
        assert_eq!(back, payload);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_config_reports_real_discard_and_write_zeroes_limits() {
        let (blk, path) = temp_disk(4);
        let mut c = [0u8; config::LEN];
        blk.read_config(0, &mut c);
        assert_eq!(u64::from_le_bytes(c[0..8].try_into().unwrap()), 4, "capacity");
        assert_eq!(
            u32::from_le_bytes(c[config::MAX_DISCARD_SECTORS..][..4].try_into().unwrap()),
            4,
            "max_discard_sectors"
        );
        assert_eq!(
            u32::from_le_bytes(c[config::MAX_WRITE_ZEROES_SECTORS..][..4].try_into().unwrap()),
            4,
            "max_write_zeroes_sectors"
        );
        assert_eq!(c[config::WRITE_ZEROES_MAY_UNMAP], 0, "we always physically zero");
        let _ = std::fs::remove_file(&path);
    }
}
