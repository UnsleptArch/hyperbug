//! Guest physical memory: a single anonymous mmap, identity-addressed
//! (guest physical address 0 == byte 0 of the mapping).
//!
//! Two access families, deliberately named so the difference is impossible
//! to miss at a call site:
//!
//! - `*_unchecked_boot_only`: for hyperbug's own boot-time layout math
//!   (`loader.rs`/`gdt.rs`/`acpi.rs`), which computes every address it
//!   passes itself and never touches guest-supplied input.
//! - `*_checked`: for anything handling a guest-controlled address (a
//!   virtqueue descriptor, a Python plugin's DMA call). These return
//!   `false`/`None` instead of touching memory when the range doesn't fit,
//!   which is a real security boundary rather than defensive habit.

use std::ptr::NonNull;

use crate::error::HyperbugError;

pub struct GuestMemory {
    ptr: NonNull<u8>,
    size: usize,
}

impl GuestMemory {
    /// Allocates `size` bytes of guest RAM via an anonymous mmap. Returns
    /// an error rather than panicking on failure — `run()` is embeddable,
    /// so an over-large `--mem` on a busy host must not abort the caller's
    /// process (see `error.rs`).
    pub fn new(size: usize) -> Result<Self, HyperbugError> {
        // SAFETY: a fresh anonymous mapping with no fixed address hint;
        // failure is reported through MAP_FAILED, checked immediately.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(HyperbugError::Io(format!(
                "mmap of {size} bytes of guest memory failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let ptr = NonNull::new(addr.cast::<u8>()).ok_or_else(|| {
            HyperbugError::Io("mmap returned NULL for guest memory".to_string())
        })?;

        // Best-effort: ask the kernel to back this mapping with
        // Transparent Huge Pages (2 MiB, opportunistically — no
        // hugetlbfs reservation needed, unlike `MAP_HUGETLB`, which would
        // instead fail the whole launch on a host that hasn't pre-
        // reserved any). Fewer, larger page-table entries means fewer
        // TLB misses on every guest memory access and fewer minor page
        // faults while guest RAM is first touched — the elite-VMM
        // baseline (crosvm/Firecracker/QEMU all do the equivalent).
        // Advisory only: a kernel with `transparent_hugepage=never`, or
        // one built without `CONFIG_TRANSPARENT_HUGEPAGE`, simply won't
        // honor it — logged once, not fatal, exactly like the reactor's
        // other "the host doesn't support this optional thing" paths.
        //
        // SAFETY: `addr`/`size` are exactly what `mmap` just returned —
        // a live, anonymous private mapping `madvise` is always valid to
        // advise on.
        if unsafe { libc::madvise(addr, size, libc::MADV_HUGEPAGE) } != 0 {
            eprintln!(
                "[hyperbug] madvise(MADV_HUGEPAGE) on guest memory failed ({}); \
                 continuing without transparent huge pages",
                std::io::Error::last_os_error()
            );
        }

        Ok(Self { ptr, size })
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Total guest RAM, in bytes. Used to reject guest-supplied ranges
    /// (virtqueue descriptors) up front, before anything sizes a host-side
    /// buffer from them — see `virtio::VirtQueue::try_pop`.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Writes `val` at guest physical address `addr`, little-endian.
    ///
    /// **Unchecked beyond a debug assert** — see the module doc comment for
    /// when this is and isn't the right method. Nothing at the type level
    /// stops the wrong choice, so the name says so instead.
    #[inline]
    pub fn write_obj_unchecked_boot_only<T: Copy>(&mut self, addr: u64, val: T) {
        let addr = addr as usize;
        debug_assert!(addr + std::mem::size_of::<T>() <= self.size);
        // SAFETY: caller guarantees the range is inside the mapping (see
        // the method name); the pointer is valid for `self.size` bytes.
        unsafe {
            std::ptr::write_unaligned(self.ptr.as_ptr().add(addr).cast::<T>(), val);
        }
    }

    /// See `write_obj_unchecked_boot_only` — same contract, slice form.
    #[inline]
    pub fn write_slice_unchecked_boot_only(&mut self, addr: u64, data: &[u8]) {
        let addr = addr as usize;
        debug_assert!(addr + data.len() <= self.size);
        // SAFETY: as above; source and destination cannot overlap, since
        // `data` never points into the guest mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr().add(addr), data.len());
        }
    }

    /// Whether `[addr, addr + len)` lies entirely within guest RAM.
    #[inline]
    pub fn in_bounds(&self, addr: u64, len: u64) -> bool {
        usize::try_from(addr)
            .ok()
            .zip(usize::try_from(len).ok())
            .and_then(|(a, l)| a.checked_add(l))
            .is_some_and(|end| end <= self.size)
    }

    #[inline]
    pub fn read_checked(&self, addr: u64, dst: &mut [u8]) -> bool {
        if !self.in_bounds(addr, dst.len() as u64) {
            return false;
        }
        // SAFETY: bounds checked immediately above; `dst` never aliases the
        // guest mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.ptr.as_ptr().add(addr as usize),
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
        true
    }

    #[inline]
    pub fn write_checked(&mut self, addr: u64, src: &[u8]) -> bool {
        if !self.in_bounds(addr, src.len() as u64) {
            return false;
        }
        // SAFETY: bounds checked immediately above; `src` never aliases the
        // guest mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.as_ptr().add(addr as usize), src.len());
        }
        true
    }

    #[inline]
    pub fn read_u16_checked(&self, addr: u64) -> Option<u16> {
        let mut buf = [0u8; 2];
        self.read_checked(addr, &mut buf).then(|| u16::from_le_bytes(buf))
    }

    /// Currently exercised only by this crate's own tests: the virtqueue
    /// descriptor walk reads all 16 bytes of a descriptor in one go now
    /// rather than field by field. Kept because it completes the checked
    /// little-endian accessor set `read_u16_checked` belongs to — the
    /// alternative is the next caller re-deriving it by hand, which is
    /// exactly the kind of thing the bounds check exists to prevent.
    #[allow(dead_code)]
    #[inline]
    pub fn read_u32_checked(&self, addr: u64) -> Option<u32> {
        let mut buf = [0u8; 4];
        self.read_checked(addr, &mut buf).then(|| u32::from_le_bytes(buf))
    }

    /// See `read_u32_checked` on why this is `allow(dead_code)`.
    #[allow(dead_code)]
    #[inline]
    pub fn read_u64_checked(&self, addr: u64) -> Option<u64> {
        let mut buf = [0u8; 8];
        self.read_checked(addr, &mut buf).then(|| u64::from_le_bytes(buf))
    }

    #[inline]
    pub fn write_u16_checked(&mut self, addr: u64, val: u16) -> bool {
        self.write_checked(addr, &val.to_le_bytes())
    }

    #[inline]
    pub fn write_u32_checked(&mut self, addr: u64, val: u32) -> bool {
        self.write_checked(addr, &val.to_le_bytes())
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`size` are exactly what `mmap` returned and are
        // never handed out as a borrow that could outlive `self`.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast::<libc::c_void>(), self.size);
        }
    }
}

// The mapping is exclusively owned by GuestMemory and only ever accessed
// through the offset-based methods above, never as a borrowed slice — so
// moving it between threads (one vCPU thread per `--smp`, plus the
// reactor) is sound; concurrent access is serialized by the `Mutex` every
// holder wraps it in.
unsafe impl Send for GuestMemory {}
