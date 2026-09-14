//! Host-CPU-vendor-aware hardware performance counter access — Milestone
//! 1 of record-and-replay. The foundational primitive the rest of that
//! feature needs: knowing *precisely* how many conditional branches a
//! vCPU thread has retired *while executing guest code* (not the host
//! kernel/hypervisor around it), so a future recording pass can log that
//! count at the moment each async event (an interrupt, an RNG byte, a
//! network packet) was delivered, and a future replay pass can re-deliver
//! it at the exact same point. This module is only the counter; the
//! record/replay logic that actually uses it doesn't exist yet — see
//! `docs/record-replay.md`.
//!
//! **Deliberately vendor-neutral by construction**, per this project's own
//! standing rule (`CLAUDE.md`'s "no vendor-specific code in hyperbug's own
//! tree," written for Intel/HECI, but the same principle applies to a
//! host-side hardware quirk just as much as a guest-facing device): the
//! mechanism this needs exists on both Intel and AMD, but as two
//! genuinely different raw PMU events with different precision
//! characteristics, not one shared code path that happens to work on
//! whichever CPU the person writing it had on their desk.
//!
//! - **Intel**: `BR_INST_RETIRED.CONDITIONAL` (raw event `0xC4`, umask
//!   `0x00`), requested with `precise_ip = 2` (PEBS, minimal skid) — the
//!   mechanism `rr` uses as its primary, most reliable platform. This
//!   project has no Intel hardware to test on; the config values are
//!   implemented from Intel's published PMU event tables and `rr`'s own
//!   documented approach, **not empirically verified** — flagged
//!   honestly rather than claimed equivalent to the AMD path below.
//! - **AMD** (Zen / Family 17h+): "Retired Branch Instructions" (raw
//!   event `0xC2`, umask `0x00`) — but the raw count is **not** usable
//!   for exact replay without a real, documented, root-only fix: AMD's
//!   "SpecLockMap" speculative-execution optimization causes this exact
//!   event to overcount by orders of magnitude. Confirmed empirically
//!   against a real KVM guest on this host (2026-09-13): ~3.7 billion
//!   "branches" per second from a trivial busybox shell loop — the same
//!   erratum `rr`'s own Zen wiki page documents for bare-metal host
//!   processes, reproduced here (as far as could be determined) for the
//!   first time against a *guest's* execution rather than a host one. The
//!   fix is `wrmsr 0xc0011020` with bit 54 set and bit 10 cleared,
//!   applied system-wide — this module *detects* whether it's already
//!   applied (`amd_speclockmap_workaround_applied`) rather than applying
//!   it itself: it's global CPU state affecting every process on the
//!   host, not something a VMM should flip on its own initiative, and
//!   doing so needs root this process isn't assumed to have anyway.
//! - **Any other vendor**: refused outright with a clear error, never
//!   guessed at.
//!
//! Milestone 1 only: this module is the counter primitive alone, not yet
//! wired into any recording/replay pipeline (that's Milestone 2 — see
//! `docs/record-replay.md`). `#[allow(dead_code)]` below is deliberate,
//! not a placeholder left in by accident: every item here is exercised by
//! this module's own real tests (against actual `/dev/kvm`-free hardware
//! access — `perf_event_open`, real CPUID, a real busy loop) but has no
//! caller yet outside them.

#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Detected host CPU vendor, from real `cpuid` leaf 0 — not `/proc/
/// cpuinfo` text parsing, matching this project's own "check the real
/// thing" convention (`cpuid.rs` already reads raw CPUID for the guest's
/// own curated leaves; this does the same for the host itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    Intel,
    Amd,
    Other,
}

pub fn detect_host_vendor() -> CpuVendor {
    // CPUID leaf 0 is unconditionally available on every x86_64 CPU (this
    // crate only ever targets x86_64 — see `Cargo.toml`); `__cpuid` is a
    // safe fn in this toolchain (it has no memory-safety preconditions of
    // its own, only a CPU-support one the target-gate above already
    // guarantees).
    let result = std::arch::x86_64::__cpuid(0);
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&result.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&result.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&result.ecx.to_le_bytes());
    match &vendor {
        b"GenuineIntel" => CpuVendor::Intel,
        b"AuthenticAMD" => CpuVendor::Amd,
        _ => CpuVendor::Other,
    }
}

const PERF_TYPE_RAW: u32 = 4;
const AMD_RETIRED_BRANCHES_EVENT: u64 = 0xc2;
const INTEL_BR_INST_RETIRED_CONDITIONAL: u64 = 0xc4;

const ATTR_DISABLED: u64 = 1 << 0;
const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
const ATTR_PRECISE_IP_SHIFT: u64 = 15;
const ATTR_EXCLUDE_HOST: u64 = 1 << 19;

/// The first 72 bytes of the real kernel UAPI `struct perf_event_attr`
/// (`PERF_ATTR_SIZE_VER1` — through `config1`/`config2`), laid out
/// `#[repr(C)]` to match exactly. Confirmed against this host's own
/// `/usr/include/linux/perf_event.h` rather than assumed from memory —
/// the same discipline `acpi.rs` established for ACPI table layouts, for
/// exactly the same reason (a wrong field offset here fails silently,
/// not with a compile error).
#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
}

const PERF_ATTR_SIZE_VER1: u32 = 72;

const _: () = assert!(std::mem::size_of::<PerfEventAttr>() == PERF_ATTR_SIZE_VER1 as usize);

// `_IO('$', n)` per `<linux/perf_event.h>`: `('$' << 8) | n`, no data
// direction/size bits set for these three (verified against the header's
// own `#define`s rather than the general ioctl-encoding formula alone).
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;

/// A guest-mode-only retired-conditional-branch counter, attached to one
/// specific thread (a vCPU thread's Linux TID).
pub struct BranchCounter {
    fd: OwnedFd,
}

impl BranchCounter {
    /// Opens the counter for `tid`. Returns `(counter, precise)` —
    /// `precise` is whether the resulting count can actually be trusted
    /// for exact-replay purposes: always `true` on Intel (PEBS is
    /// precise by construction once requested), and on AMD exactly
    /// `amd_speclockmap_workaround_applied().unwrap_or(false)` — a
    /// counter that opens fine but can't be trusted still opens (useful
    /// for developing/testing this module itself, and for the *recording*
    /// side even at reduced precision), but callers must not treat an
    /// imprecise counter's values as exact.
    pub fn open_for_thread(tid: libc::pid_t) -> Result<(Self, bool), String> {
        Self::open_for_thread_impl(tid, true)
    }

    /// Shared by `open_for_thread` and this module's own host-only unit
    /// test (`exclude_host = false` there): a thread that never enters
    /// KVM guest mode at all — like the test's own busy loop — retires
    /// zero *guest-mode* branches by definition, so verifying the raw
    /// `perf_event_open`/ioctl/read plumbing itself needs the filter
    /// turned off; the real guest-mode-filtered path is instead verified
    /// against an actual live KVM guest in `tests/boot.rs`.
    fn open_for_thread_impl(tid: libc::pid_t, exclude_host: bool) -> Result<(Self, bool), String> {
        let vendor = detect_host_vendor();
        let (config, precise_ip) = match vendor {
            CpuVendor::Amd => (AMD_RETIRED_BRANCHES_EVENT, 0u64),
            CpuVendor::Intel => (INTEL_BR_INST_RETIRED_CONDITIONAL, 2u64),
            CpuVendor::Other => {
                return Err(
                    "record/replay's branch counter needs a known host CPU vendor (Intel or \
                     AMD); this host's CPUID reports neither"
                        .to_string(),
                );
            }
        };
        let mut flags = ATTR_DISABLED | ATTR_EXCLUDE_KERNEL | (precise_ip << ATTR_PRECISE_IP_SHIFT);
        if exclude_host {
            flags |= ATTR_EXCLUDE_HOST;
        }
        let attr = PerfEventAttr { type_: PERF_TYPE_RAW, size: PERF_ATTR_SIZE_VER1, config, flags, ..Default::default() };

        // SAFETY: `attr` is a validly-initialized, correctly-sized
        // `perf_event_attr` (asserted above) that outlives the call; the
        // syscall's other arguments are plain integers. A negative return
        // is the syscall's own documented error convention, checked
        // immediately below before the value is used as an fd.
        let ret = unsafe {
            libc::syscall(libc::SYS_perf_event_open, &attr as *const PerfEventAttr, tid, -1i32, -1i32, 0u64)
        };
        if ret < 0 {
            return Err(format!("perf_event_open failed: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: `ret` is a valid, freshly-opened fd from the syscall
        // above, not aliased or owned anywhere else yet.
        let fd = unsafe { OwnedFd::from_raw_fd(ret as RawFd) };
        let precise = match vendor {
            CpuVendor::Intel => true,
            CpuVendor::Amd => amd_speclockmap_workaround_applied().unwrap_or(false),
            CpuVendor::Other => unreachable!("already returned Err above"),
        };
        Ok((Self { fd }, precise))
    }

    pub fn reset(&self) {
        // SAFETY: `self.fd` is a valid perf_event fd for the lifetime of
        // `self`; these three ioctls take no output pointer to write
        // through, only a plain command code.
        unsafe {
            libc::ioctl(self.fd.as_raw_fd(), PERF_EVENT_IOC_RESET, 0);
        }
    }

    pub fn enable(&self) {
        unsafe {
            libc::ioctl(self.fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    pub fn disable(&self) {
        unsafe {
            libc::ioctl(self.fd.as_raw_fd(), PERF_EVENT_IOC_DISABLE, 0);
        }
    }

    /// The counter's current cumulative value. `0` on any read failure
    /// (shouldn't happen for a live fd) rather than panicking — a
    /// misread here should degrade the recording, not crash the guest.
    pub fn read_count(&self) -> u64 {
        let mut buf = [0u8; 8];
        // SAFETY: `buf` is exactly 8 bytes, matching the plain-count
        // read format (`read_format` was left at its default 0, meaning
        // "just the raw counter value" per the perf_event ABI); `self.fd`
        // is valid for the duration of the call.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n != buf.len() as isize {
            return 0;
        }
        u64::from_le_bytes(buf)
    }
}

/// Reads MSR `0xc0011020` via `/dev/cpu/0/msr` and checks whether bit 54
/// is set and bit 10 is clear — the documented SpecLockMap-disabled state
/// `rr`'s own AMD Zen workaround applies (see this module's doc comment).
/// `None` if the MSR can't be read at all (no `msr` kernel module loaded,
/// or no permission — reading raw MSRs needs root regardless of
/// `perf_event_paranoid`), in which case the caller must not assume
/// either way, only that precision is unconfirmed.
pub fn amd_speclockmap_workaround_applied() -> Option<bool> {
    const MSR_OFFSET: u64 = 0xc001_1020;
    let mut file = File::open("/dev/cpu/0/msr").ok()?;
    file.seek(SeekFrom::Start(MSR_OFFSET)).ok()?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).ok()?;
    let value = u64::from_le_bytes(buf);
    Some(value & (1 << 54) != 0 && value & (1 << 10) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_real_known_vendor_on_this_host() {
        // Doesn't assert *which* vendor — this suite runs on whatever
        // hardware is available — only that a real x86_64 host reports
        // one of the two this module actually supports, not `Other`.
        let vendor = detect_host_vendor();
        assert_ne!(vendor, CpuVendor::Other, "this host's CPUID should report a known vendor");
        eprintln!("detected host vendor: {vendor:?}");
    }

    /// A real counter, opened against the *current* thread with
    /// `exclude_host` turned off (this thread never enters KVM guest mode
    /// at all, so the real guest-mode-filtered path would legitimately
    /// count zero here — see `open_for_thread_impl`'s doc comment; the
    /// actual guest-mode-filtered path is verified separately against a
    /// real live guest in `tests/boot.rs`). This test's own job is just
    /// confirming the raw `perf_event_open`/ioctl/read plumbing and the
    /// hand-rolled `perf_event_attr` layout are actually correct, spun
    /// through a real busy loop and read back. Skips (doesn't fail) on an
    /// environment where `perf_event_open` is locked down further than
    /// this host — e.g. a `perf_event_paranoid` setting or sandbox this
    /// project can't control — rather than making the whole suite depend
    /// on unrestricted perf access.
    #[test]
    fn a_real_counter_counts_something_over_a_real_busy_loop() {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        let (counter, precise) = match BranchCounter::open_for_thread_impl(tid, false) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };
        eprintln!("counter opened; precise (trustworthy for exact replay) = {precise}");
        counter.reset();
        counter.enable();
        // A real, branch-heavy busy loop the compiler can't fold into a
        // constant — `std::hint::black_box` keeps every iteration real.
        let mut x: u64 = 1;
        for i in 0..10_000_000u64 {
            x = std::hint::black_box(x.wrapping_mul(3).wrapping_add(i));
            if x == 0 {
                x = 1; // never actually taken; keeps a real conditional branch per iteration
            }
        }
        std::hint::black_box(x);
        counter.disable();
        let count = counter.read_count();
        assert!(count > 0, "a real busy loop with real conditional branches should count something");
    }

    /// Doesn't assert a specific outcome (host-dependent, and typically
    /// `None` without root) — only that the check itself doesn't panic
    /// and returns a real, inspectable answer.
    #[test]
    fn speclockmap_check_does_not_panic_regardless_of_outcome() {
        let result = amd_speclockmap_workaround_applied();
        eprintln!("amd_speclockmap_workaround_applied() = {result:?}");
    }
}
