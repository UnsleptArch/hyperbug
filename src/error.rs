//! A real error type for hyperbug's core (`run()`/`run_vcpu`), replacing
//! the `panic!`/`std::process::exit` scattered through the pre-refactor
//! code. `main.rs` (a genuine CLI
//! binary) is still allowed to translate a returned `Err` into an actual
//! process exit; nothing below `run()` does that itself, which is what
//! actually makes `run()` embeddable (a caller's process survives a
//! failed launch or a mid-run fault and gets to decide what to do next).
//!
//! Every variant stores a formatted `String` rather than the original
//! error type (`kvm_ioctls::Error`, `std::io::Error`, `pyo3::PyErr`, ...)
//! — deliberately: it keeps `HyperbugError` trivially `Clone`/`Send`/
//! `Sync` with no per-source-crate `Send` auditing, which matters because
//! it has to travel through the shared `ExitSignal` below across vCPU
//! threads. A VMM's fatal-error reporting doesn't need structured access
//! to the original error after the fact — a message is genuinely enough.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum HyperbugError {
    /// A host OS I/O failure: opening `/dev/kvm`, reading a kernel/initrd
    /// file, binding a control socket, creating a TAP interface, ...
    Io(String),
    /// A KVM ioctl failed, or a vCPU hit a VM-exit reason with nothing to
    /// handle it.
    Kvm(String),
    /// A Python device plugin failed to load or raised inside a callback
    /// path that isn't already handled as a logged no-op (see
    /// `pydevice.rs`'s own rate-limited logging for the callback case;
    /// this variant is for load-time failures only).
    Python(String),
    /// Bad configuration: a `--mem`/`--smp`/`--disk` value out of bounds,
    /// a malformed `--device`/`--pci-device` spec, or a memory-layout
    /// constraint (`gdt::setup_page_tables`, `acpi::setup_acpi`) violated
    /// by the combination given. Distinct from the other variants because
    /// it's caused by the caller's input, not something that went wrong on
    /// this host — mirrors the CLI's existing exit-code-2-vs-1 split (see
    /// `exit_code()` below and `python/hyperbug/vm.py`'s
    /// `_LAUNCH_ERROR_CODES`, which already treats both as pre-guest
    /// launch failures).
    Config(String),
}

impl fmt::Display for HyperbugError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, msg) = match self {
            Self::Io(m) => ("I/O error", m),
            Self::Kvm(m) => ("KVM error", m),
            Self::Python(m) => ("Python device error", m),
            Self::Config(m) => ("configuration error", m),
        };
        write!(f, "{kind}: {msg}")
    }
}

impl std::error::Error for HyperbugError {}

impl From<std::io::Error> for HyperbugError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<kvm_ioctls::Error> for HyperbugError {
    fn from(e: kvm_ioctls::Error) -> Self {
        Self::Kvm(e.to_string())
    }
}

impl From<pyo3::PyErr> for HyperbugError {
    fn from(e: pyo3::PyErr) -> Self {
        Self::Python(e.to_string())
    }
}

impl HyperbugError {
    /// The process exit code `main.rs` uses for this error — matches the
    /// pre-refactor behavior exactly (1 for "something failed on this
    /// host", 2 for "the arguments/config given don't work"), which is
    /// also what `python/hyperbug/vm.py`'s `_LAUNCH_ERROR_CODES` already
    /// expects.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) => 2,
            Self::Io(_) | Self::Kvm(_) | Self::Python(_) => 1,
        }
    }
}

/// Why a guest's run ended, on the success path — matches
/// `python/hyperbug/vm.py`'s `ExitCode` and `acpi::exit_code` exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestExit {
    CleanShutdown,
    RequestedReboot,
    TripleFault,
    /// The host operator pressed Ctrl-] to quit — not a guest-driven exit
    /// at all, but reported through the same path since it's still "the
    /// run ended, here's why."
    UserQuit,
    /// This process's guest was live-migrated away to a separate hyperbug
    /// process via the control socket's `migrate <host:port>` command
    /// (`migrate.rs`) — not a failure, and not a guest-driven exit either:
    /// the guest is still running, just somewhere else now.
    MigratedAway,
}

impl GuestExit {
    /// Matches the exact process exit codes hyperbug has always used for
    /// each of these (see `acpi::exit_code`); `UserQuit` keeps the `1` it
    /// always used, even though that overlaps with `HyperbugError`'s
    /// "something failed" bucket — preserving prior behavior exactly
    /// rather than changing an externally-visible exit code as a side
    /// effect of a refactor.
    pub fn code(self) -> i32 {
        match self {
            Self::CleanShutdown => crate::acpi::exit_code::CLEAN_SHUTDOWN,
            Self::RequestedReboot => crate::acpi::exit_code::REQUESTED_REBOOT,
            Self::TripleFault => crate::acpi::exit_code::TRIPLE_FAULT,
            Self::UserQuit => 1,
            Self::MigratedAway => crate::acpi::exit_code::MIGRATED_AWAY,
        }
    }
}

/// Shared across every vCPU thread, the reactor thread, and hyperbug's own
/// ACPI shutdown/reset devices (which otherwise have no way to signal
/// "stop the VM" without a `Device::write` signature change reaching every
/// third-party plugin too): the first thread or device to decide the VM
/// should stop records why here, and everyone else notices on their next
/// check. First writer wins — an AP's fatal error racing a clean guest
/// shutdown shouldn't silently overwrite the real cause.
///
/// The flag is a separate atomic from the result. Every vCPU checks "has
/// anyone asked to stop?" once per VM exit, which is the hottest loop in
/// the VMM: a relaxed-ish atomic load there costs nothing, whereas taking
/// a process-wide `Mutex` per exit on every vCPU thread (what this used to
/// do) is real contention that scales with `--smp`.
pub struct ExitSignal {
    requested: AtomicBool,
    result: Mutex<Option<Result<GuestExit, HyperbugError>>>,
}

pub type ExitSlot = Arc<ExitSignal>;

impl ExitSignal {
    /// Cheap check for "should this loop wind down?" — no lock taken.
    #[inline]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    /// The recorded outcome, once someone has asked to stop.
    pub fn take(&self) -> Option<Result<GuestExit, HyperbugError>> {
        if !self.is_requested() {
            return None;
        }
        self.result.lock().unwrap().clone()
    }
}

pub fn new_exit_slot() -> ExitSlot {
    Arc::new(ExitSignal { requested: AtomicBool::new(false), result: Mutex::new(None) })
}

pub fn request_exit(slot: &ExitSlot, result: Result<GuestExit, HyperbugError>) {
    let mut guard = slot.result.lock().unwrap();
    if guard.is_none() {
        *guard = Some(result);
        // Released *after* the result is stored, and read with Acquire, so
        // anyone who sees the flag set also sees the result behind it.
        slot.requested.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_writer_wins_and_later_ones_do_not_overwrite_it() {
        let slot = new_exit_slot();
        assert!(!slot.is_requested());
        assert!(slot.take().is_none());

        request_exit(&slot, Ok(GuestExit::CleanShutdown));
        request_exit(&slot, Err(HyperbugError::Kvm("a later, unrelated fault".into())));

        assert!(slot.is_requested());
        assert_eq!(slot.take().unwrap().unwrap(), GuestExit::CleanShutdown);
    }

    #[test]
    fn exit_codes_match_the_documented_python_side_values() {
        assert_eq!(GuestExit::CleanShutdown.code(), 0);
        assert_eq!(GuestExit::RequestedReboot.code(), 10);
        assert_eq!(GuestExit::TripleFault.code(), 11);
        assert_eq!(GuestExit::MigratedAway.code(), 13);
        assert_eq!(HyperbugError::Config(String::new()).exit_code(), 2);
        assert_eq!(HyperbugError::Kvm(String::new()).exit_code(), 1);
    }
}
