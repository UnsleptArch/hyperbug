//! Fast fork-a-running-VM (Tier 5): `fork <new-control-socket-path>` on
//! the control socket clones a *live* running guest into a brand new,
//! fully independent hyperbug process — the parent keeps running
//! completely undisturbed, and the child continues execution from
//! exactly the same point, with guest memory shared for free via a real
//! `fork()`'s copy-on-write semantics (no serialize-to-file, no memory
//! copy) instead of a full snapshot/restore round trip through disk.
//!
//! ## Why this is even possible: what `snapshot.rs` already built
//!
//! Every piece of KVM-side state a fresh VM needs to resume exactly where
//! a running one left off (`kvm_regs`/`sregs`/`xsave`/irqchip/PIT/device
//! protocol blobs) was already captured and re-applied by the
//! `--restore` feature (`snapshot.rs`'s `CapturedState`, `lib.rs`'s
//! `restore_vcpu`/`restore_device_state`). Fork reuses that exact
//! mechanism unchanged, in memory, with one real difference: it skips
//! guest memory's own copy entirely, relying on `fork()`'s own
//! copy-on-write semantics to hand the child an independent view of the
//! *same* mapping instead — the single largest cost a file-based
//! snapshot/restore round trip has (writing potentially gigabytes of RAM
//! to a file and reading it back) simply doesn't exist here.
//!
//! ## The real hazard: KVM state does not follow `fork()`, threads do not
//! either, and the reactor thread must be quiesced first
//!
//! `fork()` gives the child a real, independent copy of this process's
//! *userspace* address space, guest memory included — confirmed directly
//! against this project's own AMD/KVM host before writing a line of this
//! module: a standalone probe built a real anonymous `MAP_PRIVATE`
//! mapping, a real `KVM_CREATE_VM`, forked, and had the child stand up
//! its *own* independent `KVM_CREATE_VM` against the inherited mapping —
//! writes in the child never touched the parent's view. But `fork()`
//! does **not** give the child a working copy of the parent's
//! *kernel-side* KVM VM: the inherited `VmFd`/`VcpuFd` in the child are
//! duplicate file descriptors pointing at the exact same underlying
//! kernel VM object the parent still owns — using them from the child
//! would mean both processes driving one VM, corrupting everything. The
//! child must never touch them; it creates a brand new `KVM_CREATE_VM`
//! (reusing the same already-open `/dev/kvm` fd, which *is* fork-safe —
//! it's just a factory, not tied to a specific VM instance) and applies
//! the captured state to that instead.
//!
//! Nor does `fork()` give the child a working copy of any thread but the
//! one that called it — hyperbug's reactor thread simply doesn't exist in
//! the child at all. If the reactor thread happened to be holding a lock
//! (`SharedState`, `GuestMemory`) at the exact instant of the fork, that
//! lock would be permanently stuck in the child with no thread ever able
//! to release it — this project's own history (item 9's segfault, item
//! 35's wakeup-ticker regression) is exactly why "just fork and hope"
//! isn't a real strategy for a concurrency-adjacent feature here.
//! `reactor::ReactorPause` is a real rendezvous that parks the reactor
//! thread at a genuinely lock-free point (the very top of its loop,
//! before any dispatch) before this module ever calls `fork()`, and
//! resumes it in the parent afterward.
//!
//! ## Scope, stated plainly
//!
//! - **Single vCPU only** — an AP thread has exactly the same
//!   "vanishes in the child, possibly mid-lock" problem the reactor
//!   thread has, and quiescing an arbitrary number of them adds real
//!   complexity for no immediate need.
//! - **No device plugins of any kind** (`--device`/`--pci-device`,
//!   in-process, sandboxed, native, or WASM) — an arbitrary plugin's own
//!   internal state (and, for in-process Python plugins, PyO3's own
//!   CPython interpreter/GIL state) does not survive `fork()` safely.
//!   Same restriction `--restore` already has, for the same reason,
//!   extended to every plugin transport that exists now.
//! - **No `--record`/`--replay`/`--gdb-stub`/`--trace-file`** — each
//!   holds its own open file/socket/counter with no obviously-correct
//!   answer for "what does the child do with this," and none of them was
//!   worth improvising an answer for in this first pass.
//! - **The child's leaked handle to the parent's old `VmFd`/`SharedState`
//!   lock is deliberate, not a bug**: the child never returns through the
//!   call stack that was holding them (see `handle_fork`'s own doc
//!   comment for why), so their destructors never run — harmless, since
//!   the child never touches that old VM/state again and the OS reclaims
//!   everything when the process eventually exits.

use std::sync::{Arc, Mutex};

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuFd, VmFd};

use crate::config::Args;
use crate::control::SnapshotDeps;
use crate::error::{GuestExit, HyperbugError};
use crate::mem::GuestMemory;
use crate::reactor::ReactorPause;
use crate::snapshot::{self, CapturedState};

/// Rejects a fork request outright if this launch's configuration is one
/// of the cases this module's own doc comment names as unsupported —
/// checked before doing anything real (capturing state, pausing the
/// reactor), so an unsupported request fails cleanly and cheaply. See
/// `snapshot::validate_capturable` (shared with `migrate.rs`'s own
/// identical restriction) for the actual checks.
fn validate_forkable(args: &Args) -> Result<(), String> {
    snapshot::validate_capturable(args, "fork")
}

/// Handles a `fork <new-control-socket-path>` control-socket command.
/// Returns `Ok(child_pid)` in the parent (which keeps running completely
/// undisturbed). **Never returns at all in the child** — it instead runs
/// the new guest to completion and calls `std::process::exit` directly,
/// the same way `main.rs` does for a normal launch. That's a deliberate,
/// necessary departure from this codebase's usual "never `process::exit`
/// below `main.rs`" rule: the forked child has no meaningful way to
/// "return" a `Result` up through the control socket's own command-reply
/// plumbing, because from the moment `fork()` returns zero, this is no
/// longer a control-socket command being handled — it's an entire new
/// guest's lifecycle beginning.
pub struct ForkRequest<'a> {
    pub kvm: &'a Arc<Kvm>,
    pub old_vm: &'a VmFd,
    pub mem: &'a Arc<Mutex<GuestMemory>>,
    pub args: &'a Args,
    pub pause: &'a ReactorPause,
    pub snap: SnapshotDeps<'a>,
}

pub fn handle_fork(new_control_socket: &str, old_vcpu: &mut VcpuFd, req: ForkRequest) -> Result<i32, String> {
    let ForkRequest { kvm, old_vm, mem, args, pause, snap } = req;
    validate_forkable(args)?;

    // Captured *before* pausing the reactor or forking — reading vCPU/
    // device state only ever touches this thread's own vCPU and the
    // `SharedState` lock the caller (`control.rs`) already holds, neither
    // of which the reactor pause below is about.
    let captured = snapshot::capture_live_state(old_vm, old_vcpu, snap.serial, snap.pci_bus, snap.virtio)?;

    if !pause.request_and_wait() {
        return Err("reactor thread did not pause in time; refusing to fork".to_string());
    }

    // SAFETY: `fork()` itself has no precondition beyond "the caller is
    // prepared for a second, largely-identical thread of control to
    // return from this same call" — every branch below is written to
    // handle its own side correctly (the parent resumes the reactor and
    // returns normally; the child never touches the pre-fork
    // `old_vm`/`old_vcpu` again and builds everything else fresh).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        pause.resume();
        return Err(format!("fork() failed: {}", std::io::Error::last_os_error()));
    }
    if pid > 0 {
        pause.resume();
        return Ok(pid);
    }

    // --- Child from here on. Never returns. ---
    let mut child_args = args.clone();
    child_args.control_socket = Some(new_control_socket.to_string());
    child_args.restore = None;
    child_args.migrate_listen = None;
    child_args.record = None;
    child_args.replay = None;
    child_args.gdb_stub = None;
    child_args.trace_file = None;

    let (ptr, size) = {
        let guard = mem.lock().unwrap();
        (guard.as_ptr(), guard.size())
    };

    let exit = run_forked_child(kvm.clone(), ptr, size, captured, child_args);
    match exit {
        Ok(guest_exit) => std::process::exit(guest_exit.code()),
        Err(e) => {
            crate::log_error!("forked child failed: {e}");
            std::process::exit(e.exit_code());
        }
    }
}

/// Everything the forked child needs to become a fully independent
/// guest: a fresh `KVM_CREATE_VM` (the old one belongs to the parent's
/// still-running VM and must never be touched), the inherited (`fork()`
/// copy-on-write, not copied) memory mapping rebound to it, a fresh vCPU
/// carrying the captured state, and then the exact same "build the device
/// model and run" path (`lib.rs`'s `run_from_vcpus`) a normal launch or a
/// file-based `--restore` uses.
fn run_forked_child(
    kvm: Arc<Kvm>,
    mem_ptr: *mut u8,
    mem_size: usize,
    captured: CapturedState,
    child_args: Args,
) -> Result<GuestExit, HyperbugError> {
    let new_vm = Arc::new(kvm.create_vm()?);
    new_vm.create_irq_chip()?;
    new_vm.create_pit2(kvm_bindings::kvm_pit_config::default())?;

    // SAFETY: `mem_ptr`/`mem_size` are exactly what the parent's own
    // `GuestMemory` reported for its still-valid mapping, inherited
    // unchanged by this (freshly forked) process — see
    // `GuestMemory::from_inherited_mapping`'s own safety contract.
    let guest_mem = unsafe { GuestMemory::from_inherited_mapping(mem_ptr, mem_size) }?;

    // SAFETY: the same contract `lib::run`'s own equivalent call already
    // relies on — the mapping is `mem_size` bytes long and stays alive
    // for as long as this VM does (owned by `guest_mem`, moved into
    // `run_from_vcpus`'s own `Arc<Mutex<..>>` next).
    unsafe {
        new_vm.set_user_memory_region(kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: mem_size as u64,
            userspace_addr: mem_ptr as u64,
            flags: 0,
        })
    }?;

    let vcpus = crate::restore_vcpu(&kvm, &new_vm, &captured)?;
    crate::run_from_vcpus(child_args, kvm, new_vm, guest_mem, vcpus, Some(&captured))
}
