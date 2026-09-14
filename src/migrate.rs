//! Live migration (Tier 5's last remaining item): `migrate <host:port>`
//! on the control socket captures this process's live guest state (the
//! same `snapshot::CapturedState` mechanism `--restore`/`fork.rs` already
//! use) and streams it, guest memory included, over a plain TCP
//! connection to a *separate* hyperbug process that was launched with
//! `--migrate-listen <host:port>` and is blocked waiting to receive
//! exactly this. Once the transfer succeeds, this process's own guest is
//! retired for good (`GuestExit::MigratedAway`) — unlike `fork.rs`, there
//! is no parent left running afterward; the whole point of migration is
//! that the guest now lives somewhere else (a different process, and in
//! the real motivating case, a different host).
//!
//! ## Why this reuses `fork.rs`'s exact scope limits
//!
//! Both features serialize the same `CapturedState` off a live vCPU —
//! migration additionally has to copy every byte of guest memory across
//! the wire (unlike `fork()`'s free copy-on-write hand-off within one
//! host), but the *set* of things that don't survive being serialized at
//! all is identical to fork's own: an arbitrary device plugin's own
//! internal/interpreter state, and an in-flight `--record`/`--replay`/
//! `--gdb-stub`/`--trace-file` session, plus single-vCPU-only for the same
//! reason `--restore` already states. `snapshot::validate_capturable` is
//! the one shared check both `fork::validate_forkable` and this module's
//! own `validate_migratable` call, so the two features can't quietly
//! drift apart on what they each consider capturable.
//!
//! ## What the destination process looks like
//!
//! A separate `hyperbug --migrate-listen <host:port> --kernel ... --mem
//! ... [--disk ...] [--net] ...` process, launched ahead of time with the
//! *same* device configuration (memory size, disks, net, `--rng-modern`)
//! the source guest is running — `restore_device_state` enforces this
//! exactly the way file-based `--restore` already does, since it's the
//! literal same function either way (see `lib.rs::run`). It blocks in
//! `receive_and_wait`'s `TcpListener::accept()` until this module's
//! `handle_migrate` connects from the source, then resumes execution from
//! exactly where the source left off via the same `restore_vcpu`/
//! `run_from_vcpus` path `--restore`/`fork.rs` both already use.
//!
//! ## Scope, stated plainly
//!
//! - **No security on the migration stream at all** — a plain,
//!   unauthenticated, unencrypted TCP connection carrying a complete copy
//!   of guest memory (which can hold real guest secrets) and full vCPU
//!   state. Fine on a private/trusted network, the same threat model this
//!   project's own control socket already documents for itself (see
//!   `docs/security/security.md`); a real deployment crossing anything
//!   less trusted would want this wrapped in TLS or run over an
//!   already-trusted transport (an SSH tunnel, a private VPC/VXLAN) —
//!   not something this module attempts itself.
//! - **Stop-the-world, not pre-copy**: this pauses the guest for the
//!   entire capture-and-transfer (the vCPU isn't running while
//!   `handle_migrate` executes — same as any other control-socket
//!   command — and the reactor thread is parked via `ReactorPause` for
//!   the same reason `fork.rs` pauses it), not the iterative
//!   dirty-page pre-copy a production hypervisor's live migration uses to
//!   keep guest downtime to milliseconds against a multi-gigabyte guest.
//!   Downtime here is roughly "however long it takes to send guest memory
//!   over the network" — stated directly rather than implied seamless.
//! - **One connection, then done, and safe to retry on failure**: a
//!   failed connection or transfer leaves the source guest fully running
//!   (the reactor is resumed and no exit is ever requested) — nothing
//!   here half-migrates a guest and leaves it running nowhere.

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use kvm_ioctls::{VcpuFd, VmFd};

use crate::config::Args;
use crate::control::SnapshotDeps;
use crate::error::{ExitSlot, GuestExit, request_exit};
use crate::mem::GuestMemory;
use crate::reactor::ReactorPause;
use crate::snapshot;

/// Everything `handle_migrate` needs beyond the destination address and
/// the vCPU it captures from — bundled the same way `fork::ForkRequest`
/// is, for the same clippy `too_many_arguments` reason.
pub struct MigrateRequest<'a> {
    pub vm: &'a VmFd,
    pub mem: &'a Arc<Mutex<GuestMemory>>,
    pub args: &'a Args,
    pub pause: &'a ReactorPause,
    pub exit_slot: &'a ExitSlot,
    pub snap: SnapshotDeps<'a>,
}

/// Handles a `migrate <dest-host:dest-port>` control-socket command. On
/// success, requests `GuestExit::MigratedAway` on `exit_slot` — this
/// process's own guest run is over, for good. The caller (`control.rs`)
/// still sends its `OK`/`ERR` reply over the control socket before any
/// vCPU thread notices the exit request and winds down, so the client
/// that asked for the migration always learns whether it worked, even
/// though the process is about to exit right after replying.
pub fn handle_migrate(dest_addr: &str, vcpu: &mut VcpuFd, req: MigrateRequest) -> Result<(), String> {
    let MigrateRequest { vm, mem, args, pause, exit_slot, snap } = req;
    snapshot::validate_capturable(args, "migrate")?;

    // Captured *before* pausing the reactor — reading vCPU/device state
    // only ever touches this thread's own vCPU and the `SharedState` lock
    // the caller (`control.rs`) already holds, neither of which the
    // reactor pause below is about. Same ordering `fork.rs` uses, for the
    // same reason.
    let captured = snapshot::capture_live_state(vm, vcpu, snap.serial, snap.pci_bus, snap.virtio)?;

    if !pause.request_and_wait() {
        return Err("reactor thread did not pause in time; refusing to migrate".to_string());
    }

    let mem_guard = mem.lock().unwrap();
    let result = (|| -> Result<(), String> {
        let mut stream = TcpStream::connect(dest_addr)
            .map_err(|e| format!("connecting to migration destination {dest_addr}: {e}"))?;
        snapshot::write_to(&mut stream, &captured, &mem_guard)?;
        stream.flush().map_err(|e| format!("flushing migration stream to {dest_addr}: {e}"))
    })();
    drop(mem_guard);

    match result {
        Ok(()) => {
            request_exit(exit_slot, Ok(GuestExit::MigratedAway));
            Ok(())
        }
        Err(e) => {
            // The guest never left, so it keeps running exactly as if
            // migration was never attempted — a failed attempt is always
            // safe to retry.
            pause.resume();
            Err(e)
        }
    }
}

/// The destination side: blocks until exactly one migration arrives on
/// `addr`, then hands back the same `LoadedSnapshot` file-based
/// `--restore` (`snapshot::load_from_file`) would — `lib.rs::run()`
/// treats the two identically from here on (validated against this
/// launch's own `Args`, then applied via `restore_vcpu`/
/// `restore_device_state`, the same functions `--restore` and `fork.rs`'s
/// forked child already share).
pub fn receive_and_wait(addr: &str) -> Result<snapshot::LoadedSnapshot, String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("binding migration listener on {addr}: {e}"))?;
    crate::log_info!("waiting for an incoming migration on {addr}...");
    let (mut stream, peer) = listener.accept().map_err(|e| format!("accepting migration connection: {e}"))?;
    let _ = stream.set_nodelay(true);
    crate::log_info!("migration connection accepted from {peer}");
    snapshot::read_from(&mut stream)
}
