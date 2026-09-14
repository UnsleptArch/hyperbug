//! hyperbug's embeddable core: `run(Args) -> Result<GuestExit, HyperbugError>`
//! runs one guest to completion (or a launch/runtime failure) and returns
//! — it never calls `std::process::exit` or `panic!` on an expected
//! failure path. `main.rs` is a thin CLI wrapper around this: it parses
//! `argv` into an `Args` (which any other embedder builds directly,
//! without ever touching CLI parsing) and translates the returned
//! `Result` into a process exit code.
//!
//! This file is deliberately only the *orchestration*: validate the
//! configuration, build the VM and its memory, load the kernel, create the
//! vCPUs, then start the threads. The pieces live next door —
//! `config.rs` (what to run), `machine.rs` (the device model),
//! `vcpu.rs` (one vCPU's exit loop), `reactor.rs` (host-side I/O events),
//! `error.rs` (how a run ends).

mod acpi;
mod cgroup;
mod config;
mod control;
mod cpuid;
mod crashdump;
mod device;
mod error;
mod fork;
mod gdbstub;
mod gdt;
mod gpio;
mod i2c;
mod irq;
mod loader;
mod logging;
mod machine;
mod mem;
mod migrate;
mod native_plugin;
mod pci;
mod plugin;
/// `pub` (unlike every other internal module here) specifically so
/// `tests/boot.rs` can attach a real `BranchCounter` to a live guest's
/// vCPU thread from outside the process — the counter is meaningless
/// without a genuine external target to point it at, so testing it can't
/// stay purely internal the way the rest of this crate's unit tests do.
pub mod pmu;
/// `pub` for the same reason `pmu` is: `tests/boot.rs` needs to read a
/// real recording file back to verify `--record` actually captured
/// real, live keystrokes — there's no other way to inspect one from
/// outside the process.
pub mod record;
mod pydevice;
mod pydevice_proc;
mod reactor;
mod seccomp;
mod serial;
mod smbios;
mod snapshot;
mod trace;
mod tty;
mod vcpu;
mod virtio;
mod virtio_blk;
mod virtio_gpio;
mod virtio_i2c;
mod virtio_net;
mod virtio_vsock;
mod virtio_rng;
mod vsock;
mod wasm_plugin;

use std::sync::{Arc, Mutex};

use kvm_bindings::{
    KVM_MAX_CPUID_ENTRIES, KVM_MP_STATE_UNINITIALIZED, kvm_mp_state, kvm_regs,
    kvm_userspace_memory_region,
};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};

use error::new_exit_slot;
use irq::IrqRegistry;
use loader::{BzImage, Initramfs};
use machine::{Machine, SharedState};
use mem::GuestMemory;
use snapshot::Snapshot;
use vcpu::VcpuEnv;

pub use config::{Args, DeviceSpec, PciDeviceSpec, USAGE};
pub use error::{GuestExit, HyperbugError};

/// Below this, the fixed low-memory layout (GDT, page tables, zero page,
/// command line — all below `CMDLINE_START + 4 KiB`) wouldn't fit before
/// `loader::KERNEL_START`.
const MIN_MEM_MB: u64 = 32;

/// Cadence of the periodic `SIGALRM` that guarantees a blocked `KVM_RUN`
/// returns often enough for the BSP to poll the control socket and any
/// Python device's spontaneous interrupt flag. See
/// `tty::install_periodic_wakeup` for why this exists and what it can and
/// can't be relied on for.
const WAKEUP_INTERVAL_MS: i64 = 20;

/// Runs one guest to completion. Returns `Ok(GuestExit)` for a normal end
/// of run (clean ACPI shutdown, a requested reboot, a triple fault, or the
/// host operator quitting via Ctrl-]), or `Err(HyperbugError)` for a
/// launch failure (bad config, a file/device that couldn't be opened, a
/// KVM ioctl that failed) or a mid-run fault. Never calls
/// `std::process::exit` or panics on any of those paths — see the module
/// doc comment for why that's the point.
pub fn run(args: Args) -> Result<GuestExit, HyperbugError> {
    // `Arc`-wrapped so `fork.rs`'s forked child (a copy of this same
    // process, sharing this value via `fork()`'s own COW semantics, not
    // literal cross-process sharing) can call `.create_vm()` on it again
    // to stand up its own independent VM — `/dev/kvm`'s own fd is a
    // factory, not tied to any specific VM instance, so this is safe to
    // reuse post-fork even though the VM/vCPU fds it creates are not.
    let kvm = Arc::new(Kvm::new()?);
    let mem_size = validate_memory(&args)?;
    let num_cpus = validate_smp(&args, &kvm)?;
    validate_restore(&args)?;
    validate_record(&args)?;

    let vm = Arc::new(kvm.create_vm()?);
    vm.create_irq_chip()?;
    vm.create_pit2(kvm_bindings::kvm_pit_config::default())?;

    let mut guest_mem = GuestMemory::new(mem_size as usize)?;
    // SAFETY: the mapping is `mem_size` bytes long, stays alive for as
    // long as the VM (it's moved into the `Arc<Mutex<..>>` below), and is
    // never mapped into the guest at more than this one slot.
    unsafe {
        vm.set_user_memory_region(kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: mem_size,
            userspace_addr: guest_mem.as_ptr() as u64,
            flags: 0,
        })
    }?;

    // `--restore`/`--migrate-listen`: a snapshot supplies guest memory and
    // vCPU state wholesale instead of a normal kernel boot
    // (`validate_restore` already rejected anything this doesn't support
    // — more than one vCPU, any Python device plugin, or both flags at
    // once). See `snapshot.rs`'s module doc comment for the file-based
    // design and `migrate.rs`'s for the live-network one; both produce
    // the identical `LoadedSnapshot` shape from here on.
    let loaded_snapshot = if let Some(path) = &args.restore {
        Some(snapshot::load_from_file(path).map_err(HyperbugError::Config)?)
    } else if let Some(addr) = &args.migrate_listen {
        Some(migrate::receive_and_wait(addr).map_err(HyperbugError::Config)?)
    } else {
        None
    };
    let (vcpus, captured_state) = if let Some(snap) = &loaded_snapshot {
        if snap.mem_size != mem_size {
            return Err(HyperbugError::Config(format!(
                "snapshot was taken with {} MiB of guest memory, this launch has {} MiB \
                 (--mem must match exactly to restore)",
                snap.mem_size / (1024 * 1024),
                mem_size / (1024 * 1024)
            )));
        }
        if !guest_mem.write_checked(0, &snap.memory) {
            return Err(HyperbugError::Config(
                "snapshot's own memory dump doesn't fit the guest RAM it claims to describe".to_string(),
            ));
        }
        (restore_vcpu(&kvm, &vm, &snap.captured)?, Some(&snap.captured))
    } else {
        let entry_point = load_guest(&args, &mut guest_mem, mem_size, num_cpus)?;
        (create_vcpus(&kvm, &vm, &mut guest_mem, mem_size, num_cpus, entry_point)?, None)
    };

    run_from_vcpus(args, kvm, vm, guest_mem, vcpus, captured_state)
}

/// Everything from "guest memory becomes DMA-shared" onward — shared by
/// the normal launch path above (`run`) and `fork.rs`'s forked child,
/// which reaches this point with a *freshly created* VM/vCPU already
/// carrying restored state (`restore_vcpu`, same as `--restore`'s own
/// path) and *inherited* (copy-on-write, not copied) guest memory instead
/// of a normal boot. Nothing below this point knows or cares which of
/// those got it here — `args` is the only place that distinguishes them
/// (a forked child's `Args` has `control_socket` overridden to its own
/// new path, and `restore`/`record`/`replay`/`gdb_stub`/`trace_file`
/// cleared — see `fork.rs`'s own doc comment for why each of those is
/// disallowed for now).
pub(crate) fn run_from_vcpus(
    args: Args,
    kvm: Arc<Kvm>,
    vm: Arc<VmFd>,
    guest_mem: GuestMemory,
    vcpus: Vec<VcpuFd>,
    captured_state: Option<&snapshot::CapturedState>,
) -> Result<GuestExit, HyperbugError> {
    let mem_size = guest_mem.size() as u64;
    // From here on, guest memory is also DMA-accessible to devices (virtio
    // and anything else that reads/writes guest RAM directly), so it's
    // shared rather than exclusively owned — and with more than one vCPU
    // thread, more than one of them can trigger a DMA access concurrently.
    let guest_mem = Arc::new(Mutex::new(guest_mem));

    // First writer wins: any vCPU thread, the reactor, or hyperbug's own
    // ACPI shutdown/reset devices record the run's outcome here.
    let exit_slot = new_exit_slot();

    // `--record`: Milestone 2 of record-and-replay (`record.rs`) — tags
    // every keyboard byte, delivered TAP packet, and virtio-rng byte
    // returned to the guest with the host branch-count position it was
    // produced/delivered at. Created before `Machine::build` so it can be
    // handed to `VirtioRng` at construction time; `std::process::id()` is
    // the BSP's own thread TID because `validate_record` already required
    // `--smp 1`, and this function itself always runs on the process's
    // main thread (the same one the BSP vCPU later runs on).
    let recorder = match &args.record {
        Some(path) => Some(Arc::new(
            record::Recorder::start(path, std::process::id() as libc::pid_t, mem_size)
                .map_err(HyperbugError::Config)?,
        )),
        None => None,
    };
    // `--replay`: Milestone 3 (`record.rs`'s `Replayer`) — re-delivers a
    // previous `--record` run's keyboard/virtio-rng data. `validate_record`
    // already rejected `--record` and `--replay` together, so at most one
    // of `recorder`/`replayer` is ever `Some`.
    let replayer = match &args.replay {
        Some(path) => Some(Arc::new(Mutex::new(
            record::Replayer::start(path, std::process::id() as libc::pid_t, mem_size)
                .map_err(HyperbugError::Config)?,
        ))),
        None => None,
    };

    let mut irqs = IrqRegistry::new();
    let machine = Machine::build(&args, &vm, &guest_mem, &exit_slot, &mut irqs, recorder.clone(), replayer.clone())?;
    if let Some(snap) = captured_state {
        restore_device_state(&machine, snap)?;
    }
    let irqs = Arc::new(irqs);

    tty::install_periodic_wakeup(WAKEUP_INTERVAL_MS);
    // Raw + non-blocking stdin so the guest's console is a real two-way
    // interactive terminal (no host-side line buffering/echo fighting with
    // the guest's own tty layer) rather than output-only. A no-op (with a
    // clear reason) when stdin isn't actually a terminal — e.g. hyperbug's
    // own test harness or a piped script feeding it a kernel path only.
    // Skipped entirely under `--replay`: real typed input has no business
    // mixing with recorded input being injected instead.
    if replayer.is_none() && !tty::enable_raw_stdin() {
        eprintln!("[hyperbug] stdin isn't a terminal — guest console is output-only");
    }

    // Real, event-driven stdin/TAP handling: a dedicated thread blocking
    // in `epoll_wait`, injecting interrupts directly via `irqs` with no
    // vCPU thread involved at all — see `reactor.rs` for what deliberately
    // stays on the per-iteration poll in `vcpu.rs`, and why. Real stdin is
    // never watched under `--replay` (keyboard input comes from the
    // recording instead, delivered from `vcpu.rs`'s own poll loop — see
    // `VcpuEnv::replayer`); TAP still is, since network replay isn't
    // implemented yet and a `--net` guest's other traffic should keep
    // working normally.
    // `fork.rs`'s rendezvous for pausing this reactor thread at a safe
    // point before a `fork <path>` control-socket command forks the
    // process — see `ReactorPause`'s own doc comment.
    let reactor_pause = reactor::ReactorPause::new();
    reactor::spawn(reactor::ReactorConfig {
        shared: machine.shared.clone(),
        exit_slot: exit_slot.clone(),
        irqs: irqs.clone(),
        net_devices: machine.net_devices,
        virtio_notifies: machine.virtio_notifies,
        blk_devices: machine.blk_devices,
        gpio_devices: machine.gpio_devices,
        vsock_device: machine.vsock_device,
        recorder,
        suppress_stdin: replayer.is_some(),
        pause: reactor_pause.clone(),
    });

    // Opt-in Chrome Trace Event Format export — see `trace.rs`. `None`
    // unless `--trace-file` was given, in which case every vCPU thread
    // shares one writer (opt-in, so the extra lock per VM exit is an
    // accepted cost, not a hot-path regression on a normal run).
    let trace = match &args.trace_file {
        Some(path) => Some(Arc::new(Mutex::new(trace::TraceWriter::create(path).map_err(|e| {
            HyperbugError::Io(format!("creating trace file {path}: {e}"))
        })?))),
        None => None,
    };

    // `--gdb-stub`: blocks here (before any vCPU runs) until a debugger
    // connects — see `gdbstub.rs` for the full scope (BSP-only, software
    // breakpoints). `None` when not requested, in which case the BSP's
    // loop never even checks for one.
    let gdb = match &args.gdb_stub {
        Some(addr) => Some(
            gdbstub::GdbStub::listen(addr)
                .map_err(|e| HyperbugError::Io(format!("gdb stub: binding {addr}: {e}")))?,
        ),
        None => None,
    };

    let env = VcpuEnv {
        vm,
        guest_mem,
        shared: machine.shared,
        exit_slot: exit_slot.clone(),
        irqs,
        trace,
        crash_dir: args.crash_dir.clone(),
        replayer,
        kvm,
        fork_args: args,
        reactor_pause,
    };
    let bsp_result = spawn_vcpu_threads(vcpus, &env, gdb);
    exit_slot.take().unwrap_or(bsp_result)
}

fn validate_memory(args: &Args) -> Result<u64, HyperbugError> {
    if args.mem_mb < MIN_MEM_MB {
        return Err(HyperbugError::Config(format!("--mem must be at least {MIN_MEM_MB} MiB")));
    }
    let mem_size = args
        .mem_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| HyperbugError::Config(format!("--mem {} MiB overflows", args.mem_mb)))?;
    let max = gdt::max_identity_map();
    if mem_size > max {
        return Err(HyperbugError::Config(format!(
            "--mem {} MiB exceeds the current {} MiB identity-map limit",
            args.mem_mb,
            max / (1024 * 1024)
        )));
    }
    Ok(mem_size)
}

/// At least 1, and validated against what this host's KVM actually
/// recommends supporting rather than an arbitrary guess —
/// `get_nr_vcpus()` is a real, evidence-based bound.
fn validate_smp(args: &Args, kvm: &Kvm) -> Result<u8, HyperbugError> {
    if args.smp == 0 {
        return Err(HyperbugError::Config("--smp must be at least 1".to_string()));
    }
    let max_vcpus = kvm.get_nr_vcpus();
    if usize::from(args.smp) > max_vcpus {
        return Err(HyperbugError::Config(format!(
            "--smp {} exceeds this host's KVM_CAP_NR_VCPUS ({max_vcpus})",
            args.smp
        )));
    }
    Ok(args.smp)
}

/// `--restore`'s scope limits (see `snapshot.rs`'s module doc comment):
/// single vCPU only, and no Python device plugin (arbitrary, unserialized
/// state).
/// `--record`'s scope limit: single vCPU only, for the same reason
/// `--restore` is — the branch-count position `record.rs` tags every
/// event with is meaningless once more than one vCPU can be racing
/// against it.
fn validate_record(args: &Args) -> Result<(), HyperbugError> {
    if args.record.is_some() && args.smp != 1 {
        return Err(HyperbugError::Config("--record only supports --smp 1 today".to_string()));
    }
    if args.replay.is_some() && args.smp != 1 {
        return Err(HyperbugError::Config("--replay only supports --smp 1 today".to_string()));
    }
    if args.record.is_some() && args.replay.is_some() {
        return Err(HyperbugError::Config("--record and --replay are mutually exclusive".to_string()));
    }
    Ok(())
}

/// Shared by `--restore` and `--migrate-listen` — both feed a
/// `snapshot::LoadedSnapshot` into the exact same restore path below, so
/// they carry the exact same launch-time restrictions (single-vCPU, no
/// Python device plugin state) and can't sensibly be combined with each
/// other. Deliberately narrower than `snapshot::validate_capturable` (used
/// on the *sending* side, `fork.rs`/`migrate.rs`): a file made by
/// `--record`/`--replay`/`--gdb-stub`/`--trace-file`-adjacent code paths
/// was never possible in the first place (those flags don't touch
/// `CapturedState`), so there's nothing here to reject that isn't already
/// covered by the device-plugin/`--smp` checks.
fn validate_restore(args: &Args) -> Result<(), HyperbugError> {
    if args.restore.is_some() && args.migrate_listen.is_some() {
        return Err(HyperbugError::Config(
            "--restore and --migrate-listen are mutually exclusive".to_string(),
        ));
    }
    if args.restore.is_none() && args.migrate_listen.is_none() {
        return Ok(());
    }
    let flag = if args.restore.is_some() { "--restore" } else { "--migrate-listen" };
    if args.smp != 1 {
        return Err(HyperbugError::Config(format!("{flag} only supports --smp 1 today")));
    }
    if !args.devices.is_empty()
        || !args.pci_devices.is_empty()
        || !args.sandboxed_devices.is_empty()
        || !args.sandboxed_pci_devices.is_empty()
        || !args.i2c_devices.is_empty()
        || !args.gpio_devices.is_empty()
        || args.vsock_uds.is_some()
    {
        return Err(HyperbugError::Config(format!(
            "{flag} doesn't support Python device plugins yet — their state isn't part of a snapshot"
        )));
    }
    Ok(())
}

/// Creates the single vCPU a restore needs and loads its state from the
/// snapshot directly, instead of `create_vcpus`/`setup_bsp`'s normal boot
/// path — which would (harmlessly for a fresh boot, but not here) write a
/// brand new GDT and page tables over guest memory that was *just*
/// restored to its exact pre-snapshot bytes.
pub(crate) fn restore_vcpu(kvm: &Kvm, vm: &VmFd, snap: &snapshot::CapturedState) -> Result<Vec<VcpuFd>, HyperbugError> {
    // KVM's own in-kernel PIC/IOAPIC/PIT state, restored *before* the
    // vCPU itself resumes — see `snapshot.rs`'s module doc comment for
    // the real bug this closes: a fresh VM's fresh PIC has never had its
    // vector base (re)programmed, since a guest only ever does that once,
    // early in its own boot, long before a restored guest resumes.
    vm.set_irqchip(&snap.pic_master)?;
    vm.set_irqchip(&snap.pic_slave)?;
    vm.set_irqchip(&snap.ioapic)?;
    vm.set_pit2(&snap.pit)?;

    let vcpu = vm.create_vcpu(0)?;
    let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
    cpuid::curate(&mut cpuid, 0, snap.num_cpus);
    vcpu.set_cpuid2(&cpuid)?;
    vcpu.set_sregs(&snap.sregs)?;
    vcpu.set_regs(&snap.regs)?;
    vcpu.set_mp_state(snap.mp_state)?;
    // XCR0 (part of xcrs) before xsave: XRSTOR validates the xsave area's
    // component bitmap against the *current* XCR0, so applying them in
    // the wrong order leaves a window where they're inconsistent.
    vcpu.set_xcrs(&snap.xcrs)?;
    // SAFETY: `snap.xsave` came from this same process's own
    // `vcpu.get_xsave()` (see `snapshot::save_to_file`), a plain 4096-byte
    // `KVM_GET_XSAVE` read with no dynamically-enabled XSTATE features
    // grown past that size — `set_xsave`'s own safety contract is only
    // about a *larger*, `KVM_GET_XSAVE2`-sized buffer, which this isn't.
    unsafe {
        vcpu.set_xsave(&snap.xsave)?;
    }
    vcpu.set_vcpu_events(&snap.vcpu_events)?;
    vcpu.set_lapic(&snap.lapic)?;
    let msr_entries: Vec<_> = snap
        .msrs
        .iter()
        .map(|&(index, data)| kvm_bindings::kvm_msr_entry { index, data, ..Default::default() })
        .collect();
    let msrs = kvm_bindings::Msrs::from_entries(&msr_entries)
        .map_err(|e| HyperbugError::Config(format!("rebuilding snapshot's MSR list: {e}")))?;
    vcpu.set_msrs(&msrs)?;
    Ok(vec![vcpu])
}

/// Applies every snapshotted device's protocol state after `Machine::build`
/// has (re)constructed the same devices fresh from `Args` — see
/// `snapshot.rs`'s module doc comment for why config-space BAR mappings
/// need explicit restoring here rather than being replayed via guest PCI
/// enumeration (restoring skips boot entirely, so nothing ever re-runs it).
fn restore_device_state(machine: &Machine, snap: &snapshot::CapturedState) -> Result<(), HyperbugError> {
    let mut shared = machine.shared.lock().unwrap();
    let SharedState { serial, pci_bus, mmio_bus, io_bus, virtio_snapshots, .. } = &mut *shared;
    serial.restore_state(&snap.serial_blob).map_err(HyperbugError::Config)?;
    pci_bus.restore_state(&snap.pci_blob, mmio_bus, io_bus).map_err(HyperbugError::Config)?;
    if virtio_snapshots.len() != snap.virtio_blobs.len() {
        return Err(HyperbugError::Config(format!(
            "snapshot has {} virtio device(s), this launch's configuration has {} — \
             --disk/--net/--rng-modern must match exactly to restore",
            snap.virtio_blobs.len(),
            virtio_snapshots.len()
        )));
    }
    for (dev, blob) in virtio_snapshots.iter().zip(&snap.virtio_blobs) {
        dev.lock().unwrap().restore_state(blob).map_err(HyperbugError::Config)?;
    }
    Ok(())
}

/// Loads the kernel, initramfs, command line, zero page and ACPI tables
/// into guest memory. Returns the kernel's 64-bit entry point.
fn load_guest(
    args: &Args,
    guest_mem: &mut GuestMemory,
    mem_size: u64,
    num_cpus: u8,
) -> Result<u64, HyperbugError> {
    let kernel = BzImage::read(&args.kernel)
        .map_err(|e| HyperbugError::Io(format!("reading kernel {}: {e}", args.kernel)))?;
    let loaded = kernel.load(guest_mem, mem_size)?;

    let initramfs = match args.initrd.as_deref() {
        Some(path) => Some(
            Initramfs::load(guest_mem, path, mem_size)
                .map_err(|e| HyperbugError::Io(format!("loading initramfs {path}: {e}")))?,
        ),
        None => None,
    };

    kernel
        .write_cmdline(guest_mem, &args.cmdline)
        .map_err(|e| HyperbugError::Config(e.to_string()))?;
    kernel.build_zero_page(guest_mem, mem_size, initramfs);
    acpi::setup_acpi(guest_mem, num_cpus)?;
    smbios::setup_smbios(guest_mem)?;
    Ok(loaded.entry_point)
}

/// Creates one vCPU per `--smp` count. vCPU 0 is the boot processor (BSP)
/// and starts executing the kernel's entry point immediately, exactly like
/// the single-vCPU case always has. vCPUs 1..N (application processors,
/// APs) start `KVM_MP_STATE_UNINITIALIZED` — real hardware's own reset
/// state for every CPU but the BSP — and only actually begin executing
/// once the BSP's own boot path sends a real INIT-SIPI-SIPI sequence via
/// its local APIC, which KVM's in-kernel APIC emulation handles entirely
/// on its own (no code here implements IPI delivery — it's already there
/// the moment more than one local APIC exists).
fn create_vcpus(
    kvm: &Kvm,
    vm: &VmFd,
    guest_mem: &mut GuestMemory,
    mem_size: u64,
    num_cpus: u8,
    entry_point: u64,
) -> Result<Vec<VcpuFd>, HyperbugError> {
    let host_cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
    let mut vcpus = Vec::with_capacity(usize::from(num_cpus));

    for cpu_id in 0..num_cpus {
        let vcpu = vm.create_vcpu(u64::from(cpu_id))?;

        // Curates a handful of specific, evidence-based fixes on top of
        // the otherwise-raw host pass-through — see `cpuid.rs`. `cpu_id`
        // is what makes each vCPU's own `cpuid` instruction report the
        // *real* APIC ID KVM assigned it, matching what the MADT
        // (`acpi.rs`) says exists.
        let mut cpuid = host_cpuid.clone();
        cpuid::curate(&mut cpuid, cpu_id, num_cpus);
        vcpu.set_cpuid2(&cpuid)?;

        if cpu_id == 0 {
            setup_bsp(&vcpu, guest_mem, mem_size, entry_point)?;
        } else {
            // Left at `KVM_CREATE_VCPU`'s own real-mode reset defaults —
            // see `setup_bsp` for why that's deliberate, not an oversight.
            // Only the mp_state is set explicitly, so this AP does nothing
            // at all until the BSP's real INIT-SIPI-SIPI sequence starts it.
            vcpu.set_mp_state(kvm_mp_state { mp_state: KVM_MP_STATE_UNINITIALIZED })?;
        }

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

/// The GDT and page tables are guest-memory-resident, built once here, and
/// identical for every vCPU (one guest address space) — but only the BSP's
/// *own* sregs get switched into protected/paged/long mode ahead of time.
/// A real AP's SIPI reset state is 16-bit real mode with paging off
/// (matching actual hardware, and what `KVM_CREATE_VCPU` already leaves an
/// AP in by default) — the kernel's own real-mode trampoline is what
/// switches an AP into protected/long mode once it actually starts
/// running, using these same memory-resident tables itself.
///
/// Giving an AP the BSP's already-paging-enabled sregs *before* its first
/// SIPI is exactly the bug a real boot caught here: KVM rejected it as
/// `InternalError` the instant the AP tried to start, since a SIPI's CS:IP
/// reset is inconsistent with an already-paging-enabled CR0/EFER.
fn setup_bsp(
    vcpu: &VcpuFd,
    guest_mem: &mut GuestMemory,
    mem_size: u64,
    entry_point: u64,
) -> Result<(), HyperbugError> {
    let mut sregs = vcpu.get_sregs()?;
    gdt::setup_gdt(guest_mem, &mut sregs);
    gdt::setup_page_tables(guest_mem, &mut sregs, mem_size).map_err(HyperbugError::Config)?;
    vcpu.set_sregs(&sregs)?;

    vcpu.set_regs(&kvm_regs {
        rip: entry_point,
        rsi: loader::ZERO_PAGE_START, // boot_params pointer, per the 64-bit boot protocol
        rsp: loader::BOOT_STACK_TOP,
        rflags: 0x2, // reserved bit 1 must be set
        ..Default::default()
    })?;
    Ok(())
}

/// Runs vCPU 0 (the BSP) on the caller's own thread and every AP on its
/// own dedicated OS thread, returning the BSP's result.
///
/// AP threads are deliberately *not* joined before this returns: a
/// genuinely idle AP's `vcpu.run()` can block indefinitely (see
/// `tty::install_periodic_wakeup` on why only one thread gets forcibly
/// interrupted out of that), so waiting for every AP to notice the exit
/// signal could make `run` itself hang past the point where the guest's
/// run has genuinely ended. Each AP still records its own result on the
/// exit signal if it happens to return on its own. For the CLI binary this
/// is harmless (`main`'s `std::process::exit` tears every thread down
/// regardless); a library caller keeping the process alive after `run`
/// returns should be aware these threads may still be running — a known,
/// stated limitation, whose proper fix needs a real per-vCPU kick
/// mechanism that was attempted and reverted after it caused a worse
/// regression (see `docs/architecture.md`'s History section).
fn spawn_vcpu_threads(
    mut vcpus: Vec<VcpuFd>,
    env: &VcpuEnv,
    gdb: Option<gdbstub::GdbStub>,
) -> Result<GuestExit, HyperbugError> {
    for (index, ap) in vcpus.drain(1..).enumerate() {
        let cpu_id = index as u8 + 1;
        let env = env.clone();
        std::thread::spawn(move || vcpu::run(cpu_id, ap, false, &env, None));
    }
    vcpu::run(0, vcpus.remove(0), true, env, gdb)
}
