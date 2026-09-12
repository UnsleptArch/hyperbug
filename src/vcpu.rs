//! One vCPU's VM-exit loop: `KVM_RUN`, dispatch whatever trapped, repeat
//! until the shared `ExitSignal` says the run is over.
//!
//! Split out of `lib.rs` (which used to hold this, device construction,
//! memory setup and thread orchestration in one file) so the exit
//! dispatch is a small set of named handlers rather than a 100-line
//! `match` nested inside a 300-line function.

use std::sync::{Arc, Mutex};

use kvm_bindings::{KVM_MP_STATE_RUNNABLE, kvm_msi};
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};

use crate::device::SharedDevice;
use crate::error::{ExitSlot, GuestExit, HyperbugError, request_exit};
use crate::irq::IrqRegistry;
use crate::machine::SharedState;
use crate::mem::GuestMemory;
use crate::{pci, serial, tty};

/// The classic QEMU/Bochs debug-console port: a raw byte straight to the
/// host's stdout, independent of the serial console. Load-bearing as a
/// diagnostic — it's how the still-open console-under-ACPI bug (DEBTS.md
/// item 33) was finally instrumented, precisely because it doesn't share
/// any code with the path under suspicion.
const DEBUG_CONSOLE_PORT: u16 = 0xe9;

/// How long an application processor waits between `KVM_GET_MP_STATE`
/// checks before its first SIPI arrives.
const AP_WAIT: std::time::Duration = std::time::Duration::from_millis(1);

/// Everything a vCPU thread needs besides its own `cpu_id`/`is_bsp`/
/// `VcpuFd`. Every field is itself already an `Arc`-ish shared handle, so
/// cloning this (one per spawned thread) is cheap.
#[derive(Clone)]
pub struct VcpuEnv {
    pub vm: Arc<VmFd>,
    pub guest_mem: Arc<Mutex<GuestMemory>>,
    pub shared: Arc<Mutex<SharedState>>,
    pub exit_slot: ExitSlot,
    pub irqs: Arc<IrqRegistry>,
}

/// Runs one vCPU's exit loop until the shared exit signal has a result —
/// either because this thread put one there itself, or because another
/// thread (or an ACPI shutdown/reset device write) already did. Every
/// internal fallibility (KVM ioctls, an unhandled VM-exit reason) returns
/// through this `Result` rather than panicking or calling
/// `std::process::exit`.
pub fn run(cpu_id: u8, mut vcpu: VcpuFd, is_bsp: bool, env: &VcpuEnv) -> Result<GuestExit, HyperbugError> {
    let result = Runner { cpu_id, is_bsp, env }.run(&mut vcpu);
    request_exit(&env.exit_slot, result.clone());
    result
}

struct Runner<'a> {
    cpu_id: u8,
    is_bsp: bool,
    env: &'a VcpuEnv,
}

/// What the exit loop should do next, once a VM exit has been dispatched.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Continue,
    TripleFault,
}

impl Runner<'_> {
    fn run(&self, vcpu: &mut VcpuFd) -> Result<GuestExit, HyperbugError> {
        // Whether the once-per-iteration host-side polling below has
        // anything to do at all, decided once instead of re-checked (under
        // the shared lock) on every single VM exit.
        let (has_control, has_plugin_devices) = {
            let state = self.env.shared.lock().unwrap();
            (
                state.control.is_some(),
                !state.plugin_pci_devices.is_empty(),
            )
        };
        let polls_host = self.is_bsp && (has_control || has_plugin_devices);
        let mut pending_irqs = Vec::new();
        let mut plugin_devices = Vec::new();

        loop {
            // Someone else (another vCPU thread, or an ACPI device write
            // handled inside this very loop) may already have decided the
            // run is over — notice within one periodic-wakeup tick rather
            // than spinning until this thread's own exit condition happens
            // to fire too.
            if let Some(result) = self.env.exit_slot.take() {
                return result;
            }

            if !self.is_bsp && !self.wait_for_sipi(vcpu)? {
                continue;
            }

            // `VcpuExit` borrows the vCPU's shared `kvm_run` page, so
            // nothing in this match may touch `vcpu` again; the match
            // yields a plain `Action` instead, which ends that borrow and
            // lets the triple-fault report below read registers.
            let action = match vcpu.run() {
                Ok(exit) => self.handle_exit(exit)?,
                // Expected and frequent: the periodic wakeup timer
                // installed in `lib::run` interrupting a `KVM_RUN` that was
                // blocked waiting for the next guest event (see
                // `tty::install_periodic_wakeup`). Nothing to handle —
                // fall through to the polling below.
                Err(e) if e.errno() == libc::EINTR => Action::Continue,
                Err(e) => return Err(e.into()),
            };
            if action == Action::TripleFault {
                self.report_triple_fault(vcpu)?;
                return Ok(GuestExit::TripleFault);
            }

            if polls_host {
                self.poll_host(vcpu, has_control, has_plugin_devices, &mut pending_irqs, &mut plugin_devices);
            }
        }
    }

    /// An AP starts `KVM_MP_STATE_UNINITIALIZED` (see `lib::run`) and stays
    /// that way until the BSP's own vCPU thread processes a real
    /// INIT-SIPI-SIPI sequence through its local APIC — KVM updates *this*
    /// vCPU's mp_state as a side effect of that, entirely inside the
    /// kernel, without this thread doing anything. Checking first and
    /// skipping `vcpu.run()` avoids hammering the ioctl in a tight loop
    /// before that happens; once it flips to RUNNABLE this thread starts
    /// executing from the real-mode SIPI vector like real hardware would.
    fn wait_for_sipi(&self, vcpu: &VcpuFd) -> Result<bool, HyperbugError> {
        match vcpu.get_mp_state()?.mp_state {
            KVM_MP_STATE_RUNNABLE => Ok(true),
            _ => {
                std::thread::sleep(AP_WAIT);
                Ok(false)
            }
        }
    }

    /// Handles one VM exit. Deliberately takes no `VcpuFd`: `exit` borrows
    /// the vCPU's `kvm_run` page for as long as it's alive, so anything
    /// that needs the vCPU itself (reading registers after a triple fault)
    /// has to happen after this returns — hence `Action` rather than doing
    /// it here.
    fn handle_exit(&self, exit: VcpuExit<'_>) -> Result<Action, HyperbugError> {
        match exit {
            VcpuExit::IoOut(port, data) if serial::COM1_PORTS.contains(&port) => {
                let wants_irq = self.env.shared.lock().unwrap().serial.handle_out(port, data);
                if wants_irq {
                    self.env.irqs.pulse(serial::COM1_IRQ);
                }
            }
            VcpuExit::IoIn(port, data) if serial::COM1_PORTS.contains(&port) => {
                self.env.shared.lock().unwrap().serial.handle_in(port, data);
            }
            VcpuExit::IoOut(DEBUG_CONSOLE_PORT, data) => tty::write_stdout(data),
            VcpuExit::IoOut(port, data) if pci::PciBus::owns_port(port) => {
                let mut state = self.env.shared.lock().unwrap();
                let SharedState { pci_bus, mmio_bus, io_bus, .. } = &mut *state;
                pci_bus.io_out(port, data, mmio_bus, io_bus);
            }
            VcpuExit::IoIn(port, data) if pci::PciBus::owns_port(port) => {
                self.env.shared.lock().unwrap().pci_bus.io_in(port, data);
            }
            VcpuExit::IoOut(port, data) => {
                // BAR-mapped I/O device, or silently ignored if none is
                // there. `dispatch_write` releases `SharedState`'s lock
                // before actually calling into the device.
                if let Some(Some(irq)) = self.dispatch_write(false, u64::from(port), data) {
                    let state = self.env.shared.lock().unwrap();
                    self.signal_pci_irq(irq, &state);
                }
            }
            VcpuExit::IoIn(port, data) => {
                if !self.dispatch_read(false, u64::from(port), data) {
                    data.fill(0xff); // floating bus, matches real hardware convention
                }
            }
            VcpuExit::MmioRead(addr, data) => {
                if !self.dispatch_read(true, addr, data) {
                    data.fill(0);
                    eprintln!("[hyperbug] unmodeled MMIO read at {addr:#x} ({} bytes)", data.len());
                }
            }
            VcpuExit::MmioWrite(addr, data) => match self.dispatch_write(true, addr, data) {
                Some(Some(irq)) => {
                    let state = self.env.shared.lock().unwrap();
                    self.signal_pci_irq(irq, &state);
                }
                Some(None) => {}
                None => eprintln!("[hyperbug] unmodeled MMIO write at {addr:#x}: {data:?}"),
            },
            VcpuExit::Hlt => {
                // Real, ordinary cpu-idle — not "the guest is done", just
                // "nothing to do until the next interrupt". `KVM_RUN`
                // naturally blocks here until one arrives (our own irqfd
                // pulses and the in-kernel PIT both still work while
                // blocked in the ioctl), then resumes right after the HLT
                // on its own.
            }
            VcpuExit::Shutdown => return Ok(Action::TripleFault),
            other => {
                return Err(HyperbugError::Kvm(format!(
                    "cpu{}: unhandled VM exit: {other:?}",
                    self.cpu_id
                )));
            }
        }
        Ok(Action::Continue)
    }

    /// Dispatches a guest write to a BAR-mapped device (I/O-space if
    /// `is_mmio` is false, memory-space otherwise). `None` if nothing is
    /// mapped at `addr`; `Some(irq)` (itself possibly `None`, if the write
    /// didn't request one) if some device handled it.
    ///
    /// Looks the device up under `SharedState`'s lock, then **releases
    /// it** before actually calling the device's own `write` — a Python
    /// plugin's `write()` runs arbitrary guest-supplied logic under the
    /// GIL, and a sandboxed plugin's is a real subprocess round trip (up
    /// to its own 200ms timeout); either one holding this lock for its
    /// entire duration would block every *other* device sharing it
    /// (serial, PCI config space, every other device on the bus) for just
    /// as long, on every vCPU. The device's own `Arc<Mutex<..>>` — always
    /// held regardless — is what still makes concurrent access to *that*
    /// device safe.
    fn dispatch_write(&self, is_mmio: bool, addr: u64, data: &[u8]) -> Option<Option<u32>> {
        let (device, offset, irq) = self.find_device(is_mmio, addr)?;
        let wants_irq = device.lock().unwrap().write(offset, data);
        Some(wants_irq.then_some(irq).flatten())
    }

    /// As `dispatch_write`, for a guest read. `false` if nothing is mapped
    /// at `addr` (the caller fills `data` with the floating-bus/unmodeled
    /// convention itself).
    fn dispatch_read(&self, is_mmio: bool, addr: u64, data: &mut [u8]) -> bool {
        let Some((device, offset, _irq)) = self.find_device(is_mmio, addr) else {
            return false;
        };
        device.lock().unwrap().read(offset, data);
        true
    }

    #[inline]
    fn find_device(&self, is_mmio: bool, addr: u64) -> Option<(SharedDevice, u64, Option<u32>)> {
        let mut state = self.env.shared.lock().unwrap();
        let bus = if is_mmio { &mut state.mmio_bus } else { &mut state.io_bus };
        bus.find_device(addr)
    }

    fn report_triple_fault(&self, vcpu: &VcpuFd) -> Result<(), HyperbugError> {
        let r = vcpu.get_regs()?;
        let s = vcpu.get_sregs()?;
        eprintln!(
            "[hyperbug] cpu{} triple-faulted / shut down: rip={:#x} rsp={:#x} cr0={:#x} \
             cr3={:#x} cr4={:#x} efer={:#x} cs.sel={:#x} cs.l={}",
            self.cpu_id, r.rip, r.rsp, s.cr0, s.cr3, s.cr4, s.efer, s.cs.selector, s.cs.l
        );
        Ok(())
    }

    /// The two host-facing sources `reactor.rs` deliberately doesn't own,
    /// polled once per loop iteration on the BSP only — and skipped
    /// entirely (no lock taken at all) when neither is configured.
    fn poll_host(
        &self,
        vcpu: &mut VcpuFd,
        has_control: bool,
        has_plugin_devices: bool,
        pending_irqs: &mut Vec<u32>,
        plugin_devices: &mut Vec<(SharedDevice, u32)>,
    ) {
        // A control connection can send a command at any time. Reports
        // vCPU 0's registers regardless of which vCPU is "interesting" at
        // the moment — a known limitation for a multi-vCPU guest (DEBTS.md
        // item 20). Deliberately not moved to the reactor: a live vCPU's
        // registers can only safely be read from that vCPU's own thread.
        if has_control {
            let mut state = self.env.shared.lock().unwrap();
            let crate::machine::SharedState { control, serial, pci_bus, virtio_snapshots, .. } = &mut *state;
            if let Some(control) = control {
                let snap = crate::control::SnapshotDeps { serial, pci_bus, virtio: virtio_snapshots };
                control.poll(&self.env.vm, &self.env.guest_mem, vcpu, snap);
            }
        }

        // A `--pci-device`/`--pci-device-sandboxed` plugin can call
        // `hyperbug.raise_irq()` at any time (a simulated timer, an
        // external event), not just synchronously from inside `write()`.
        // Also not moved to the reactor: an arbitrary Python-spawned
        // background thread (in-process) or the sandboxed device's reader
        // thread has no fd for `epoll` to wait on in the first place, only
        // `Device::take_pending_irq`'s own flag. One loop drives both
        // in-process and sandboxed plugins identically — see
        // `machine::PluginPciDevice`.
        if has_plugin_devices {
            // Handles cloned under a brief lock, then run with it released
            // — `tick()` can be a real Python call (arbitrary guest-facing
            // logic under the GIL, or a sandboxed subprocess round trip),
            // and holding `SharedState`'s lock for every plugin's `tick()`
            // in the same iteration would block unrelated devices (serial,
            // PCI config space, every other vCPU's own dispatch) for the
            // combined duration of all of them, not just the slow one's.
            // `plugin_devices` is reused across iterations, same as
            // `pending_irqs`, so this costs no allocation once warmed up.
            plugin_devices.clear();
            {
                let state = self.env.shared.lock().unwrap();
                plugin_devices.extend(state.plugin_pci_devices.iter().map(|e| (e.device.clone(), e.irq)));
            }

            pending_irqs.clear();
            for (device, irq) in plugin_devices.iter() {
                let mut device = device.lock().unwrap();
                // `tick()` runs first: a plugin's own tick can itself call
                // `raise_irq()` (e.g. an async transaction completing),
                // and this way that shows up in the same iteration's
                // `take_pending_irq` check instead of waiting one more.
                device.tick();
                if device.take_pending_irq() {
                    pending_irqs.push(*irq);
                }
            }
            if !pending_irqs.is_empty() {
                let state = self.env.shared.lock().unwrap();
                for &irq in pending_irqs.iter() {
                    self.signal_pci_irq(irq, &state);
                }
            }
        }
    }

    /// Delivers an interrupt for legacy line `irq`, upgrading to a real
    /// `KVM_SIGNAL_MSI` instead of the irqfd pulse if `irq` belongs to a
    /// device that opted into `PciDevice::msi_capable()` *and* currently
    /// has MSI enabled. Only `--pci-device` plugins can be in that state:
    /// hyperbug's own virtio devices deliberately never request MSI (see
    /// `pci.rs`'s module doc comment).
    fn signal_pci_irq(&self, irq: u32, state: &SharedState) {
        if let Some(devfn) = state.msi_devfn(irq)
            && let Some((address, data)) = state.pci_bus.msi_state(devfn)
        {
            let msi = kvm_msi {
                address_lo: address,
                address_hi: 0,
                data: u32::from(data),
                flags: 0,
                devid: 0,
                pad: [0; 12],
            };
            // A failed MSI delivery is a best-effort-interrupt-delivery
            // hiccup, not a reason to end the whole run.
            if let Err(e) = self.env.vm.signal_msi(msi) {
                eprintln!("[hyperbug] KVM_SIGNAL_MSI failed: {e}");
            }
            return;
        }
        self.env.irqs.pulse(irq);
    }
}
