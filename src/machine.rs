//! Assembles the guest's device model: the serial port, the MMIO/PIO
//! buses, the PCI bus and everything on it, and the optional control
//! socket — everything a VM-exit handler needs besides the vCPU that
//! trapped and guest memory.
//!
//! Split out of `lib.rs`, which had grown into one 300-line function doing
//! memory setup, kernel loading, vCPU creation, device construction and
//! thread orchestration together. `run()` now reads as those five steps;
//! this file owns exactly one of them.

use std::sync::{Arc, Mutex};

use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::EventFd;

use crate::config::Args;
use crate::control::ControlServer;
use crate::device::{Device, IoBus, MmioBus, SharedDevice};
use crate::error::{ExitSlot, HyperbugError};
use crate::i2c::I2cBus;
use crate::irq::IrqRegistry;
use crate::mem::GuestMemory;
use crate::pci::{HostBridge, PciBus, PciDevice};
use crate::plugin::ScriptedDevice;
use crate::{native_plugin, pydevice, pydevice_proc, wasm_plugin};
use crate::reactor::VirtioNotifyTarget;
use crate::record::Recorder;
use crate::serial::Serial;
use crate::virtio::{VirtioLegacyPci, VirtioModernPci};
use crate::virtio_blk::VirtioBlk;
use crate::virtio_gpio::VirtioGpio;
use crate::virtio_i2c::VirtioI2c;
use crate::virtio_net::{TapDevice, VirtioNet};
use crate::virtio_rng::VirtioRng;
use crate::virtio_vsock::VirtioVsock;
use crate::{acpi, serial};

/// Fixed PCI slot assignment. Every slot here is
/// static regardless of *which* `--disk`/`--net`/`--pci-device` flags are
/// actually present at runtime, on purpose: `acpi/dsdt.asl`'s `_PRT`
/// hardcodes GSI routing for these exact slots, so a device landing on a
/// *different* slot depending on argument count (the old behavior) would
/// silently desync from it. Slot 0 is the host bridge; 1-3 and 24-31 are
/// free for `--pci-device`.
mod slots {
    pub const HOST_BRIDGE: u8 = 0;
    pub const BLK_BASE: u8 = 4;
    pub const BLK_MAX_DISKS: usize = 8; // slots 4-11, matching acpi/dsdt.asl's _PRT
    pub const NET: u8 = 16;
    pub const RNG: u8 = 17;
    pub const I2C: u8 = 18;
    pub const GPIO_BASE: u8 = 19;
    pub const GPIO_MAX_BANKS: usize = 4; // slots 19-22, matching acpi/dsdt.asl's _PRT
    pub const VSOCK: u8 = 23;
}

/// Legacy interrupt lines for hyperbug's own virtio devices. All < 16, so
/// the PIC-only routing `acpi.rs`'s MADT deliberately keeps the guest on
/// can deliver every one of them.
mod gsi {
    pub const BLK: u8 = 10; // shared across disks, like real PCI IRQ sharing
    pub const NET: u8 = 11;
    pub const RNG: u8 = 12;
    pub const I2C: u8 = 13;
    pub const GPIO: u8 = 14; // shared across banks, like real PCI IRQ sharing
    pub const VSOCK: u8 = 15;
}

type NetDevice = Arc<Mutex<VirtioLegacyPci<VirtioNet>>>;
type BlkDevice = Arc<Mutex<VirtioLegacyPci<VirtioBlk>>>;
type GpioDevice = Arc<Mutex<VirtioModernPci<VirtioGpio>>>;
type VsockDevice = Arc<Mutex<VirtioModernPci<VirtioVsock>>>;

/// What `--pci-device`/`--pci-device-sandboxed` plugins contribute to the
/// machine: the ones with an interrupt line to poll, and the GSI -> devfn
/// entries for the subset that also opted into MSI.
#[derive(Default)]
struct PciPlugins {
    interrupt_sources: Vec<PluginPciDevice>,
    msi_devfns: Vec<(u32, u8)>,
}

/// A `--pci-device`/`--pci-device-sandboxed` plugin that can raise its own
/// interrupt, with the routing information resolved once at setup instead
/// of re-derived (through the GIL, or a subprocess round trip) on every
/// poll. Held as `dyn Device` — both an in-process and a sandboxed plugin
/// are actually the same concrete `plugin::ScriptedDevice` type today
/// (see `plugin.rs`), differing only in which `PluginTransport`
/// implementation they're built with, so `vcpu::poll_host` drives every
/// plugin through one loop over one `Vec` with no per-transport branching
/// at all.
pub struct PluginPciDevice {
    pub device: SharedDevice,
    /// The GSI to raise. `vcpu::signal_pci_irq` upgrades it to a real MSI
    /// if this device is in `msi_devfns` and the guest has enabled MSI.
    pub irq: u32,
}

/// Identifies one `--device`/`--pci-device` plugin (in-process or
/// sandboxed) for the control socket's `reset_device`/`reload_device`
/// commands — an MMIO plugin by its fixed base address, a PCI plugin by
/// its device number (matching what the operator already passed on the
/// CLI, not the internal devfn).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PluginSelector {
    Mmio(u64),
    Pci(u8),
}

/// Everything needed to re-load one plugin from disk with its original
/// arguments — the actual mechanism behind hot-reload
/// (`reload_device`/`reset_device` in `control.rs`). Kept alongside (not
/// instead of) the `Arc<Mutex<dyn Device>>`/`Arc<Mutex<dyn PciDevice>>`
/// handles registered with the buses: `device` here is the *same*
/// allocation, just still concretely typed as `ScriptedDevice` so
/// `ScriptedDevice::reload`/`identity`/`Device::reset` are reachable
/// without a downcast.
pub struct PluginRegistryEntry {
    pub selector: PluginSelector,
    pub path: String,
    /// `None` for a native (`--native-device`/`--native-pci-device`)
    /// plugin — a shared object has no equivalent of a named Python
    /// class to instantiate.
    pub class: Option<String>,
    pub dma_range: Option<(u64, u64)>,
    pub resource_limits: Option<crate::config::ResourceLimits>,
    pub transport: PluginTransportKind,
    pub is_pci: bool,
    pub device: Arc<Mutex<ScriptedDevice>>,
}

/// Which loader originally built this plugin — `reload_plugin` needs to
/// know which one to call again.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PluginTransportKind {
    InProcess,
    Sandboxed,
    Native,
    Wasm,
}

/// Everything a VM-exit handler needs besides the vCPU that trapped and
/// guest memory — bundled into one struct behind one `Mutex` for bus/
/// dispatch lookups rather than each bus getting its own lock, because
/// `PciBus::io_out`/`io_in` already need simultaneous `&mut` access to
/// `MmioBus`/`IoBus` internally; one lock avoids any multi-lock ordering
/// question entirely. `GuestMemory` stays a *separate* `Arc<Mutex<...>>`
/// since device code (virtio, Python DMA) needs to lock it independently,
/// nested *inside* a call that's already holding this struct's lock — a
/// single shared lock covering both would deadlock the moment a device
/// tried to re-enter it.
pub struct SharedState {
    pub serial: Serial,
    /// COM2/COM3/COM4 (`--uart2-log`/`--uart3-log`/`--uart4-log`), in
    /// that fixed order — `None` for a port nothing asked for. See
    /// `serial.rs`'s own module doc comment for the design (output-only,
    /// no snapshot support).
    pub extra_uarts: [Option<Serial>; 3],
    pub mmio_bus: MmioBus,
    pub io_bus: IoBus,
    pub pci_bus: PciBus,
    /// Polled once per vCPU-loop iteration for a pending
    /// `hyperbug.raise_irq()`. Empty (and so skipped entirely) unless a
    /// `--pci-device`/`--pci-device-sandboxed` plugin declared an
    /// `interrupt_line`.
    pub plugin_pci_devices: Vec<PluginPciDevice>,
    /// GSI -> devfn, for the `--pci-device` plugins that opted into MSI.
    /// Only those: hyperbug's own virtio devices deliberately never do
    /// (see `pci.rs`'s module doc comment), so nothing else needs the
    /// lookup.
    pub msi_devfns: Vec<(u32, u8)>,
    pub control: Option<ControlServer>,
    /// Every hyperbug-owned virtio device that can serialize its protocol
    /// state for snapshot/restore, in the exact order `Machine::build`
    /// constructs them: disks, then net if present, then rng. `snapshot.
    /// rs`'s `save_to_file`/`load_from_file` rely on that order matching
    /// on both sides, since a fresh launch reconstructs it identically
    /// from the same `Args`.
    pub virtio_snapshots: Vec<Arc<Mutex<dyn crate::snapshot::Snapshot>>>,
    /// Every `--device`/`--pci-device` plugin (in-process or sandboxed),
    /// for the control socket's `reset_device`/`reload_device` commands —
    /// see `PluginRegistryEntry`.
    pub plugin_registry: Vec<PluginRegistryEntry>,
}

impl SharedState {
    /// The devfn whose MSI state should be consulted before delivering
    /// `irq`, if any device asked for that. A short linear scan over at
    /// most a handful of entries — cheaper than a hash lookup at this size
    /// and, unlike the `HashMap` it replaces, allocation-free.
    #[inline]
    pub fn msi_devfn(&self, irq: u32) -> Option<u8> {
        self.msi_devfns.iter().find(|(line, _)| *line == irq).map(|(_, devfn)| *devfn)
    }
}

/// The assembled device model, plus the handles `run()` needs to hand to
/// the reactor thread.
pub struct Machine {
    pub shared: Arc<Mutex<SharedState>>,
    pub net_devices: Vec<NetDevice>,
    /// Every hyperbug-owned virtio (legacy transport) device's queue-notify
    /// ioeventfd bindings, handed to `reactor::spawn` — see
    /// `reactor::VirtioNotifyTarget` and `pci.rs`'s `ioevent_entries`.
    pub virtio_notifies: Vec<VirtioNotifyTarget>,
    /// Every virtio-blk device, handed to `reactor::spawn` so it can poll
    /// each one's io_uring completion eventfd — see
    /// `VirtioBlk`'s module doc comment and `reactor::handle_blk_completion`.
    pub blk_devices: Vec<BlkDevice>,
    /// Every virtio-gpio adapter, handed to `reactor::spawn` so it can
    /// poll each one's completion eventfd for a plugin-raised interrupt —
    /// see `VirtioGpio`'s module doc comment and
    /// `reactor::handle_gpio_completion`.
    pub gpio_devices: Vec<GpioDevice>,
    /// The one optional virtio-vsock adapter (`--vsock-uds`), handed to
    /// `reactor::spawn` so it can watch its bridge thread's eventfd — see
    /// `VirtioVsock`'s module doc comment and
    /// `reactor::handle_vsock_bridge`.
    pub vsock_device: Option<VsockDevice>,
}

impl Machine {
    /// Builds every device the given `args` ask for, registering each
    /// one's interrupt line with `irqs` as it goes.
    pub fn build(
        args: &Args,
        vm: &Arc<VmFd>,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        exit_slot: &ExitSlot,
        irqs: &mut IrqRegistry,
        recorder: Option<Arc<Recorder>>,
        replayer: Option<Arc<Mutex<crate::record::Replayer>>>,
    ) -> Result<Self, HyperbugError> {
        let mut mmio_bus = MmioBus::new();
        let mut io_bus = IoBus::new();
        let mut pci_bus = PciBus::with_vm(vm.clone());
        let mut virtio_notifies = Vec::new();
        let mut blk_devices = Vec::new();

        // COM1 is unconditional; everything else registers its line as it
        // is created below.
        irqs.register(vm, serial::COM1_IRQ)?;
        let extra_uarts = Self::add_extra_uarts(args, vm, irqs)?;

        register_io(&mut io_bus, acpi::SLEEP_CONTROL_PORT, 2, acpi::SleepControl::new(exit_slot.clone()));
        register_io(&mut io_bus, acpi::RESET_PORT, 1, acpi::ResetControl::new(exit_slot.clone()));

        let mut plugin_registry = Vec::new();
        Self::add_mmio_plugins(args, guest_mem, &mut mmio_bus, &mut plugin_registry)?;
        Self::add_sandboxed_mmio_plugins(args, guest_mem, &mut mmio_bus, &mut plugin_registry)?;
        Self::add_native_mmio_plugins(args, guest_mem, &mut mmio_bus, &mut plugin_registry)?;
        Self::add_wasm_mmio_plugins(args, guest_mem, &mut mmio_bus, &mut plugin_registry)?;

        let host_bridge = Arc::new(Mutex::new(HostBridge));
        register_pci(&mut pci_bus, slots::HOST_BRIDGE, host_bridge.clone(), host_bridge)?;

        let mut virtio_snapshots =
            Self::add_disks(args, vm, guest_mem, irqs, &mut pci_bus, &mut virtio_notifies, &mut blk_devices)?;
        let net_devices = Self::add_net(args, vm, guest_mem, irqs, &mut pci_bus, &mut virtio_notifies)?;
        if let Some(net) = net_devices.first() {
            virtio_snapshots.push(net.clone());
        }

        if let Some(i2c) = Self::add_i2c(args, vm, guest_mem, irqs, &mut pci_bus)? {
            virtio_snapshots.push(i2c);
        }

        let gpio_devices = Self::add_gpio(args, vm, guest_mem, irqs, &mut pci_bus)?;
        for gpio in &gpio_devices {
            virtio_snapshots.push(gpio.clone());
        }

        let vsock_device = Self::add_vsock(args, vm, guest_mem, irqs, &mut pci_bus)?;

        // Always present, low risk, and a real systemd/journald boot can
        // stall a long time on entropy with no hardware RNG. `--rng-modern`
        // swaps this same device onto the modern virtio 1.0 PCI transport
        // (same slot/GSI, so `acpi/dsdt.asl`'s `_PRT` needs no changes) —
        // the transport's first real vertical slice, not yet extended to
        // virtio-blk/virtio-net. Ioeventfd wiring is legacy-transport-only
        // for now (see `virtio.rs`'s `VirtioLegacyPci::ioevent_entries`),
        // so the modern branch doesn't feed `virtio_notifies`.
        if args.rng_modern {
            const VIRTIO_DEVICE_TYPE_ENTROPY: u16 = 4;
            let rng = Arc::new(Mutex::new(VirtioModernPci::new(
                VirtioRng::new(recorder.clone(), replayer.clone()),
                guest_mem.clone(),
                gsi::RNG,
                VIRTIO_DEVICE_TYPE_ENTROPY,
                0, // no device-specific config space
            )));
            virtio_snapshots.push(rng.clone());
            register_pci(&mut pci_bus, slots::RNG, rng.clone(), rng)?;
        } else {
            let rng = new_virtio(VirtioRng::new(recorder.clone(), replayer.clone()), guest_mem, gsi::RNG);
            virtio_snapshots.push(rng.clone());
            let events = register_pci(&mut pci_bus, slots::RNG, rng.clone(), rng.clone())?;
            push_virtio_notifies(&mut virtio_notifies, events, rng, gsi::RNG);
        }
        irqs.register(vm, u32::from(gsi::RNG))?;

        let plugins = Self::add_pci_plugins(args, vm, guest_mem, irqs, &mut pci_bus, &mut plugin_registry)?;

        // Live VM control — peek/poke a *running*
        // guest's memory and registers from outside the process, not just
        // launch/wait/stop. Optional: only opened if asked for.
        let control = match args.control_socket.as_deref() {
            Some(path) => Some(ControlServer::bind(path).map_err(|e| {
                HyperbugError::Io(format!("binding control socket {path}: {e}"))
            })?),
            None => None,
        };

        Ok(Self {
            shared: Arc::new(Mutex::new(SharedState {
                serial: Serial::new(),
                extra_uarts,
                mmio_bus,
                io_bus,
                pci_bus,
                plugin_pci_devices: plugins.interrupt_sources,
                msi_devfns: plugins.msi_devfns,
                control,
                virtio_snapshots,
                plugin_registry,
            })),
            net_devices,
            virtio_notifies,
            blk_devices,
            gpio_devices,
            vsock_device,
        })
    }

    fn add_mmio_plugins(
        args: &Args,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        mmio_bus: &mut MmioBus,
        registry: &mut Vec<PluginRegistryEntry>,
    ) -> Result<(), HyperbugError> {
        for spec in &args.devices {
            let device = pydevice::load(&spec.path, &spec.class, guest_mem.clone(), spec.dma_range).map_err(|e| {
                HyperbugError::Python(format!("loading device {} ({}): {e}", spec.path, spec.class))
            })?;
            let device = Arc::new(Mutex::new(device));
            // A fixed-address MMIO device (unlike a --pci-device) has no
            // configured interrupt line at all, so a spontaneous
            // `hyperbug.raise_irq()` from one has nothing to pulse — it's
            // simply never polled. DMA via `hyperbug.read_mem`/`write_mem`
            // works the same either way.
            mmio_bus.register(spec.base, spec.size, device.clone(), None);
            registry.push(PluginRegistryEntry {
                selector: PluginSelector::Mmio(spec.base),
                path: spec.path.clone(),
                class: Some(spec.class.clone()),
                dma_range: spec.dma_range,
                resource_limits: None,
                transport: PluginTransportKind::InProcess,
                is_pci: false,
                device,
            });
        }
        Ok(())
    }

    fn add_sandboxed_mmio_plugins(
        args: &Args,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        mmio_bus: &mut MmioBus,
        registry: &mut Vec<PluginRegistryEntry>,
    ) -> Result<(), HyperbugError> {
        for spec in &args.sandboxed_devices {
            let device = pydevice_proc::load(&spec.path, &spec.class, guest_mem.clone(), spec.dma_range, spec.resource_limits.clone())
                .map_err(|e| {
                    HyperbugError::Python(format!(
                        "loading sandboxed device {} ({}): {e}",
                        spec.path, spec.class
                    ))
                })?;
            let device = Arc::new(Mutex::new(device));
            mmio_bus.register(spec.base, spec.size, device.clone(), None);
            registry.push(PluginRegistryEntry {
                selector: PluginSelector::Mmio(spec.base),
                path: spec.path.clone(),
                class: Some(spec.class.clone()),
                dma_range: spec.dma_range,
                resource_limits: spec.resource_limits.clone(),
                transport: PluginTransportKind::Sandboxed,
                is_pci: false,
                device,
            });
        }
        Ok(())
    }

    /// `--native-device`: a `dlopen()`ed C-ABI plugin, always in-process
    /// (there is no sandboxed native transport) — see `native_plugin.rs`.
    fn add_native_mmio_plugins(
        args: &Args,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        mmio_bus: &mut MmioBus,
        registry: &mut Vec<PluginRegistryEntry>,
    ) -> Result<(), HyperbugError> {
        for spec in &args.native_devices {
            let device = native_plugin::load(&spec.path, guest_mem.clone(), spec.dma_range)
                .map_err(|e| HyperbugError::Io(format!("loading native device {}: {e}", spec.path)))?;
            let device = Arc::new(Mutex::new(device));
            mmio_bus.register(spec.base, spec.size, device.clone(), None);
            registry.push(PluginRegistryEntry {
                selector: PluginSelector::Mmio(spec.base),
                path: spec.path.clone(),
                class: None,
                dma_range: spec.dma_range,
                resource_limits: None,
                transport: PluginTransportKind::Native,
                is_pci: false,
                device,
            });
        }
        Ok(())
    }

    /// `--wasm-device`: a `wasmtime`-executed WASM plugin — an additional
    /// sandbox tier alongside (not instead of) the subprocess model, see
    /// `wasm_plugin.rs`.
    fn add_wasm_mmio_plugins(
        args: &Args,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        mmio_bus: &mut MmioBus,
        registry: &mut Vec<PluginRegistryEntry>,
    ) -> Result<(), HyperbugError> {
        for spec in &args.wasm_devices {
            let device = wasm_plugin::load(&spec.path, guest_mem.clone(), spec.dma_range)
                .map_err(|e| HyperbugError::Io(format!("loading wasm device {}: {e}", spec.path)))?;
            let device = Arc::new(Mutex::new(device));
            mmio_bus.register(spec.base, spec.size, device.clone(), None);
            registry.push(PluginRegistryEntry {
                selector: PluginSelector::Mmio(spec.base),
                path: spec.path.clone(),
                class: None,
                dma_range: spec.dma_range,
                resource_limits: None,
                transport: PluginTransportKind::Wasm,
                is_pci: false,
                device,
            });
        }
        Ok(())
    }

    fn add_disks(
        args: &Args,
        vm: &VmFd,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        irqs: &mut IrqRegistry,
        pci_bus: &mut PciBus,
        virtio_notifies: &mut Vec<VirtioNotifyTarget>,
        blk_devices: &mut Vec<BlkDevice>,
    ) -> Result<Vec<Arc<Mutex<dyn crate::snapshot::Snapshot>>>, HyperbugError> {
        if args.disks.len() > slots::BLK_MAX_DISKS {
            return Err(HyperbugError::Config(format!(
                "--disk given {} times, but only {} PCI slots are reserved for disks",
                args.disks.len(),
                slots::BLK_MAX_DISKS
            )));
        }
        if args.disks.is_empty() {
            return Ok(Vec::new());
        }
        irqs.register(vm, u32::from(gsi::BLK))?;
        let mut snapshots: Vec<Arc<Mutex<dyn crate::snapshot::Snapshot>>> = Vec::new();
        for (devnum, path) in (slots::BLK_BASE..).zip(&args.disks) {
            let blk = VirtioBlk::open(path)
                .map_err(|e| HyperbugError::Io(format!("opening disk image {path}: {e}")))?;
            let device = new_virtio(blk, guest_mem, gsi::BLK);
            snapshots.push(device.clone());
            blk_devices.push(device.clone());
            let events = register_pci(pci_bus, devnum, device.clone(), device.clone())?;
            push_virtio_notifies(virtio_notifies, events, device, gsi::BLK);
        }
        Ok(snapshots)
    }

    fn add_net(
        args: &Args,
        vm: &VmFd,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        irqs: &mut IrqRegistry,
        pci_bus: &mut PciBus,
        virtio_notifies: &mut Vec<VirtioNotifyTarget>,
    ) -> Result<Vec<NetDevice>, HyperbugError> {
        if !args.net {
            return Ok(Vec::new());
        }
        let tap = TapDevice::create("hyperbug%d").map_err(|e| {
            HyperbugError::Io(format!("creating TAP interface (needs CAP_NET_ADMIN or root): {e}"))
        })?;
        eprintln!("[hyperbug] created TAP interface {}", tap.name);
        // Locally-administered, QEMU-convention prefix.
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let device = new_virtio(VirtioNet::new(mac, tap), guest_mem, gsi::NET);
        let events = register_pci(pci_bus, slots::NET, device.clone(), device.clone())?;
        push_virtio_notifies(virtio_notifies, events, device.clone(), gsi::NET);
        irqs.register(vm, u32::from(gsi::NET))?;
        Ok(vec![device])
    }

    /// Builds hyperbug's single virtual I2C bus from every `--i2c-device`
    /// spec and, only if at least one was given, attaches it to the guest
    /// via a real `virtio-i2c` adapter (`VirtioI2c`, over the modern
    /// virtio 1.0 transport — no legacy virtio-i2c PCI ID exists, see
    /// `virtio_i2c.rs`'s own module doc comment). `None` with zero
    /// `--i2c-device` flags: unlike virtio-rng, there's no "always
    /// present, low risk" case for an I2C adapter with nothing behind it.
    ///
    /// **Known gap, stated rather than silently accepted**: I2C target
    /// devices aren't registered in `plugin_registry`, so the control
    /// socket's `reset_device`/`reload_device` commands don't reach them
    /// yet — those commands are keyed by MMIO base or PCI device number
    /// (`PluginSelector`), neither of which fits "one of several targets
    /// sharing one adapter's PCI identity." A `PluginSelector::I2c(addr)`
    /// variant would be the natural extension; not built this pass.
    /// Builds `SharedState::extra_uarts` from `--uart2-log`/`--uart3-log`/
    /// `--uart4-log`, registering each configured port's (possibly
    /// shared, per real ISA convention — see `serial.rs`) GSI as it goes.
    /// A port nothing asked for stays `None` — real hardware behavior for
    /// an unpopulated UART slot (the guest's own autoconfig probe reads
    /// back nothing meaningful and skips it), not a config error.
    fn add_extra_uarts(args: &Args, vm: &VmFd, irqs: &mut IrqRegistry) -> Result<[Option<Serial>; 3], HyperbugError> {
        let mut ports = [const { None }; 3];
        let specs = [
            (&args.uart2_log, serial::COM2_BASE, serial::COM2_IRQ),
            (&args.uart3_log, serial::COM3_BASE, serial::COM3_IRQ),
            (&args.uart4_log, serial::COM4_BASE, serial::COM4_IRQ),
        ];
        for (i, (log_path, base, irq)) in specs.into_iter().enumerate() {
            let Some(path) = log_path else { continue };
            let serial = Serial::new_capture(base, path)
                .map_err(|e| HyperbugError::Io(format!("opening UART log {path}: {e}")))?;
            irqs.register(vm, irq)?;
            ports[i] = Some(serial);
        }
        Ok(ports)
    }

    fn add_i2c(
        args: &Args,
        vm: &VmFd,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        irqs: &mut IrqRegistry,
        pci_bus: &mut PciBus,
    ) -> Result<Option<Arc<Mutex<VirtioModernPci<VirtioI2c>>>>, HyperbugError> {
        if args.i2c_devices.is_empty() {
            return Ok(None);
        }
        let mut bus = I2cBus::new();
        for spec in &args.i2c_devices {
            let target = pydevice::load_i2c(&spec.path, &spec.class).map_err(|e| {
                HyperbugError::Python(format!("loading I2C device {} ({}): {e}", spec.path, spec.class))
            })?;
            bus.register(spec.addr, Arc::new(Mutex::new(target))).map_err(HyperbugError::Config)?;
        }
        const VIRTIO_DEVICE_TYPE_I2C_ADAPTER: u16 = 34;
        let i2c = Arc::new(Mutex::new(VirtioModernPci::new(
            VirtioI2c::new(Arc::new(Mutex::new(bus))),
            guest_mem.clone(),
            gsi::I2C,
            VIRTIO_DEVICE_TYPE_I2C_ADAPTER,
            0, // no device-specific config space
        )));
        register_pci(pci_bus, slots::I2C, i2c.clone(), i2c.clone())?;
        irqs.register(vm, u32::from(gsi::I2C))?;
        Ok(Some(i2c))
    }

    /// Builds one `virtio-gpio` adapter per `--gpio-device` spec, each its
    /// own PCI device sharing GSI 14 (real PCI INTx sharing, same as
    /// `gsi::BLK` across up to 8 disks) — unlike `add_i2c`'s single shared
    /// bus, a GPIO bank has no natural multiplexing point, matching real
    /// BMC hardware's typically several independent GPIO controllers.
    ///
    /// **Known gap, stated rather than silently accepted**: like I2C
    /// targets, GPIO banks aren't in `plugin_registry` — the control
    /// socket's `reset_device`/`reload_device` don't reach them yet.
    fn add_gpio(
        args: &Args,
        vm: &VmFd,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        irqs: &mut IrqRegistry,
        pci_bus: &mut PciBus,
    ) -> Result<Vec<GpioDevice>, HyperbugError> {
        if args.gpio_devices.is_empty() {
            return Ok(Vec::new());
        }
        if args.gpio_devices.len() > slots::GPIO_MAX_BANKS {
            return Err(HyperbugError::Config(format!(
                "--gpio-device given {} times, but only {} PCI slots are reserved for GPIO banks",
                args.gpio_devices.len(),
                slots::GPIO_MAX_BANKS
            )));
        }
        irqs.register(vm, u32::from(gsi::GPIO))?;
        const VIRTIO_DEVICE_TYPE_GPIO: u16 = 41;
        const GPIO_CONFIG_LEN: u32 = 8; // struct virtio_gpio_config
        let mut devices = Vec::new();
        for (devnum, spec) in (slots::GPIO_BASE..).zip(&args.gpio_devices) {
            let bank = pydevice::load_gpio_bank(&spec.path, &spec.class).map_err(|e| {
                HyperbugError::Python(format!("loading GPIO device {} ({}): {e}", spec.path, spec.class))
            })?;
            let device = Arc::new(Mutex::new(VirtioModernPci::new(
                VirtioGpio::new(Box::new(bank)),
                guest_mem.clone(),
                gsi::GPIO,
                VIRTIO_DEVICE_TYPE_GPIO,
                GPIO_CONFIG_LEN,
            )));
            register_pci(pci_bus, devnum, device.clone(), device.clone())?;
            devices.push(device);
        }
        Ok(devices)
    }

    /// Builds the one optional virtio-vsock adapter (`--vsock-uds`) —
    /// see `virtio_vsock.rs`'s own module doc comment for the bridging
    /// model and its scope. `None` with no `--vsock-uds` at all — no
    /// "always present, low risk" case the way virtio-rng has, since a
    /// vsock adapter with nothing to bridge to has no such justification.
    fn add_vsock(
        args: &Args,
        vm: &VmFd,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        irqs: &mut IrqRegistry,
        pci_bus: &mut PciBus,
    ) -> Result<Option<VsockDevice>, HyperbugError> {
        let Some(uds_path) = &args.vsock_uds else { return Ok(None) };
        const VIRTIO_DEVICE_TYPE_VSOCK: u16 = 19;
        const VSOCK_CONFIG_LEN: u32 = 8; // struct virtio_vsock_config { guest_cid: u64 }
        let vsock = VirtioVsock::new(uds_path.clone())
            .map_err(|e| HyperbugError::Io(format!("setting up virtio-vsock bridge: {e}")))?;
        let device = Arc::new(Mutex::new(VirtioModernPci::new(
            vsock,
            guest_mem.clone(),
            gsi::VSOCK,
            VIRTIO_DEVICE_TYPE_VSOCK,
            VSOCK_CONFIG_LEN,
        )));
        register_pci(pci_bus, slots::VSOCK, device.clone(), device.clone())?;
        irqs.register(vm, u32::from(gsi::VSOCK))?;
        Ok(Some(device))
    }

    fn add_pci_plugins(
        args: &Args,
        vm: &VmFd,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        irqs: &mut IrqRegistry,
        pci_bus: &mut PciBus,
        registry: &mut Vec<PluginRegistryEntry>,
    ) -> Result<PciPlugins, HyperbugError> {
        let mut plugins = PciPlugins::default();
        for spec in &args.pci_devices {
            let device =
                pydevice::load_pci(&spec.path, &spec.class, guest_mem.clone(), spec.dma_range).map_err(|e| {
                    HyperbugError::Python(format!(
                        "loading PCI device {} ({}): {e}",
                        spec.path, spec.class
                    ))
                })?;
            let devfn = spec.devfn();
            let line = crate::pci::PciDevice::interrupt_line(&device);
            let msi_capable = crate::pci::PciDevice::msi_capable(&device);
            if line != 0 {
                irqs.register(vm, u32::from(line))?;
                if msi_capable {
                    plugins.msi_devfns.push((u32::from(line), devfn));
                }
            }
            let device = Arc::new(Mutex::new(device));
            register_pci(pci_bus, spec.device_number, device.clone(), device.clone())?;
            registry.push(PluginRegistryEntry {
                selector: PluginSelector::Pci(spec.device_number),
                path: spec.path.clone(),
                class: Some(spec.class.clone()),
                dma_range: spec.dma_range,
                resource_limits: None,
                transport: PluginTransportKind::InProcess,
                is_pci: true,
                device: device.clone(),
            });
            if line != 0 {
                plugins.interrupt_sources.push(PluginPciDevice { device, irq: u32::from(line) });
            }
        }

        for spec in &args.sandboxed_pci_devices {
            let device = pydevice_proc::load_pci(&spec.path, &spec.class, guest_mem.clone(), spec.dma_range, spec.resource_limits.clone())
                .map_err(|e| {
                    HyperbugError::Python(format!(
                        "loading sandboxed PCI device {} ({}): {e}",
                        spec.path, spec.class
                    ))
                })?;
            let devfn = spec.devfn();
            let line = crate::pci::PciDevice::interrupt_line(&device);
            let msi_capable = crate::pci::PciDevice::msi_capable(&device);
            if line != 0 {
                irqs.register(vm, u32::from(line))?;
                if msi_capable {
                    plugins.msi_devfns.push((u32::from(line), devfn));
                }
            }
            let device = Arc::new(Mutex::new(device));
            register_pci(pci_bus, spec.device_number, device.clone(), device.clone())?;
            registry.push(PluginRegistryEntry {
                selector: PluginSelector::Pci(spec.device_number),
                path: spec.path.clone(),
                class: Some(spec.class.clone()),
                dma_range: spec.dma_range,
                resource_limits: spec.resource_limits.clone(),
                transport: PluginTransportKind::Sandboxed,
                is_pci: true,
                device: device.clone(),
            });
            if line != 0 {
                plugins.interrupt_sources.push(PluginPciDevice { device, irq: u32::from(line) });
            }
        }

        for spec in &args.native_pci_devices {
            let device = native_plugin::load_pci(&spec.path, guest_mem.clone(), spec.dma_range)
                .map_err(|e| HyperbugError::Io(format!("loading native PCI device {}: {e}", spec.path)))?;
            let devfn = spec.devfn();
            let line = crate::pci::PciDevice::interrupt_line(&device);
            let msi_capable = crate::pci::PciDevice::msi_capable(&device);
            if line != 0 {
                irqs.register(vm, u32::from(line))?;
                if msi_capable {
                    plugins.msi_devfns.push((u32::from(line), devfn));
                }
            }
            let device = Arc::new(Mutex::new(device));
            register_pci(pci_bus, spec.device_number, device.clone(), device.clone())?;
            registry.push(PluginRegistryEntry {
                selector: PluginSelector::Pci(spec.device_number),
                path: spec.path.clone(),
                class: None,
                dma_range: spec.dma_range,
                resource_limits: None,
                transport: PluginTransportKind::Native,
                is_pci: true,
                device: device.clone(),
            });
            if line != 0 {
                plugins.interrupt_sources.push(PluginPciDevice { device, irq: u32::from(line) });
            }
        }

        for spec in &args.wasm_pci_devices {
            let device = wasm_plugin::load_pci(&spec.path, guest_mem.clone(), spec.dma_range)
                .map_err(|e| HyperbugError::Io(format!("loading wasm PCI device {}: {e}", spec.path)))?;
            let devfn = spec.devfn();
            let line = crate::pci::PciDevice::interrupt_line(&device);
            let msi_capable = crate::pci::PciDevice::msi_capable(&device);
            if line != 0 {
                irqs.register(vm, u32::from(line))?;
                if msi_capable {
                    plugins.msi_devfns.push((u32::from(line), devfn));
                }
            }
            let device = Arc::new(Mutex::new(device));
            register_pci(pci_bus, spec.device_number, device.clone(), device.clone())?;
            registry.push(PluginRegistryEntry {
                selector: PluginSelector::Pci(spec.device_number),
                path: spec.path.clone(),
                class: None,
                dma_range: spec.dma_range,
                resource_limits: None,
                transport: PluginTransportKind::Wasm,
                is_pci: true,
                device: device.clone(),
            });
            if line != 0 {
                plugins.interrupt_sources.push(PluginPciDevice { device, irq: u32::from(line) });
            }
        }
        Ok(plugins)
    }
}

fn new_virtio<D: crate::virtio::VirtioDeviceOps>(
    dev: D,
    guest_mem: &Arc<Mutex<GuestMemory>>,
    irq: u8,
) -> Arc<Mutex<VirtioLegacyPci<D>>> {
    Arc::new(Mutex::new(VirtioLegacyPci::new(dev, guest_mem.clone(), irq)))
}

fn register_io<D: Device + 'static>(io_bus: &mut IoBus, port: u16, size: u64, device: D) {
    io_bus.register(u64::from(port), size, Arc::new(Mutex::new(device)), None);
}

/// Re-loads one plugin from disk using its original launch parameters
/// (`path`/`class`/`dma_range`/`resource_limits` — unchanged, since this
/// is for picking up an edited plugin *file*, not switching to a
/// different one) and swaps the result into its existing slot in place —
/// the mechanism behind the control socket's `reload_device` command
/// (`control.rs`). The device's PCI/MMIO address never changes (the same
/// `Arc<Mutex<ScriptedDevice>>` the bus already holds is mutated, not
/// replaced), so the guest never needs to re-enumerate anything.
///
/// For a PCI plugin, refuses the reload — returning an error, leaving the
/// running device completely untouched — if the freshly-loaded identity
/// doesn't exactly match the one already registered. `PciBus` snapshots a
/// device's config-space identity once, at `register()` time, and has no
/// mechanism to notice it changed later; silently accepting a mismatched
/// reload would desync the guest's PCI config-space view (what
/// `lspci`/the driver sees) from the plugin code actually answering
/// behind it. A plain MMIO (`--device`) plugin has no such concern — its
/// address comes from the CLI, not the plugin's own attributes.
pub fn reload_plugin(entry: &PluginRegistryEntry, guest_mem: &Arc<Mutex<GuestMemory>>) -> Result<(), String> {
    let class = || {
        entry
            .class
            .as_deref()
            .expect("in-process/sandboxed registry entries always have a class")
    };
    let fresh = match entry.transport {
        PluginTransportKind::Sandboxed if entry.is_pci => pydevice_proc::load_pci(
            &entry.path,
            class(),
            guest_mem.clone(),
            entry.dma_range,
            entry.resource_limits.clone(),
        )
        .map_err(|e| e.to_string())?,
        PluginTransportKind::Sandboxed => pydevice_proc::load(
            &entry.path,
            class(),
            guest_mem.clone(),
            entry.dma_range,
            entry.resource_limits.clone(),
        )
        .map_err(|e| e.to_string())?,
        PluginTransportKind::InProcess if entry.is_pci => {
            pydevice::load_pci(&entry.path, class(), guest_mem.clone(), entry.dma_range).map_err(|e| e.to_string())?
        }
        PluginTransportKind::InProcess => {
            pydevice::load(&entry.path, class(), guest_mem.clone(), entry.dma_range).map_err(|e| e.to_string())?
        }
        PluginTransportKind::Native if entry.is_pci => {
            native_plugin::load_pci(&entry.path, guest_mem.clone(), entry.dma_range).map_err(|e| e.to_string())?
        }
        PluginTransportKind::Native => {
            native_plugin::load(&entry.path, guest_mem.clone(), entry.dma_range).map_err(|e| e.to_string())?
        }
        PluginTransportKind::Wasm if entry.is_pci => {
            wasm_plugin::load_pci(&entry.path, guest_mem.clone(), entry.dma_range).map_err(|e| e.to_string())?
        }
        PluginTransportKind::Wasm => {
            wasm_plugin::load(&entry.path, guest_mem.clone(), entry.dma_range).map_err(|e| e.to_string())?
        }
    };

    if entry.is_pci {
        let old_identity = entry.device.lock().unwrap().identity();
        let new_identity = fresh.identity();
        if new_identity != old_identity {
            return Err(format!(
                "reload refused: the reloaded plugin's PCI identity changed — vendor/device/class/BAR \
                 sizes/IRQ/MSI must stay exactly the same across a reload, since the PCI bus caches them \
                 at first registration and won't notice a change here (old={old_identity:?}, \
                 new={new_identity:?})"
            ));
        }
    }

    entry.device.lock().unwrap().reload(fresh);
    Ok(())
}

/// Registers a device on the PCI bus, turning a slot collision into a
/// configuration error (a `--pci-device` can be pointed at a slot
/// hyperbug's own virtio devices already occupy). Returns whatever
/// `PciBus::register` created for the device's own `ioevent_entries()` —
/// empty for everything except hyperbug's own legacy virtio devices.
fn register_pci<D>(
    pci_bus: &mut PciBus,
    devnum: u8,
    pci: Arc<Mutex<D>>,
    mmio: Arc<Mutex<D>>,
) -> Result<Vec<(Arc<EventFd>, u16)>, HyperbugError>
where
    D: crate::pci::PciDevice + Device + 'static,
{
    pci_bus.register(devnum << 3, pci, mmio).map_err(HyperbugError::Config)
}

/// Zips `PciBus::register`'s `(eventfd, datamatch)` output with the
/// device (as `Arc<Mutex<dyn PciDevice>>` — `handle_ioevent` is all the
/// reactor needs) and its GSI into `reactor::VirtioNotifyTarget`s, and
/// appends them to `out`. A no-op if `events` is empty (every non-virtio
/// device, and the modern-transport rng branch, which doesn't call this).
fn push_virtio_notifies<D: PciDevice + 'static>(
    out: &mut Vec<VirtioNotifyTarget>,
    events: Vec<(Arc<EventFd>, u16)>,
    device: Arc<Mutex<D>>,
    gsi: u8,
) {
    if events.is_empty() {
        return;
    }
    let device: Arc<Mutex<dyn PciDevice>> = device;
    for (eventfd, datamatch) in events {
        out.push(VirtioNotifyTarget { eventfd, device: device.clone(), datamatch, gsi: u32::from(gsi) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Device;

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hyperbug-reload-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The actual point of hot-reload: a plugin file is edited on disk
    /// (simulating a developer changing their device's logic) and
    /// `reload_plugin` picks up the change — same address, same `Arc`,
    /// no guest re-enumeration — without a fresh boot. Uses the
    /// in-process loader (no `python3` subprocess needed) since the
    /// property under test is `reload_plugin`'s own logic, not either
    /// transport.
    #[test]
    fn reload_plugin_picks_up_a_genuinely_edited_plugin_file() {
        let dir = scratch_dir("mmio");
        let path = dir.join("versioned.py");
        std::fs::write(
            &path,
            "class Versioned:\n\
            \x20   def read(self, offset, size):\n\
            \x20       return (1).to_bytes(size, 'little')\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        )
        .unwrap();

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let device = pydevice::load(path.to_str().unwrap(), "Versioned", mem.clone(), None).unwrap();
        let device = Arc::new(Mutex::new(device));

        let mut val = [0u8; 4];
        Device::read(&mut *device.lock().unwrap(), 0, &mut val);
        assert_eq!(u32::from_le_bytes(val), 1, "the original plugin should report version 1");

        // The "developer edits the file" step — a genuinely different
        // return value, not just a comment change.
        std::fs::write(
            &path,
            "class Versioned:\n\
            \x20   def read(self, offset, size):\n\
            \x20       return (2).to_bytes(size, 'little')\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        )
        .unwrap();

        let entry = PluginRegistryEntry {
            selector: PluginSelector::Mmio(0xd0000000),
            path: path.to_str().unwrap().to_string(),
            class: Some("Versioned".to_string()),
            dma_range: None,
            resource_limits: None,
            transport: PluginTransportKind::InProcess,
            is_pci: false,
            device: device.clone(),
        };
        reload_plugin(&entry, &mem).expect("reload should succeed — no PCI identity to conflict");

        Device::read(&mut *device.lock().unwrap(), 0, &mut val);
        assert_eq!(u32::from_le_bytes(val), 2, "the reloaded plugin should report the edited version");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A PCI plugin's reload is refused outright — the running device
    /// left completely untouched — if the edited file declares a
    /// different PCI identity, since `PciBus` caches the identity once
    /// at registration and has no way to notice a change afterward.
    #[test]
    fn reload_plugin_refuses_a_pci_identity_change_and_leaves_the_device_untouched() {
        let dir = scratch_dir("pci");
        let path = dir.join("pcidev.py");
        let source_with_device_id = |device_id: u32| {
            format!(
                "class PciDev:\n\
                \x20   vendor_id = 0x1234\n\
                \x20   device_id = {device_id:#x}\n\
                \x20   class_code = 0xff0000\n\
                \x20   bar_sizes = [0x10]\n\
                \x20   def read(self, offset, size):\n\
                \x20       return bytes(size)\n\
                \x20   def write(self, offset, data):\n\
                \x20       return False\n"
            )
        };
        std::fs::write(&path, source_with_device_id(1)).unwrap();

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let device = pydevice::load_pci(path.to_str().unwrap(), "PciDev", mem.clone(), None).unwrap();
        let original_identity = device.identity();
        let device = Arc::new(Mutex::new(device));

        // Change the declared device_id — a real identity change.
        std::fs::write(&path, source_with_device_id(2)).unwrap();

        let entry = PluginRegistryEntry {
            selector: PluginSelector::Pci(5),
            path: path.to_str().unwrap().to_string(),
            class: Some("PciDev".to_string()),
            dma_range: None,
            resource_limits: None,
            transport: PluginTransportKind::InProcess,
            is_pci: true,
            device: device.clone(),
        };
        let err = reload_plugin(&entry, &mem).expect_err("a changed PCI identity must refuse the reload");
        assert!(err.contains("identity changed"), "got: {err}");

        // The running device must be entirely untouched by the refused
        // reload — still the original identity.
        assert_eq!(device.lock().unwrap().identity(), original_identity);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
