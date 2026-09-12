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
use crate::irq::IrqRegistry;
use crate::mem::GuestMemory;
use crate::pci::{HostBridge, PciBus, PciDevice};
use crate::pydevice::PyDevice;
use crate::pydevice_proc::SandboxedPyDevice;
use crate::reactor::VirtioNotifyTarget;
use crate::serial::Serial;
use crate::virtio::{VirtioLegacyPci, VirtioModernPci};
use crate::virtio_blk::VirtioBlk;
use crate::virtio_net::{TapDevice, VirtioNet};
use crate::virtio_rng::VirtioRng;
use crate::{acpi, serial};

/// Fixed PCI slot assignment. Every slot here is
/// static regardless of *which* `--disk`/`--net`/`--pci-device` flags are
/// actually present at runtime, on purpose: `acpi/dsdt.asl`'s `_PRT`
/// hardcodes GSI routing for these exact slots, so a device landing on a
/// *different* slot depending on argument count (the old behavior) would
/// silently desync from it. Slot 0 is the host bridge; 1-3 and 18-31 are
/// free for `--pci-device`.
mod slots {
    pub const HOST_BRIDGE: u8 = 0;
    pub const BLK_BASE: u8 = 4;
    pub const BLK_MAX_DISKS: usize = 8; // slots 4-11, matching acpi/dsdt.asl's _PRT
    pub const NET: u8 = 16;
    pub const RNG: u8 = 17;
}

/// Legacy interrupt lines for hyperbug's own virtio devices. All < 16, so
/// the PIC-only routing `acpi.rs`'s MADT deliberately keeps the guest on
/// can deliver every one of them.
mod gsi {
    pub const BLK: u8 = 10; // shared across disks, like real PCI IRQ sharing
    pub const NET: u8 = 11;
    pub const RNG: u8 = 12;
}

type NetDevice = Arc<Mutex<VirtioLegacyPci<VirtioNet>>>;
type BlkDevice = Arc<Mutex<VirtioLegacyPci<VirtioBlk>>>;

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
/// poll. Held as `dyn Device` rather than a concrete `PyDevice`/
/// `SandboxedPyDevice` so `vcpu::poll_host` can drive both in-process and
/// sandboxed plugins through one loop over one `Vec` — they still run
/// completely differently under the hood (a PyO3 call vs. a subprocess
/// round trip), but that difference is now confined to each type's own
/// `Device::take_pending_irq` override instead of leaking into the poll
/// loop as two parallel lists.
pub struct PluginPciDevice {
    pub device: SharedDevice,
    /// The GSI to raise. `vcpu::signal_pci_irq` upgrades it to a real MSI
    /// if this device is in `msi_devfns` and the guest has enabled MSI.
    pub irq: u32,
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
    ) -> Result<Self, HyperbugError> {
        let mut mmio_bus = MmioBus::new();
        let mut io_bus = IoBus::new();
        let mut pci_bus = PciBus::with_vm(vm.clone());
        let mut virtio_notifies = Vec::new();
        let mut blk_devices = Vec::new();

        // COM1 is unconditional; everything else registers its line as it
        // is created below.
        irqs.register(vm, serial::COM1_IRQ)?;

        register_io(&mut io_bus, acpi::SLEEP_CONTROL_PORT, 2, acpi::SleepControl::new(exit_slot.clone()));
        register_io(&mut io_bus, acpi::RESET_PORT, 1, acpi::ResetControl::new(exit_slot.clone()));

        Self::add_mmio_plugins(args, guest_mem, &mut mmio_bus)?;
        Self::add_sandboxed_mmio_plugins(args, guest_mem, &mut mmio_bus)?;

        let host_bridge = Arc::new(Mutex::new(HostBridge));
        register_pci(&mut pci_bus, slots::HOST_BRIDGE, host_bridge.clone(), host_bridge)?;

        let mut virtio_snapshots =
            Self::add_disks(args, vm, guest_mem, irqs, &mut pci_bus, &mut virtio_notifies, &mut blk_devices)?;
        let net_devices = Self::add_net(args, vm, guest_mem, irqs, &mut pci_bus, &mut virtio_notifies)?;
        if let Some(net) = net_devices.first() {
            virtio_snapshots.push(net.clone());
        }

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
                VirtioRng::new(),
                guest_mem.clone(),
                gsi::RNG,
                VIRTIO_DEVICE_TYPE_ENTROPY,
                0, // no device-specific config space
            )));
            virtio_snapshots.push(rng.clone());
            register_pci(&mut pci_bus, slots::RNG, rng.clone(), rng)?;
        } else {
            let rng = new_virtio(VirtioRng::new(), guest_mem, gsi::RNG);
            virtio_snapshots.push(rng.clone());
            let events = register_pci(&mut pci_bus, slots::RNG, rng.clone(), rng.clone())?;
            push_virtio_notifies(&mut virtio_notifies, events, rng, gsi::RNG);
        }
        irqs.register(vm, u32::from(gsi::RNG))?;

        let plugins = Self::add_pci_plugins(args, vm, guest_mem, irqs, &mut pci_bus)?;

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
                mmio_bus,
                io_bus,
                pci_bus,
                plugin_pci_devices: plugins.interrupt_sources,
                msi_devfns: plugins.msi_devfns,
                control,
                virtio_snapshots,
            })),
            net_devices,
            virtio_notifies,
            blk_devices,
        })
    }

    fn add_mmio_plugins(
        args: &Args,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        mmio_bus: &mut MmioBus,
    ) -> Result<(), HyperbugError> {
        for spec in &args.devices {
            let device = PyDevice::load(&spec.path, &spec.class, guest_mem.clone(), spec.dma_range).map_err(|e| {
                HyperbugError::Python(format!("loading device {} ({}): {e}", spec.path, spec.class))
            })?;
            // A fixed-address MMIO device (unlike a --pci-device) has no
            // configured interrupt line at all, so a spontaneous
            // `hyperbug.raise_irq()` from one has nothing to pulse — it's
            // simply never polled. DMA via `hyperbug.read_mem`/`write_mem`
            // works the same either way.
            mmio_bus.register(spec.base, spec.size, Arc::new(Mutex::new(device)), None);
        }
        Ok(())
    }

    fn add_sandboxed_mmio_plugins(
        args: &Args,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        mmio_bus: &mut MmioBus,
    ) -> Result<(), HyperbugError> {
        for spec in &args.sandboxed_devices {
            let device = SandboxedPyDevice::load(&spec.path, &spec.class, guest_mem.clone(), spec.dma_range)
                .map_err(|e| {
                    HyperbugError::Python(format!(
                        "loading sandboxed device {} ({}): {e}",
                        spec.path, spec.class
                    ))
                })?;
            mmio_bus.register(spec.base, spec.size, Arc::new(Mutex::new(device)), None);
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

    fn add_pci_plugins(
        args: &Args,
        vm: &VmFd,
        guest_mem: &Arc<Mutex<GuestMemory>>,
        irqs: &mut IrqRegistry,
        pci_bus: &mut PciBus,
    ) -> Result<PciPlugins, HyperbugError> {
        let mut plugins = PciPlugins::default();
        for spec in &args.pci_devices {
            let device =
                PyDevice::load_pci(&spec.path, &spec.class, guest_mem.clone(), spec.dma_range).map_err(|e| {
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
            if line != 0 {
                plugins.interrupt_sources.push(PluginPciDevice { device, irq: u32::from(line) });
            }
        }

        for spec in &args.sandboxed_pci_devices {
            let device = SandboxedPyDevice::load_pci(&spec.path, &spec.class, guest_mem.clone(), spec.dma_range)
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
