//! Minimal PCI config-space emulation: just enough for the guest's PCI core
//! to enumerate a handful of devices on bus 0 via the standard
//! `0xCF8`/`0xCFC` I/O mechanism, size and program their BARs, and have
//! BAR-mapped registers show up on the `MmioBus`/`IoBus`.
//!
//! Deliberately not a general/spec-complete PCI host bridge: no bridges,
//! no multi-function devices. Has a capability list and single-message
//! (32-bit, no per-vector masking) MSI — opt-in via
//! `PciDevice::msi_capable()`, for a **custom `--pci-device` Python
//! plugin's own device model**, not hyperbug's own virtio devices.
//! Checked directly against the real Linux virtio driver source
//! (`drivers/virtio/virtio_pci_common.c`) before touching anything here:
//! `vp_find_vqs` only ever tries MSI-X or falls straight back to INTx —
//! there is no third path that requests plain (non-X) MSI at all, and
//! the *legacy* virtio-pci transport hyperbug's own devices use can't
//! support MSI-X in the first place (that needs the modern,
//! capability-list-based transport — a separate, much larger project).
//!
//! **Config-space identity is snapshotted at registration** into
//! `PciIdentity`, not queried from the device on every access. That
//! matches real hardware (a device's vendor/device/class/interrupt-pin
//! bytes are fixed), and it matters here for a concrete reason: a Python
//! `--pci-device` plugin's identity lives in Python attributes, so the old
//! per-access lookup meant acquiring the GIL and doing several attribute
//! reads *for every single config-space dword the guest touched during
//! enumeration* — including `msi_capable()`, which was consulted on every
//! read regardless of which register was selected.

use std::sync::{Arc, Mutex};

use kvm_ioctls::{IoEventAddress, VmFd};
use vmm_sys_util::eventfd::EventFd;

use crate::device::{Bus, Device, IoBus, MmioBus, SharedDevice};

pub const CONFIG_ADDRESS: u16 = 0xcf8;
pub const CONFIG_DATA: u16 = 0xcfc;
/// The CF8/CFC data window is four ports wide; a sub-dword access selects
/// its byte within the addressed dword by which of them it targets.
pub const CONFIG_DATA_END: u16 = CONFIG_DATA + 3;

pub const NUM_BARS: usize = 6;
const BAR_OFFSET: u16 = 0x10;
const BAR_OFFSET_END: u16 = BAR_OFFSET + (NUM_BARS as u16 - 1) * 4;

/// Type-0 config-space registers this emulation answers.
const REG_ID: u16 = 0x00;
const REG_COMMAND_STATUS: u16 = 0x04;
const REG_CLASS: u16 = 0x08;
const REG_HEADER_TYPE: u16 = 0x0c;
const REG_CAPABILITIES_PTR: u16 = 0x34;
const REG_INTERRUPT: u16 = 0x3c;

/// Status bit 4: "Capabilities List present". Must be set whenever offset
/// 0x34 points anywhere real, or the guest's PCI core won't even look.
const STATUS_CAP_LIST: u16 = 0x0010;

/// A PCI device's config-space identity (vendor/device/class, BAR sizes).
/// The same underlying object typically also implements `Device`, to
/// handle accesses once a BAR is mapped into a bus.
pub trait PciDevice: Send {
    fn vendor_id(&self) -> u16;
    fn device_id(&self) -> u16;
    fn class_code(&self) -> u32; // class/subclass/prog-if, in the standard 24-bit packing
    /// Sizes of implemented BARs; index absent or 0 means "not implemented".
    fn bar_sizes(&self) -> [u32; NUM_BARS];
    /// Whether BAR `index` is I/O-space rather than memory-space. Real
    /// hardware fixes this per BAR; only legacy virtio needs `true` today.
    fn bar_is_io(&self, _index: usize) -> bool {
        false
    }
    fn interrupt_line(&self) -> u8 {
        0
    }
    fn interrupt_pin(&self) -> u8 {
        1 // INTA#
    }
    /// Opt-in to a single-message, 32-bit-address MSI capability (no
    /// MSI-X, no per-vector masking — the simplest real form). A device
    /// that returns `true` here is responsible for actually requesting an
    /// interrupt (see `vcpu::signal_pci_irq`) rather than relying on the
    /// legacy `interrupt_line` pulse, once the guest has enabled it.
    fn msi_capable(&self) -> bool {
        false
    }
    /// Raw bytes of zero or more additional PCI capability structures to
    /// splice into the capability chain, verbatim — for a transport whose
    /// capabilities are static once BAR layout is known (unlike MSI's
    /// guest-writable enable bit), e.g. modern virtio 1.0's
    /// `virtio_pci_cap` structures (`VirtioModernPci`). Each structure's
    /// own `cap_next` byte (its 2nd byte) must already be set to the
    /// offset of the following one within this buffer, based at
    /// `EXTRA_CAP_OFFSET`; the last one's `cap_next` must be 0.
    /// `PciBus` places this buffer verbatim at `EXTRA_CAP_OFFSET` and
    /// does not alter it — a device combining this with `msi_capable()`
    /// is not supported (no current device needs both).
    fn extra_capabilities(&self) -> Vec<u8> {
        Vec::new()
    }
    /// PCI Revision ID (config offset 0x08, the low byte of the class
    /// dword). Real hardware fixes this; virtio 1.0 "modern-only" devices
    /// must report 1 (0 is reserved for the legacy/transitional layout).
    fn revision_id(&self) -> u8 {
        0
    }
    /// `(bar_index, offset_within_bar, 16-bit datamatch)` entries this
    /// device wants KVM to handle via a real `KVM_IOEVENTFD` once the
    /// named BAR is assigned a real address — a guest write matching
    /// `base + offset` (exactly, at the 2-byte width `datamatch`'s type
    /// implies) is then handled **entirely in-kernel**: it never reaches
    /// this process as a VM exit at all, let alone a `Device::write` call.
    /// Default: none — opt-in, and only hyperbug's own legacy virtio
    /// transport uses this today (`virtio.rs`'s queue-notify register;
    /// see `VirtioLegacyPci::ioevent_entries`). `PciBus::register` creates
    /// one `EventFd` per entry; `handle_ioevent` below is what actually
    /// runs when one fires.
    fn ioevent_entries(&self) -> Vec<(u8, u64, u16)> {
        Vec::new()
    }
    /// Called (from the reactor thread, never a vCPU thread — see
    /// `reactor.rs`) when a previously-registered `ioevent_entries` fires,
    /// with the `datamatch` value of the entry that matched. Returns
    /// whether this device's configured interrupt should be raised as a
    /// result. Default: never called (meaningless without a non-empty
    /// `ioevent_entries`).
    fn handle_ioevent(&mut self, _datamatch: u16) -> bool {
        false
    }
}

/// Capability ID for MSI (not MSI-X — that's 0x11), per the PCI spec.
const CAP_ID_MSI: u8 = 0x05;
/// Fixed offset for the (only) capability this emulation ever exposes —
/// real devices often have more than one, chained via each capability's
/// own "next pointer" byte, but one is enough for what any device here
/// actually needs.
const MSI_CAP_OFFSET: u16 = 0x40;
const MSI_CAP_ADDRESS: u16 = MSI_CAP_OFFSET + 4;
const MSI_CAP_DATA: u16 = MSI_CAP_OFFSET + 8;
/// Bit 0 of the Message Control word (at `MSI_CAP_OFFSET + 2`): MSI Enable.
const MSI_CTRL_ENABLE: u16 = 1 << 0;
/// Byte position of Message Control within the `MSI_CAP_OFFSET` dword.
const MSI_CTRL_BYTE: u16 = 2;

/// Fixed offset for a device's `extra_capabilities()` buffer, if any —
/// after MSI's 3 dwords (0x40-0x4b), with padding to the next dword.
pub const EXTRA_CAP_OFFSET: u16 = 0x50;

#[derive(Default)]
struct MsiState {
    enabled: bool,
    address: u32,
    data: u16,
}

/// Every real x86 system has a PCI host bridge at 00:00.0; some guest PCI
/// core sanity checks (deciding whether the CF8/CFC mechanism is even
/// trustworthy) key off a device actually being there. No BARs — a host
/// bridge doesn't need any.
pub struct HostBridge;

impl PciDevice for HostBridge {
    fn vendor_id(&self) -> u16 {
        // 0x1234 is the long-standing "this is not real silicon" placeholder
        // vendor ID (as used by e.g. the QEMU/Bochs VGA device) — hyperbug
        // isn't modeling any specific real chipset's host bridge.
        0x1234
    }
    fn device_id(&self) -> u16 {
        0x0001
    }
    fn class_code(&self) -> u32 {
        0x06_00_00 // bridge, host bridge
    }
    fn bar_sizes(&self) -> [u32; NUM_BARS] {
        [0; NUM_BARS]
    }
    fn interrupt_pin(&self) -> u8 {
        0 // a host bridge doesn't raise interrupts
    }
}

impl Device for HostBridge {
    fn read(&mut self, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }
    fn write(&mut self, _offset: u64, _data: &[u8]) -> bool {
        false
    }
}

/// The fixed part of a device's config space, read once at registration —
/// see this module's doc comment for why it isn't queried per access.
#[derive(Clone)]
struct PciIdentity {
    vendor_id: u16,
    device_id: u16,
    class_code: u32,
    revision_id: u8,
    interrupt_line: u8,
    interrupt_pin: u8,
    msi_capable: bool,
    extra_caps: Arc<Vec<u8>>,
}

impl PciIdentity {
    fn snapshot(dev: &dyn PciDevice) -> Self {
        Self {
            vendor_id: dev.vendor_id(),
            device_id: dev.device_id(),
            class_code: dev.class_code(),
            revision_id: dev.revision_id(),
            interrupt_line: dev.interrupt_line(),
            interrupt_pin: dev.interrupt_pin(),
            msi_capable: dev.msi_capable(),
            extra_caps: Arc::new(dev.extra_capabilities()),
        }
    }

    /// The GSI to hand a bus mapping, or `None` for a device with no
    /// legacy interrupt line (0 means "none", same as `PciDevice`'s own
    /// trait default).
    fn irq(&self) -> Option<u32> {
        (self.interrupt_line != 0).then_some(u32::from(self.interrupt_line))
    }
}

struct BarState {
    size: u32,
    is_io: bool,
    base: Option<u32>,
    sizing: bool, // guest wrote all-1s and hasn't read back yet
}

impl BarState {
    /// Bits a base address actually occupies: the low 4 bits of a memory
    /// BAR (type + prefetch) and the low 2 of an I/O BAR are flags, not
    /// address.
    #[inline]
    fn align_mask(&self) -> u32 {
        if self.is_io { !0x3 } else { !0xf }
    }

    /// Bit 0 of a BAR: 1 = I/O space, 0 = memory space.
    #[inline]
    fn space_bit(&self) -> u32 {
        u32::from(self.is_io)
    }

    #[inline]
    fn implemented(&self) -> bool {
        self.size != 0
    }
}

/// One `ioevent_entries()` entry, tracked from creation through every BAR
/// (re)assignment. `registered_addr` is `None` until the owning BAR gets a
/// real base (or after it's cleared/moved) — `rebind_ioevents` is the only
/// place that changes it.
struct IoEventBinding {
    bar_index: u8,
    offset: u64,
    datamatch: u16,
    eventfd: Arc<EventFd>,
    registered_addr: Option<u64>,
}

struct Slot {
    identity: PciIdentity,
    mmio_device: SharedDevice,
    bars: [BarState; NUM_BARS],
    command: u16,
    msi: MsiState,
    ioevents: Vec<IoEventBinding>,
}

#[derive(Default)]
pub struct PciBus {
    slots: Vec<(u8, Slot)>, // (devfn on bus 0, slot)
    /// Latched value of the last CONFIG_ADDRESS write.
    address: u32,
    /// `None` in tests (and anywhere else `KVM_IOEVENTFD` doesn't apply,
    /// e.g. this module's own unit tests, which drive the config-space
    /// protocol with no real `/dev/kvm` involved at all) — `ioevent_entries`
    /// bindings are then simply never registered with KVM, and a matching
    /// guest write just falls through to the ordinary VM-exit path, exactly
    /// as if `ioevent_entries` had returned nothing. `Some` for every real
    /// launch (`Machine::build` uses `with_vm`).
    vm: Option<Arc<VmFd>>,
}

impl PciBus {
    /// No `KVM_IOEVENTFD` support (`ioevent_entries` bindings are never
    /// registered with KVM — see `PciBus::vm`'s doc comment). Every real
    /// launch uses `with_vm` instead; this is what the config-space unit
    /// tests in this module use to drive `io_out`/`io_in` with no real
    /// `/dev/kvm` involved at all, so it's test-only rather than kept as
    /// unused production API.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Real guest writes matching a registered device's `ioevent_entries`
    /// are handled by KVM entirely in-kernel once that device's BAR is
    /// assigned — see `PciDevice::ioevent_entries`.
    pub fn with_vm(vm: Arc<VmFd>) -> Self {
        Self { vm: Some(vm), ..Self::default() }
    }

    /// Whether `port` belongs to the CF8/CFC config mechanism at all —
    /// the single place that decode lives, so a vCPU exit handler doesn't
    /// have to open-code the port range.
    #[inline]
    pub fn owns_port(port: u16) -> bool {
        port == CONFIG_ADDRESS || (CONFIG_DATA..=CONFIG_DATA_END).contains(&port)
    }

    /// Registers a device at PCI bus 0, the given devfn, function 0.
    /// `device` provides config-space identity (snapshotted here, then
    /// dropped); `mmio_device` handles reads/writes once a BAR is mapped
    /// (usually the same underlying object).
    ///
    /// Returns an error rather than panicking on a devfn collision: a
    /// `--pci-device` plugin can be pointed at a slot hyperbug's own
    /// virtio devices already use, and that's bad configuration, not a
    /// reason to abort an embedding process.
    /// Registers `device` at bus 0, devfn `devfn`. Returns the `(eventfd,
    /// datamatch)` pairs created for each of the device's own
    /// `ioevent_entries()` (empty for the overwhelming majority of
    /// devices, which don't opt in) — the caller (`machine.rs`) is what
    /// actually knows which interrupt line and reactor thread these
    /// belong to, so it's handed back rather than kept opaque here.
    pub fn register(
        &mut self,
        devfn: u8,
        device: Arc<Mutex<dyn PciDevice>>,
        mmio_device: SharedDevice,
    ) -> Result<Vec<(Arc<EventFd>, u16)>, String> {
        if self.slots.iter().any(|(d, _)| *d == devfn) {
            return Err(format!(
                "PCI device number {} (devfn {devfn:#x}) is already in use — \
                 two devices were registered at the same slot",
                devfn >> 3
            ));
        }
        let (identity, bars, ioevents, notify_out) = {
            let dev = device.lock().unwrap();
            let sizes = dev.bar_sizes();
            let bars = std::array::from_fn(|i| BarState {
                size: sizes[i],
                is_io: dev.bar_is_io(i),
                base: None,
                sizing: false,
            });
            let mut ioevents = Vec::new();
            let mut notify_out = Vec::new();
            for (bar_index, offset, datamatch) in dev.ioevent_entries() {
                let eventfd = Arc::new(
                    EventFd::new(0).map_err(|e| format!("creating ioeventfd for devfn {devfn:#x}: {e}"))?,
                );
                ioevents.push(IoEventBinding {
                    bar_index,
                    offset,
                    datamatch,
                    eventfd: eventfd.clone(),
                    registered_addr: None,
                });
                notify_out.push((eventfd, datamatch));
            }
            (PciIdentity::snapshot(&*dev), bars, ioevents, notify_out)
        };
        self.slots.push((
            devfn,
            Slot { identity, mmio_device, bars, command: 0, msi: MsiState::default(), ioevents },
        ));
        Ok(notify_out)
    }

    pub fn io_out(&mut self, port: u16, data: &[u8], mmio: &mut MmioBus, io: &mut IoBus) {
        match port {
            CONFIG_ADDRESS if data.len() == 4 => {
                self.address = u32::from_le_bytes(data.try_into().unwrap());
            }
            CONFIG_DATA..=CONFIG_DATA_END => self.config_write(port - CONFIG_DATA, data, mmio, io),
            _ => {}
        }
    }

    pub fn io_in(&mut self, port: u16, data: &mut [u8]) {
        match port {
            CONFIG_ADDRESS if data.len() == 4 => {
                data.copy_from_slice(&self.address.to_le_bytes());
            }
            CONFIG_DATA..=CONFIG_DATA_END => self.config_read(port - CONFIG_DATA, data),
            _ => data.fill(0xff),
        }
    }

    fn decode_address(&self) -> Option<(u8, u16)> {
        // CONFIG_ADDRESS: bit31 enable, bits[23:16] bus, [15:11] device,
        // [10:8] function, [7:2] register (dword-aligned).
        if self.address & 0x8000_0000 == 0 {
            return None;
        }
        if (self.address >> 16) & 0xff != 0 {
            return None; // single-bus host bridge only
        }
        let devfn = ((self.address >> 8) & 0xff) as u8; // device<<3 | function
        let reg = (self.address & 0xfc) as u16;
        Some((devfn, reg))
    }

    fn find_slot(&mut self, devfn: u8) -> Option<&mut Slot> {
        self.slots.iter_mut().find(|(d, _)| *d == devfn).map(|(_, s)| s)
    }

    /// The BAR index a dword-aligned register offset names, if any.
    fn bar_index(reg: u16) -> Option<usize> {
        ((BAR_OFFSET..=BAR_OFFSET_END).contains(&reg) && (reg - BAR_OFFSET).is_multiple_of(4))
            .then(|| usize::from((reg - BAR_OFFSET) / 4))
    }

    fn config_read(&mut self, byte_offset: u16, data: &mut [u8]) {
        data.fill(0xff); // no device present / not implemented
        let Some((devfn, reg)) = self.decode_address() else {
            return;
        };
        // A whole-dword access is what every real PCI core uses to size a
        // BAR (write all-1s, read back, restore); only that should consume
        // the one-shot `sizing` latch.
        let full_dword = byte_offset == 0 && data.len() == 4;
        let Some(slot) = self.find_slot(devfn) else {
            return;
        };
        let id = slot.identity.clone();
        let has_caps = id.msi_capable || !id.extra_caps.is_empty();

        let dword = match reg {
            REG_ID => (u32::from(id.device_id) << 16) | u32::from(id.vendor_id),
            REG_COMMAND_STATUS => {
                let status = if has_caps { STATUS_CAP_LIST } else { 0 };
                (u32::from(status) << 16) | u32::from(slot.command)
            }
            REG_CLASS => (id.class_code << 8) | u32::from(id.revision_id),
            REG_HEADER_TYPE => 0, // header type 0, no BIST/latency/cache-line
            REG_CAPABILITIES_PTR if id.msi_capable => u32::from(MSI_CAP_OFFSET),
            REG_CAPABILITIES_PTR if !id.extra_caps.is_empty() => u32::from(EXTRA_CAP_OFFSET),
            REG_INTERRUPT => u32::from(id.interrupt_line) | (u32::from(id.interrupt_pin) << 8),
            MSI_CAP_OFFSET if id.msi_capable => {
                let ctrl = if slot.msi.enabled { MSI_CTRL_ENABLE } else { 0 };
                let next = if id.extra_caps.is_empty() { 0 } else { u32::from(EXTRA_CAP_OFFSET) };
                u32::from(CAP_ID_MSI) | (next << 8) | (u32::from(ctrl) << 16)
            }
            MSI_CAP_ADDRESS if id.msi_capable => slot.msi.address,
            MSI_CAP_DATA if id.msi_capable => u32::from(slot.msi.data),
            _ => match Self::bar_index(reg) {
                Some(i) => Self::read_bar(&mut slot.bars[i], full_dword),
                None => Self::read_extra_cap(&id.extra_caps, reg),
            },
        };

        let bytes = dword.to_le_bytes();
        let off = usize::from(byte_offset % 4);
        let n = data.len().min(4 - off);
        data[..n].copy_from_slice(&bytes[off..off + n]);
    }

    /// Reads one dword out of a device's static `extra_capabilities()`
    /// buffer, zero-filling past its end (mirrors `read_bar`'s "not
    /// implemented" behavior rather than exposing stale/garbage bytes).
    fn read_extra_cap(bytes: &[u8], reg: u16) -> u32 {
        let Some(start) = reg.checked_sub(EXTRA_CAP_OFFSET) else { return 0 };
        let mut buf = [0u8; 4];
        if let Some(slice) = bytes.get(usize::from(start)..) {
            let n = slice.len().min(4);
            buf[..n].copy_from_slice(&slice[..n]);
        }
        u32::from_le_bytes(buf)
    }

    fn read_bar(bar: &mut BarState, full_dword: bool) -> u32 {
        if !bar.implemented() {
            return 0;
        }
        if bar.sizing {
            if full_dword {
                bar.sizing = false;
            }
            return (!(bar.size - 1) & bar.align_mask()) | bar.space_bit();
        }
        bar.base.map_or(0, |b| b | bar.space_bit())
    }

    fn config_write(&mut self, byte_offset: u16, data: &[u8], mmio: &mut MmioBus, io: &mut IoBus) {
        let Some((devfn, reg)) = self.decode_address() else {
            return;
        };
        // Snapshotted before `find_slot` borrows `self` mutably — `slot`
        // below borrows all of `self` for the borrow checker's purposes
        // (the lifetime isn't split per-field), so `self.vm` can't be read
        // again while it's alive. Cheap either way: `None` or one `Arc`
        // clone (a refcount bump).
        let vm = self.vm.clone();
        let Some(slot) = self.find_slot(devfn) else {
            return;
        };
        let msi_capable = slot.identity.msi_capable;

        match reg {
            REG_COMMAND_STATUS if byte_offset == 0 && data.len() >= 2 => {
                slot.command = u16::from_le_bytes(data[..2].try_into().unwrap());
            }
            // Real drivers write these sub-dword (a 16-bit Message Control
            // at cap+2, e.g.), so `byte_offset` — the actual target byte
            // within the CF8/CFC-selected dword — has to be honored here
            // or an MSI-enabling write would silently land on the wrong
            // field. BAR/command writes don't need it: real PCI cores
            // always do those as full, aligned accesses.
            MSI_CAP_OFFSET if msi_capable && byte_offset == MSI_CTRL_BYTE && data.len() >= 2 => {
                let ctrl = u16::from_le_bytes(data[..2].try_into().unwrap());
                slot.msi.enabled = ctrl & MSI_CTRL_ENABLE != 0;
            }
            MSI_CAP_ADDRESS if msi_capable && byte_offset == 0 && data.len() == 4 => {
                slot.msi.address = u32::from_le_bytes(data.try_into().unwrap());
            }
            MSI_CAP_DATA if msi_capable && byte_offset == 0 && data.len() >= 2 => {
                slot.msi.data = u16::from_le_bytes(data[..2].try_into().unwrap());
            }
            _ => {
                if let Some(i) = Self::bar_index(reg)
                    && byte_offset == 0
                    && data.len() == 4
                {
                    let val = u32::from_le_bytes(data.try_into().unwrap());
                    Self::write_bar(slot, i, val, mmio, io, vm.as_ref());
                }
            }
        }
    }

    fn write_bar(slot: &mut Slot, index: usize, val: u32, mmio: &mut MmioBus, io: &mut IoBus, vm: Option<&Arc<VmFd>>) {
        let irq = slot.identity.irq();
        let bar = &mut slot.bars[index];
        if !bar.implemented() {
            return;
        }
        if val == 0xffff_ffff {
            bar.sizing = true;
            return;
        }
        let base = val & bar.align_mask();
        let is_io = bar.is_io;
        bar.base = Some(base);

        let bus: &mut Bus = if is_io { io } else { mmio };
        if base == 0 {
            // A write of 0 isn't a real assignment — it's the PCI core
            // restoring the BAR to "unassigned" after probing its size
            // (write all-1s, read size, write the original value back).
            // Any previous mapping has to go with it: leaving it live
            // would keep answering at an address the guest has explicitly
            // reclaimed, and would then collide with whatever gets mapped
            // there next.
            bus.unregister(&slot.mmio_device);
        } else {
            bus.register(u64::from(base), u64::from(bar.size), slot.mmio_device.clone(), irq);
        }

        Self::rebind_ioevents(slot, index, is_io, base, vm);
    }

    /// (Re)binds every `ioevents` entry whose `bar_index == index` to the
    /// new base address, unregistering any stale KVM binding first — a
    /// real guest moving or clearing a BAR after boot (or the one-shot
    /// sizing sequence's final "restore to 0") would otherwise leave KVM
    /// still matching writes at an address the guest no longer owns.
    /// A no-op when `vm` is `None` (see `PciBus::vm`'s doc comment).
    fn rebind_ioevents(slot: &mut Slot, index: usize, is_io: bool, base: u32, vm: Option<&Arc<VmFd>>) {
        let Some(vm) = vm else { return };
        for binding in slot.ioevents.iter_mut().filter(|b| usize::from(b.bar_index) == index) {
            if let Some(old_addr) = binding.registered_addr.take() {
                let addr = if is_io { IoEventAddress::Pio(old_addr) } else { IoEventAddress::Mmio(old_addr) };
                if let Err(e) = vm.unregister_ioevent(&binding.eventfd, &addr, binding.datamatch) {
                    eprintln!("[hyperbug] unregistering stale ioeventfd at {old_addr:#x}: {e}");
                }
            }
            if base != 0 {
                let new_addr = u64::from(base) + binding.offset;
                let addr = if is_io { IoEventAddress::Pio(new_addr) } else { IoEventAddress::Mmio(new_addr) };
                match vm.register_ioevent(&binding.eventfd, &addr, binding.datamatch) {
                    Ok(()) => binding.registered_addr = Some(new_addr),
                    Err(e) => eprintln!("[hyperbug] registering ioeventfd at {new_addr:#x}: {e}"),
                }
            }
        }
    }

    /// `Some((address, data))` if this devfn's MSI is currently enabled —
    /// checked before delivering an interrupt for a device that opted into
    /// `msi_capable()`, to decide `vm.signal_msi()` versus the legacy
    /// `interrupt_line` pulse (see `vcpu::signal_pci_irq`).
    pub fn msi_state(&self, devfn: u8) -> Option<(u32, u16)> {
        self.slots
            .iter()
            .find(|(d, _)| *d == devfn)
            .and_then(|(_, s)| s.msi.enabled.then_some((s.msi.address, s.msi.data)))
    }

    /// Serializes every slot's *config-space* state (BAR base addresses,
    /// the command register, MSI enable/address/data) — not identity
    /// (vendor/device/class etc.), which `restore_state` gets for free by
    /// registering the same devices at the same devfns again from `Args`,
    /// same as a normal launch. See `snapshot.rs`'s module doc comment for
    /// the full save/restore design.
    pub fn save_state(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.slots.len() as u32).to_le_bytes());
        for (devfn, slot) in &self.slots {
            buf.push(*devfn);
            for bar in &slot.bars {
                match bar.base {
                    Some(base) => {
                        buf.push(1);
                        buf.extend_from_slice(&base.to_le_bytes());
                    }
                    None => buf.push(0),
                }
            }
            buf.extend_from_slice(&slot.command.to_le_bytes());
            buf.push(u8::from(slot.msi.enabled));
            buf.extend_from_slice(&slot.msi.address.to_le_bytes());
            buf.extend_from_slice(&slot.msi.data.to_le_bytes());
        }
        buf
    }

    /// The inverse of `save_state`. Must run *after* every device for this
    /// launch has already been `register`ed (normal `Machine::build`
    /// order) — a snapshot referencing a devfn this launch's `Args` didn't
    /// also wire up (a disk/`--pci-device` removed between save and
    /// restore) is a config error, not something to guess around.
    /// Re-maps each restored BAR into `mmio`/`io` via the exact same
    /// `write_bar` logic a guest's own BAR-programming write would use,
    /// since restoring doesn't replay guest PCI enumeration at all.
    pub fn restore_state(&mut self, data: &[u8], mmio: &mut MmioBus, io: &mut IoBus) -> Result<(), String> {
        use crate::snapshot::{take_u8, take_u16, take_u32};
        let vm = self.vm.clone();
        let mut buf = data;
        let count = take_u32(&mut buf)?;
        for _ in 0..count {
            let devfn = take_u8(&mut buf)?;
            let mut bars = [None; NUM_BARS];
            for slot in &mut bars {
                if take_u8(&mut buf)? != 0 {
                    *slot = Some(take_u32(&mut buf)?);
                }
            }
            let command = take_u16(&mut buf)?;
            let msi_enabled = take_u8(&mut buf)? != 0;
            let msi_address = take_u32(&mut buf)?;
            let msi_data = take_u16(&mut buf)?;

            let Some(slot) = self.find_slot(devfn) else {
                return Err(format!(
                    "snapshot references PCI devfn {devfn:#x}, which this launch's \
                     configuration doesn't have — device wiring must match exactly"
                ));
            };
            slot.command = command;
            slot.msi.enabled = msi_enabled;
            slot.msi.address = msi_address;
            slot.msi.data = msi_data;
            for (i, base) in bars.into_iter().enumerate() {
                if let Some(base) = base {
                    Self::write_bar(slot, i, base, mmio, io, vm.as_ref());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    struct DummyMsiDevice {
        bar0: u32,
    }

    impl PciDevice for DummyMsiDevice {
        fn vendor_id(&self) -> u16 {
            0x1234
        }
        fn device_id(&self) -> u16 {
            0xbeef
        }
        fn class_code(&self) -> u32 {
            0xff_00_00
        }
        fn bar_sizes(&self) -> [u32; NUM_BARS] {
            [self.bar0, 0, 0, 0, 0, 0]
        }
        fn interrupt_line(&self) -> u8 {
            9
        }
        fn msi_capable(&self) -> bool {
            true
        }
    }

    impl Device for DummyMsiDevice {
        fn read(&mut self, _offset: u64, data: &mut [u8]) {
            data.fill(0x5a);
        }
        fn write(&mut self, _offset: u64, _data: &[u8]) -> bool {
            false
        }
    }

    struct Harness {
        bus: PciBus,
        mmio: MmioBus,
        io: IoBus,
    }

    impl Harness {
        fn new(devfn: u8, bar0: u32) -> (Self, Arc<Mutex<DummyMsiDevice>>) {
            let dev = Arc::new(Mutex::new(DummyMsiDevice { bar0 }));
            let mut bus = PciBus::new();
            bus.register(devfn, dev.clone(), dev.clone()).unwrap();
            (Self { bus, mmio: MmioBus::new(), io: IoBus::new() }, dev)
        }

        /// Drives the *actual* `io_out`/`io_in` port interface a real guest
        /// uses (CONFIG_ADDRESS latch, then CONFIG_DATA), not the private
        /// `config_read`/`config_write` directly.
        fn select(&mut self, devfn: u8, reg: u16) {
            let address = 0x8000_0000 | (u32::from(devfn) << 8) | u32::from(reg);
            self.bus.io_out(CONFIG_ADDRESS, &address.to_le_bytes(), &mut self.mmio, &mut self.io);
        }

        fn read_dword(&mut self) -> u32 {
            let mut data = [0u8; 4];
            self.bus.io_in(CONFIG_DATA, &mut data);
            u32::from_le_bytes(data)
        }

        fn write_at(&mut self, byte_offset: u16, data: &[u8]) {
            self.bus.io_out(CONFIG_DATA + byte_offset, data, &mut self.mmio, &mut self.io);
        }
    }

    #[test]
    fn a_non_msi_capable_device_reports_no_capabilities() {
        let dev = Arc::new(Mutex::new(HostBridge));
        let mut bus = PciBus::new();
        bus.register(0, dev.clone(), dev).unwrap();
        let mut h = Harness { bus, mmio: MmioBus::new(), io: IoBus::new() };

        h.select(0, REG_COMMAND_STATUS);
        assert_eq!(h.read_dword() >> 16, 0, "no capabilities-list bit without msi_capable");

        h.select(0, REG_CAPABILITIES_PTR);
        assert_eq!(h.read_dword(), 0, "capabilities pointer must be 0");
    }

    #[test]
    fn registering_two_devices_at_one_slot_is_an_error_not_a_panic() {
        let dev = Arc::new(Mutex::new(HostBridge));
        let mut bus = PciBus::new();
        assert!(bus.register(0x20, dev.clone(), dev.clone()).is_ok());
        assert!(bus.register(0x20, dev.clone(), dev).is_err());
    }

    #[test]
    fn msi_capable_device_advertises_the_capability_and_status_bit() {
        let (mut h, _dev) = Harness::new(0x08, 0);

        h.select(0x08, REG_COMMAND_STATUS);
        assert_eq!(h.read_dword() >> 16, u32::from(STATUS_CAP_LIST));

        h.select(0x08, REG_CAPABILITIES_PTR);
        assert_eq!(h.read_dword(), u32::from(MSI_CAP_OFFSET));

        h.select(0x08, MSI_CAP_OFFSET);
        let cap_header = h.read_dword();
        assert_eq!(cap_header & 0xff, u32::from(CAP_ID_MSI), "capability ID must be MSI (0x05)");
        assert_eq!((cap_header >> 16) & 1, 0, "MSI must start disabled");
    }

    #[test]
    fn enabling_msi_and_programming_address_data_is_reflected_in_msi_state() {
        let devfn = 0x10;
        let (mut h, _dev) = Harness::new(devfn, 0);
        assert_eq!(h.bus.msi_state(devfn), None, "MSI starts disabled");

        h.select(devfn, MSI_CAP_ADDRESS);
        h.write_at(0, &0xfee0_1234u32.to_le_bytes());

        h.select(devfn, MSI_CAP_DATA);
        h.write_at(0, &0x0042u16.to_le_bytes());

        // The enable bit's own sub-dword write (byte_offset == 2 within the
        // MSI_CAP_OFFSET dword) — exactly the access a silently-ignored
        // `byte_offset` would have corrupted.
        h.select(devfn, MSI_CAP_OFFSET);
        h.write_at(MSI_CTRL_BYTE, &MSI_CTRL_ENABLE.to_le_bytes());

        assert_eq!(h.bus.msi_state(devfn), Some((0xfee0_1234, 0x0042)));
    }

    #[test]
    fn the_standard_bar_sizing_sequence_reports_the_size_and_maps_the_final_address() {
        let devfn = 0x18;
        let (mut h, _dev) = Harness::new(devfn, 0x1000);
        h.select(devfn, BAR_OFFSET);

        // 1. write all-1s, 2. read back the size mask...
        h.write_at(0, &0xffff_ffffu32.to_le_bytes());
        assert_eq!(h.read_dword(), 0xffff_f000, "size mask for a 4 KiB memory BAR");

        // 3. ...restore the original (unassigned) value: nothing should be
        // mapped at guest-physical 0 as a result.
        h.write_at(0, &0u32.to_le_bytes());
        let mut probe = [0u8; 1];
        assert!(!h.mmio.read(0, &mut probe), "restoring a BAR to 0 must map nothing");

        // 4. the real assignment maps it for real.
        h.write_at(0, &0xd000_0000u32.to_le_bytes());
        assert!(h.mmio.read(0xd000_0000, &mut probe));
        assert_eq!(probe[0], 0x5a);
    }

    #[test]
    fn reprogramming_a_bar_back_to_unassigned_removes_the_stale_mapping() {
        let devfn = 0x18;
        let (mut h, _dev) = Harness::new(devfn, 0x1000);
        h.select(devfn, BAR_OFFSET);

        h.write_at(0, &0xd000_0000u32.to_le_bytes());
        let mut probe = [0u8; 1];
        assert!(h.mmio.read(0xd000_0000, &mut probe));

        h.write_at(0, &0u32.to_le_bytes());
        assert!(
            !h.mmio.read(0xd000_0000, &mut probe),
            "a device whose BAR the guest reclaimed must stop answering there"
        );
    }

    #[test]
    fn snapshot_round_trip_restores_bar_mapping_command_and_msi_state() {
        let devfn = 0x20;
        let (mut h, dev) = Harness::new(devfn, 0x1000);
        h.select(devfn, BAR_OFFSET);
        h.write_at(0, &0xd000_0000u32.to_le_bytes());
        h.select(devfn, REG_COMMAND_STATUS);
        h.write_at(0, &0x0007u16.to_le_bytes());
        h.select(devfn, MSI_CAP_ADDRESS);
        h.write_at(0, &0xfee0_1234u32.to_le_bytes());
        h.select(devfn, MSI_CAP_DATA);
        h.write_at(0, &0x0042u16.to_le_bytes());
        h.select(devfn, MSI_CAP_OFFSET);
        h.write_at(MSI_CTRL_BYTE, &MSI_CTRL_ENABLE.to_le_bytes());

        let blob = h.bus.save_state();

        // Restoring into a *fresh* bus (same devices registered, as a real
        // relaunch from `Args` would do) and fresh buses (nothing mapped
        // yet, as a restore's freshly-built `Machine` would have) — the
        // whole point is that this doesn't depend on guest PCI enumeration
        // ever running.
        let mut fresh_bus = PciBus::new();
        fresh_bus.register(devfn, dev.clone(), dev).unwrap();
        let mut fresh_mmio = MmioBus::new();
        let mut fresh_io = IoBus::new();
        fresh_bus.restore_state(&blob, &mut fresh_mmio, &mut fresh_io).unwrap();

        let mut probe = [0u8; 1];
        assert!(fresh_mmio.read(0xd000_0000, &mut probe), "BAR mapping must be restored");
        assert_eq!(probe[0], 0x5a);
        assert_eq!(fresh_bus.msi_state(devfn), Some((0xfee0_1234, 0x0042)), "MSI state must be restored");

        let mut h2 = Harness { bus: fresh_bus, mmio: fresh_mmio, io: fresh_io };
        h2.select(devfn, REG_COMMAND_STATUS);
        assert_eq!(h2.read_dword() & 0xffff, 0x0007, "command register must be restored");
    }

    #[test]
    fn restoring_a_devfn_the_current_launch_never_registered_is_an_error() {
        let mut bus = PciBus::new();
        let mut mmio = MmioBus::new();
        let mut io = IoBus::new();
        // A single-slot save whose one entry (devfn 0x40) has no BARs/
        // MSI set — restoring it against an empty bus must fail cleanly,
        // not panic or silently do nothing.
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes()); // one slot
        blob.push(0x40); // devfn
        blob.extend(std::iter::repeat_n(0u8, NUM_BARS)); // no BAR present, for every BAR
        blob.extend_from_slice(&0u16.to_le_bytes()); // command
        blob.push(0); // msi disabled
        blob.extend_from_slice(&0u32.to_le_bytes()); // msi address
        blob.extend_from_slice(&0u16.to_le_bytes()); // msi data
        assert!(bus.restore_state(&blob, &mut mmio, &mut io).is_err());
    }

    /// A device with `ioevent_entries()` registered via `PciBus::with_vm`
    /// gets a real `KVM_IOEVENTFD` binding once its BAR is assigned
    /// (`write_bar` -> `rebind_ioevents`) — this drives that with an
    /// actual `/dev/kvm` VM and a real vCPU (not through any PCI/virtio
    /// machinery, since the point is to check the raw KVM mechanism
    /// `rebind_ioevents` depends on, in isolation) executing a real 2-byte
    /// `out` instruction at the registered port/datamatch. Confirms two
    /// things at once: the eventfd actually fires (its counter becomes
    /// readable), and — the actual point of `KVM_IOEVENTFD` — the vCPU
    /// never exits to userspace for that specific write at all (`vcpu.
    /// run()` reports `Hlt`, the very next instruction, not `IoOut`).
    #[test]
    fn a_registered_ioeventfd_intercepts_a_real_vcpu_write_with_no_vm_exit() {
        let Ok(kvm) = kvm_ioctls::Kvm::new() else {
            eprintln!("skipping: /dev/kvm not available");
            return;
        };
        let vm = Arc::new(kvm.create_vm().expect("create_vm"));

        let mem_size = 0x10000usize;
        let mut guest_mem = crate::mem::GuestMemory::new(mem_size).expect("guest memory");
        // SAFETY: the mapping is `mem_size` bytes long and outlives `vm`.
        unsafe {
            vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: mem_size as u64,
                userspace_addr: guest_mem.as_ptr() as u64,
                flags: 0,
            })
        }
        .expect("set_user_memory_region");

        const CODE_ADDR: u64 = 0x1000;
        const PORT: u16 = 0x900; // arbitrary, unused-elsewhere I/O port
        const DATAMATCH: u16 = 0x1234;
        // mov dx, PORT; mov ax, DATAMATCH; out dx, ax; hlt
        let mut code = Vec::new();
        code.push(0xba);
        code.extend_from_slice(&PORT.to_le_bytes());
        code.push(0xb8);
        code.extend_from_slice(&DATAMATCH.to_le_bytes());
        code.push(0xef); // out dx, ax
        code.push(0xf4); // hlt
        guest_mem.write_checked(CODE_ADDR, &code);

        let mut vcpu = vm.create_vcpu(0).expect("create_vcpu");
        let mut sregs = vcpu.get_sregs().expect("get_sregs");
        // Real mode, flat: base 0 so `CODE_ADDR` is a real linear address
        // (the reset-vector default segment base — 0xffff0000 — would put
        // our code far outside the mapped region).
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        vcpu.set_sregs(&sregs).expect("set_sregs");
        let mut regs = vcpu.get_regs().expect("get_regs");
        regs.rip = CODE_ADDR;
        regs.rflags = 0x2; // reserved bit only, matching real hardware reset
        vcpu.set_regs(&regs).expect("set_regs");

        let eventfd = Arc::new(EventFd::new(0).expect("EventFd::new"));
        vm.register_ioevent(&eventfd, &IoEventAddress::Pio(u64::from(PORT)), DATAMATCH)
            .expect("register_ioevent");

        match vcpu.run().expect("vcpu.run") {
            kvm_ioctls::VcpuExit::Hlt => {}
            other => panic!(
                "expected the `out` to be handled entirely by KVM_IOEVENTFD, landing straight on \
                 `hlt` with no VM exit for the write itself; got {other:?} instead"
            ),
        }
        assert_eq!(eventfd.read().expect("eventfd should be signaled"), 1);

        vm.unregister_ioevent(&eventfd, &IoEventAddress::Pio(u64::from(PORT)), DATAMATCH)
            .expect("unregister_ioevent");
    }

    /// One CF8/CFC-level operation a guest (or a fuzzer standing in for
    /// one) can issue against config space, at the raw `io_out`/`io_in`
    /// port level — the same interface `Harness::select`/`write_at`/
    /// `read_dword` wrap for the hand-picked tests above.
    #[derive(Debug, Clone)]
    enum ConfigOp {
        Select { devfn: u8, reg: u16 },
        Write { byte_offset: u16, data: Vec<u8> },
        Read,
    }

    fn arbitrary_config_op() -> impl Strategy<Value = ConfigOp> {
        prop_oneof![
            (any::<u8>(), any::<u16>()).prop_map(|(devfn, reg)| ConfigOp::Select { devfn, reg }),
            // `byte_offset` is bounded to 0..=3: the real CONFIG_DATA/
            // CONFIG_DATA_END port window (`Harness::write_at` computes
            // `CONFIG_DATA + byte_offset` as the port to drive `io_out`
            // with, and only that 4-byte window is real CF8/CFC address
            // space at all — anything else falls outside `io_out`'s own
            // `CONFIG_DATA..=CONFIG_DATA_END` match arm and is a no-op, or
            // for a large enough offset, overflows the `u16` addition
            // itself. Testing that unreachable range would just be
            // asserting properties of `Harness`'s own test-only port
            // arithmetic, not of anything a real guest can reach.
            (0u16..4, proptest::collection::vec(any::<u8>(), 0..8))
                .prop_map(|(byte_offset, data)| ConfigOp::Write { byte_offset, data }),
            Just(ConfigOp::Read),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

        /// Drives `PciBus::io_out`/`io_in` — the exact entry point a real
        /// guest's `out`/`in` instructions reach — with an arbitrary
        /// sequence of config-address selections, writes of arbitrary
        /// length/offset/content, and reads, against a real registered
        /// MSI-capable device. Nothing here asserts a specific resulting
        /// value; the property is that **no sequence of guest-controlled
        /// config-space traffic panics**, regardless of devfn, register,
        /// byte offset, or data length — including sequences that select
        /// a devfn with no device registered at all, write a length other
        /// than 1/2/4 bytes, or hit the BAR/MSI/command registers in any
        /// order (interleaving a partial BAR-sizing sequence with MSI
        /// writes, say — exactly the kind of ordering a hand-picked test
        /// wouldn't think to try).
        #[test]
        fn arbitrary_config_space_traffic_never_panics(
            ops in proptest::collection::vec(arbitrary_config_op(), 0..64),
        ) {
            let (mut h, _dev) = Harness::new(0x08, 0x1000);
            for op in ops {
                match op {
                    ConfigOp::Select { devfn, reg } => h.select(devfn, reg & 0xfc),
                    ConfigOp::Write { byte_offset, data } => h.write_at(byte_offset, &data),
                    ConfigOp::Read => {
                        let _ = h.read_dword();
                    }
                }
            }
        }
    }
}
