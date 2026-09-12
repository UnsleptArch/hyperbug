//! The scriptable device ABI: any virtual device (native Rust or a Python
//! plugin) implements `Device`, and a `Bus` dispatches guest accesses to
//! whichever registered device owns that address/port range. `MmioBus` and
//! `IoBus` are the same dispatch logic — one keyed on guest-physical
//! addresses, the other on 16-bit I/O ports (legacy virtio's BAR0 is
//! I/O-space, not memory) — so they share one implementation.
//!
//! Devices are held as `Arc<Mutex<dyn Device>>` rather than owned outright,
//! since a PCI device's BAR-mapped registers need to be reachable both from
//! a `Bus` (for the actual reads/writes) and from `PciBus` (which moves the
//! mapping around as the guest sizes and programs the BAR).
//!
//! `Arc<Mutex<...>>`, not `Rc<RefCell<...>>` (DEBTS.md item 11, SMP):
//! multiple vCPU threads can trigger accesses to the same device
//! concurrently once there's more than one vCPU — the lock is what makes
//! that safe, and `Arc`/`Mutex` (rather than `Rc`/`RefCell`) is what makes
//! it *possible* to share a device across threads at all (`Rc` is never
//! `Send`, regardless of what guards it).

use std::sync::{Arc, Mutex};

/// The `Device`/`PciDevice` plugin ABI version this build implements — kept
/// in lockstep with `python/hyperbug/device.py`'s `HYPERBUG_API_VERSION`,
/// the single source of truth for what the number means and when to bump
/// it. Checked once at plugin load time (`pydevice.rs`/`pydevice_proc.rs`)
/// against a plugin's own `hyperbug_api_version` attribute, so a plugin
/// written against a since-changed contract fails loudly at load instead
/// of silently misbehaving against a `Device`/`PciDevice` shape that's
/// moved out from under it.
pub const PLUGIN_API_VERSION: u32 = 1;

/// Whether `[addr, addr + len)` lies entirely within a device's declared
/// DMA-confinement range (`config::DeviceSpec`/`PciDeviceSpec`'s optional
/// `dma_range`, a `(base, size)` pair) — the host-side enforcement half of
/// a real, if narrowly-scoped, vIOMMU-shaped control: any Python device
/// plugin's `self.hyperbug.read_mem`/`write_mem` can otherwise touch all
/// of guest RAM, which is fine for a trusted first-party plugin but not
/// once plugins are numerous or third-party (a compromised/malicious
/// plugin could read or corrupt memory belonging to anything else in the
/// guest). `range` is `None` for a plugin launched with no confinement —
/// unrestricted, the only behavior that existed before this — in which
/// case this always returns `true`.
///
/// This is *not* a guest-visible IOMMU: the guest's own OS/drivers see
/// nothing about it, and a device's own descriptor-supplied buffer
/// addresses (what virtio devices are handed by the guest) still need
/// broad reach by design — a real per-guest-programmed IOMMU (DMAR/IVRS
/// tables, an emulated translation-table walker) is a much larger, and
/// still entirely undone, feature. This is deliberately the smaller,
/// tractable piece: an *operator*-declared bound (on the CLI, not trusted
/// from the plugin's own Python attributes — the plugin is exactly the
/// untrusted party here, so it can't be allowed to declare its own
/// confinement) on what a specific plugin instance may touch.
#[inline]
pub fn dma_range_allows(range: Option<(u64, u64)>, addr: u64, len: u64) -> bool {
    let Some((base, size)) = range else { return true };
    let Some(end) = addr.checked_add(len) else { return false };
    let Some(range_end) = base.checked_add(size) else { return false };
    addr >= base && end <= range_end
}

/// A device addressed by an offset-relative-to-its-own-base range. `offset`
/// is relative to that base, not the raw guest-physical address or port.
/// `Send`: required for `Arc<Mutex<dyn Device>>` itself to be shareable
/// across the per-vCPU threads that call into it.
pub trait Device: Send {
    fn read(&mut self, offset: u64, data: &mut [u8]);
    /// Returns `true` if this write should raise the device's configured
    /// interrupt right now (e.g. a virtio device just advanced its used
    /// ring, or a Python device's `write()` returned a truthy value). A
    /// device with no configured IRQ (see `Bus::register`) has this
    /// silently ignored rather than needing to know that itself.
    fn write(&mut self, offset: u64, data: &[u8]) -> bool;

    /// Checked once per vCPU-loop iteration for a spontaneous interrupt
    /// this device wants to raise outside of `write()` (a Python plugin's
    /// `hyperbug.raise_irq()`, in-process or sandboxed). Clears whatever
    /// pending state it reports either way. Most devices never raise one
    /// this way, hence the default; `PyDevice`/`SandboxedPyDevice` are the
    /// only overrides today.
    fn take_pending_irq(&self) -> bool {
        false
    }

    /// Called once per vCPU-loop iteration, before `take_pending_irq`, for
    /// logic that needs to run independent of any guest register access —
    /// e.g. a simulated timer, or an async transaction (a doorbell-style
    /// device bridging to something that completes on its own schedule)
    /// whose completion isn't driven by the guest touching a register at
    /// all (DEBTS.md item 32). Most devices have nothing to do here, hence
    /// the default; a `PyDevice`/`SandboxedPyDevice` whose plugin class
    /// defines `tick()` are the only overrides today.
    fn tick(&mut self) {}
}

/// A shared, lockable handle to a device — the only form a `Bus` (or
/// `PciBus`) ever holds one in.
pub type SharedDevice = Arc<Mutex<dyn Device>>;

struct Region {
    base: u64,
    /// The last address this region covers, **inclusive**. Deliberately
    /// not "one past the end": a device mapped against the very top of
    /// the address space has no representable exclusive end, and
    /// saturating one at `u64::MAX` silently drops the final byte from
    /// the region (which is exactly what the overflow-region test caught).
    /// An inclusive end can express every legal region without wrapping,
    /// and — unlike a saturating exclusive end — stays correct even when
    /// checking two regions that both reach `u64::MAX` for overlap.
    last: u64,
    device: SharedDevice,
    irq: Option<u32>,
}

impl Region {
    /// `addr` is covered iff it falls in `[base, last]` inclusive — not
    /// `addr < base + size`, which is exactly the saturating-exclusive-end
    /// comparison that excludes `u64::MAX` itself from a region that
    /// legitimately reaches it (a BAR placed at the very top of the
    /// guest's address space) — caught by a real test, not found by
    /// inspection.
    #[inline]
    fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr <= self.last
    }
}

#[derive(Default)]
pub struct Bus {
    regions: Vec<Region>,
}

pub type MmioBus = Bus;
pub type IoBus = Bus;

impl Bus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `device` to handle addresses/ports `[base, base + size)`.
    /// If `device` already has a mapping (e.g. a PCI BAR being
    /// reprogrammed), that old mapping is replaced rather than left stale.
    /// `irq`, if given, is the GSI to report from `write()` when the
    /// device requests an interrupt.
    pub fn register(&mut self, base: u64, size: u64, device: SharedDevice, irq: Option<u32>) {
        self.unregister(&device);
        if size == 0 {
            return; // a zero-sized region maps nothing
        }
        // Saturating, not wrapping: a guest is free to program a BAR near
        // the top of the address space, and overflowing here would
        // otherwise turn the overlap test below into a no-op and make
        // `contains` reject every address. Saturation only ever *shrinks*
        // an already-impossible region (one running past `u64::MAX`), so
        // no legal mapping loses an address to it.
        let last = base.saturating_add(size - 1);
        // Two inclusive ranges overlap iff each starts at or before the
        // other's end.
        if let Some(clash) = self.regions.iter().find(|r| base <= r.last && r.base <= last) {
            // A misbehaving guest (or plugin) shouldn't take the whole VMM
            // down over this: refuse the new mapping and leave whatever
            // was already there working, rather than panicking.
            eprintln!(
                "[hyperbug] refusing to map [{base:#x}, {last:#x}]: overlaps existing mapping \
                 [{:#x}, {:#x}]",
                clash.base, clash.last
            );
            return;
        }
        self.regions.push(Region { base, last, device, irq });
    }

    /// Drops `device`'s mapping, if it has one. Used when a PCI BAR is
    /// reprogrammed back to "unassigned" (base 0): leaving the old mapping
    /// live would keep answering accesses at an address the guest has
    /// explicitly reclaimed.
    pub fn unregister(&mut self, device: &SharedDevice) {
        self.regions.retain(|r| !Arc::ptr_eq(&r.device, device));
    }

    #[inline]
    fn find(&mut self, addr: u64) -> Option<(&mut Region, u64)> {
        let region = self.regions.iter_mut().find(|r| r.contains(addr))?;
        let offset = addr - region.base;
        Some((region, offset))
    }

    /// Looks up the device (if any) covering `addr` and returns a cloned
    /// handle — plus its offset and configured IRQ — *without* locking or
    /// calling into the device itself. Exists so a caller holding a
    /// coarser lock around this `Bus` (`SharedState`'s, in practice) can
    /// release it before actually invoking the device: a device's own
    /// `read`/`write` can be slow (a Python plugin runs arbitrary guest
    /// code under the GIL; a sandboxed plugin is a subprocess round trip,
    /// up to its own 200ms timeout) and must not block every *other*
    /// device sharing that outer lock for the whole duration — see
    /// `vcpu::Runner::dispatch_write`/`dispatch_read`, the only callers.
    #[inline]
    pub fn find_device(&mut self, addr: u64) -> Option<(SharedDevice, u64, Option<u32>)> {
        let (region, offset) = self.find(addr)?;
        Some((region.device.clone(), offset, region.irq))
    }

    /// Returns true if some registered device handled the access. A
    /// combined find-then-call convenience; production code uses
    /// `find_device` instead so it can release its own lock around this
    /// `Bus` before calling into a device (see `find_device`'s doc
    /// comment) — this stays test-only rather than as unused production
    /// API.
    #[cfg(test)]
    pub fn read(&mut self, addr: u64, data: &mut [u8]) -> bool {
        match self.find(addr) {
            Some((region, offset)) => {
                region.device.lock().unwrap().read(offset, data);
                true
            }
            None => false,
        }
    }

    /// `None` if no registered device covers `addr` at all. `Some(irq)`
    /// (where `irq` is `None` if the write didn't request one, or none is
    /// configured for that region) if some device did handle it. Test-only
    /// — see `read`'s doc comment.
    #[cfg(test)]
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Option<Option<u32>> {
        let (region, offset) = self.find(addr)?;
        let wants_irq = region.device.lock().unwrap().write(offset, data);
        Some(wants_irq.then_some(region.irq).flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dma_range_allows_only_ranges_fully_inside_the_declared_bound() {
        assert!(dma_range_allows(None, 0, u64::MAX), "no declared range means unrestricted");

        let range = Some((0x1000, 0x1000)); // [0x1000, 0x2000)
        assert!(dma_range_allows(range, 0x1000, 0x1000), "exactly the whole range");
        assert!(dma_range_allows(range, 0x1500, 0x100), "a sub-range");
        assert!(!dma_range_allows(range, 0x0f00, 0x100), "starts before the range");
        assert!(!dma_range_allows(range, 0x1f00, 0x200), "ends past the range");
        assert!(!dma_range_allows(range, 0, 0x2000), "spans the whole range and beyond");
        assert!(!dma_range_allows(range, u64::MAX - 15, 32), "an overflowing request");
    }

    struct Dummy;

    impl Device for Dummy {
        fn read(&mut self, _offset: u64, data: &mut [u8]) {
            data.fill(0xa5);
        }
        fn write(&mut self, _offset: u64, _data: &[u8]) -> bool {
            true
        }
    }

    fn dummy() -> SharedDevice {
        Arc::new(Mutex::new(Dummy))
    }

    #[test]
    fn a_region_whose_end_would_overflow_still_dispatches_correctly() {
        // A guest is free to program a BAR near the top of the address
        // space; `base + size` wrapping used to make `contains` reject
        // every address and turn the overlap check into a silent no-op.
        let mut bus = Bus::new();
        bus.register(u64::MAX - 15, 64, dummy(), None);

        let mut data = [0u8; 4];
        assert!(bus.read(u64::MAX - 15, &mut data), "the base address must dispatch");
        assert_eq!(data, [0xa5; 4]);
        assert!(bus.read(u64::MAX, &mut data), "the saturated top address must dispatch");
        assert!(!bus.read(u64::MAX - 16, &mut data), "one below the base must not");
    }

    #[test]
    fn find_device_returns_the_same_handle_offset_and_irq_as_a_direct_dispatch() {
        let mut bus = Bus::new();
        let dev = dummy();
        bus.register(0x2000, 0x100, dev.clone(), Some(7));

        let (found, offset, irq) = bus.find_device(0x2010).expect("must find the registered device");
        assert!(Arc::ptr_eq(&found, &dev), "must be the same underlying device, not a copy");
        assert_eq!(offset, 0x10);
        assert_eq!(irq, Some(7));

        assert!(bus.find_device(0x3000).is_none(), "an unmapped address must find nothing");
    }

    #[test]
    fn re_registering_a_device_moves_its_mapping_instead_of_duplicating_it() {
        let mut bus = Bus::new();
        let dev = dummy();
        bus.register(0x1000, 0x100, dev.clone(), None);
        bus.register(0x2000, 0x100, dev.clone(), None);

        let mut data = [0u8; 1];
        assert!(!bus.read(0x1000, &mut data), "the old mapping must be gone");
        assert!(bus.read(0x2000, &mut data), "the new mapping must be live");
    }

    #[test]
    fn unregister_removes_a_mapping_entirely() {
        let mut bus = Bus::new();
        let dev = dummy();
        bus.register(0x1000, 0x100, dev.clone(), Some(9));
        assert_eq!(bus.write(0x1000, &[1]), Some(Some(9)));

        bus.unregister(&dev);
        assert_eq!(bus.write(0x1000, &[1]), None, "nothing should answer at a reclaimed address");
    }

    #[test]
    fn an_overlapping_registration_is_refused_and_leaves_the_original_working() {
        let mut bus = Bus::new();
        bus.register(0x1000, 0x100, dummy(), None);
        bus.register(0x1080, 0x100, dummy(), None); // overlaps the tail of the first

        let mut data = [0u8; 1];
        assert!(bus.read(0x10ff, &mut data), "the original mapping must survive");
        assert!(!bus.read(0x1100, &mut data), "the refused mapping must not be live");
    }
}
