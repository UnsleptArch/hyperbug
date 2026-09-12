//! Whole-machine save/restore (DEBTS.md item 8): serialize a running
//! guest's vCPU state, memory, and every snapshotted device's protocol
//! state to a file, and reload it later to resume execution from exactly
//! that point.
//!
//! **Deliberately scoped down, not spec-complete** — the same "one real
//! vertical slice beats several partial ones" discipline `--rng-modern`
//! already established for the modern virtio transport:
//! - **Single vCPU only.** `lib.rs` rejects `--restore` combined with
//!   `--smp` > 1 up front. Multi-vCPU needs real thought about AP
//!   `mp_state`/in-flight-SIPI semantics that would double this item's
//!   scope for no immediate benefit.
//! - **No Python device plugin state** (`--device`/`--pci-device`, in-
//!   process or sandboxed) — an arbitrary Python object's state has no
//!   generic serialization here, so `lib.rs` rejects `--restore` combined
//!   with any of them rather than silently produce an incomplete
//!   snapshot.
//! - **Only hyperbug's own virtio devices** (block/net/rng, whichever
//!   transport) plus the serial port and PCI config space are covered.
//!   virtio-blk/-net/-rng currently hold no protocol state beyond what
//!   `VirtioLegacyPci`/`VirtioModernPci` themselves already track (their
//!   backing file/TAP handle are external resources reopened identically
//!   from `Args` on restore, not part of the snapshot) — a future virtio
//!   device with real internal state would need a hook added to
//!   `VirtioDeviceOps` for it; none of the three existing ones need one
//!   today.
//! - **ACPI's `SleepControl`/`ResetControl` hold no state at all** (just
//!   an `ExitSlot` handle) — nothing to snapshot there.
//!
//! **A real, live-guest-verified bug this design started without**: vCPU
//! registers and guest memory alone are not enough. The very first
//! restore attempt resumed a guest to an instant "Oops: overflow" +
//! "Attempted to kill the idle task!" panic the moment a keystroke
//! delivered an interrupt — `KVM_IRQCHIP_PIC_MASTER`'s vector-base
//! (`ICW2`) had never been reprogrammed on the *fresh* VM's fresh
//! in-kernel PIC, because a guest only ever does that once, early in its
//! own boot, and a restored guest resumes long after that already
//! happened — so the fresh PIC's still-zero vector base turned "deliver
//! IRQ4" into "raw vector 4", which is x86's `#OF` (overflow) exception,
//! not an interrupt the guest's IDT was ever going to handle sanely.
//! Fixed by snapshotting KVM's own in-kernel interrupt-controller state
//! too (`KVM_GET_IRQCHIP` ×3 for both PICs and the IOAPIC, `KVM_GET_PIT2`
//! for the PIT, `KVM_GET_LAPIC` per vCPU) alongside `kvm_regs`/
//! `kvm_sregs`/`kvm_mp_state` — all `kvm-ioctls` getters/setters that
//! already existed, just never called anywhere in this codebase before
//! this feature needed them.
//!
//! File format: a fixed header (magic, memory size, vCPU count, then raw
//! bytes of every one of the KVM structs named above — all plain-old-data
//! with no pointers, the same assumption `kvm-ioctls` itself relies on to
//! pass them across the ioctl boundary), a length-prefixed list of
//! device-state blobs (order is deterministic: it's the order
//! `machine.rs` constructs devices in from the same `Args`), then the raw
//! guest memory dump. Hand-rolled rather than pulling in `serde` — same
//! "keep the core small, no dependency for what a few dozen lines cover"
//! convention `control.rs`'s own hex protocol and `acpi.rs`'s table
//! byte-packing already follow.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, Msrs, kvm_irqchip, kvm_lapic_state,
    kvm_mp_state, kvm_msr_entry, kvm_pit_state2, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs, kvm_xsave,
};
use kvm_ioctls::{VcpuFd, VmFd};

use crate::mem::GuestMemory;
use crate::pci::PciBus;
use crate::serial::Serial;

const MAGIC: &[u8; 8] = b"HBSNAP01";

/// MSRs that matter for a real 64-bit Linux guest's syscall/sysret fast
/// path (`STAR`/`LSTAR`/`CSTAR`/`SYSCALL_MASK`, `KERNEL_GS_BASE` — the
/// `swapgs` shadow, distinct from the `FS_BASE`/`GS_BASE` `kvm_sregs`
/// already covers), the legacy `SYSENTER` triple, and `EFER` (also in
/// `sregs`; harmless, cheap to double-cover). Verified against this
/// host's own kernel header (`arch/x86/include/asm/msr-index.h`), not
/// remembered — the same discipline that found the irqchip gap below in
/// the first place. Found necessary the same way: a live restore attempt
/// without these produced real, varying corruption (a kernel stack-guard-
/// page hit, a GPF inside FPU restore) the instant the resumed guest's
/// very first syscall/sysret ran with a fresh vCPU's zeroed
/// `KERNEL_GS_BASE` instead of the guest's real one — `swapgs` then
/// handed the kernel a bogus GS base for every subsequent per-CPU-data
/// access.
const MSR_INDICES: [u32; 9] = [
    0xc000_0080, // EFER
    0xc000_0081, // STAR
    0xc000_0082, // LSTAR
    0xc000_0083, // CSTAR
    0xc000_0084, // SYSCALL_MASK (SFMASK)
    0xc000_0102, // KERNEL_GS_BASE
    0x0000_0174, // IA32_SYSENTER_CS
    0x0000_0175, // IA32_SYSENTER_ESP
    0x0000_0176, // IA32_SYSENTER_EIP
];

fn msrs_to_get() -> Msrs {
    Msrs::from_entries(&MSR_INDICES.map(|index| kvm_msr_entry { index, ..Default::default() }))
        .expect("MSR_INDICES is far under KVM_MAX_MSR_ENTRIES")
}

/// Anything with internal protocol state worth surviving a save/restore
/// round trip — see the module doc comment for exactly what implements
/// this and why nothing else needs to.
pub trait Snapshot: Send {
    fn save_state(&self) -> Vec<u8>;
    fn restore_state(&mut self, data: &[u8]) -> Result<(), String>;
}

// --- Byte-level helpers, shared by every impl in this file and in
// virtio.rs/pci.rs/serial.rs's own `Snapshot`/save-restore code ----------

pub(crate) fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
    if buf.len() < n {
        return Err(format!("snapshot data truncated: needed {n} more bytes, had {}", buf.len()));
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}
pub(crate) fn take_u8(buf: &mut &[u8]) -> Result<u8, String> {
    Ok(take(buf, 1)?[0])
}
pub(crate) fn take_u16(buf: &mut &[u8]) -> Result<u16, String> {
    Ok(u16::from_le_bytes(take(buf, 2)?.try_into().unwrap()))
}
pub(crate) fn take_u32(buf: &mut &[u8]) -> Result<u32, String> {
    Ok(u32::from_le_bytes(take(buf, 4)?.try_into().unwrap()))
}
pub(crate) fn take_u64(buf: &mut &[u8]) -> Result<u64, String> {
    Ok(u64::from_le_bytes(take(buf, 8)?.try_into().unwrap()))
}

/// Reinterprets a plain-old-data KVM struct as raw bytes to write. Not
/// bounded on `Copy` — it only ever reads through a shared reference, so
/// even `kvm_xsave` (which can't derive `Copy`/`Clone` because of its
/// trailing incomplete-array-member field, though that field itself
/// contributes 0 to `size_of`) works here.
///
/// SAFETY: `T` is one of `kvm-bindings`' generated ioctl-argument structs
/// (`kvm_regs`/`kvm_sregs`/`kvm_mp_state`/etc.) — fixed-size integers and
/// arrays only, no pointers, no padding-sensitive invariants beyond what
/// reading it back into a same-layout `T` already preserves. This is the
/// same assumption `kvm-ioctls` itself relies on to hand these structs to
/// the kernel across the ioctl boundary as raw bytes.
fn struct_as_bytes<T>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }
}

/// The inverse of `struct_as_bytes`: reconstructs a `T` from exactly
/// `size_of::<T>()` bytes. See `struct_as_bytes` for the safety argument.
fn struct_from_bytes<T>(buf: &mut &[u8]) -> Result<T, String> {
    let bytes = take(buf, size_of::<T>())?;
    // SAFETY: `zeroed` is valid for `T` (all-zero integers/arrays are a
    // legitimate `kvm_regs`/`kvm_sregs`/`kvm_mp_state` value — KVM itself
    // treats a freshly-`KVM_CREATE_VCPU`'d state as meaningfully close to
    // this), and `bytes.len() == size_of::<T>()` was just guaranteed by
    // `take`.
    unsafe {
        let mut v: T = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), (&mut v as *mut T).cast::<u8>(), size_of::<T>());
        Ok(v)
    }
}

/// Everything `load_from_file` hands back to `lib.rs` to apply — vCPU
/// state and the raw memory dump are ready to use directly; the device
/// blobs are handed to each device's own `restore_state` in the same
/// order `save_to_file` wrote them (disks, then net if present, then
/// rng, then serial, then PCI config space — see `save_to_file`).
pub struct LoadedSnapshot {
    pub mem_size: u64,
    pub num_cpus: u8,
    pub regs: kvm_regs,
    pub sregs: kvm_sregs,
    pub mp_state: kvm_mp_state,
    /// FPU/SSE/AVX (XSAVE) state, its enabled-component control register
    /// (XCR0/`xcrs`), and pending-exception/interrupt/NMI/SMI state
    /// (`vcpu_events`) — found necessary the same way the irqchip state
    /// below was: a live restore attempt without this general-protection-
    /// faulted the instant the guest's own FPU context switch path
    /// (`restore_fpregs_from_fpstate`) ran against a fresh vCPU's
    /// default/uninitialized XSAVE area.
    pub xsave: kvm_xsave,
    pub xcrs: kvm_xcrs,
    pub vcpu_events: kvm_vcpu_events,
    /// `(index, data)` pairs for `MSR_INDICES` — see its own doc comment.
    pub msrs: Vec<(u32, u64)>,
    /// KVM's own in-kernel interrupt-controller state — see the module
    /// doc comment for why a resumed guest needs this restored just as
    /// much as its own registers.
    pub pic_master: kvm_irqchip,
    pub pic_slave: kvm_irqchip,
    pub ioapic: kvm_irqchip,
    pub pit: kvm_pit_state2,
    pub lapic: kvm_lapic_state,
    pub memory: Vec<u8>,
    pub serial_blob: Vec<u8>,
    pub pci_blob: Vec<u8>,
    pub virtio_blobs: Vec<Vec<u8>>,
}

/// Serializes the whole machine to `path`. Called from the control
/// socket's `snapshot <path>` command (`control.rs`), on the vCPU's own
/// thread — the same "only touched from the vCPU's own thread" rule the
/// existing `regs`/`write_regs` commands already follow, since reading
/// `vcpu`'s registers is only safe there.
pub fn save_to_file(
    path: &str,
    vm: &VmFd,
    mem: &Arc<Mutex<GuestMemory>>,
    vcpu: &VcpuFd,
    serial: &Serial,
    pci_bus: &PciBus,
    virtio: &[Arc<Mutex<dyn Snapshot>>],
) -> Result<(), String> {
    let regs = vcpu.get_regs().map_err(|e| format!("KVM_GET_REGS: {e}"))?;
    let sregs = vcpu.get_sregs().map_err(|e| format!("KVM_GET_SREGS: {e}"))?;
    let mp_state = vcpu.get_mp_state().map_err(|e| format!("KVM_GET_MP_STATE: {e}"))?;
    let xsave = vcpu.get_xsave().map_err(|e| format!("KVM_GET_XSAVE: {e}"))?;
    let xcrs = vcpu.get_xcrs().map_err(|e| format!("KVM_GET_XCRS: {e}"))?;
    let vcpu_events = vcpu.get_vcpu_events().map_err(|e| format!("KVM_GET_VCPU_EVENTS: {e}"))?;
    let lapic = vcpu.get_lapic().map_err(|e| format!("KVM_GET_LAPIC: {e}"))?;
    let mut msrs = msrs_to_get();
    vcpu.get_msrs(&mut msrs).map_err(|e| format!("KVM_GET_MSRS: {e}"))?;

    let mut pic_master = kvm_irqchip { chip_id: KVM_IRQCHIP_PIC_MASTER, ..Default::default() };
    vm.get_irqchip(&mut pic_master).map_err(|e| format!("KVM_GET_IRQCHIP (PIC master): {e}"))?;
    let mut pic_slave = kvm_irqchip { chip_id: KVM_IRQCHIP_PIC_SLAVE, ..Default::default() };
    vm.get_irqchip(&mut pic_slave).map_err(|e| format!("KVM_GET_IRQCHIP (PIC slave): {e}"))?;
    let mut ioapic = kvm_irqchip { chip_id: KVM_IRQCHIP_IOAPIC, ..Default::default() };
    vm.get_irqchip(&mut ioapic).map_err(|e| format!("KVM_GET_IRQCHIP (IOAPIC): {e}"))?;
    let pit = vm.get_pit2().map_err(|e| format!("KVM_GET_PIT2: {e}"))?;

    let mem = mem.lock().unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(mem.size() as u64).to_le_bytes());
    out.push(1); // num_cpus — always 1 today, see the module doc comment
    out.extend_from_slice(struct_as_bytes(&regs));
    out.extend_from_slice(struct_as_bytes(&sregs));
    out.extend_from_slice(struct_as_bytes(&mp_state));
    out.extend_from_slice(struct_as_bytes(&xsave));
    out.extend_from_slice(struct_as_bytes(&xcrs));
    out.extend_from_slice(struct_as_bytes(&vcpu_events));
    out.extend_from_slice(&(msrs.as_slice().len() as u32).to_le_bytes());
    for entry in msrs.as_slice() {
        out.extend_from_slice(&entry.index.to_le_bytes());
        out.extend_from_slice(&entry.data.to_le_bytes());
    }
    out.extend_from_slice(struct_as_bytes(&pic_master));
    out.extend_from_slice(struct_as_bytes(&pic_slave));
    out.extend_from_slice(struct_as_bytes(&ioapic));
    out.extend_from_slice(struct_as_bytes(&pit));
    out.extend_from_slice(struct_as_bytes(&lapic));

    let mut blobs = Vec::with_capacity(virtio.len() + 2);
    for dev in virtio {
        blobs.push(dev.lock().unwrap().save_state());
    }
    blobs.push(serial.save_state());
    blobs.push(pci_bus.save_state());

    out.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
    for blob in &blobs {
        out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        out.extend_from_slice(blob);
    }

    // The raw memory dump comes last, and last-written: it's the biggest
    // part of the file by far, and reading it back is a single bulk copy
    // rather than something that needs framing at all.
    let mem_start = out.len();
    out.resize(mem_start + mem.size(), 0);
    assert!(mem.read_checked(0, &mut out[mem_start..]), "guest memory's own size must contain itself");

    std::fs::File::create(path)
        .and_then(|mut f| f.write_all(&out))
        .map_err(|e| format!("writing snapshot to {path}: {e}"))
}

/// Reads and validates a snapshot file's structure, without yet applying
/// any of it — `lib.rs` decides how to use `LoadedSnapshot` against the
/// *current* launch's `Args` (memory size must match, exactly one virtio
/// device blob per device `machine.rs` is about to construct, etc.).
pub fn load_from_file(path: &str) -> Result<LoadedSnapshot, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("opening snapshot {path}: {e}"))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| format!("reading snapshot {path}: {e}"))?;
    let mut buf = data.as_slice();

    let magic = take(&mut buf, MAGIC.len())?;
    if magic != MAGIC {
        return Err(format!("{path} is not a hyperbug snapshot (bad magic)"));
    }
    let mem_size = take_u64(&mut buf)?;
    let num_cpus = take_u8(&mut buf)?;
    let regs = struct_from_bytes(&mut buf)?;
    let sregs = struct_from_bytes(&mut buf)?;
    let mp_state = struct_from_bytes(&mut buf)?;
    let xsave = struct_from_bytes(&mut buf)?;
    let xcrs = struct_from_bytes(&mut buf)?;
    let vcpu_events = struct_from_bytes(&mut buf)?;
    let msr_count = take_u32(&mut buf)?;
    let mut msrs = Vec::with_capacity(msr_count as usize);
    for _ in 0..msr_count {
        let index = take_u32(&mut buf)?;
        let data = take_u64(&mut buf)?;
        msrs.push((index, data));
    }
    let pic_master = struct_from_bytes(&mut buf)?;
    let pic_slave = struct_from_bytes(&mut buf)?;
    let ioapic = struct_from_bytes(&mut buf)?;
    let pit = struct_from_bytes(&mut buf)?;
    let lapic = struct_from_bytes(&mut buf)?;

    let blob_count = take_u32(&mut buf)?;
    let mut blobs = Vec::with_capacity(blob_count as usize);
    for _ in 0..blob_count {
        let len = take_u32(&mut buf)? as usize;
        blobs.push(take(&mut buf, len)?.to_vec());
    }
    // The last two blobs written are always serial then PCI (see
    // `save_to_file`); everything before them is the virtio device list,
    // in construction order.
    let pci_blob = blobs.pop().ok_or("snapshot has no PCI config-space blob")?;
    let serial_blob = blobs.pop().ok_or("snapshot has no serial-state blob")?;
    let virtio_blobs = blobs;

    if buf.len() as u64 != mem_size {
        return Err(format!(
            "snapshot's memory dump is {} bytes, but its own header says {mem_size} bytes",
            buf.len()
        ));
    }
    let memory = buf.to_vec();

    Ok(LoadedSnapshot {
        mem_size,
        num_cpus,
        regs,
        sregs,
        mp_state,
        xsave,
        xcrs,
        vcpu_events,
        msrs,
        pic_master,
        pic_slave,
        ioapic,
        pit,
        lapic,
        memory,
        serial_blob,
        pci_blob,
        virtio_blobs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::PciBus;
    use crate::serial::Serial;

    #[test]
    fn file_round_trip_preserves_header_and_device_blobs() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        mem.lock().unwrap().write_checked(0, b"hello snapshot");

        let mut serial = Serial::new();
        serial.push_rx_byte(b'x');
        let pci_bus = PciBus::new();

        let dir = std::env::temp_dir().join(format!("hyperbug-snapshot-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snap.bin");

        // `save_to_file` normally reads real vCPU registers via `VcpuFd`,
        // which needs `/dev/kvm` — not available to every environment
        // this test runs in, so this test drives the file format directly
        // via hand-built header bytes instead, the same way `pci.rs`'s own
        // tests avoid needing a live VM. What's genuinely under test here
        // is `load_from_file`'s parsing, not vCPU-register plumbing (which
        // is a one-line pass-through covered by the real boot test).
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.extend_from_slice(&4096u64.to_le_bytes());
        data.push(1);
        data.extend_from_slice(&[0u8; size_of::<kvm_regs>()]);
        data.extend_from_slice(&[0u8; size_of::<kvm_sregs>()]);
        data.extend_from_slice(&[0u8; size_of::<kvm_mp_state>()]);
        data.extend_from_slice(&[0u8; size_of::<kvm_xsave>()]);
        data.extend_from_slice(&[0u8; size_of::<kvm_xcrs>()]);
        data.extend_from_slice(&[0u8; size_of::<kvm_vcpu_events>()]);
        data.extend_from_slice(&0u32.to_le_bytes()); // no MSR entries
        data.extend_from_slice(&[0u8; size_of::<kvm_irqchip>()]); // PIC master
        data.extend_from_slice(&[0u8; size_of::<kvm_irqchip>()]); // PIC slave
        data.extend_from_slice(&[0u8; size_of::<kvm_irqchip>()]); // IOAPIC
        data.extend_from_slice(&[0u8; size_of::<kvm_pit_state2>()]);
        data.extend_from_slice(&[0u8; size_of::<kvm_lapic_state>()]);
        let blobs = [serial.save_state(), pci_bus.save_state()];
        data.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
        for blob in &blobs {
            data.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            data.extend_from_slice(blob);
        }
        let mut mem_dump = vec![0u8; 4096];
        assert!(mem.lock().unwrap().read_checked(0, &mut mem_dump));
        data.extend_from_slice(&mem_dump);
        std::fs::write(&path, &data).unwrap();

        let loaded = load_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.mem_size, 4096);
        assert_eq!(loaded.num_cpus, 1);
        assert_eq!(&loaded.memory[..14], b"hello snapshot");
        assert!(loaded.virtio_blobs.is_empty());

        let mut restored_serial = Serial::new();
        restored_serial.restore_state(&loaded.serial_blob).unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_truncated_file_is_a_clean_error_not_a_panic() {
        let dir = std::env::temp_dir().join(format!("hyperbug-snapshot-trunc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trunc.bin");
        std::fs::write(&path, MAGIC).unwrap(); // magic only, nothing else
        assert!(load_from_file(path.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let dir = std::env::temp_dir().join(format!("hyperbug-snapshot-magic-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.bin");
        std::fs::write(&path, b"NOTASNAP").unwrap();
        assert!(load_from_file(path.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
