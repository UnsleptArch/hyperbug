//! Whole-machine save/restore: serialize a running
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

use crate::config::Args;
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

/// Rejects an operation that needs to serialize live machine state as
/// `CapturedState` (`fork.rs`'s `fork <path>`, `migrate.rs`'s
/// `migrate <host:port>`) if this launch's configuration includes
/// anything that has no representation there — the same scope limits
/// file-based `--restore` states in its own `lib.rs::validate_restore`
/// (single-vCPU only, no device plugin state), extended to also name the
/// runtime-only restrictions (`--record`/`--replay`/`--gdb-stub`/
/// `--trace-file`) that only apply to a *live* capture, not a file someone
/// already made with `--restore` in mind. Shared by both callers so they
/// can't quietly drift apart on what each considers capturable.
/// `feature` names the caller (`"fork"` or `"migrate"`) in the resulting
/// error message.
pub fn validate_capturable(args: &Args, feature: &str) -> Result<(), String> {
    if args.smp != 1 {
        return Err(format!("{feature} only supports --smp 1 today"));
    }
    if !args.devices.is_empty()
        || !args.pci_devices.is_empty()
        || !args.sandboxed_devices.is_empty()
        || !args.sandboxed_pci_devices.is_empty()
        || !args.native_devices.is_empty()
        || !args.native_pci_devices.is_empty()
        || !args.wasm_devices.is_empty()
        || !args.wasm_pci_devices.is_empty()
        || !args.i2c_devices.is_empty()
        || !args.gpio_devices.is_empty()
        || args.vsock_uds.is_some()
    {
        return Err(format!(
            "{feature} doesn't support device plugins yet (their internal state doesn't survive it safely)"
        ));
    }
    if args.record.is_some() || args.replay.is_some() {
        return Err(format!("{feature} doesn't support --record/--replay yet"));
    }
    if args.gdb_stub.is_some() {
        return Err(format!("{feature} doesn't support --gdb-stub yet"));
    }
    if args.trace_file.is_some() {
        return Err(format!("{feature} doesn't support --trace-file yet"));
    }
    Ok(())
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

/// Reads exactly `n` bytes from `r`, or a clean error on early EOF —
/// shared by `read_from` (a `File` or a live `TcpStream`, for migration)
/// and its own small `read_u*`/`struct_from_reader` helpers below.
/// Reading from a generic `Read` instead of a pre-loaded `&[u8]` (the
/// pre-migration design) is what let `read_from` serve both a file and a
/// live network connection unchanged — a `TcpStream` has no fixed length
/// to read into a buffer up front the way a file does.
fn read_exact_vec(r: &mut impl Read, n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).map_err(|e| format!("snapshot stream ended early: {e}"))?;
    Ok(buf)
}
fn read_u8(r: &mut impl Read) -> Result<u8, String> {
    Ok(read_exact_vec(r, 1)?[0])
}
fn read_u32(r: &mut impl Read) -> Result<u32, String> {
    Ok(u32::from_le_bytes(read_exact_vec(r, 4)?.try_into().unwrap()))
}
fn read_u64(r: &mut impl Read) -> Result<u64, String> {
    Ok(u64::from_le_bytes(read_exact_vec(r, 8)?.try_into().unwrap()))
}

/// The inverse of `struct_as_bytes`: reconstructs a `T` from exactly
/// `size_of::<T>()` bytes read off `r`. See `struct_as_bytes` for the
/// safety argument.
fn struct_from_reader<T>(r: &mut impl Read) -> Result<T, String> {
    let bytes = read_exact_vec(r, size_of::<T>())?;
    // SAFETY: `zeroed` is valid for `T` (all-zero integers/arrays are a
    // legitimate `kvm_regs`/`kvm_sregs`/`kvm_mp_state` value — KVM itself
    // treats a freshly-`KVM_CREATE_VCPU`'d state as meaningfully close to
    // this), and `bytes.len() == size_of::<T>()` was just guaranteed by
    // `read_exact_vec`.
    unsafe {
        let mut v: T = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), (&mut v as *mut T).cast::<u8>(), size_of::<T>());
        Ok(v)
    }
}

/// Every piece of live machine state a fresh KVM VM needs applied to
/// resume exactly where a running guest left off — **except guest memory
/// itself**, which is handled differently by this struct's two callers:
/// `save_to_file`/`load_from_file` copy it into/out of a file; `fork.rs`
/// doesn't copy it at all, relying on a real `fork()`'s copy-on-write
/// semantics to hand the child the identical mapping for free. Sharing
/// this struct (rather than each caller capturing/applying these fields
/// independently) is what lets `lib.rs`'s `restore_vcpu`/
/// `restore_device_state` serve both the file-based restore path and the
/// fork path unchanged.
pub struct CapturedState {
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
    pub serial_blob: Vec<u8>,
    pub pci_blob: Vec<u8>,
    pub virtio_blobs: Vec<Vec<u8>>,
}

/// Reads every piece of `CapturedState` off a *live* vCPU/VM — the shared
/// core of both `save_to_file` (which adds a memory dump and writes it
/// all to a file) and `fork.rs` (which uses this directly, no file, no
/// memory copy: the child inherits guest memory via `fork()`'s own
/// copy-on-write semantics instead). Called on the vCPU's own thread —
/// the same "only touched from the vCPU's own thread" rule the control
/// socket's existing `regs`/`write_regs` commands already follow, since
/// reading `vcpu`'s registers is only safe there.
pub fn capture_live_state(
    vm: &VmFd,
    vcpu: &VcpuFd,
    serial: &Serial,
    pci_bus: &PciBus,
    virtio: &[Arc<Mutex<dyn Snapshot>>],
) -> Result<CapturedState, String> {
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

    let msrs = msrs.as_slice().iter().map(|e| (e.index, e.data)).collect();

    let mut blobs = Vec::with_capacity(virtio.len() + 2);
    for dev in virtio {
        blobs.push(dev.lock().unwrap().save_state());
    }
    blobs.push(serial.save_state());
    blobs.push(pci_bus.save_state());
    let pci_blob = blobs.pop().unwrap();
    let serial_blob = blobs.pop().unwrap();
    let virtio_blobs = blobs;

    Ok(CapturedState {
        num_cpus: 1, // always 1 today, see the module doc comment
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
        serial_blob,
        pci_blob,
        virtio_blobs,
    })
}

/// Everything `load_from_file` hands back to `lib.rs` to apply.
pub struct LoadedSnapshot {
    pub mem_size: u64,
    pub captured: CapturedState,
    pub memory: Vec<u8>,
}

/// Writes the whole machine's serialized form to `w` — a `File` for
/// `save_to_file`, or (for live migration) a `TcpStream` connected to a
/// waiting destination process, with no format difference between the
/// two: the byte layout is entirely self-delimiting (every variable-
/// length section carries its own count/length, and the fixed header
/// states the memory dump's exact size), so a destination reading from
/// either a file or a live socket parses it identically via `read_from`.
pub fn write_to(w: &mut impl Write, captured: &CapturedState, mem: &GuestMemory) -> Result<(), String> {
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&(mem.size() as u64).to_le_bytes());
    header.push(captured.num_cpus);
    header.extend_from_slice(struct_as_bytes(&captured.regs));
    header.extend_from_slice(struct_as_bytes(&captured.sregs));
    header.extend_from_slice(struct_as_bytes(&captured.mp_state));
    header.extend_from_slice(struct_as_bytes(&captured.xsave));
    header.extend_from_slice(struct_as_bytes(&captured.xcrs));
    header.extend_from_slice(struct_as_bytes(&captured.vcpu_events));
    header.extend_from_slice(&(captured.msrs.len() as u32).to_le_bytes());
    for &(index, data) in &captured.msrs {
        header.extend_from_slice(&index.to_le_bytes());
        header.extend_from_slice(&data.to_le_bytes());
    }
    header.extend_from_slice(struct_as_bytes(&captured.pic_master));
    header.extend_from_slice(struct_as_bytes(&captured.pic_slave));
    header.extend_from_slice(struct_as_bytes(&captured.ioapic));
    header.extend_from_slice(struct_as_bytes(&captured.pit));
    header.extend_from_slice(struct_as_bytes(&captured.lapic));

    let blobs: Vec<&Vec<u8>> =
        captured.virtio_blobs.iter().chain([&captured.serial_blob, &captured.pci_blob]).collect();
    header.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
    for blob in &blobs {
        header.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        header.extend_from_slice(blob);
    }
    w.write_all(&header).map_err(|e| format!("writing snapshot header: {e}"))?;

    // The raw memory dump is written last and streamed straight from the
    // live mapping (`as_slice`) rather than copied into another buffer
    // first — the biggest part of the transfer by far, so avoiding a
    // second full-guest-RAM copy matters more here than it did when this
    // only ever wrote to a file.
    w.write_all(mem.as_slice()).map_err(|e| format!("writing snapshot memory: {e}"))
}

/// Serializes the whole machine to `path`. Called from the control
/// socket's `snapshot <path>` command (`control.rs`), on the vCPU's own
/// thread — see `capture_live_state`'s own doc comment for why.
pub fn save_to_file(
    path: &str,
    vm: &VmFd,
    mem: &Arc<Mutex<GuestMemory>>,
    vcpu: &VcpuFd,
    serial: &Serial,
    pci_bus: &PciBus,
    virtio: &[Arc<Mutex<dyn Snapshot>>],
) -> Result<(), String> {
    let captured = capture_live_state(vm, vcpu, serial, pci_bus, virtio)?;
    let mem = mem.lock().unwrap();
    let mut file = std::fs::File::create(path).map_err(|e| format!("creating snapshot {path}: {e}"))?;
    write_to(&mut file, &captured, &mem).map_err(|e| format!("writing snapshot to {path}: {e}"))
}

/// Reads and validates a serialized machine's structure off `r`, without
/// yet applying any of it — `lib.rs` decides how to use `LoadedSnapshot`
/// against the *current* launch's `Args` (memory size must match, exactly
/// one virtio device blob per device `machine.rs` is about to construct,
/// etc.). Works identically for a `File` (`load_from_file`) or a live
/// `TcpStream` (migration's destination side, `migrate.rs`) — nothing
/// here needs to know the transport's total length up front, since every
/// section is read exactly as many bytes as its own header/count says.
pub fn read_from(r: &mut impl Read) -> Result<LoadedSnapshot, String> {
    let magic = read_exact_vec(r, MAGIC.len())?;
    if magic != MAGIC {
        return Err("not a hyperbug snapshot (bad magic)".to_string());
    }
    let mem_size = read_u64(r)?;
    let num_cpus = read_u8(r)?;
    let regs = struct_from_reader(r)?;
    let sregs = struct_from_reader(r)?;
    let mp_state = struct_from_reader(r)?;
    let xsave = struct_from_reader(r)?;
    let xcrs = struct_from_reader(r)?;
    let vcpu_events = struct_from_reader(r)?;
    let msr_count = read_u32(r)?;
    let mut msrs = Vec::with_capacity(msr_count as usize);
    for _ in 0..msr_count {
        let index = read_u32(r)?;
        let data = read_u64(r)?;
        msrs.push((index, data));
    }
    let pic_master = struct_from_reader(r)?;
    let pic_slave = struct_from_reader(r)?;
    let ioapic = struct_from_reader(r)?;
    let pit = struct_from_reader(r)?;
    let lapic = struct_from_reader(r)?;

    let blob_count = read_u32(r)?;
    let mut blobs = Vec::with_capacity(blob_count as usize);
    for _ in 0..blob_count {
        let len = read_u32(r)? as usize;
        blobs.push(read_exact_vec(r, len)?);
    }
    // The last two blobs written are always serial then PCI (see
    // `write_to`); everything before them is the virtio device list, in
    // construction order.
    let pci_blob = blobs.pop().ok_or("snapshot has no PCI config-space blob")?;
    let serial_blob = blobs.pop().ok_or("snapshot has no serial-state blob")?;
    let virtio_blobs = blobs;

    let memory = read_exact_vec(r, mem_size as usize)?;

    Ok(LoadedSnapshot {
        mem_size,
        captured: CapturedState {
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
            serial_blob,
            pci_blob,
            virtio_blobs,
        },
        memory,
    })
}

/// Reads and validates a snapshot file specifically — see `read_from` for
/// the actual parsing, which is transport-agnostic.
pub fn load_from_file(path: &str) -> Result<LoadedSnapshot, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("opening snapshot {path}: {e}"))?;
    read_from(&mut file).map_err(|e| format!("reading snapshot {path}: {e}"))
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
        assert_eq!(loaded.captured.num_cpus, 1);
        assert_eq!(&loaded.memory[..14], b"hello snapshot");
        assert!(loaded.captured.virtio_blobs.is_empty());

        let mut restored_serial = Serial::new();
        restored_serial.restore_state(&loaded.captured.serial_blob).unwrap();

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
