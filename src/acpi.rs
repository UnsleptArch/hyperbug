//! Minimal ACPI tables: RSDP, RSDT/XSDT, FADT, MADT, and a tiny compiled
//! DSDT (just enough for a `\_S5` shutdown package). All field layouts are
//! taken directly from this host's own ACPICA kernel headers
//! (`/usr/lib/modules/*/build/include/acpi/{actbl,actbl1,actbl2,actypes}.h`,
//! all `#pragma pack(1)`), not from memory — ACPI table layout has enough
//! historical revision-to-revision quirks that "roughly remembered" isn't
//! good enough here.
//!
//! Deliberately uses the ACPI 5.0+ "hardware-reduced" model (FADT
//! `HW_REDUCED` flag, all legacy PM1x/GPE blocks zeroed): hyperbug doesn't
//! implement any real fixed ACPI hardware, so pretending to have some (and
//! leaving it non-functional) is worse than honestly declaring none.
//! Shutdown goes through the modern `SLEEP_CONTROL_REG`/`SLEEP_STATUS_REG`
//! (a plain 2-byte I/O port device, see `SleepControl` below) rather than
//! the legacy PM1a_CNT register. The one thing hardware-reduced mode does
//! *not* remove is needing `\_S5` from AML — that value is still evaluated
//! from the ACPI namespace regardless of which register receives it — so
//! `dsdt.aml` (compiled from `acpi/dsdt.asl` via the real `iasl` compiler,
//! not hand-encoded) exists solely to provide that one object.

use crate::device::Device;
use crate::error::{ExitSlot, GuestExit, HyperbugError, request_exit};
use crate::mem::GuestMemory;

// Real, fixed x86 physical addresses for KVM's default in-kernel local APIC
// and I/O APIC — not something we choose, so not configurable.
// `KVM_CREATE_IRQCHIP` always creates both, and KVM's default GSI routing
// (installed at VM creation, with no `KVM_SET_GSI_ROUTING` call needed —
// checked, hyperbug never makes one) already identity-maps GSIs 0-23 to
// both the PIC and these I/O APIC pins simultaneously. See `build_madt`
// for why the guest needs to be *told* the I/O APIC exists at all.
const LAPIC_ADDR: u32 = 0xfee0_0000;
const IOAPIC_ADDR: u32 = 0xfec0_0000;

/// ACPI tables live in `[0xE0000, 0xFFFFF]` — the range the spec requires
/// every OS to scan unconditionally for the RSDP signature, so nothing has
/// to set up a BDA/EBDA pointer to make them discoverable. That range also
/// isn't covered by either e820 entry `loader.rs` emits, matching real
/// hardware's BIOS ROM/reserved area rather than being an oversight.
const ACPI_BASE: u64 = 0xe0000;
const ACPI_LIMIT: u64 = 0x10_0000; // 1 MiB: where the kernel image starts
/// The RSDP is the one table at a *fixed* address (it's found by scanning
/// for its signature, so it has to be where the scan starts and 16-byte
/// aligned). Everything else is packed after it by `TableWriter`.
const RSDP_ADDR: u64 = ACPI_BASE;
const RSDP_LEN: u64 = 36;
/// The ACPI spec's own alignment requirement for table starts.
const TABLE_ALIGN: u64 = 16;

pub const SLEEP_CONTROL_PORT: u16 = 0x600;
// Bit 5 of the ACPI hardware-reduced Sleep Control Register, per the real
// ACPICA headers (ACPI_X_SLEEP_ENABLE in actbl.h) — not bit 13 (legacy
// PM1a_CNT's SLP_EN) and not bit 4, which this was wrongly set to before a
// real boot caught it (the guest's S5 write never matched, so shutdown
// hung forever after "Preparing to enter system sleep state S5").
const SLP_EN: u8 = 1 << 5;

// A dedicated reset port, distinct from sleep control: `reboot=k`'s
// fallback path and a kernel panic's `panic=1` auto-reboot both trigger a
// deliberate triple fault with no way to tell them apart, or apart from a
// genuine crash, from VcpuExit::Shutdown alone. A *requested* reboot
// through this ACPI-advertised register takes a distinguishable path
// instead — see main.rs's exit codes.
pub const RESET_PORT: u16 = 0x604;
const RESET_VALUE: u8 = 0x01;

static DSDT_AML: &[u8] = include_bytes!("dsdt.aml");

fn checksum(bytes: &[u8]) -> u8 {
    0u8.wrapping_sub(bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)))
}

/// Common 36-byte ACPI SDT header, per `struct acpi_table_header`. The
/// length and checksum fields are placeholders here; `finish` fills both
/// in once the caller has appended the table's body.
fn sdt_header(signature: &[u8; 4], revision: u8, oem_table_id: &[u8; 8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(36);
    h.extend_from_slice(signature);
    h.extend_from_slice(&0u32.to_le_bytes()); // length placeholder
    h.push(revision);
    h.push(0); // checksum placeholder
    h.extend_from_slice(b"HYPRBG"); // oem_id[6]
    h.extend_from_slice(oem_table_id); // oem_table_id[8]
    h.extend_from_slice(&1u32.to_le_bytes()); // oem_revision
    h.extend_from_slice(b"HYBG"); // asl_compiler_id[4]
    h.extend_from_slice(&1u32.to_le_bytes()); // asl_compiler_revision
    h
}

/// Completes an SDT: patches in the real length (offset 4) now that the
/// table is fully assembled, then the checksum byte (offset 9) so the
/// whole thing sums to zero. Every `build_*` below ended with the same
/// three lines before this existed, and forgetting either half produces a
/// table an OS silently ignores.
fn finish(mut table: Vec<u8>) -> Vec<u8> {
    let len = table.len() as u32;
    table[4..8].copy_from_slice(&len.to_le_bytes());
    table[9] = 0;
    table[9] = checksum(&table);
    table
}

fn build_madt(num_cpus: u8) -> Vec<u8> {
    let mut t = sdt_header(b"APIC", 3, b"HBMADT\0\0");
    t.extend_from_slice(&LAPIC_ADDR.to_le_bytes());
    t.extend_from_slice(&1u32.to_le_bytes()); // flags: PCAT_COMPAT (dual 8259s present)

    // struct acpi_madt_local_apic: subtable header(type=0,len=8) +
    // processor_id + id + lapic_flags(u32, bit0=enabled) — one per vCPU,
    // id matching exactly what KVM assigns that vCPU (its creation index)
    // and what cpuid.rs reports back via CPUID.01H:EBX bits 31:24, so the
    // guest's own self-identification during SMP bring-up lines up with
    // what this table says exists.
    for cpu in 0..num_cpus {
        t.extend_from_slice(&[0, 8, cpu, cpu]);
        t.extend_from_slice(&1u32.to_le_bytes());
    }

    // struct acpi_madt_io_apic (type=1, len=12): id, reserved, address,
    // global_irq_base. This table used to omit this subtable entirely
    // (DEBTS.md item 29/33's history), on the theory that keeping the
    // guest ignorant of any I/O APIC would keep Linux on the legacy 8259
    // PIC for every interrupt. Real evidence (a kprobe on
    // `request_threaded_irq`, see DEBTS.md item 33) showed that theory was
    // wrong: once ACPI enables Local APIC mode (which happens the moment
    // *any* Local APIC entries exist above, regardless of PCAT_COMPAT),
    // Linux abandons the 8259 entirely — `/proc/interrupts` under ACPI
    // showed no PIC lines *and* no I/O APIC lines at all, i.e. ISA IRQ4
    // had no interrupt controller claiming it, which is exactly why
    // `request_threaded_irq(4, ...)` returned `-EINVAL`: the IRQ had no
    // valid chip to attach a handler to. The fix is to actually describe
    // the I/O APIC KVM already provides (`KVM_CREATE_IRQCHIP` always
    // creates one, and KVM's default GSI routing already identity-maps
    // every GSI here to it with no extra setup needed), not to keep hiding
    // it.
    t.extend_from_slice(&[1, 12]); // subtable header: type=1 (I/O APIC), length=12
    t.push(0); // id
    t.push(0); // reserved
    t.extend_from_slice(&IOAPIC_ADDR.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes()); // global_irq_base: GSI 0 starts at this I/O APIC's pin 0

    finish(t)
}

/// A zeroed 12-byte Generic Address Structure: the spec's own convention
/// for "this register block doesn't exist."
fn zero_gas() -> [u8; 12] {
    [0; 12]
}

fn system_io_gas(port: u16) -> [u8; 12] {
    let mut g = [0u8; 12];
    g[0] = 1; // space_id: SystemIO
    g[1] = 8; // bit_width
    g[2] = 0; // bit_offset
    g[3] = 1; // access_width: byte
    g[4..12].copy_from_slice(&u64::from(port).to_le_bytes());
    g
}

fn build_fadt(dsdt_addr: u32) -> Vec<u8> {
    let mut t = sdt_header(b"FACP", 6, b"HBFADT\0\0");
    t.extend_from_slice(&0u32.to_le_bytes()); // facs: none (hardware-reduced, no S3/waking vector)
    t.extend_from_slice(&dsdt_addr.to_le_bytes()); // dsdt
    t.push(0); // model (obsolete, superseded by MADT)
    t.push(0); // preferred_profile: unspecified
    // sci_interrupt: 0, honestly — hardware-reduced mode means no GPE
    // blocks exist to ever generate a real SCI event, so there's nothing
    // to assign a plausible-but-fake IRQ number to.
    t.extend_from_slice(&0u16.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes()); // smi_command: 0 = always in ACPI mode, no SMI enable/disable needed
    t.push(0); // acpi_enable
    t.push(0); // acpi_disable
    t.push(0); // s4_bios_request
    t.push(0); // pstate_control
    t.extend_from_slice(&0u32.to_le_bytes()); // pm1a_event_block: none (hardware-reduced)
    t.extend_from_slice(&0u32.to_le_bytes()); // pm1b_event_block
    t.extend_from_slice(&0u32.to_le_bytes()); // pm1a_control_block
    t.extend_from_slice(&0u32.to_le_bytes()); // pm1b_control_block
    t.extend_from_slice(&0u32.to_le_bytes()); // pm2_control_block
    t.extend_from_slice(&0u32.to_le_bytes()); // pm_timer_block
    t.extend_from_slice(&0u32.to_le_bytes()); // gpe0_block
    t.extend_from_slice(&0u32.to_le_bytes()); // gpe1_block
    t.push(0); // pm1_event_length
    t.push(0); // pm1_control_length
    t.push(0); // pm2_control_length
    t.push(0); // pm_timer_length
    t.push(0); // gpe0_block_length
    t.push(0); // gpe1_block_length
    t.push(0); // gpe1_base
    t.push(0); // cst_control
    t.extend_from_slice(&0xffffu16.to_le_bytes()); // c2_latency: not supported
    t.extend_from_slice(&0xffffu16.to_le_bytes()); // c3_latency: not supported
    t.extend_from_slice(&0u16.to_le_bytes()); // flush_size (obsolete)
    t.extend_from_slice(&0u16.to_le_bytes()); // flush_stride (obsolete)
    t.push(0); // duty_offset
    t.push(0); // duty_width
    t.push(0); // day_alarm
    t.push(0); // month_alarm
    t.push(0); // century
    // boot_flags: NO_VGA | NO_MSI. Deliberately *not* setting the 8042
    // flag, so Linux skips probing a controller that isn't there instead
    // of printing the "Can't read CTR" error it currently does without
    // any ACPI info to tell it otherwise.
    t.extend_from_slice(&0x000cu16.to_le_bytes());
    t.push(0); // reserved
    // flags: WBINVD (bit0, correctly implemented — real on any real CPU)
    // | HW_REDUCED (bit20) | RESET_REGISTER (bit10 — see reset_register
    // below: a real reset path lets a *requested* reboot be told apart
    // from a genuine triple-fault crash, which reboot=k's fallback
    // mechanism alone can't do — see RESET_VALUE's doc comment).
    t.extend_from_slice(&0x0010_0401u32.to_le_bytes());
    t.extend_from_slice(&system_io_gas(RESET_PORT)); // reset_register
    t.push(RESET_VALUE);
    t.extend_from_slice(&0u16.to_le_bytes()); // arm_boot_flags (x86 only, unused)
    t.push(0); // minor_revision
    t.extend_from_slice(&0u64.to_le_bytes()); // Xfacs: none
    t.extend_from_slice(&u64::from(dsdt_addr).to_le_bytes()); // Xdsdt
    t.extend_from_slice(&zero_gas()); // xpm1a_event_block
    t.extend_from_slice(&zero_gas()); // xpm1b_event_block
    t.extend_from_slice(&zero_gas()); // xpm1a_control_block
    t.extend_from_slice(&zero_gas()); // xpm1b_control_block
    t.extend_from_slice(&zero_gas()); // xpm2_control_block
    t.extend_from_slice(&zero_gas()); // xpm_timer_block
    t.extend_from_slice(&zero_gas()); // xgpe0_block
    t.extend_from_slice(&zero_gas()); // xgpe1_block
    t.extend_from_slice(&system_io_gas(SLEEP_CONTROL_PORT)); // sleep_control
    t.extend_from_slice(&system_io_gas(SLEEP_CONTROL_PORT + 1)); // sleep_status
    t.extend_from_slice(&0u64.to_le_bytes()); // hypervisor_id: none — not claiming to be a real hypervisor

    finish(t)
}

fn build_xsdt(entries: &[u64]) -> Vec<u8> {
    let mut t = sdt_header(b"XSDT", 1, b"HBXSDT\0\0");
    for e in entries {
        t.extend_from_slice(&e.to_le_bytes());
    }
    finish(t)
}

fn build_rsdt(entries: &[u32]) -> Vec<u8> {
    let mut t = sdt_header(b"RSDT", 1, b"HBRSDT\0\0");
    for e in entries {
        t.extend_from_slice(&e.to_le_bytes());
    }
    finish(t)
}

/// The ACPI 2.0+ RSDP, per `struct acpi_table_rsdp` (36 bytes).
fn build_rsdp(rsdt_addr: u32, xsdt_addr: u64) -> Vec<u8> {
    let mut r = Vec::with_capacity(36);
    r.extend_from_slice(b"RSD PTR ");
    r.push(0); // checksum (v1 portion), fixed up below
    r.extend_from_slice(b"HYPRBG"); // oem_id
    r.push(2); // revision: ACPI 2.0+
    r.extend_from_slice(&rsdt_addr.to_le_bytes());
    r.extend_from_slice(&36u32.to_le_bytes()); // length
    r.extend_from_slice(&xsdt_addr.to_le_bytes());
    r.push(0); // extended_checksum, fixed up below
    r.extend_from_slice(&[0, 0, 0]); // reserved

    r[8] = 0;
    r[8] = checksum(&r[..20]); // v1 checksum covers only the first 20 bytes
    r[32] = 0;
    r[32] = checksum(&r); // extended checksum covers the whole 36-byte table
    r
}

/// Packs ACPI tables into the BIOS-area window one after another, 16-byte
/// aligned, and reports an overrun instead of silently writing past the
/// window into the kernel image.
///
/// The previous fixed per-table addresses looked safe but weren't: the
/// MADT grows by 8 bytes per vCPU, and its hardcoded 256-byte gap before
/// the XSDT meant `--smp 27` or more silently corrupted the XSDT and RSDT
/// that followed it. (The same class of bug — a table outgrowing its
/// hardcoded gap — was already caught once here in a real boot, when
/// adding `_CRS` pushed the DSDT past its own 256-byte budget and
/// scribbled over the FADT.)
struct TableWriter<'a> {
    mem: &'a mut GuestMemory,
    next: u64,
}

impl TableWriter<'_> {
    /// Writes `table` at the next aligned address and returns where it
    /// landed.
    fn place(&mut self, name: &str, table: &[u8]) -> Result<u64, HyperbugError> {
        let addr = self.next;
        let end = addr + table.len() as u64;
        if end > ACPI_LIMIT {
            return Err(HyperbugError::Config(format!(
                "ACPI {name} table ({} bytes) overruns the {} bytes of BIOS-area window \
                 at {ACPI_BASE:#x} — reduce --smp, or move the tables",
                table.len(),
                ACPI_LIMIT - ACPI_BASE
            )));
        }
        self.mem.write_slice_unchecked_boot_only(addr, table);
        self.next = end.div_ceil(TABLE_ALIGN) * TABLE_ALIGN;
        Ok(addr)
    }
}

/// Writes RSDP/RSDT/XSDT/FADT/MADT/DSDT into guest memory. See
/// `TableWriter` for the layout, and `ACPI_BASE` for why this window.
pub fn setup_acpi(mem: &mut GuestMemory, num_cpus: u8) -> Result<(), HyperbugError> {
    let mut writer = TableWriter { mem, next: RSDP_ADDR + RSDP_LEN.div_ceil(TABLE_ALIGN) * TABLE_ALIGN };

    let dsdt_addr = writer.place("DSDT", DSDT_AML)?;
    let fadt_addr = writer.place("FADT", &build_fadt(dsdt_addr as u32))?;
    let madt_addr = writer.place("MADT", &build_madt(num_cpus))?;
    let xsdt_addr = writer.place("XSDT", &build_xsdt(&[fadt_addr, madt_addr]))?;
    let rsdt_addr = writer.place("RSDT", &build_rsdt(&[fadt_addr as u32, madt_addr as u32]))?;

    // Last, now that it can point at the two root tables — and at its own
    // fixed address, which is what an OS actually scans for.
    let rsdp = build_rsdp(rsdt_addr as u32, xsdt_addr);
    debug_assert_eq!(rsdp.len() as u64, RSDP_LEN);
    writer.mem.write_slice_unchecked_boot_only(RSDP_ADDR, &rsdp);
    Ok(())
}

/// Process exit codes for how the guest's run ended. `0` (clean shutdown)
/// and `RESET` (clean, requested reboot) are the only two hyperbug can
/// actually be sure of — a `VcpuExit::Shutdown` triple fault is
/// inherently ambiguous between "genuine crash", "reboot=k's fallback
/// mechanism", and "panic=1's auto-reboot", since real Linux uses the
/// exact same triple-fault trick for the latter two as an unrequested
/// crash would produce.
pub mod exit_code {
    pub const CLEAN_SHUTDOWN: i32 = 0;
    pub const REQUESTED_REBOOT: i32 = 10;
    pub const TRIPLE_FAULT: i32 = 11;
    // 12 (HALTED) is retired now that HLT is ordinary cpu-idle (masking
    // MWAIT out of CPUID makes Linux use HLT constantly, not just at a
    // genuine dead end — see main.rs's VcpuExit::Hlt handling and
    // DEBTS.md item 30) — kept reserved, not reused, since
    // python/hyperbug/vm.py's ExitCode.HALTED still documents it for any
    // process that was built before this change.
}

/// The `SLEEP_CONTROL_REG`/`SLEEP_STATUS_REG` pair (ACPI 5.0's
/// hardware-reduced alternative to PM1a_CNT): a real Linux `acpi_power_off`
/// writes `SLP_TYPa | SLP_EN` here to shut down. hyperbug doesn't
/// implement any other sleep state, so *any* SLP_EN write just ends the
/// run — there's no real distinction to make between S1-S4 when none of
/// them exist.
///
/// Records the shutdown request on the shared `ExitSlot` (see `error.rs`)
/// rather than calling `std::process::exit` itself — a `Device` is
/// something a third-party Python plugin also implements, so its `write`
/// signature can't grow a "please terminate the VM" return value just for
/// these two hyperbug-internal devices; every vCPU thread polls the exit
/// slot once per loop iteration instead.
pub struct SleepControl {
    exit: ExitSlot,
}

impl SleepControl {
    pub fn new(exit: ExitSlot) -> Self {
        Self { exit }
    }
}

impl Device for SleepControl {
    fn read(&mut self, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }

    fn write(&mut self, _offset: u64, data: &[u8]) -> bool {
        if data.first().is_some_and(|&b| b & SLP_EN != 0) {
            eprintln!("[hyperbug] guest requested ACPI shutdown (S5)");
            request_exit(&self.exit, Ok(GuestExit::CleanShutdown));
        }
        false
    }
}

/// The `RESET_REG` from FADT: any write of `RESET_VALUE` here is a real,
/// deliberate "please reboot" request, distinguishable from a triple
/// fault (see `exit_code` above) precisely because it doesn't go through
/// the ambiguous triple-fault path at all. Same `ExitSlot` reasoning as
/// `SleepControl` above.
pub struct ResetControl {
    exit: ExitSlot,
}

impl ResetControl {
    pub fn new(exit: ExitSlot) -> Self {
        Self { exit }
    }
}

impl Device for ResetControl {
    fn read(&mut self, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }

    fn write(&mut self, _offset: u64, data: &[u8]) -> bool {
        if data.first() == Some(&RESET_VALUE) {
            eprintln!("[hyperbug] guest requested ACPI reset (reboot)");
            request_exit(&self.exit, Ok(GuestExit::RequestedReboot));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // DEBTS.md item 16: every field offset here was checked against real
    // ACPICA headers, but the *assembled* tables were only ever checksum-
    // reasoned by hand. These tests check the checksum arithmetic in pure
    // Rust (no external tool needed), then — if `iasl` is installed —
    // additionally round-trip every table through it (the same real
    // compiler/disassembler used for the DSDT), which validates the
    // signature/length/structure fields an independent tool actually
    // parses, not just "the bytes sum to zero".

    // Plausible stand-in addresses for the tests that need one; the real
    // ones are assigned dynamically by `setup_acpi`.
    const SOME_DSDT: u64 = 0xe0020;
    const SOME_FADT: u64 = 0xe0100;
    const SOME_MADT: u64 = 0xe0300;

    fn table_checksum_is_zero(table: &[u8]) {
        let sum = table.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "table doesn't sum to zero — checksum is wrong");
    }

    /// Reads the 4-byte signature and 32-bit length every SDT header
    /// starts with, so a test can find a placed table without knowing the
    /// layout `setup_acpi` chose.
    fn header_at(mem: &GuestMemory, addr: u64) -> ([u8; 4], u32) {
        let mut sig = [0u8; 4];
        assert!(mem.read_checked(addr, &mut sig));
        (sig, mem.read_u32_checked(addr + 4).unwrap())
    }

    #[test]
    fn table_checksums_are_valid() {
        table_checksum_is_zero(&build_madt(1));
        table_checksum_is_zero(&build_fadt(SOME_DSDT as u32));
        table_checksum_is_zero(&build_xsdt(&[SOME_FADT, SOME_MADT]));
        table_checksum_is_zero(&build_rsdt(&[SOME_FADT as u32, SOME_MADT as u32]));
        // RSDP has two independent checksums (v1 covers the first 20
        // bytes, extended covers all 36) — check both explicitly rather
        // than just the whole-table sum, since a bug isolated to just the
        // extended-checksum byte's own placement wouldn't show up in a
        // single whole-table check.
        let rsdp = build_rsdp(SOME_FADT as u32, SOME_MADT);
        table_checksum_is_zero(&rsdp[..20]);
        table_checksum_is_zero(&rsdp);
    }

    /// The bug the dynamic layout exists to make impossible: the MADT
    /// grows 8 bytes per vCPU, and the old hardcoded 256-byte gap before
    /// the XSDT meant `--smp 27` silently scribbled over the XSDT and RSDT
    /// that followed it. Every table must still be intact at the maximum
    /// vCPU count the CLI can express.
    #[test]
    fn every_table_survives_the_largest_possible_madt() {
        let mut mem = GuestMemory::new(0x20_0000).unwrap();
        setup_acpi(&mut mem, u8::MAX).expect("255 vCPUs' worth of tables must still fit");

        let mut rsdp = [0u8; 8];
        assert!(mem.read_checked(RSDP_ADDR, &mut rsdp));
        assert_eq!(&rsdp, b"RSD PTR ", "the RSDP must be where an OS scans for it");

        // Walk the RSDT the way an OS does, and confirm each entry it
        // points at still has its own intact signature and length.
        let rsdt_addr = u64::from(mem.read_u32_checked(RSDP_ADDR + 16).unwrap());
        let (sig, rsdt_len) = header_at(&mem, rsdt_addr);
        assert_eq!(&sig, b"RSDT");
        table_checksum_is_zero(&read_table(&mem, rsdt_addr, rsdt_len));

        let entries = (rsdt_len as u64 - 36) / 4;
        assert_eq!(entries, 2, "FADT and MADT");
        for i in 0..entries {
            let entry = u64::from(mem.read_u32_checked(rsdt_addr + 36 + i * 4).unwrap());
            let (sig, len) = header_at(&mem, entry);
            assert!(&sig == b"FACP" || &sig == b"APIC", "unexpected table signature {sig:?}");
            table_checksum_is_zero(&read_table(&mem, entry, len));
        }
    }

    fn read_table(mem: &GuestMemory, addr: u64, len: u32) -> Vec<u8> {
        let mut buf = vec![0u8; len as usize];
        assert!(mem.read_checked(addr, &mut buf));
        buf
    }

    #[test]
    fn tables_are_placed_without_overlapping_each_other() {
        let mut mem = GuestMemory::new(0x20_0000).unwrap();
        setup_acpi(&mut mem, 4).unwrap();

        let rsdt_addr = u64::from(mem.read_u32_checked(RSDP_ADDR + 16).unwrap());
        let xsdt_addr = mem.read_u64_checked(RSDP_ADDR + 24).unwrap();
        let (_, rsdt_len) = header_at(&mem, rsdt_addr);
        let (_, xsdt_len) = header_at(&mem, xsdt_addr);

        let fadt_addr = u64::from(mem.read_u32_checked(rsdt_addr + 36).unwrap());
        let madt_addr = u64::from(mem.read_u32_checked(rsdt_addr + 40).unwrap());
        let (_, fadt_len) = header_at(&mem, fadt_addr);
        let (_, madt_len) = header_at(&mem, madt_addr);
        // FADT offset 40 is the 32-bit DSDT pointer.
        let dsdt_addr = u64::from(mem.read_u32_checked(fadt_addr + 40).unwrap());

        let mut spans = [
            (RSDP_ADDR, RSDP_LEN),
            (dsdt_addr, DSDT_AML.len() as u64),
            (fadt_addr, u64::from(fadt_len)),
            (madt_addr, u64::from(madt_len)),
            (xsdt_addr, u64::from(xsdt_len)),
            (rsdt_addr, u64::from(rsdt_len)),
        ];
        spans.sort_unstable();
        for pair in spans.windows(2) {
            let (addr, len) = pair[0];
            assert!(addr + len <= pair[1].0, "table at {addr:#x} overlaps the next one");
        }
        assert!(spans.last().unwrap().0 + spans.last().unwrap().1 <= ACPI_LIMIT);
    }

    /// Runs `iasl -d` on `table` (named `name`, e.g. "fadt") and returns
    /// its stdout+stderr. Panics on a nonzero exit — a real parse failure
    /// is exactly the kind of bug this test exists to catch.
    fn disassemble_with_iasl(name: &str, table: &[u8]) -> String {
        let dir = std::env::temp_dir().join(format!("hyperbug_acpi_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.bin"));
        std::fs::File::create(&path).unwrap().write_all(table).unwrap();

        let output = std::process::Command::new("iasl")
            .arg("-d")
            .arg(&path)
            .current_dir(&dir)
            .output()
            .expect("iasl should run if this test wasn't skipped");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "iasl -d failed on {name}:
{text}");
        text
    }

    #[test]
    fn tables_are_well_formed_per_iasl() {
        if std::process::Command::new("iasl").arg("-v").output().is_err() {
            eprintln!("iasl not installed — skipping independent-tool verification (item 16)");
            return;
        }

        disassemble_with_iasl("dsdt", DSDT_AML);
        disassemble_with_iasl("fadt", &build_fadt(SOME_DSDT as u32));
        disassemble_with_iasl("madt", &build_madt(1));
        disassemble_with_iasl("xsdt", &build_xsdt(&[SOME_FADT, SOME_MADT]));
        disassemble_with_iasl("rsdt", &build_rsdt(&[SOME_FADT as u32, SOME_MADT as u32]));
        // iasl's disassembler doesn't take RSDP directly (it's not an
        // SDT-header table — no 4-byte ACPI signature at offset 0 the
        // dispatcher recognizes), so it isn't included here; its checksum
        // is covered by `table_checksums_are_valid` above instead.
    }
}
