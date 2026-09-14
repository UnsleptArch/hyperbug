//! Minimal SMBIOS/DMI tables: a real 32-bit `_SM_`/`_DMI_` entry point
//! plus a handful of structures (BIOS Information, System Information,
//! System Enclosure, and the mandatory End-of-Table marker) — real BMC/
//! management firmware routinely reads these for asset/inventory
//! information, and hyperbug's own Linux boot protocol path (no BIOS, no
//! UEFI) otherwise leaves them entirely absent.
//!
//! **Verified against the real Linux DMI scanner**
//! (`drivers/firmware/dmi_scan.c`, fetched from `torvalds/linux`), the
//! same "check a real source of truth" discipline `acpi.rs` already
//! established for its own table layouts — every field offset below,
//! and the exact checksum/scan-window semantics, are taken from
//! `dmi_present()`'s own byte-offset arithmetic, not the spec page alone.
//!
//! **Placement**: the real Linux non-EFI fallback path
//! (`dmi_scan_machine()`, active here since hyperbug's boot never sets up
//! any EFI config tables) scans `[0xF0000, 0xFFFFF]` in 16-byte steps for
//! the `_SM_` anchor — a narrower window than ACPI's own RSDP scan
//! (`[0xE0000, 0xFFFFF]`). `SMBIOS_BASE` sits in the last 4 KiB of that
//! shared region, which `acpi.rs`'s own `ACPI_LIMIT` is shrunk by exactly
//! that much to never grow into, regardless of `--smp`.
//!
//! **Scope**: Types 0 (BIOS), 1 (System), 3 (Chassis), and 127
//! (End-of-Table) only — the ones a real guest's own `dmi_decode()`
//! actually extracts into `/sys/class/dmi/id/*`, and so the ones this
//! module's own boot test can verify through a real, unmodified kernel
//! path rather than only by re-parsing the bytes it wrote. Processor/
//! memory-device tables (Types 4/16/17) aren't extracted by
//! `dmi_decode()` at all — a real consumer would need to walk the raw
//! table directly (`dmidecode`-style), which this project has no
//! automated way to verify against right now — so they're a deliberately
//! deferred extension, not silently forgotten.

use crate::acpi::checksum;
use crate::error::HyperbugError;
use crate::mem::GuestMemory;

/// The last 4 KiB before `0x100000` — see this module's own doc comment
/// and `acpi.rs`'s `ACPI_LIMIT` for why this specific placement.
const SMBIOS_BASE: u64 = 0xff000;
const SMBIOS_LIMIT: u64 = 0x10_0000;
/// Real `_SM_`/`_DMI_` combined entry point length (31 bytes) per SMBIOS
/// 2.1+; the structure table itself starts right after, 16-byte aligned
/// the same way ACPI's own tables are.
const ENTRY_POINT_LEN: u64 = 31;
const TABLE_ADDR: u64 = SMBIOS_BASE + 32; // one 16-byte step past the entry point

/// Appends a structure's string-set terminator: each string NUL-
/// terminated, followed by one *more* NUL byte — or, if there are no
/// strings at all, a bare double-NUL. Per spec, every DMI structure ends
/// this way regardless of how many strings it references.
fn append_strings(t: &mut Vec<u8>, strings: &[&str]) {
    if strings.is_empty() {
        t.extend_from_slice(&[0, 0]);
        return;
    }
    for s in strings {
        t.extend_from_slice(s.as_bytes());
        t.push(0);
    }
    t.push(0);
}

/// Type 0 (BIOS Information). Formatted area through offset 23
/// (Embedded Controller Firmware Minor Release) — long enough for every
/// field `dmi_decode()`'s `DMI_ENTRY_BIOS` case reads
/// (vendor/version/date/release/EC-release).
fn build_bios_info(handle: u16) -> Vec<u8> {
    let mut t = vec![0u8; 24];
    t[0] = 0; // type
    t[1] = 24; // formatted-area length (string-set length isn't part of it)
    t[2..4].copy_from_slice(&handle.to_le_bytes());
    t[4] = 1; // Vendor -> string 1
    t[5] = 2; // BIOS Version -> string 2
    t[6..8].copy_from_slice(&0xE000u16.to_le_bytes()); // BIOS starting segment (arbitrary, real BIOSes vary)
    t[8] = 3; // BIOS Release Date -> string 3
    t[9] = 0; // BIOS ROM size (unspecified)
    // offsets 10-17: BIOS Characteristics (u64 bitfield) — left at 0,
    // meaning "no characteristics claimed" (honest, since nothing behind
    // this table implements any of them) rather than falsely claiming
    // support hyperbug doesn't have.
    t[18] = 0; // Characteristics Extension Byte 1
    t[19] = 0; // Characteristics Extension Byte 2
    t[20] = 1; // System BIOS Major Release
    t[21] = 0; // System BIOS Minor Release
    t[22] = 0xFF; // EC Firmware Major Release: 0xFF = not supported (real spec convention)
    t[23] = 0xFF; // EC Firmware Minor Release: ditto
    append_strings(&mut t, &["hyperbug", "1.0", "01/01/2026"]);
    t
}

/// Type 1 (System Information). A fixed, obviously-synthetic UUID —
/// this is a virtual machine's identity, not real hardware's, and
/// nothing here is meant to be mistaken for a genuine asset tag.
fn build_system_info(handle: u16) -> Vec<u8> {
    let mut t = vec![0u8; 27];
    t[0] = 1;
    t[1] = 27;
    t[2..4].copy_from_slice(&handle.to_le_bytes());
    t[4] = 1; // Manufacturer
    t[5] = 2; // Product Name
    t[6] = 3; // Version
    t[7] = 4; // Serial Number
    // UUID, offset 8..24 (16 bytes) — SMBIOS >= 2.6 (declared below)
    // encodes the first three fields little-endian, matching what
    // `dmi_save_uuid` expects for that version range.
    t[8..24].copy_from_slice(&[
        0x48, 0x59, 0x42, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x48, 0x59, 0x42, 0x55, 0x47, 0x00,
    ]);
    t[24] = 0x06; // Wake-up Type: Power Switch
    t[25] = 0; // SKU Number (none)
    t[26] = 5; // Family
    append_strings(&mut t, &["hyperbug", "hyperbug-vm", "1.0", "HB-0000-0001", "hyperbug"]);
    t
}

/// Type 3 (System Enclosure/Chassis). Minimal 9-byte formatted area
/// (valid since SMBIOS 2.1) — long enough for every field
/// `dmi_decode()`'s `DMI_ENTRY_CHASSIS` case reads.
fn build_chassis_info(handle: u16) -> Vec<u8> {
    let mut t = vec![0u8; 9];
    t[0] = 3;
    t[1] = 9;
    t[2..4].copy_from_slice(&handle.to_le_bytes());
    t[4] = 1; // Manufacturer
    t[5] = 0x17; // Chassis Type: Rack Mount Chassis (23) — fits the BMC-shaped target this is for
    t[6] = 2; // Version
    t[7] = 3; // Serial Number
    t[8] = 0; // Asset Tag (none)
    append_strings(&mut t, &["hyperbug", "1.0", "HB-CHASSIS-0001"]);
    t
}

/// Type 127 (End-of-Table) — mandatory: `dmi_walk_early`'s loop keeps
/// consuming structures until it sees this one.
fn build_end_marker(handle: u16) -> Vec<u8> {
    let mut t = vec![0u8; 4];
    t[0] = 127;
    t[1] = 4;
    t[2..4].copy_from_slice(&handle.to_le_bytes());
    append_strings(&mut t, &[]);
    t
}

/// Builds the real `_SM_`/`_DMI_` combined 32-bit entry point. Field
/// offsets and the two-checksum structure (`_SM_`'s own checksum over
/// all `entry_len` bytes, `_DMI_`'s separate checksum over its own
/// trailing 15) are exactly what `dmi_present()` validates — see this
/// module's own doc comment.
fn build_entry_point(table_addr: u32, table_len: u16, num_structures: u16, max_structure_size: u16) -> [u8; ENTRY_POINT_LEN as usize] {
    let mut e = [0u8; ENTRY_POINT_LEN as usize];
    e[0..4].copy_from_slice(b"_SM_");
    e[5] = ENTRY_POINT_LEN as u8;
    e[6] = 2; // SMBIOS major version
    e[7] = 8; // SMBIOS minor version (2.8 — >= 2.6 for the UUID endianness `build_system_info` assumes)
    e[8..10].copy_from_slice(&max_structure_size.to_le_bytes());
    e[10] = 0; // entry point revision
    // e[11..16]: formatted area, left zero.
    e[16..21].copy_from_slice(b"_DMI_");
    e[22..24].copy_from_slice(&table_len.to_le_bytes());
    e[24..28].copy_from_slice(&table_addr.to_le_bytes());
    e[28..30].copy_from_slice(&num_structures.to_le_bytes());
    e[30] = 0x28; // SMBIOS BCD revision, 2.8
    e[21] = checksum(&e[16..31]); // "_DMI_" sub-structure's own checksum, computed first —
    e[4] = checksum(&e[..]); // — since the whole entry point's checksum covers it too.
    e
}

/// Writes the SMBIOS entry point and structure table into guest memory.
/// Called once, unconditionally (like ACPI) — this is static asset/
/// inventory data, not something any `--` flag configures.
pub fn setup_smbios(mem: &mut GuestMemory) -> Result<(), HyperbugError> {
    let bios = build_bios_info(0);
    let system = build_system_info(1);
    let chassis = build_chassis_info(2);
    let end = build_end_marker(3);
    let max_structure_size =
        [bios.len(), system.len(), chassis.len(), end.len()].into_iter().max().unwrap() as u16;

    let mut table = Vec::new();
    table.extend_from_slice(&bios);
    table.extend_from_slice(&system);
    table.extend_from_slice(&chassis);
    table.extend_from_slice(&end);

    if TABLE_ADDR + table.len() as u64 > SMBIOS_LIMIT {
        return Err(HyperbugError::Config(format!(
            "SMBIOS table ({} bytes) overflowed its reserved region ({} bytes free)",
            table.len(),
            SMBIOS_LIMIT - TABLE_ADDR
        )));
    }

    let entry = build_entry_point(TABLE_ADDR as u32, table.len() as u16, 4, max_structure_size);
    mem.write_slice_unchecked_boot_only(SMBIOS_BASE, &entry);
    mem.write_slice_unchecked_boot_only(TABLE_ADDR, &table);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every structure's declared `length` (offset 1) must never exceed
    /// its own formatted area — a real DMI walker trusts this field to
    /// find the next structure's start (skip `length` bytes, then scan
    /// for the double-NUL string-set terminator), so an inflated value
    /// would make it skip into the middle of this structure's own
    /// strings.
    #[test]
    fn every_structures_declared_length_is_at_most_its_formatted_area() {
        for t in [build_bios_info(0), build_system_info(1), build_chassis_info(2), build_end_marker(3)] {
            let declared_len = t[1] as usize;
            assert!(declared_len <= t.len(), "type {} declares length {declared_len} but is only {} bytes", t[0], t.len());
        }
    }

    /// A real DMI walker (`dmi_walk_early`) finds the next structure by
    /// skipping `length` bytes, then scanning forward for a `\0\0` pair
    /// — this must actually find the *real* end of the string-set, not
    /// wander into whatever follows.
    #[test]
    fn each_structures_string_set_is_correctly_double_nul_terminated() {
        for t in [build_bios_info(0), build_system_info(1), build_chassis_info(2), build_end_marker(3)] {
            let formatted_len = t[1] as usize;
            let strings = &t[formatted_len..];
            // Find the first `\0\0` pair scanning from the start of the
            // string-set — it must be exactly the tail of `t`, i.e. the
            // structure doesn't have trailing garbage after its real
            // terminator.
            let mut i = 0;
            while i + 1 < strings.len() && !(strings[i] == 0 && strings[i + 1] == 0) {
                i += 1;
            }
            assert_eq!(i + 2, strings.len(), "type {}'s string-set has trailing bytes after its double-NUL terminator", t[0]);
        }
    }

    /// The combined `_SM_`/`_DMI_` entry point must satisfy both
    /// checksums `dmi_present()` actually validates — a real,
    /// independent re-check of `build_entry_point`'s own arithmetic, not
    /// a tautology (recomputes both sums directly here rather than
    /// calling `checksum()` again).
    #[test]
    fn the_entry_point_satisfies_both_real_checksums() {
        let entry = build_entry_point(0x1234, 100, 4, 27);
        assert_eq!(&entry[0..4], b"_SM_");
        assert_eq!(&entry[16..21], b"_DMI_");
        let sum_all: u8 = entry.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum_all, 0, "the whole 31-byte entry point must sum to zero");
        let sum_dmi: u8 = entry[16..31].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum_dmi, 0, "the trailing 15-byte _DMI_ sub-structure must independently sum to zero");
    }

    /// `setup_smbios` must actually fit its table inside the reserved
    /// region without ever touching guest memory past `SMBIOS_LIMIT` —
    /// checked here against real numbers rather than trusted by
    /// inspection.
    #[test]
    fn the_real_table_fits_comfortably_inside_the_reserved_region() {
        let total = build_bios_info(0).len() + build_system_info(1).len() + build_chassis_info(2).len() + build_end_marker(3).len();
        assert!(
            TABLE_ADDR + total as u64 <= SMBIOS_LIMIT,
            "the real table ({total} bytes) must fit in [{TABLE_ADDR:#x}, {SMBIOS_LIMIT:#x})"
        );
    }

    /// `setup_smbios` actually writes real, checksummed bytes into guest
    /// memory at the addresses a real Linux guest's `dmi_scan_machine`
    /// would scan.
    #[test]
    fn setup_smbios_writes_a_real_valid_entry_point_into_guest_memory() {
        let mut mem = GuestMemory::new(2 * 1024 * 1024).unwrap();
        setup_smbios(&mut mem).unwrap();
        let mut entry = [0u8; ENTRY_POINT_LEN as usize];
        assert!(mem.read_checked(SMBIOS_BASE, &mut entry));
        assert_eq!(&entry[0..4], b"_SM_");
        let sum: u8 = entry.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0);
    }
}
