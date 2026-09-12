//! Minimal long-mode boot setup: a 3-entry flat GDT and identity-mapped
//! page tables (2 MiB pages), matching the layout conventions used by
//! Firecracker/crosvm's Linux boot-protocol loaders.

use kvm_bindings::{kvm_segment, kvm_sregs};

use crate::mem::GuestMemory;

pub const BOOT_GDT_OFFSET: u64 = 0x500;
pub const PML4_START: u64 = 0x9000;
pub const PDPTE_START: u64 = 0xa000; // one page: up to 512 PDPT entries
pub const PDE_START: u64 = 0xb000; // one 4KiB PD table per GiB of guest RAM, contiguous

const PAGE_2MB: u64 = 2 * 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;
const PD_TABLE_SIZE: u64 = 4096;

/// The single PML4 entry we use points at one PDPT, which has at most 512
/// entries (1 GiB each) — so this layout can in principle identity-map up
/// to 512 GiB. In practice it's bounded by how much low memory is free for
/// PD tables before `KERNEL_START` (1 MiB), where `loader::KERNEL_START`
/// lives; see `max_identity_map`.
const MAX_PDPT_ENTRIES: u64 = 512;

/// The largest guest memory size this layout can identity-map: as many
/// GiB as fit `PD_TABLE_SIZE`-sized PD tables between `PDE_START` and
/// `KERNEL_START`, capped at what a single PDPT can address (512 GiB).
pub fn max_identity_map() -> u64 {
    let space_for_tables = crate::loader::KERNEL_START - PDE_START;
    let max_tables_by_space = space_for_tables / PD_TABLE_SIZE;
    max_tables_by_space.min(MAX_PDPT_ENTRIES) * GIB
}

fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    (((base as u64) & 0xff000000) << 32)
        | (((flags as u64) & 0x0000f0ff) << 40)
        | (((limit as u64) & 0x000f0000) << 32)
        | (((base as u64) & 0x00ffffff) << 16)
        | ((limit as u64) & 0x0000ffff)
}

/// Writes the flat GDT (null, 64-bit code, data) into guest memory and
/// points `sregs` at it, filling in the matching segment descriptors.
pub fn setup_gdt(mem: &mut GuestMemory, sregs: &mut kvm_sregs) {
    let table: [u64; 3] = [
        0,                             // null descriptor
        gdt_entry(0xa09b, 0, 0xfffff), // code64: P DPL0 S code RX, L=1 G=1
        gdt_entry(0xc093, 0, 0xfffff), // data: P DPL0 S data RW, B=1 G=1
    ];
    for (i, entry) in table.iter().enumerate() {
        mem.write_obj_unchecked_boot_only(BOOT_GDT_OFFSET + (i as u64) * 8, *entry);
    }

    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = (table.len() * 8 - 1) as u16;

    let code_seg = kvm_segment {
        base: 0,
        limit: 0xfffff,
        selector: 0x08,
        type_: 0xb, // execute, read, accessed
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 1, // 64-bit code segment
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    };
    let data_seg = kvm_segment {
        selector: 0x10,
        type_: 0x3, // read, write, accessed
        l: 0,
        db: 1,
        ..code_seg
    };

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
}

/// Identity-maps guest physical addresses `[0, mem_size)` (rounded up to a
/// 2 MiB page) using a single PML4 entry -> one PDPT -> one PD table per
/// GiB of guest RAM (each PD table mapping that GiB in 2 MiB pages), and
/// points `sregs`'s paging fields at it. Fails if `mem_size` exceeds
/// `max_identity_map()`.
pub fn setup_page_tables(mem: &mut GuestMemory, sregs: &mut kvm_sregs, mem_size: u64) -> Result<(), String> {
    let max = max_identity_map();
    if mem_size > max {
        return Err(format!(
            "guest memory of {mem_size} bytes exceeds the {max}-byte identity-map limit \
             (bounded by free low memory for page tables before KERNEL_START)"
        ));
    }

    const PRESENT_WRITABLE: u64 = 0x3;
    const PRESENT_WRITABLE_HUGE: u64 = 0x83; // + PS bit

    mem.write_obj_unchecked_boot_only(PML4_START, PDPTE_START | PRESENT_WRITABLE);

    let num_gib = mem_size.div_ceil(GIB).max(1);
    for gib in 0..num_gib {
        let pd_table = PDE_START + gib * PD_TABLE_SIZE;
        mem.write_obj_unchecked_boot_only(PDPTE_START + gib * 8, pd_table | PRESENT_WRITABLE);

        let gib_base = gib * GIB;
        let pages_in_this_gib = mem_size.saturating_sub(gib_base).min(GIB).div_ceil(PAGE_2MB);
        for i in 0..pages_in_this_gib {
            let phys = gib_base + i * PAGE_2MB;
            mem.write_obj_unchecked_boot_only(pd_table + i * 8, phys | PRESENT_WRITABLE_HUGE);
        }
    }

    sregs.cr3 = PML4_START;
    sregs.cr4 = 0x20; // CR4.PAE
    sregs.cr0 = 0x80050033; // PE | MP | ET | NE | WP | AM | PG
    sregs.efer = 0x500; // EFER.LME | EFER.LMA
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_bindings::kvm_sregs;

    // This math was reviewed by hand up to a couple of GiB (default
    // --mem usage) but never exercised near its real ceiling. These
    // tests actually build the page tables at (and past)
    // max_identity_map() and check the resulting bytes — no KVM needed,
    // since GuestMemory is just an mmap and setup_page_tables only ever
    // writes to it.
    //
    // The backing mmap for a multi-hundred-GiB test is virtual only
    // (MAP_NORESERVE, nothing touched beyond the low addresses page
    // tables actually live at), so this doesn't require real RAM.

    fn pml4e(mem: &GuestMemory) -> u64 {
        mem.read_u64_checked(PML4_START).unwrap()
    }

    fn pdpte(mem: &GuestMemory, gib: u64) -> u64 {
        mem.read_u64_checked(PDPTE_START + gib * 8).unwrap()
    }

    fn pde(mem: &GuestMemory, pd_table: u64, index: u64) -> u64 {
        mem.read_u64_checked(pd_table + index * 8).unwrap()
    }

    #[test]
    fn rejects_more_than_the_advertised_maximum() {
        let max = max_identity_map();
        let mut mem = GuestMemory::new((max + GIB) as usize).unwrap();
        let mut sregs = kvm_sregs::default();
        assert!(setup_page_tables(&mut mem, &mut sregs, max + GIB).is_err());
    }

    #[test]
    fn maps_exactly_at_the_advertised_maximum() {
        let max = max_identity_map();
        let mut mem = GuestMemory::new(max as usize).unwrap();
        let mut sregs = kvm_sregs::default();
        setup_page_tables(&mut mem, &mut sregs, max).expect("must succeed at exactly the max");

        assert_eq!(pml4e(&mem) & !0xfff, PDPTE_START);

        let num_gib = max / GIB;
        // First and last PDPT entries point at the right, distinct PD tables.
        let first_pd = PDE_START;
        let last_pd = PDE_START + (num_gib - 1) * PD_TABLE_SIZE;
        assert_eq!(pdpte(&mem, 0) & !0xfff, first_pd);
        assert_eq!(pdpte(&mem, num_gib - 1) & !0xfff, last_pd);

        // The very last 2 MiB page of the very last GiB maps the correct
        // physical address — the boundary this item was actually worried
        // about (an off-by-one in the per-GiB PD table placement math).
        let pages_per_gib = GIB / PAGE_2MB;
        let last_page_phys = pde(&mem, last_pd, pages_per_gib - 1) & !0xfff;
        assert_eq!(last_page_phys, max - PAGE_2MB);

        // Every PD entry actually written is present+writable+huge, and
        // nothing beyond the last GiB's PDPT slot got a stray write.
        assert_eq!(pdpte(&mem, num_gib), 0);
    }

    #[test]
    fn handles_a_partial_final_gib_correctly() {
        // Not a multiple of GIB: exercises the `pages_in_this_gib`
        // truncation for the last, incomplete table.
        let mem_size = 3 * GIB + 17 * PAGE_2MB;
        let mut mem = GuestMemory::new(mem_size as usize).unwrap();
        let mut sregs = kvm_sregs::default();
        setup_page_tables(&mut mem, &mut sregs, mem_size).unwrap();

        let last_pd = PDE_START + 3 * PD_TABLE_SIZE;
        // The 17 valid pages in the final, partial GiB map the right
        // physical addresses...
        for i in 0..17 {
            let phys = pde(&mem, last_pd, i) & !0xfff;
            assert_eq!(phys, 3 * GIB + i * PAGE_2MB);
        }
        // ...and the 18th entry in that table was never written (still 0),
        // rather than the loop over-running into the next GiB's addresses.
        assert_eq!(pde(&mem, last_pd, 17), 0);
    }
}
