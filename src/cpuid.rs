//! Curates `KVM_GET_SUPPORTED_CPUID`'s raw host pass-through down to a
//! handful of specific, evidence-based fixes — not a full from-scratch
//! CPUID (DEBTS.md item 12 stays open as "otherwise uncurated"; this is
//! deliberately narrow, verified via `tests/boot.rs`'s real boot test
//! rather than trusted by inspection).
//!
//! Every leaf/field touched here was checked directly against this host's
//! own `KVM_GET_SUPPORTED_CPUID` output (a throwaway `kvm-ioctls` program
//! dumping raw leaf values) rather than assumed from the Intel/AMD SDMs
//! from memory — the same "verify against something real" discipline
//! `acpi.rs` already uses for table layouts.

use kvm_bindings::CpuId;

/// CPUID.01H:ECX, bit 3 (MONITOR/MWAIT).
const ECX_MONITOR: u32 = 1 << 3;
/// CPUID.01H:EDX, bit 28 (HTT — "this vCPU has SMT/multi-core siblings").
const EDX_HTT: u32 = 1 << 28;

/// Curates the raw `KVM_GET_SUPPORTED_CPUID` set for one vCPU of an
/// `N`-vCPU guest (`N` == 1 is just the single-vCPU case).
///
/// **Corrected history, since this function's first version got its own
/// justification wrong**: an earlier session masked MONITOR/MWAIT here,
/// attributing it to fixing a real hang (a guest MWAIT idle loop running
/// inside KVM with zero VM-exits, starving hyperbug's host-I/O polling
/// forever). Checked directly against this host's own
/// `KVM_GET_SUPPORTED_CPUID` output while doing the *rest* of this
/// curation and found: KVM already reports MONITOR/MWAIT as *unsupported*
/// on this AMD host (bit already 0) even though the raw CPU has real
/// `monitor` in `/proc/cpuinfo` — a known KVM/AMD policy, not something
/// hyperbug controls. The mask was therefore inert here; the actual fix
/// for that hang was entirely `tty::install_periodic_wakeup`'s SIGALRM
/// mechanism (see `DEBTS.md` item 29's corrected entry). The mask stays —
/// masking a feature hyperbug's own `VcpuExit::Hlt` handling isn't built
/// to make interruptible is still the right defensive choice for an
/// Intel host or a future KVM policy change — but is documented honestly
/// now as defense-in-depth, not as "the fix."
///
/// Also curates two confirmed, concrete host-topology leaks that have
/// nothing to do with the above and are worth fixing on their own merits
/// (a "repeatable rehosting target," per the external review that
/// prompted this pass, shouldn't expose whatever the host CPU happens to
/// be): CPUID.01H:EBX bits 23:16 (logical processor count) reported this
/// host's real 16 hardware threads despite HTT already being 0 — harmless
/// today since HTT is clear (an OS should ignore that field when HTT
/// isn't set), but non-reproducible and worth being explicit about rather
/// than "whatever the host happens to have." Leaf 0BH's EDX (x2APIC ID)
/// leaked a real host thread's APIC ID (`0xa` on this host) the same way
/// — harmless since EBX=0 already terminates topology enumeration at that
/// subleaf per spec, but likewise worth zeroing rather than trusting an
/// OS to always respect the termination convention.
/// `apic_id` is *this* vCPU's real initial local APIC ID — KVM assigns it
/// equal to the vCPU index at `KVM_CREATE_VCPU` time, and the guest's own
/// `cpuid` instruction on that vCPU has to report the same value back
/// (bits 31:24 of leaf 1's EBX), or its self-identification during SMP
/// bring-up wouldn't match what the MADT (`acpi.rs`) and INIT-SIPI
/// targeting actually use. `num_cpus` only feeds the informational
/// logical-processor-count field (bits 23:16) — HTT (bit 28 of EDX) stays
/// cleared regardless of `num_cpus`: these are modeled as separate cores
/// via distinct MADT local-APIC entries, not SMT siblings on one core,
/// and ACPI/MADT is the authoritative source Linux actually uses to bring
/// up APs, not this cosmetic topology bit.
pub fn curate(cpuid: &mut CpuId, apic_id: u8, num_cpus: u8) {
    for entry in cpuid.as_mut_slice() {
        match entry.function {
            1 => {
                entry.ecx &= !ECX_MONITOR;
                entry.edx &= !EDX_HTT;
                entry.ebx = (entry.ebx & !0xffff_0000)
                    | (u32::from(apic_id) << 24)
                    | (u32::from(num_cpus) << 16);
            }
            0x0000_000b => {
                // Extended topology enumeration: EBX (logical processors
                // at this level) is already 0 from KVM on this host,
                // which per spec means "this subleaf doesn't describe a
                // real level" — an OS should stop here regardless of
                // EDX. Zero EDX (x2APIC ID) too rather than rely on every
                // possible guest OS honoring that convention.
                entry.edx = 0;
            }
            0x8000_0008 => {
                // AMD's "number of physical threads" (bits 7:0, minus
                // one) and APIC ID core-ID field size (bits 15:12) — both
                // describe *host* topology, which has nothing to do with
                // however many vCPUs this guest has; the MADT
                // (`acpi.rs`) is the authoritative source Linux actually
                // uses to bring APs up. eax (physical/linear address size bits)
                // is left untouched: that describes real addressing
                // width our own page tables (gdt.rs) depend on matching.
                entry.ecx &= !0xf0ff;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_bindings::kvm_cpuid_entry2;

    /// Built from this host's own real `KVM_GET_SUPPORTED_CPUID` output
    /// (captured via a throwaway `kvm-ioctls` program while writing this
    /// module — see the module doc comment) rather than invented values,
    /// so this test exercises the actual bit patterns `curate` has to
    /// handle, not a convenient fiction.
    fn real_leaf(function: u32, index: u32, eax: u32, ebx: u32, ecx: u32, edx: u32) -> kvm_cpuid_entry2 {
        kvm_cpuid_entry2 { function, index, eax, ebx, ecx, edx, ..Default::default() }
    }

    #[test]
    fn clears_monitor_mwait_and_htt_and_sets_this_vcpus_real_apic_id() {
        let leaf1 = real_leaf(1, 0, 0x00a60f12, 0x0a100800, 0xf7f83203, 0x078bfbff);
        let mut cpuid = CpuId::from_entries(&[leaf1]).unwrap();
        curate(&mut cpuid, 3, 4);
        let e = &cpuid.as_slice()[0];

        assert_eq!(e.ecx & ECX_MONITOR, 0, "MONITOR/MWAIT must be cleared");
        assert_eq!(e.edx & EDX_HTT, 0, "HTT must be cleared — MADT is the authoritative SMP topology source");
        assert_eq!(e.ebx >> 24, 3, "initial APIC ID must match this specific vCPU, not the host's");
        assert_eq!((e.ebx >> 16) & 0xff, 4, "logical processor count must reflect the real vCPU count");
        // eax (stepping/model/family) and the rest of ebx (brand index,
        // CLFLUSH size) are real, needed values — curate must leave them
        // alone.
        assert_eq!(e.eax, 0x00a60f12);
        assert_eq!(e.ebx & 0x0000_ffff, 0x0a100800 & 0x0000_ffff);
    }

    #[test]
    fn zeroes_the_leaked_x2apic_id_in_leaf_0xb() {
        // Real capture: EBX=0 already terminates topology enumeration
        // per spec, but EDX leaked a real host thread's x2APIC id (0xa).
        let leaf_b = real_leaf(0xb, 0, 0x0, 0x0, 0x0, 0xa);
        let mut cpuid = CpuId::from_entries(&[leaf_b]).unwrap();
        curate(&mut cpuid, 0, 1);
        assert_eq!(cpuid.as_slice()[0].edx, 0, "x2APIC id must not leak the host's");
    }

    #[test]
    fn clears_the_host_physical_thread_count_from_leaf_0x80000008() {
        // Real capture: ecx=0x400f encodes "16 physical threads" (0xf+1)
        // in bits 7:0 and an ApicIdCoreIdSize in bits 15:12 — both
        // host-topology fields hyperbug shouldn't repeat regardless of
        // how many vCPUs it's actually modeling.
        let leaf_ext8 = real_leaf(0x8000_0008, 0, 0x00303030, 0x531ad205, 0x400f, 0x0);
        let mut cpuid = CpuId::from_entries(&[leaf_ext8]).unwrap();
        curate(&mut cpuid, 0, 1);
        let e = &cpuid.as_slice()[0];
        assert_eq!(e.ecx & 0xf0ff, 0, "physical thread count / APIC core-ID size must be cleared");
        // eax (physical/linear address size) feeds gdt.rs's page tables —
        // must survive untouched.
        assert_eq!(e.eax, 0x00303030);
    }
}
