/*
 * hyperbug's minimal DSDT. Three things live here, all because there is
 * no way to provide them from anywhere else in the boot path:
 *
 * 1. \_S5 (shutdown sleep-state package). hyperbug uses ACPI's
 *    hardware-reduced sleep model (see acpi.rs — FADT HW_REDUCED flag,
 *    SLEEP_CONTROL_REG/SLEEP_STATUS_REG instead of the legacy PM1a_CNT
 *    register), but the OS still needs \_S5's SLP_TYP value from AML
 *    regardless of which register receives it. The actual value (0) is
 *    arbitrary and meaningful only to hyperbug's own sleep-control-
 *    register handler: any write with SLP_EN set means "power off," full
 *    stop, since hyperbug doesn't implement S1-S4 at all.
 *
 * 2. \_SB.COM1 (the legacy serial port's ACPI resource description).
 *    Without this, Linux's ACPI-aware PNP resource management treats
 *    ISA IRQ4 as unclaimed by anything in the ACPI namespace and marks
 *    its irq_desc IRQ_NOREQUEST — a real boot found this via a kprobe on
 *    request_threaded_irq() (DEBTS.md item 33): it returned -EINVAL
 *    before ever calling irq_to_desc(), and disassembling the running
 *    kernel's actual request_threaded_irq (via its real vmlinux, not
 *    memory) showed the exact check — `test $0x800 (IRQ_NOREQUEST),
 *    %ecx; jne <fail>` — confirming the descriptor exists but is marked
 *    unrequestable. This is exactly what a real BIOS's DSDT normally
 *    prevents by describing every legacy device (PNP0501 is the
 *    standard EISA ID for a 16550-compatible serial port) so ACPI's own
 *    resource tracking knows the IRQ is legitimately spoken for.
 *
 * 3. \_SB.PCI0's _PRT (PCI interrupt routing table). Without this,
 *    hyperbug's PCI devices only work because Linux happens to trust the
 *    raw `interrupt_line` byte in their config space directly (see
 *    DEBTS.md item 3) — untested, and not something newer kernels are
 *    guaranteed to keep doing. This table makes the routing explicit and
 *    ACPI-discoverable instead.
 *
 *    The four slot ranges below (disks, net, rng) are `main.rs`'s *fixed*
 *    PCI slot assignment (DEBTS.md item 4's fix) — they do not move based
 *    on how many --disk/--net/--pci-device flags are actually given at
 *    runtime, which is exactly what makes a static, compiled-ahead-of-time
 *    table like this correct at all. If `main.rs`'s slot/IRQ constants
 *    ever change, this table has to change with them — nothing enforces
 *    that link automatically.
 *
 * Regenerate with: iasl dsdt.asl   (produces dsdt.aml; then
 * `cp dsdt.aml ../src/dsdt.aml` — or just run `cargo build`, which
 * verifies but does not auto-copy; see build.rs)
 */
DefinitionBlock ("dsdt.aml", "DSDT", 2, "HYPRBG", "HBDSDT", 1)
{
    Name (\_S5, Package (0x04)
    {
        0x00,
        0x00,
        0x00,
        0x00
    })

    Scope (\_SB)
    {
        Device (COM1)
        {
            Name (_HID, EisaId ("PNP0501")) // 16550A-compatible serial port
            Name (_UID, 0x01)
            Name (_CRS, ResourceTemplate ()
            {
                IO (Decode16, 0x03F8, 0x03F8, 0x00, 0x08)
                IRQNoFlags () {4}
            })
        }

        Device (PCI0)
        {
            Name (_HID, EisaId ("PNP0A03")) // PCI root bridge
            Name (_UID, 0x00)
            Name (_BBN, 0x00) // bus 0, hyperbug's only bus

            // Without a _CRS, "PCI: Using host bridge windows from ACPI"
            // (main.rs prints no host-bridge hint of its own, so ACPI is
            // authoritative once present) leaves the PCI core with *no*
            // I/O or memory apertures to allocate BARs from at all — every
            // device's BAR assignment then fails with "can't assign; no
            // space", which is exactly what a real boot caught (every
            // virtio-pci probe returning -EIO from a NULL pci_iomap()).
            // I/O window avoids every fixed port hyperbug's own code uses
            // (COM1 0x3f8-0x3ff, PIC 0x20/0xa0, PIT 0x40-0x43, CMOS
            // 0x70-0x71, ACPI 0x600-0x605, CF8/CFC config space); memory
            // window sits in the classic sub-4GiB "PCI hole", below the
            // IOAPIC at 0xfec00000.
            Name (_CRS, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    0x0000, 0x0000, 0x0000, 0x0000, 0x0001)
                DWordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000, 0x0000C000, 0x0000FFFF, 0x0000, 0x00004000)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
                    0x00000000, 0xC0000000, 0xFEBFFFFF, 0x00000000, 0x3EC00000)
            })

            // Package { Address, Pin, Source, SourceIndex }. Every
            // hyperbug PCI device uses INTA# (Pin 0) and Source=Zero
            // (GSI given directly via SourceIndex, no Link Device
            // indirection) — matching the fixed IRQs main.rs assigns.
            Name (_PRT, Package (0x0A)
            {
                // virtio-blk: slots 4-11 (main.rs::VIRTIO_BLK_SLOT_BASE/
                // MAX_DISKS), all sharing IRQ 10 (main.rs::VIRTIO_BLK_IRQ).
                Package (0x04) { 0x0004FFFF, 0x00, Zero, 0x0A },
                Package (0x04) { 0x0005FFFF, 0x00, Zero, 0x0A },
                Package (0x04) { 0x0006FFFF, 0x00, Zero, 0x0A },
                Package (0x04) { 0x0007FFFF, 0x00, Zero, 0x0A },
                Package (0x04) { 0x0008FFFF, 0x00, Zero, 0x0A },
                Package (0x04) { 0x0009FFFF, 0x00, Zero, 0x0A },
                Package (0x04) { 0x000AFFFF, 0x00, Zero, 0x0A },
                Package (0x04) { 0x000BFFFF, 0x00, Zero, 0x0A },
                // virtio-net: slot 16 (main.rs::VIRTIO_NET_SLOT), IRQ 11.
                Package (0x04) { 0x0010FFFF, 0x00, Zero, 0x0B },
                // virtio-rng: slot 17 (main.rs::VIRTIO_RNG_SLOT), IRQ 12.
                Package (0x04) { 0x0011FFFF, 0x00, Zero, 0x0C }
            })
        }
    }
}
