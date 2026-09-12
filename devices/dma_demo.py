# Reference device demonstrating the `self.hyperbug` context (DMA +
# spontaneous interrupts) added alongside the plain register-file ABI that
# scratch.py demonstrates. Register layout, all little-endian, offsets
# relative to this device's own BAR0:
#
#   0x00  buffer_addr (8 bytes) : guest-physical address of the buffer
#   0x08  length      (4 bytes) : number of bytes to operate on
#   0x0c  command     (1 byte)  : write 1 to reverse `length` bytes at
#                                 `buffer_addr` in place via DMA, then
#                                 raise this device's interrupt
#
# A real device would do this asynchronously (queue the work, do it on a
# "tick", raise_irq() later); this one does it synchronously from inside
# write() for a self-contained, single-file demonstration of both halves
# of the context (`read_mem`/`write_mem` and `raise_irq`) together. See
# python/hyperbug/device.py for the full PciDevice contract this device
# also demonstrates the `interrupt_line` attribute of.

from hyperbug import PciDevice

CMD_REVERSE = 1


class DmaDemoDevice(PciDevice):
    # 0x1234/0x0001: the same "not real silicon" placeholder vendor used
    # elsewhere in this repo (pci.rs's HostBridge) — this is a
    # demonstration device, not a real one.
    vendor_id = 0x1234
    device_id = 0x0001
    class_code = 0xFF0000  # "unassigned class", matching virtio's own convention
    bar_sizes = [0x10]
    # Must be a legacy ISA IRQ (1-15) actually routed to this slot's _PRT
    # entry under ACPI, or trusted directly via the raw PCI config-space
    # `interrupt_line` byte otherwise — this example
    # picks 9, a commonly-free legacy IRQ, and assumes whoever wires this
    # device up with `--pci-device` has picked a slot/IRQ pairing that
    # doesn't collide with anything else on the bus. Also the fallback
    # `raise_irq()` uses if `msi_capable` below is true but the guest
    # hasn't (or can't) enable MSI.
    interrupt_line = 9
    # Opts into a real PCI MSI capability. A guest driver
    # that enables it makes `raise_irq()` deliver via `KVM_SIGNAL_MSI`
    # instead of the legacy `interrupt_line` pulse — transparent to this
    # device, which always just calls `raise_irq()` either way.
    msi_capable = True

    def __init__(self):
        self.buffer_addr = 0
        self.length = 0

    def read(self, offset, size):
        if offset == 0:
            return self.buffer_addr.to_bytes(8, "little")[:size]
        if offset == 8:
            return self.length.to_bytes(4, "little")[:size]
        return bytes(size)

    def write(self, offset, data):
        if offset == 0:
            self.buffer_addr = int.from_bytes(data, "little")
        elif offset == 8:
            self.length = int.from_bytes(data, "little")
        elif offset == 0xC and data and data[0] == CMD_REVERSE:
            buf = bytearray(self.hyperbug.read_mem(self.buffer_addr, self.length))
            buf.reverse()
            self.hyperbug.write_mem(self.buffer_addr, bytes(buf))
            self.hyperbug.raise_irq()
