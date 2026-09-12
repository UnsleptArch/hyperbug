# Reference device for hyperbug's Python device ABI: a toy 16-byte MMIO
# register block. Every register echoes back the last value written to it,
# except register 0, which counts how many times it's been written and
# requests an interrupt on every 4th write, just to demonstrate the hook.
#
# See python/hyperbug/device.py for the full Device contract.

from hyperbug import Device


class ScratchDevice(Device):
    def __init__(self):
        self.regs = bytearray(16)
        self.write_count = 0

    def read(self, offset, size):
        return bytes(self.regs[offset : offset + size])

    def write(self, offset, data):
        self.regs[offset : offset + len(data)] = data
        if offset == 0:
            self.write_count += 1
            return self.write_count % 4 == 0
