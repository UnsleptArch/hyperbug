"""A reference I2C target device: a simple, self-invented temperature
sensor exercising the extremely common real-world "write register
pointer, then read its contents" idiom — not a clone of any specific real
chip's register layout (deliberately: hyperbug's own vendor-neutrality
rule applies to plugins meant as reference examples too, the same way
`devices/doorbell_demo.py` invented its own register map instead of
copying real silicon).

Register map (selected by a 1-byte write, exactly like a real sensor):
  0x00  temperature, big-endian signed 16-bit, tenths of a degree C
  0x01  a single read/write configuration byte (unused by anything
        except this demo, to show a write can also carry a value:
        `i2c_write(bytes([1, value]))` sets register 1 to `value`)

Attach with e.g.::

    hyperbug --kernel vmlinuz --i2c-device devices/i2c_temp_sensor.py:I2cTempSensor:0x48 ...

0x48 is an arbitrary, unassigned 7-bit address chosen only for the demo —
picking a real chip's well-known address here would misleadingly suggest
this behaves like that chip, which it doesn't.
"""

import struct

from hyperbug.device import I2cDevice

REG_TEMPERATURE = 0x00
REG_CONFIG = 0x01


class I2cTempSensor(I2cDevice):
    def __init__(self):
        self._register = REG_TEMPERATURE
        self._temp_tenths_c = 235  # 23.5 C, an arbitrary fixed reading
        self._config = 0

    def i2c_write(self, data: bytes) -> None:
        if not data:
            return
        self._register = data[0]
        if len(data) > 1 and self._register == REG_CONFIG:
            self._config = data[1]

    def i2c_read(self, length: int) -> bytes:
        if self._register == REG_TEMPERATURE:
            return struct.pack(">h", self._temp_tenths_c)[:length]
        if self._register == REG_CONFIG:
            return bytes([self._config])[:length]
        return bytes(length)  # an unrecognized register reads as zero
