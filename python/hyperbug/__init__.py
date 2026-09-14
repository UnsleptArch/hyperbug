"""hyperbug: a scriptable KVM VMM.

- `hyperbug.Device` / `hyperbug.PciDevice` — base classes for device
  plugins, loaded by the Rust side via `--device`/`--pci-device`.
- `hyperbug.I2cDevice` / `hyperbug.GpioBank` — base classes for the
  separate I2C target-device and GPIO-bank contracts, loaded via
  `--i2c-device`/`--gpio-device`.
- `hyperbug.VM` — a Pythonic wrapper for launching the `hyperbug` binary,
  for scripting/tooling that drives a guest rather than running it by hand.
"""

from .device import Device, GpioBank, I2cDevice, PciDevice
from .vm import (
    VM,
    ControlConnection,
    DeviceSpec,
    ExitCode,
    GpioDeviceSpec,
    HyperbugLaunchError,
    I2cDeviceSpec,
    PciDeviceSpec,
)

__all__ = [
    "Device",
    "PciDevice",
    "I2cDevice",
    "GpioBank",
    "VM",
    "ControlConnection",
    "DeviceSpec",
    "PciDeviceSpec",
    "I2cDeviceSpec",
    "GpioDeviceSpec",
    "ExitCode",
    "HyperbugLaunchError",
]
