"""hyperbug: a scriptable KVM VMM.

- `hyperbug.Device` / `hyperbug.PciDevice` — base classes for device
  plugins, loaded by the Rust side via `--device`/`--pci-device`.
- `hyperbug.VM` — a Pythonic wrapper for launching the `hyperbug` binary,
  for scripting/tooling that drives a guest rather than running it by hand.
"""

from .device import Device, PciDevice
from .vm import VM, ControlConnection, DeviceSpec, ExitCode, HyperbugLaunchError, PciDeviceSpec

__all__ = [
    "Device",
    "PciDevice",
    "VM",
    "ControlConnection",
    "DeviceSpec",
    "PciDeviceSpec",
    "ExitCode",
    "HyperbugLaunchError",
]
