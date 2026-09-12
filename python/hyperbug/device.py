"""Base classes for hyperbug device plugins.

hyperbug's Rust side loads a device plugin file, instantiates a named
class from it, and calls `read`/`write` by plain attribute/method access
(see src/pydevice.rs) — subclassing these base classes is not required for
that to work, but gets you the documented contract, type hints, and a
clear place to look up what's expected instead of it living only in a
Rust doc comment.
"""

from abc import ABC, abstractmethod

#: Bumped only when a *breaking* change is made to the `Device`/`PciDevice`
#: contract itself (a required method's signature, the meaning of an
#: existing attribute, ...) — not for additions like `tick()`, which are
#: purely opt-in and never break an existing plugin that doesn't define
#: them. `Device`/`PciDevice` subclasses pick this up automatically as
#: `self.hyperbug_api_version`; hyperbug's Rust side checks it once at load
#: (see `src/pydevice.rs`) and refuses to load a plugin that declares a
#: version other than what this build implements, rather than silently
#: running it against a contract that's since changed underneath it. A
#: plugin that doesn't subclass `Device` at all (duck-typing is explicitly
#: supported — see the module docstring) has no version to check, and
#: loads exactly as before this existed.
HYPERBUG_API_VERSION = 1


class Device(ABC):
    """A memory-mapped (or I/O-port-mapped) device.

    Register with hyperbug via ``--device <path>:<ClassName>:<base>:<size>``
    for a fixed-address MMIO device, or as part of a `PciDevice` for one
    whose address comes from PCI enumeration instead.

    Every instance also gets a ``self.hyperbug`` attribute set right after
    construction (not available inside ``__init__`` — defer anything that
    needs it to the first `read`/`write` call instead), giving access to:

    - ``self.hyperbug.read_mem(addr, size) -> bytes`` /
      ``self.hyperbug.write_mem(addr, data)`` — real DMA against guest
      physical memory, bounds-checked (raises `OSError` on an
      out-of-range address, since a guest-supplied address is untrusted
      input). Lets a device act like real hardware would: read a
      descriptor the guest posted, write a response into a
      guest-supplied buffer, instead of only ever exposing its own
      internal register state.

      **Also raises `OSError`** if the operator launched this plugin with
      a declared DMA-confinement range (the optional trailing
      ``:<dma_base>:<dma_size>`` on ``--device``/``--pci-device`` and
      their ``-sandboxed`` variants) and `addr` falls outside it — a
      host-side vIOMMU-shaped control, invisible to the guest, that
      bounds what this specific plugin instance may touch regardless of
      what its own code does. Not something a plugin can query or opt out
      of from inside itself: whether it's applied, and to what range, is
      entirely the launching operator's decision. Most plugins (including
      every one shipped in `devices/`) run with no such restriction and
      never see this — it exists for confining a numerous or third-party
      plugin an operator doesn't fully trust with all of guest RAM.
    - ``self.hyperbug.raise_irq()`` — requests this device's configured
      interrupt (see `PciDevice.interrupt_line` below) *spontaneously*,
      any time, not only synchronously from inside `write()` the way a
      truthy return does. This is a **separate mechanism** from `write`'s
      return value below — a device that raises its interrupt via
      `raise_irq()` should not also return `True`, and vice versa; mixing
      them up is an easy mistake (see `devices/dma_demo.py` for a worked
      example using `raise_irq()`, and `devices/scratch.py` for the
      plain-return-value style).
    """

    #: See `HYPERBUG_API_VERSION` above — checked once at load, not meant
    #: to be overridden by a plugin.
    hyperbug_api_version: int = HYPERBUG_API_VERSION

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Return exactly `size` bytes read from `offset` (relative to
        this device's own base address, not the raw guest address)."""
        raise NotImplementedError

    @abstractmethod
    def write(self, offset: int, data: bytes) -> bool | None:
        """Handle `data` written at `offset`.

        Return `True` to request that this device's configured interrupt
        (if it has one — only meaningful for a `PciDevice` registered via
        `--pci-device`) be raised right now, synchronously. Returning
        `None` (i.e. not returning anything) is the same as `False`. See
        `self.hyperbug.raise_irq()` above for the spontaneous alternative.
        """
        raise NotImplementedError

    # `tick(self) -> None` is *not* defined here, deliberately: hyperbug
    # checks once at load whether a plugin defines one **at all** (see
    # `check_api_version`'s sibling check in `src/pydevice.rs`/
    # `_sandbox_runner.py`) and only ever calls a plugin that does — giving
    # `Device` itself a no-op `tick` would make every subclass "define
    # one" whether it overrides it or not, defeating that. If you want
    # one, just add:
    #
    #     def tick(self) -> None:
    #         """Called once per host vCPU-loop iteration, independent of
    #         any guest register access. Use it for logic that shouldn't
    #         wait for the guest to touch a register first: a simulated
    #         timer, or an asynchronous transaction (post a request, then
    #         some time later — not necessarily in response to any guest
    #         write — call `self.hyperbug.raise_irq()` once it completes).
    #         See `devices/doorbell_demo.py` for a worked example of the
    #         latter."""


class PciDevice(Device):
    """A `Device` that also declares a PCI identity, for
    ``--pci-device <path>:<ClassName>:<device_number>``.

    hyperbug's own code has no opinion on what any specific PCI device is
    — vendor ID, device ID, and everything else about a real device's
    identity belongs here, in your plugin, not in hyperbug's Rust core.

    Set these as class or instance attributes. hyperbug reads them
    **once**, when the device is loaded, and serves PCI config space from
    that snapshot afterwards — the same way a real device's config-space
    identity bytes are fixed in silicon. Changing one of these attributes
    later, at runtime, has no effect (and reading them per config-space
    access would mean taking the GIL for every dword the guest touches
    while enumerating the bus).
    """

    #: 16-bit PCI vendor ID.
    vendor_id: int
    #: 16-bit PCI device ID.
    device_id: int
    #: Packed 24-bit (base class << 16 | subclass << 8 | prog-if) PCI
    #: class code, e.g. 0x020000 for an Ethernet controller.
    class_code: int
    #: BAR sizes in bytes, BAR0 first; up to 6 entries, 0 (or omitted)
    #: meaning "this BAR isn't implemented".
    bar_sizes: list[int]
    #: Optional: BAR indices (0-5) that are I/O-space rather than
    #: memory-space. Omit entirely (the default) if every BAR is
    #: memory-space, which is what real hardware almost always is outside
    #: of legacy devices like virtio's own BAR0.
    io_bars: list[int]
    #: Optional: the legacy ISA IRQ (1-15) this device's interrupt is
    #: wired to. Without one, both `write()`'s truthy-return path and
    #: `self.hyperbug.raise_irq()` have nothing to pulse (0, the default,
    #: means "no interrupt" throughout hyperbug — see `pci.rs`). Must
    #: actually be routed: a `--pci-device` slot outside the ranges
    #: `acpi/dsdt.asl`'s `_PRT` already covers (disks 4-11, net 16, rng
    #: 17) has no ACPI routing entry for whatever IRQ you pick here, so it
    #: won't deliver under ACPI without adding one there too — it will
    #: still work with ACPI disabled, which trusts this value directly.
    interrupt_line: int
    #: Optional: set `True` to give this device a real PCI MSI capability
    #: (single message, 32-bit address, no per-vector masking — the
    #: simplest real form; not MSI-X). If a guest driver enables it,
    #: `write()`'s truthy return and `self.hyperbug.raise_irq()` both
    #: deliver via a real `KVM_SIGNAL_MSI` instead of pulsing
    #: `interrupt_line` — transparent to your device code either way, you
    #: still just return `True` or call `raise_irq()`. See
    #: `devices/dma_demo.py` for a worked example. **Not useful for
    #: emulating virtio**: hyperbug's own virtio devices deliberately
    #: never set this — checked directly against the real Linux virtio
    #: driver source, which only ever requests MSI-X or falls back to
    #: plain INTx, never single-vector MSI, so a virtio-shaped device
    #: would never actually have this used by a real driver. It's for a
    #: *custom* device model with its own (real or hypothetical) driver
    #: that genuinely requests plain MSI.
    msi_capable: bool
