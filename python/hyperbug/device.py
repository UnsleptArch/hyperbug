"""Base classes for hyperbug device plugins.

hyperbug's Rust side loads a device plugin file, instantiates a named
class from it, and calls `read`/`write` by plain attribute/method access
(see src/pydevice.rs) — subclassing these base classes is not required for
that to work, but gets you the documented contract, type hints, and a
clear place to look up what's expected instead of it living only in a
Rust doc comment.
"""

from abc import ABC, abstractmethod

#: The newest plugin ABI version this hyperbug build implements. Bumped
#: only when a *breaking* change is made to the `Device`/`PciDevice`
#: contract itself (a required method's signature, the meaning of an
#: existing attribute, ...) — not for additions like `tick()`, which are
#: purely opt-in and never break an existing plugin that doesn't define
#: them. `Device`/`PciDevice` subclasses pick this up automatically as
#: `self.hyperbug_api_version`; hyperbug's Rust side checks it once at
#: load (see `src/pydevice.rs`/`src/pydevice_proc.rs`) against the
#: inclusive range `[HYPERBUG_API_MIN_SUPPORTED, HYPERBUG_API_VERSION]` —
#: declaring something newer means the plugin needs a newer hyperbug;
#: declaring something older than `HYPERBUG_API_MIN_SUPPORTED` means
#: hyperbug has since dropped support for that contract. Either fails
#: loudly at load, saying which, instead of silently running the plugin
#: against a shape it never agreed to. A plugin that doesn't subclass
#: `Device` at all (duck-typing is explicitly supported — see the module
#: docstring) has no version to check, and loads exactly as before this
#: existed.
HYPERBUG_API_VERSION = 1

#: The oldest `hyperbug_api_version` a plugin may declare and still be
#: accepted — see `HYPERBUG_API_VERSION` above. Equal to it today (only
#: one contract has ever existed); bumped only alongside
#: `HYPERBUG_API_VERSION` when an old, numbered contract can no longer be
#: supported.
HYPERBUG_API_MIN_SUPPORTED = 1


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

    # `reset(self) -> None` is *not* defined here either, same reasoning
    # and same opt-in check (`HAS_RESET`) as `tick` above. The difference
    # from `tick`: nothing in hyperbug calls this automatically — there's
    # no in-guest reset trigger modeled today (no PCI function-level
    # reset, no guest-driver-initiated reset). The only real caller is the
    # live control socket's `reset_device <mmio|pci> <selector>` command
    # (see `hyperbug.vm.ControlConnection.reset_device`) — an operator
    # explicitly asking this specific device to reinitialize. If you want
    # one, just add:
    #
    #     def reset(self) -> None:
    #         """Reinitialize this device's internal state, analogous to
    #         a real hardware reset line. Called only when an operator
    #         explicitly asks for it via the control socket — never
    #         automatically."""


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


class I2cDevice(ABC):
    """A target device on hyperbug's single virtual I2C bus.

    Register with ``--i2c-device <path>:<ClassName>:<addr>`` (a 7-bit
    address, 0x00-0x7f). The guest reaches this through a real
    ``virtio-i2c`` adapter (``VIRTIO_ID_I2C_ADAPTER``) that its own
    unmodified ``i2c-virtio`` kernel driver binds to -- no custom guest
    driver needed, and no fixed register-offset addressing the way
    `Device` has: I2C messages are just address + direction + a byte
    buffer, matching the guest's own ``i2c_msg`` abstraction.

    Unlike `Device`, an `I2cDevice` gets **no** ``self.hyperbug`` DMA
    context -- it never sees guest memory directly, only the bytes of
    whichever message was addressed to it. Also unlike `Device`, there's
    no PCI identity to declare here: the *adapter* (one per hyperbug
    process, created automatically the moment any `I2cDevice` is
    attached) is what the guest's PCI core sees; individual targets are
    invisible to PCI enumeration, exactly like real I2C peripherals.

    Real I2C transactions frequently chain a write (setting an internal
    "register pointer") immediately followed by a read (returning data
    from that pointer) with no bus release in between -- the standard way
    almost every real sensor works. hyperbug delivers `i2c_write`/
    `i2c_read` calls to the *same* long-lived instance, strictly in the
    order the guest issued them, which is enough for a stateful device to
    implement that idiom correctly with nothing more than an instance
    attribute (see `devices/i2c_temp_sensor.py` for a worked example) --
    there's no separate "transaction" object or start/stop callback to
    manage.
    """

    #: See `HYPERBUG_API_VERSION` above -- checked once at load, same as
    #: `Device`.
    hyperbug_api_version: int = HYPERBUG_API_VERSION

    @abstractmethod
    def i2c_write(self, data: bytes) -> None:
        """Handle a write-direction message: `data` is exactly what the
        guest wrote in one `i2c_msg` (may be empty -- a real I2C master
        can issue a zero-length write purely to probe whether a device
        answers this address at all; that case never reaches this
        method, since hyperbug ACKs/NAKs a zero-length probe from
        whether a device is registered at all, with no `i2c_write`/
        `i2c_read` call either way)."""
        raise NotImplementedError

    @abstractmethod
    def i2c_read(self, length: int) -> bytes:
        """Return up to `length` bytes for a read-direction message.
        Returning fewer than `length` bytes is fine (only the bytes you
        return are transferred); returning more is truncated."""
        raise NotImplementedError


class GpioBank(ABC):
    """One virtual GPIO chip on hyperbug's guest-facing GPIO surface.

    Register with ``--gpio-device <path>:<ClassName>`` -- unlike
    `I2cDevice` (many targets sharing one bus), each `GpioBank` gets its
    own independent PCI slot and its own real ``virtio-gpio`` adapter
    (``VIRTIO_ID_GPIO``), matching real BMC hardware's typically several
    separate GPIO controllers rather than one shared bus.

    Every instance also gets a ``self.hyperbug`` attribute (set right
    after construction, same timing as `Device`'s) with exactly one
    method: ``self.hyperbug.raise_irq(line)``, which marks `line` as
    having spontaneously changed state. It's delivered to the guest as a
    real interrupt only if that line currently has one armed (the guest
    posted a buffer for it) and enabled (`IRQ_TYPE` isn't `NONE`) --
    otherwise dropped, matching a real masked/disabled interrupt. This is
    real eventfd-backed and thread-safe to call from anywhere, including
    your own background Python thread (`threading.Timer`, a polling
    loop) -- there's no per-iteration `tick()` hook the way `Device` has,
    since this already covers the same need with no extra polling path.
    """

    #: See `HYPERBUG_API_VERSION` above.
    hyperbug_api_version: int = HYPERBUG_API_VERSION

    #: Number of lines this bank exposes. Fixed for the life of the bank
    #: -- read once when the plugin is loaded.
    ngpio: int

    #: Optional per-line names, exposed to the guest via
    #: `GPIO_V2_GET_LINEINFO_IOCTL`-shaped introspection. Either omit
    #: entirely (no names offered at all -- the real driver never even
    #: asks) or supply exactly `ngpio` entries.
    names: list[str] = []

    @abstractmethod
    def get_direction(self, line: int) -> int:
        """Return one of `hyperbug.gpio`'s `DIRECTION_NONE`/`DIRECTION_
        OUT`/`DIRECTION_IN` for `line`."""
        raise NotImplementedError

    @abstractmethod
    def set_direction(self, line: int, direction: int) -> None:
        """`direction` is one of `DIRECTION_NONE`/`DIRECTION_OUT`/
        `DIRECTION_IN` -- already validated before this is called."""
        raise NotImplementedError

    @abstractmethod
    def get_value(self, line: int) -> int:
        """Return 0 or 1 for `line`'s current value."""
        raise NotImplementedError

    @abstractmethod
    def set_value(self, line: int, value: int) -> None:
        """`value` is 0 or 1 -- already masked before this is called."""
        raise NotImplementedError
