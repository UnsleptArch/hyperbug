"""A Pythonic wrapper around the `hyperbug` binary.

This shells out to the compiled VMM (there's no in-process FFI binding —
hyperbug the binary owns the KVM fds, guest memory, and the run loop) but
gives you a normal Python object instead of hand-building a CLI string.
"""

from __future__ import annotations

import enum
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


class ExitCode(enum.IntEnum):
    """Why the guest's run ended, from `wait()`/`poll()`'s return value —
    matches `acpi::exit_code` on the Rust side.

    A triple fault is inherently ambiguous: real Linux uses the exact same
    mechanism for a genuine crash, `panic=1`'s auto-reboot, and (absent a
    working ACPI reset path) a plain requested reboot. `REQUESTED_REBOOT`
    only fires when the guest's ACPI reset register was used, which
    hyperbug advertises by default — so it mostly separates "asked to
    reboot" from "crashed", but a kernel panic that then auto-reboots via
    that same clean ACPI path will *also* show as `REQUESTED_REBOOT`, not
    a distinct "panicked" code — hyperbug has no way to tell those apart
    without parsing the guest's own kernel log for "Kernel panic".
    """

    CLEAN_SHUTDOWN = 0
    REQUESTED_REBOOT = 10
    TRIPLE_FAULT = 11
    HALTED = 12
    #: The guest was live-migrated away via a control connection's
    #: `migrate(host, port)` — not a failure; the guest is simply running
    #: in a different (destination) process now. See `migrate()` on
    #: `ControlConnection`.
    MIGRATED_AWAY = 13


#: Exit codes hyperbug itself uses for "refused to even start" (bad CLI
#: args, a device plugin that failed to load, a disk/TAP that couldn't be
#: opened) — distinct from the guest-lifecycle codes in `ExitCode` above.
_LAUNCH_ERROR_CODES = frozenset({1, 2})


class HyperbugLaunchError(RuntimeError):
    """hyperbug exited before the guest ever ran (bad arguments, a device
    plugin failing to load, etc.) — only raised when `start(capture_output=
    True)` was used, since otherwise there's no captured stderr to explain
    why."""

    def __init__(self, returncode: int, stderr: str):
        super().__init__(f"hyperbug exited {returncode} before the guest ran: {stderr.strip()}")
        self.returncode = returncode
        self.stderr = stderr


@dataclass(frozen=True)
class DeviceSpec:
    """A `--device` entry: a Python device plugin at a fixed MMIO address."""

    path: str | Path
    class_name: str
    base: int
    size: int
    #: Optional host-side DMA confinement `(base, size)` for this
    #: plugin's `self.hyperbug.read_mem`/`write_mem` — see
    #: `hyperbug.device.Device`'s docstring. `None` (the default) is
    #: unrestricted, the same as omitting it from the CLI entirely.
    dma_range: tuple[int, int] | None = None

    def to_arg(self) -> str:
        arg = f"{self.path}:{self.class_name}:{self.base:#x}:{self.size:#x}"
        if self.dma_range is not None:
            dma_base, dma_size = self.dma_range
            arg += f":{dma_base:#x}:{dma_size:#x}"
        return arg


@dataclass(frozen=True)
class PciDeviceSpec:
    """A `--pci-device` entry: a Python PCI device plugin (see
    `hyperbug.device.PciDevice`) at the given PCI device number."""

    path: str | Path
    class_name: str
    device_number: int
    #: See `DeviceSpec.dma_range`.
    dma_range: tuple[int, int] | None = None

    def to_arg(self) -> str:
        arg = f"{self.path}:{self.class_name}:{self.device_number}"
        if self.dma_range is not None:
            dma_base, dma_size = self.dma_range
            arg += f":{dma_base:#x}:{dma_size:#x}"
        return arg


@dataclass(frozen=True)
class I2cDeviceSpec:
    """An `--i2c-device` entry: a Python `hyperbug.device.I2cDevice`
    target attached to hyperbug's single virtual I2C bus at a fixed
    7-bit address. The adapter itself (a real `virtio-i2c` device) is
    created automatically the moment any `I2cDeviceSpec` is present."""

    path: str | Path
    class_name: str
    addr: int

    def to_arg(self) -> str:
        return f"{self.path}:{self.class_name}:{self.addr:#x}"


@dataclass(frozen=True)
class GpioDeviceSpec:
    """A `--gpio-device` entry: a Python `hyperbug.device.GpioBank`
    attached as its own independent virtual GPIO bank (its own real
    `virtio-gpio` PCI adapter, unlike `I2cDeviceSpec`'s shared bus)."""

    path: str | Path
    class_name: str

    def to_arg(self) -> str:
        return f"{self.path}:{self.class_name}"


class ControlConnection:
    """A live connection to a *running* guest's `--control-socket`: peek/poke
    a VM's memory and registers while it's actually
    running, not just launch/wait/stop. See `control.rs` on the Rust side
    for the wire protocol this speaks (plain hex-encoded text lines);
    get one via `VM.connect_control()` rather than constructing directly.
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._file = sock.makefile("rwb")

    def read_mem(self, addr: int, size: int) -> bytes:
        """Reads `size` bytes from the live guest's physical memory at
        `addr`. Raises `OSError` if the range is out of bounds."""
        return bytes.fromhex(self._command(f"read_mem {addr:x} {size}"))

    def write_mem(self, addr: int, data: bytes) -> None:
        """Writes `data` into the live guest's physical memory at `addr`.
        Raises `OSError` if the range is out of bounds. There is nothing
        stopping this from corrupting a running guest if you pick a bad
        address — that's the actual point of "live control," and the
        same responsibility a real debugger's memory-write command has."""
        self._command(f"write_mem {addr:x} {data.hex()}")

    def regs(self) -> dict[str, int]:
        """A snapshot of the live guest's vCPU general-purpose registers
        (rip, rsp, rax, ... every `kvm_regs` field) at the moment this is
        called — not a live view, the guest keeps running the instant
        this returns."""
        reply = self._command("regs")
        return {k: int(v, 16) for k, v in (pair.split("=", 1) for pair in reply.split())}

    def write_regs(self, **values: int) -> None:
        """Writes vCPU general-purpose registers on the live guest, e.g.
        `conn.write_regs(rip=0x1000, rax=1)`. Read-modify-write: registers
        you don't name keep their current values, so this is symmetric
        with `regs()` — you can read a snapshot, change one entry, and
        hand it back as `conn.write_regs(**snapshot)`.

        Accepts exactly the field names `regs()` returns. Raises
        `OSError` on an unknown register name, or if KVM rejects the
        values (an `rflags` with its always-set bit 1 cleared, say).
        Like `write_mem`, nothing stops this from wedging a running
        guest — that's the point of live control."""
        if not values:
            raise ValueError("write_regs needs at least one register to write")
        assignments = " ".join(f"{name}={value:x}" for name, value in values.items())
        self._command(f"write_regs {assignments}")

    def snapshot(self, path: str | Path) -> None:
        """Serializes the whole running guest (vCPU state, memory, and
        hyperbug's own device state) to `path`.
        Reload it later with `VM(restore=path, ...)`. Raises `OSError` on
        failure (e.g. an unwritable path)."""
        self._command(f"snapshot {path}")

    def reset_device(self, mmio_base: int | None = None, pci_device_number: int | None = None) -> None:
        """Calls a live `--device`/`--pci-device` plugin's `reset()`
        method, if it defines one (a no-op otherwise), without touching
        its code. Select the device by exactly one of `mmio_base` (the
        fixed address it was loaded at) or `pci_device_number` (the
        number passed to `--pci-device`/`--pci-device-sandboxed`, not the
        internal devfn). Raises `OSError` if no matching device is
        attached."""
        selector = _device_selector(mmio_base, pci_device_number)
        self._command(f"reset_device {selector}")

    def reload_device(self, mmio_base: int | None = None, pci_device_number: int | None = None) -> None:
        """Re-reads a live plugin's file from disk and swaps in a fresh
        instance in place — the same path/class/DMA-range/resource-limits
        it was originally loaded with, just re-instantiated — without
        restarting the guest or changing the device's address. See
        `reset_device` for how to select the device. Raises `OSError` if
        no matching device is attached, or (for a `--pci-device`) if the
        reloaded plugin's PCI identity (vendor/device/class/BAR sizes/
        IRQ/MSI) doesn't exactly match what's already registered — the
        PCI bus caches that identity once and has no way to notice it
        changed later, so a mismatched reload is refused outright rather
        than silently desyncing the guest's view of the device."""
        selector = _device_selector(mmio_base, pci_device_number)
        self._command(f"reload_device {selector}")

    def fork(self, new_control_socket: str | Path) -> int:
        """Clones the *live, running* guest into a brand new, fully
        independent hyperbug process, without disturbing this one at all.
        Guest memory is shared via real copy-on-write (no serialize/copy
        step — this is why fork is dramatically cheaper than
        `snapshot()` + `VM(restore=...)` for the same effect), so the
        child resumes from exactly this instant. Returns the child
        process's real PID. Connect to the child's own new control
        socket (it appears shortly after this call returns, same as any
        `--control-socket` launch) to interact with it.

        Scope, enforced on the Rust side, not just documented: single-vCPU
        only; no `--device`/`--pci-device` plugins of any kind attached;
        and not combinable with `--record`/`--replay`/`--gdb-stub`/
        `--trace-file`. Raises `OSError` if this launch doesn't qualify,
        or if the reactor thread doesn't quiesce in time (fails closed —
        never forks a guest whose background I/O thread might be mid-lock)."""
        return int(self._command(f"fork {new_control_socket}"))

    def migrate(self, dest_addr: str) -> None:
        """Live-migrates the *running* guest to a separate hyperbug
        process listening at `dest_addr` (`"host:port"`) via
        `VM(migrate_listen=dest_addr)`. Streams vCPU state, guest memory,
        and device state over a plain TCP connection to it, then retires
        this process's own guest (`wait()` will return
        `ExitCode.MIGRATED_AWAY`) — unlike `fork()`, nothing is left
        running in this process afterward. Connect to the destination the
        same way as any other control socket once its own launch's
        `control_socket` (if any) is reachable.

        Raises `OSError` if this launch doesn't qualify (multi-vCPU, any
        `devices`/`pci_devices` attached, or `--record`/`--replay`/
        `--gdb-stub`/`--trace-file` in use — see `migrate.rs`'s own scope
        limits), if the destination can't be reached, or if the reactor
        thread can't be quiesced in time (fails closed: never migrates a
        guest whose background I/O thread might be mid-lock). A failed
        attempt leaves this guest running untouched — always safe to
        retry.

        **No encryption or authentication on the migration stream** — see
        `migrate.rs`'s own module doc comment. Fine on a trusted network;
        wrap it in your own tunnel (SSH, a private VPC) for anything
        else."""
        self._command(f"migrate {dest_addr}")

    def close(self) -> None:
        self._file.close()
        self._sock.close()

    def __enter__(self) -> ControlConnection:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def _command(self, line: str) -> str:
        self._file.write((line + "\n").encode())
        self._file.flush()
        reply = self._file.readline().decode().rstrip("\n")
        if reply.startswith("ERR"):
            raise OSError(reply.removeprefix("ERR").strip())
        return reply.removeprefix("OK").strip()


def _device_selector(mmio_base: int | None, pci_device_number: int | None) -> str:
    """Builds the `<mmio|pci> <value>` selector `reset_device`/
    `reload_device` expect — exactly one of `mmio_base`/`pci_device_number`
    must be given."""
    if (mmio_base is None) == (pci_device_number is None):
        raise ValueError("pass exactly one of mmio_base or pci_device_number")
    if mmio_base is not None:
        return f"mmio {mmio_base:#x}"
    return f"pci {pci_device_number}"


def _default_binary() -> str:
    """Finds the hyperbug binary: on PATH first, else the dev build next
    to this checkout (`target/release/hyperbug`, three levels up from
    this file — `python/hyperbug/vm.py`)."""
    found = shutil.which("hyperbug")
    if found:
        return found
    dev_build = Path(__file__).resolve().parents[2] / "target" / "release" / "hyperbug"
    if dev_build.exists():
        return str(dev_build)
    raise FileNotFoundError(
        "hyperbug binary not found on PATH or at the expected dev-build location "
        f"({dev_build}); build it with `cargo build --release` or pass binary=..."
    )


@dataclass
class VM:
    """A hyperbug guest, not yet started until you call `start()` (or use
    this as a context manager, which starts it on entry and terminates it
    on exit).

    Example::

        with VM("vmlinuz", mem_mb=512, disks=["disk.img"], net=True) as vm:
            vm.wait()
    """

    kernel: str | Path
    binary: str | None = None
    initrd: str | Path | None = None
    mem_mb: int = 256
    cmdline: str | None = None
    devices: list[DeviceSpec] = field(default_factory=list)
    pci_devices: list[PciDeviceSpec] = field(default_factory=list)
    #: `--device-sandboxed`: same `DeviceSpec` shape as `devices`, but each
    #: plugin runs in its own subprocess instead of
    #: in-process — a hung or crashed plugin gets killed rather than
    #: stalling or taking down the whole guest.
    sandboxed_devices: list[DeviceSpec] = field(default_factory=list)
    #: `--pci-device-sandboxed`: the `pci_devices` equivalent.
    sandboxed_pci_devices: list[PciDeviceSpec] = field(default_factory=list)
    #: `--i2c-device`: target devices on hyperbug's single virtual I2C
    #: bus. Attaches a real `virtio-i2c` adapter automatically the moment
    #: this is non-empty; empty (the default) means no I2C bus at all.
    i2c_devices: list[I2cDeviceSpec] = field(default_factory=list)
    #: `--gpio-device`: each entry attaches its own independent virtual
    #: GPIO bank (own real `virtio-gpio` PCI adapter).
    gpio_devices: list[GpioDeviceSpec] = field(default_factory=list)
    disks: list[str | Path] = field(default_factory=list)
    net: bool = False
    #: Attaches virtio-rng over the modern virtio 1.0 PCI transport instead
    #: of the legacy I/O-BAR one every other virtio device here still uses
    #: (`--rng-modern`).
    rng_modern: bool = False
    #: Path for a live-control Unix socket — set this
    #: and call `connect_control()` after `start()` to peek/poke the
    #: running guest's memory and registers. `None` (the default) means
    #: no control socket at all.
    control_socket: str | Path | None = None
    #: Number of vCPUs — real multi-vCPU execution, not
    #: a fake reported count: vCPU 0 boots the kernel directly, vCPUs
    #: 1..N come up through a genuine INIT-SIPI-SIPI sequence. 1 (the
    #: default) matches every prior single-vCPU behavior exactly.
    smp: int = 1
    #: Path to a snapshot written by `ControlConnection.snapshot()`.
    #: When set, boots from the snapshot instead of
    #: `kernel`/`initrd` — `kernel` is still required by the CLI parser
    #: but unused. Single-vCPU only; not combinable with `devices`/
    #: `pci_devices` (Python plugin state isn't part of a snapshot).
    restore: str | Path | None = None
    #: `<host>:<port>` to listen on for an incoming live migration
    #: (`--migrate-listen`) instead of booting `kernel`/`initrd` normally.
    #: `kernel` is still required by the CLI parser but unused, same as
    #: `restore` — mutually exclusive with it. Blocks until a separate
    #: hyperbug process's `ControlConnection.migrate()` connects; the rest
    #: of this `VM`'s configuration (`mem_mb`, `disks`, `net`,
    #: `rng_modern`) must match the source guest's exactly. Single-vCPU
    #: only, no `devices`/`pci_devices` — same restrictions as `restore`.
    migrate_listen: str | None = None

    _process: subprocess.Popen | None = field(default=None, init=False, repr=False)
    _capture_output: bool = field(default=False, init=False, repr=False)

    def add_device(self, path: str | Path, class_name: str, base: int, size: int) -> None:
        self.devices.append(DeviceSpec(path, class_name, base, size))

    def add_pci_device(self, path: str | Path, class_name: str, device_number: int) -> None:
        self.pci_devices.append(PciDeviceSpec(path, class_name, device_number))

    def add_sandboxed_device(self, path: str | Path, class_name: str, base: int, size: int) -> None:
        self.sandboxed_devices.append(DeviceSpec(path, class_name, base, size))

    def add_sandboxed_pci_device(self, path: str | Path, class_name: str, device_number: int) -> None:
        self.sandboxed_pci_devices.append(PciDeviceSpec(path, class_name, device_number))

    def add_i2c_device(self, path: str | Path, class_name: str, addr: int) -> None:
        self.i2c_devices.append(I2cDeviceSpec(path, class_name, addr))

    def add_gpio_device(self, path: str | Path, class_name: str) -> None:
        self.gpio_devices.append(GpioDeviceSpec(path, class_name))

    def _build_args(self) -> list[str]:
        args = [self.binary or _default_binary(), "--kernel", str(self.kernel), "--mem", str(self.mem_mb)]
        if self.initrd is not None:
            args += ["--initrd", str(self.initrd)]
        if self.cmdline is not None:
            args += ["--cmdline", self.cmdline]
        if self.restore is not None:
            args += ["--restore", str(self.restore)]
        if self.migrate_listen is not None:
            args += ["--migrate-listen", self.migrate_listen]
        for d in self.devices:
            args += ["--device", d.to_arg()]
        for d in self.pci_devices:
            args += ["--pci-device", d.to_arg()]
        for d in self.sandboxed_devices:
            args += ["--device-sandboxed", d.to_arg()]
        for d in self.sandboxed_pci_devices:
            args += ["--pci-device-sandboxed", d.to_arg()]
        for d in self.i2c_devices:
            args += ["--i2c-device", d.to_arg()]
        for d in self.gpio_devices:
            args += ["--gpio-device", d.to_arg()]
        for disk in self.disks:
            args += ["--disk", str(disk)]
        if self.net:
            args.append("--net")
        if self.rng_modern:
            args.append("--rng-modern")
        if self.control_socket is not None:
            args += ["--control-socket", str(self.control_socket)]
        if self.smp != 1:
            args += ["--smp", str(self.smp)]
        return args

    def start(self, capture_output: bool = False, **popen_kwargs) -> None:
        """Launches the VM. `**popen_kwargs` is passed through to
        `subprocess.Popen` (e.g. `stdout=subprocess.PIPE`).

        By default hyperbug's stdio is inherited — you see the guest's
        serial console live, same as running it by hand. Pass
        `capture_output=True` to instead pipe stderr (so `wait()` can
        raise `HyperbugLaunchError` with the actual message if hyperbug
        refuses to start, e.g. a bad `--mem` value or a device plugin that
        failed to load) — at the cost of no longer seeing that output live
        unless you read `self._process.stdout`/`.stderr` yourself.
        """
        if self._process is not None:
            raise RuntimeError("VM already started")
        self._capture_output = capture_output
        if capture_output:
            popen_kwargs.setdefault("stderr", subprocess.PIPE)
            popen_kwargs.setdefault("stdout", subprocess.PIPE)
        self._process = subprocess.Popen(self._build_args(), **popen_kwargs)

    def wait(self, timeout: float | None = None) -> int:
        """Blocks until the VM exits (the guest halted, shut down, or the
        process otherwise ended) and returns its exit code.

        Raises `HyperbugLaunchError` instead, if `start(capture_output=
        True)` was used and hyperbug exited with one of its own
        launch-failure codes (as opposed to a guest-lifecycle exit code —
        see `ExitCode`) — hyperbug never got as far as running a guest at
        all, so there's a real, specific error message worth surfacing
        rather than just an exit code.
        """
        if self._process is None:
            raise RuntimeError("VM not started")
        code = self._process.wait(timeout=timeout)
        if self._capture_output and code in _LAUNCH_ERROR_CODES:
            stderr = self._process.stderr.read().decode(errors="replace") if self._process.stderr else ""
            raise HyperbugLaunchError(code, stderr)
        return code

    def poll(self) -> int | None:
        """Non-blocking: `None` if still running, else the exit code."""
        if self._process is None:
            raise RuntimeError("VM not started")
        return self._process.poll()

    def connect_control(self, timeout: float = 5.0) -> ControlConnection:
        """Connects to this VM's `--control-socket` (must have been set
        before `start()`) for live memory/register access. Waits up to
        `timeout` seconds for the socket file to appear,
        since it's created once hyperbug binds it, shortly after `start()`
        returns but not necessarily before this is called.
        """
        if self.control_socket is None:
            raise RuntimeError("control_socket wasn't set before start()")
        path = Path(self.control_socket)
        deadline = time.monotonic() + timeout
        while not path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError(f"control socket {path} never appeared after {timeout}s")
            time.sleep(0.02)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(path))
        return ControlConnection(sock)

    def stop(self, timeout: float = 5.0) -> None:
        """Terminates the VM if it's still running (SIGTERM, then SIGKILL
        after `timeout` seconds). A no-op if it already exited."""
        if self._process is None or self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()

    def __enter__(self) -> VM:
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()
