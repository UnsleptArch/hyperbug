"""Internal: runs one device plugin in its own process, talking to
hyperbug's Rust side over stdin/stdout with a small binary framed
protocol.

Not part of the public API — `hyperbug.VM`/device authors never import
this directly. Invoked by the Rust side (`src/pydevice_proc.rs`) as::

    python3 -m hyperbug._sandbox_runner <plugin_path> <class_name>

Why a real subprocess instead of another in-process interruption trick:
two different ways to forcibly interrupt a stuck plugin call from
*inside* the same process were tried first (`PyErr_SetInterrupt`,
`PyThreadState_SetAsyncExc`) — one hung under real concurrent load, the
other segfaulted. Neither failure mode is possible here: a subprocess
that stops responding gets killed at the OS level (`SIGKILL`), which
cannot hang or corrupt the parent process's own state.

Wire protocol: length-prefixed binary frames, not hex-encoded text —
picked over the original text protocol once payload volume started to
matter (a device with real bulk data, not just register-sized traffic,
pays double for hex encoding and for parsing it byte-pair by byte-pair).
Every frame is ``<u32 length, little-endian><type byte><payload>``, where
`length` counts the type byte plus the payload (so the minimum frame is 5
bytes: a 4-byte length of 1, plus one type byte and no payload).

Message types, parent -> child (always exactly one outstanding, since the
parent only ever holds one device behind one lock, same as the in-process
model):
  - ``IDENTITY`` (no payload) -> ``OK_IDENTITY`` (see below) if the class
    is a `PciDevice`, or ``OK_IDENTITY`` with a leading zero byte for a
    plain `Device`.
  - ``READ`` (payload: ``<u64 offset><u32 size>``) -> ``OK_BYTES``
    (payload: the bytes) or ``ERR`` (payload: a UTF-8 message)
  - ``WRITE`` (payload: ``<u64 offset><data>``) -> ``OK_BOOL`` (payload:
    one byte, 1 = the device's `write()` requested its interrupt) or
    ``ERR``
  - ``HAS_TICK`` (no payload) -> ``OK_BOOL`` — whether the class defines a
    `tick` method at all, checked once at load so the parent only ever
    sends `TICK` (below) to a plugin that actually implements one.
  - ``TICK`` (no payload) -> ``OK`` or ``ERR`` — calls `instance.tick()`,
    for logic that needs to run independent of any register access (a
    simulated timer, an async transaction whose completion isn't driven
    by the guest touching a register at all). Only ever sent if
    `HAS_TICK` reported true.
  - ``HAS_RESET`` (no payload) -> ``OK_BOOL`` — whether the class defines
    a `reset` method, mirroring `HAS_TICK`.
  - ``RESET`` (no payload) -> ``OK`` or ``ERR`` — calls `instance.reset()`,
    asking the plugin to reinitialize its internal state. Unlike `TICK`,
    nothing in hyperbug sends this automatically; it only ever arrives in
    response to the live control socket's `reset_device` command — an
    operator explicitly asking a specific device to reset. Only ever
    sent if `HAS_RESET` reported true.
  - ``SHUTDOWN`` (no payload) -> child exits cleanly, no reply expected

Child -> parent, sent *while* handling a `READ`/`WRITE` (nested — the
parent answers immediately and the child's original command is still
pending):
  - ``CB_READ_MEM`` (payload: ``<u64 addr><u32 size>``) -> ``OK_BYTES`` or
    ``ERR``
  - ``CB_WRITE_MEM`` (payload: ``<u64 addr><data>``) -> ``OK`` or ``ERR``

Child -> parent, sent at *any* time with no reply expected (fire-and-
forget — the plugin's own background thread can call
``self.hyperbug.raise_irq()`` whenever it wants, same as the in-process
model's spontaneous-interrupt path):
  - ``CB_RAISE_IRQ`` (no payload)

`OK_IDENTITY`'s payload (only meaningful when the class is a `PciDevice`):
a leading byte (1 = identity follows, 0 = none), then if 1:
``<u16 vendor><u16 device><u32 class><6x u32 bar_sizes><u8 io_bar_mask>
<u8 interrupt_line><u8 msi_capable>`` — `io_bar_mask` is a bitmask, bit i
set meaning BAR i is I/O-space.
"""

from __future__ import annotations

import importlib.util
import struct
import sys
import threading

_stdout_lock = threading.Lock()

# Parent -> child requests.
MSG_IDENTITY = 1
MSG_READ = 2
MSG_WRITE = 3
MSG_HAS_TICK = 4
MSG_TICK = 5
MSG_SHUTDOWN = 6
MSG_HAS_RESET = 7
MSG_RESET = 8

# Replies, either direction.
MSG_OK = 0x80
MSG_OK_BYTES = 0x81
MSG_OK_BOOL = 0x82
MSG_OK_IDENTITY = 0x83
MSG_ERR = 0xFF

# Child -> parent, nested callbacks.
MSG_CB_READ_MEM = 0x90
MSG_CB_WRITE_MEM = 0x91
MSG_CB_RAISE_IRQ = 0x92

_NUM_BARS = 6


def _read_exact(n: int) -> bytes | None:
    """Reads exactly `n` bytes from stdin, looping over short reads (a
    pipe can hand back fewer bytes than requested). `None` on EOF before
    `n` bytes were seen."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sys.stdin.buffer.read(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _read_frame() -> tuple[int, bytes] | None:
    header = _read_exact(4)
    if header is None:
        return None
    (length,) = struct.unpack("<I", header)
    if length == 0:
        return None  # malformed: every frame has at least a type byte
    body = _read_exact(length)
    if body is None:
        return None
    return body[0], body[1:]


def _write_frame(msg_type: int, payload: bytes = b"") -> None:
    body = bytes([msg_type]) + payload
    with _stdout_lock:
        sys.stdout.buffer.write(struct.pack("<I", len(body)))
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()


class _RemoteHyperbugCtx:
    """What `self.hyperbug` is inside the sandboxed plugin — same three
    calls as the in-process `HyperbugCtx`, each a synchronous round trip
    to the parent over the same stdin/stdout pair `_dispatch` below reads
    commands from. Safe to call from any thread: `_stdout_lock` (module-
    level, shared with the main dispatch loop) serializes every write, and
    a reply always follows the request that caused it before anything
    else reads stdin again (the parent never sends an unsolicited frame).
    """

    def read_mem(self, addr: int, size: int) -> bytes:
        _write_frame(MSG_CB_READ_MEM, struct.pack("<QI", addr, size))
        frame = _read_frame()
        if frame is None:
            raise OSError("parent closed the connection")
        msg_type, payload = frame
        if msg_type == MSG_ERR:
            raise OSError(payload.decode(errors="replace"))
        if msg_type != MSG_OK_BYTES:
            raise OSError(f"unexpected reply type {msg_type:#x} to CB_READ_MEM")
        return payload

    def write_mem(self, addr: int, data: bytes) -> None:
        _write_frame(MSG_CB_WRITE_MEM, struct.pack("<Q", addr) + data)
        frame = _read_frame()
        if frame is None:
            raise OSError("parent closed the connection")
        msg_type, payload = frame
        if msg_type == MSG_ERR:
            raise OSError(payload.decode(errors="replace"))

    def raise_irq(self) -> None:
        _write_frame(MSG_CB_RAISE_IRQ)


def _load_plugin(path: str, class_name: str):
    spec = importlib.util.spec_from_file_location(f"hyperbug_sandboxed_{class_name}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"couldn't load {path!r} as a module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cls = getattr(module, class_name)
    instance = cls()
    _check_api_version(instance, path)
    instance.hyperbug = _RemoteHyperbugCtx()
    return instance


def _check_api_version(instance, path: str) -> None:
    """Mirrors `pydevice.rs::check_api_version` for the in-process loader —
    see `HYPERBUG_API_VERSION`/`HYPERBUG_API_MIN_SUPPORTED` in
    `hyperbug.device` for what the range means. A plugin with no
    `hyperbug_api_version` attribute at all (duck-typed, not subclassing
    `Device`/`PciDevice`) has nothing to check.
    """
    declared = getattr(instance, "hyperbug_api_version", None)
    if declared is None:
        return
    from hyperbug.device import HYPERBUG_API_MIN_SUPPORTED, HYPERBUG_API_VERSION

    if declared > HYPERBUG_API_VERSION:
        raise RuntimeError(
            f"{path} declares hyperbug_api_version={declared}, but this hyperbug build only "
            f"implements up to version {HYPERBUG_API_VERSION} — this plugin needs a newer hyperbug"
        )
    if declared < HYPERBUG_API_MIN_SUPPORTED:
        raise RuntimeError(
            f"{path} declares hyperbug_api_version={declared}, but this hyperbug build no longer "
            f"supports anything older than version {HYPERBUG_API_MIN_SUPPORTED} — the plugin needs "
            "updating for a breaking ABI change"
        )


def _identity_payload(instance) -> bytes:
    if not hasattr(instance, "vendor_id"):
        return b"\x00"
    bars = (list(getattr(instance, "bar_sizes", [])) + [0] * _NUM_BARS)[:_NUM_BARS]
    io_bars = set(getattr(instance, "io_bars", []))
    io_mask = sum(1 << i for i in io_bars if 0 <= i < _NUM_BARS)
    payload = bytearray(b"\x01")
    payload += struct.pack("<HHI", int(instance.vendor_id), int(instance.device_id), int(instance.class_code))
    for b in bars:
        payload += struct.pack("<I", int(b))
    payload += struct.pack(
        "<BBB", io_mask, int(getattr(instance, "interrupt_line", 0)), 1 if getattr(instance, "msi_capable", False) else 0
    )
    return bytes(payload)


def _dispatch(instance, msg_type: int, payload: bytes) -> tuple[int, bytes] | None:
    """Returns `(reply_type, reply_payload)`, or `None` for `SHUTDOWN`
    (caller exits)."""
    if msg_type == MSG_SHUTDOWN:
        return None
    if msg_type == MSG_IDENTITY:
        return MSG_OK_IDENTITY, _identity_payload(instance)
    if msg_type == MSG_HAS_TICK:
        return MSG_OK_BOOL, bytes([1 if hasattr(instance, "tick") else 0])
    if msg_type == MSG_TICK:
        try:
            instance.tick()
        except Exception as e:  # noqa: BLE001 - a plugin exception must not kill the runner
            return MSG_ERR, str(e).encode()
        return MSG_OK, b""
    if msg_type == MSG_HAS_RESET:
        return MSG_OK_BOOL, bytes([1 if hasattr(instance, "reset") else 0])
    if msg_type == MSG_RESET:
        try:
            instance.reset()
        except Exception as e:  # noqa: BLE001
            return MSG_ERR, str(e).encode()
        return MSG_OK, b""
    if msg_type == MSG_READ:
        if len(payload) < 12:
            return MSG_ERR, b"malformed READ"
        offset, size = struct.unpack_from("<QI", payload)
        try:
            data = instance.read(offset, size)
        except Exception as e:  # noqa: BLE001
            return MSG_ERR, str(e).encode()
        if len(data) != size:
            return MSG_ERR, f"read() returned {len(data)} bytes, expected {size}".encode()
        return MSG_OK_BYTES, data
    if msg_type == MSG_WRITE:
        if len(payload) < 8:
            return MSG_ERR, b"malformed WRITE"
        (offset,) = struct.unpack_from("<Q", payload)
        data = payload[8:]
        try:
            wants_irq = bool(instance.write(offset, data))
        except Exception as e:  # noqa: BLE001
            return MSG_ERR, str(e).encode()
        return MSG_OK_BOOL, bytes([1 if wants_irq else 0])
    return MSG_ERR, f"unknown message type {msg_type:#x}".encode()


def main() -> None:
    if len(sys.argv) != 3:
        print("usage: python3 -m hyperbug._sandbox_runner <plugin_path> <class_name>", file=sys.stderr)
        sys.exit(2)
    path, class_name = sys.argv[1], sys.argv[2]

    try:
        instance = _load_plugin(path, class_name)
    except Exception as e:  # noqa: BLE001
        _write_frame(MSG_ERR, str(e).encode())
        sys.exit(1)
    _write_frame(MSG_OK)

    while True:
        frame = _read_frame()
        if frame is None:
            return  # parent closed the pipe (process shutting down)
        msg_type, payload = frame
        reply = _dispatch(instance, msg_type, payload)
        if reply is None:
            return
        _write_frame(*reply)


if __name__ == "__main__":
    main()
