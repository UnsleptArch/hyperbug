"""Internal: runs one device plugin in its own process, talking to
hyperbug's Rust side over stdin/stdout with a small line-based protocol.

Not part of the public API — `hyperbug.VM`/device authors never import
this directly. Invoked by the Rust side (`src/pydevice_proc.rs`) as::

    python3 -m hyperbug._sandbox_runner <plugin_path> <class_name>

Why a real subprocess instead of another in-process interruption trick:
this project already tried two different ways to forcibly interrupt a
stuck plugin call from *inside* the same process (`PyErr_SetInterrupt`,
`PyThreadState_SetAsyncExc`) — one hung under real concurrent load, the
other segfaulted. Neither failure mode is possible here: a subprocess that
stops responding gets killed at the OS level (`SIGKILL`), which cannot
hang or corrupt the parent process's own state.

Wire protocol: plain ASCII lines, hex-encoded binary payloads, no
framing beyond newlines (matches `src/control.rs`'s own convention — no
serde dependency needed for something this simple).

Parent -> child (always exactly one outstanding, since the parent only
ever holds one device behind one lock, same as the in-process model):
  - ``IDENTITY`` -> ``OK <space-separated key=value pairs>`` if the class
    is a `PciDevice` (see below for the keys), or ``NONE`` for a plain
    `Device`.
  - ``READ <offset_hex> <size_hex>`` -> ``OK <hex_bytes>`` or
    ``ERR <message>``
  - ``WRITE <offset_hex> <hex_bytes>`` -> ``OK <0|1>`` (1 = the device's
    write() requested its interrupt) or ``ERR <message>``
  - ``HAS_TICK`` -> ``OK <0|1>`` — whether the class defines a `tick`
    method at all, checked once at load so the parent only ever sends
    `TICK` (below) to a plugin that actually implements one.
  - ``TICK`` -> ``OK`` or ``ERR <message>`` — calls `instance.tick()`,
    for logic that needs to run independent of any register access (a
    simulated timer, an async transaction whose completion isn't driven
    by the guest touching a register at all). Only ever sent if
    `HAS_TICK` reported `1`.
  - ``SHUTDOWN`` -> child exits cleanly, no reply expected

Child -> parent, sent *while* handling a READ/WRITE (nested — the parent
answers immediately and the child's original command is still pending):
  - ``CB_READ_MEM <addr_hex> <size_hex>`` -> ``OK <hex_bytes>`` or
    ``ERR <message>``
  - ``CB_WRITE_MEM <addr_hex> <hex_bytes>`` -> ``OK``

Child -> parent, sent at *any* time with no reply expected (fire-and-
forget — the plugin's own background thread can call
``self.hyperbug.raise_irq()`` whenever it wants, same as the in-process
model's spontaneous-interrupt path):
  - ``CB_RAISE_IRQ``

Identity keys (only present when the class is a `PciDevice`): ``vendor``,
``device``, ``class`` (all hex), ``bars`` (comma-separated hex, 6 entries,
0 for unimplemented), ``io_bars`` (comma-separated BAR indices, may be
empty), ``irq`` (hex), ``msi`` (``0``/``1``).
"""

from __future__ import annotations

import importlib.util
import sys
import threading

_stdout_lock = threading.Lock()


def _write_line(line: str) -> None:
    with _stdout_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def _read_line() -> str | None:
    line = sys.stdin.readline()
    return None if line == "" else line.rstrip("\n")


def _to_hex(data: bytes) -> str:
    return data.hex()


def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


class _RemoteHyperbugCtx:
    """What `self.hyperbug` is inside the sandboxed plugin — same three
    calls as the in-process `HyperbugCtx`, each a synchronous round trip
    to the parent over the same stdin/stdout pair `_dispatch` below reads
    commands from. Safe to call from any thread: `_stdout_lock` (module-
    level, shared with the main dispatch loop) serializes every write, and
    a reply always follows the request that caused it before anything
    else reads stdin again (the parent never sends an unsolicited line).
    """

    def read_mem(self, addr: int, size: int) -> bytes:
        _write_line(f"CB_READ_MEM {addr:x} {size:x}")
        reply = _read_line()
        if reply is None or reply.startswith("ERR"):
            raise OSError(reply[4:] if reply else "parent closed the connection")
        return _from_hex(reply[3:])

    def write_mem(self, addr: int, data: bytes) -> None:
        _write_line(f"CB_WRITE_MEM {addr:x} {_to_hex(data)}")
        reply = _read_line()
        if reply is None or reply.startswith("ERR"):
            raise OSError(reply[4:] if reply else "parent closed the connection")

    def raise_irq(self) -> None:
        _write_line("CB_RAISE_IRQ")


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
    see `HYPERBUG_API_VERSION` in `hyperbug.device` for what the number
    means. A plugin with no `hyperbug_api_version` attribute at all (duck-
    typed, not subclassing `Device`/`PciDevice`) has nothing to check.
    """
    declared = getattr(instance, "hyperbug_api_version", None)
    if declared is None:
        return
    from hyperbug.device import HYPERBUG_API_VERSION

    if declared != HYPERBUG_API_VERSION:
        raise RuntimeError(
            f"{path} declares hyperbug_api_version={declared}, but this hyperbug build implements "
            f"version {HYPERBUG_API_VERSION} — the plugin may need updating for a breaking ABI change"
        )


def _identity_line(instance) -> str:
    if not hasattr(instance, "vendor_id"):
        return "NONE"
    bars = list(getattr(instance, "bar_sizes", []))
    bars = (bars + [0] * 6)[:6]
    io_bars = getattr(instance, "io_bars", [])
    fields = {
        "vendor": f"{instance.vendor_id:x}",
        "device": f"{instance.device_id:x}",
        "class": f"{instance.class_code:x}",
        "bars": ",".join(f"{b:x}" for b in bars),
        "io_bars": ",".join(str(i) for i in io_bars),
        "irq": f"{getattr(instance, 'interrupt_line', 0):x}",
        "msi": "1" if getattr(instance, "msi_capable", False) else "0",
    }
    return "OK " + " ".join(f"{k}={v}" for k, v in fields.items())


def _dispatch(instance, line: str) -> str | None:
    """Returns the reply line, or `None` for `SHUTDOWN` (caller exits)."""
    parts = line.split(" ", 2)
    cmd = parts[0]

    if cmd == "SHUTDOWN":
        return None
    if cmd == "IDENTITY":
        return _identity_line(instance)
    if cmd == "HAS_TICK":
        return "OK 1" if hasattr(instance, "tick") else "OK 0"
    if cmd == "TICK":
        try:
            instance.tick()
        except Exception as e:  # noqa: BLE001 - a plugin exception must not kill the runner
            return f"ERR {e}"
        return "OK"
    if cmd == "READ":
        offset, size = int(parts[1], 16), int(parts[2], 16)
        try:
            data = instance.read(offset, size)
        except Exception as e:  # noqa: BLE001 - a plugin exception must not kill the runner
            return f"ERR {e}"
        if len(data) != size:
            return f"ERR read() returned {len(data)} bytes, expected {size}"
        return f"OK {_to_hex(data)}"
    if cmd == "WRITE":
        offset = int(parts[1], 16)
        data = _from_hex(parts[2]) if len(parts) > 2 and parts[2] else b""
        try:
            wants_irq = bool(instance.write(offset, data))
        except Exception as e:  # noqa: BLE001
            return f"ERR {e}"
        return f"OK {1 if wants_irq else 0}"
    return f"ERR unknown command {cmd!r}"


def main() -> None:
    if len(sys.argv) != 3:
        print("usage: python3 -m hyperbug._sandbox_runner <plugin_path> <class_name>", file=sys.stderr)
        sys.exit(2)
    path, class_name = sys.argv[1], sys.argv[2]

    try:
        instance = _load_plugin(path, class_name)
    except Exception as e:  # noqa: BLE001
        _write_line(f"LOAD_ERR {e}")
        sys.exit(1)
    _write_line("LOAD_OK")

    while True:
        line = _read_line()
        if line is None:
            return  # parent closed the pipe (process shutting down)
        reply = _dispatch(instance, line)
        if reply is None:
            return
        _write_line(reply)


if __name__ == "__main__":
    main()
