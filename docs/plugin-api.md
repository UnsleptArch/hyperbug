# Device plugin API reference

This is the authoritative reference for hyperbug's device-plugin contract
— the ABI a Python file implements to become a virtual device — and for
the `hyperbug` Python package used to launch and control a VM. If code and
this document disagree, treat it as a bug in one of them and check
`python/hyperbug/device.py`/`vm.py` and `src/pydevice.rs`/
`src/pydevice_proc.rs` directly.

## Versioning

`hyperbug.device.HYPERBUG_API_VERSION` (currently `1`) is bumped only for
a *breaking* change to the `Device`/`PciDevice` contract itself — a
required method's signature changing, or the meaning of an existing
attribute changing. Purely additive changes (like `tick()` was) never bump
it, since they can't break an existing plugin that doesn't use them.

A plugin that subclasses `Device`/`PciDevice` automatically declares
`hyperbug_api_version = HYPERBUG_API_VERSION` (of whatever `hyperbug`
package version it was written against). hyperbug's Rust side checks this
attribute once, at load: a mismatch is refused with a clear error instead
of running the plugin against a contract that's since changed underneath
it. A plugin that doesn't declare the attribute at all — duck-typed,
implementing `read`/`write` without subclassing anything — has nothing to
check and loads exactly as it always has. This applies identically to the
in-process and sandboxed loaders.

## The `Device` contract

A plugin file defines a class (any name — given explicitly on the
command line or in `DeviceSpec`/`PciDeviceSpec`) implementing:

```python
def __init__(self):
    ...

def read(self, offset: int, size: int) -> bytes:
    """Return exactly `size` bytes read from `offset`, relative to this
    device's own base address (not the raw guest-physical address)."""

def write(self, offset: int, data: bytes) -> bool | None:
    """Handle `data` written at `offset`. Return True to request this
    device's configured interrupt be raised synchronously, right now.
    None (i.e. no explicit return) is the same as False."""
```

Subclassing `hyperbug.Device` (an `abc.ABC`) is not required — hyperbug
calls `read`/`write` by plain attribute access — but is recommended: it
gets you `HYPERBUG_API_VERSION` checking, type hints, and this contract
documented in one place instead of only in a Rust doc comment.

Exceptions raised from `read`/`write`/`tick` are caught, logged to stderr
(rate-limited after the first few occurrences, so a systematically-buggy
device being polled in a tight loop can't flood stderr), and treated as a
no-op — a `read` that raises returns all-zero bytes, a `write` that raises
requests no interrupt. A misbehaving plugin degrades to "an unmapped-ish
device," it does not take down the guest or the VMM process. This applies
to the in-process loader; see "Sandboxed plugins" below for what a plugin
that *hangs* (rather than raises) does.

### `self.hyperbug`

Set on the instance immediately after construction — **not available
inside `__init__`**; defer anything that needs it to the first `read`/
`write`/`tick` call. Provides:

- **`read_mem(addr: int, size: int) -> bytes`** / **`write_mem(addr: int,
  data: bytes) -> None`** — real, bounds-checked DMA against guest
  physical memory. Raises `OSError` if any part of the range falls
  outside guest RAM (a guest-supplied address is untrusted input), or
  outside this device instance's declared DMA-confinement range if the
  operator set one (see "DMA confinement" below). This is what lets a
  device act like real hardware: read a descriptor the guest posted at an
  address it told you about, write a response into a guest-supplied
  buffer — rather than only ever exposing the device's own internal
  register state through `read`/`write`.
- **`raise_irq() -> None`** — requests this device's configured interrupt
  (see `PciDevice.interrupt_line`/`msi_capable` below) be raised as soon
  as hyperbug's vCPU loop next checks, i.e. *spontaneously*, independent
  of any register access. This is a **separate mechanism** from `write`'s
  truthy-return path — use one or the other for a given event, not both;
  mixing them produces a double interrupt request. See `devices/dma_demo.py`
  for the `raise_irq()` style and `devices/scratch.py` for the
  truthy-return style.

### `tick(self) -> None` — optional

Not declared on the `Device` base class itself, deliberately: hyperbug
checks once at load whether a plugin defines a `tick` method **at all**,
and only ever calls one that does. Giving `Device` a no-op default would
make every subclass "define one" whether it overrides it or not, silently
defeating that opt-in check. If you want one, just add it:

```python
def tick(self) -> None:
    """Called once per host vCPU-loop iteration, independent of any
    guest register access. Use it for a simulated timer, or an
    asynchronous transaction: post a request from write(), then some
    number of ticks later — not in response to any guest access — call
    self.hyperbug.raise_irq() once it completes."""
```

See `devices/doorbell_demo.py` for a complete worked example: a
doorbell/status/result register set where a request submitted in `write()`
completes several `tick()` calls later, the pattern a real asynchronous
bridged transport (submit now, completion interrupt arrives on its own
schedule) needs — as opposed to `devices/dma_demo.py`'s synchronous,
inside-`write()` completion.

A plugin without `tick` pays nothing for it: hyperbug checks once at load
(no per-iteration attribute lookup), and calling it is then a plain
`Option`/boolean check with no Python round trip at all.

## The `PciDevice` contract

A `Device` subclass registered via `--pci-device`/`--pci-device-sandboxed`
additionally declares these as class or instance attributes, **read once
when the device is loaded** and served from a Rust-side snapshot
afterward — the same way a real device's config-space identity bytes are
fixed in silicon. Changing one of these attributes later, at runtime, has
no effect.

| Attribute | Type | Meaning |
|---|---|---|
| `vendor_id` | `int` | 16-bit PCI vendor ID. hyperbug's own code has no opinion on this value — a real vendor's ID belongs entirely in your plugin file, never in hyperbug's Rust core. |
| `device_id` | `int` | 16-bit PCI device ID. |
| `class_code` | `int` | Packed 24-bit `(base_class << 16 | subclass << 8 | prog_if)`, e.g. `0x020000` for an Ethernet controller. |
| `bar_sizes` | `list[int]` | BAR sizes in bytes, BAR0 first; up to 6 entries. `0` (or an omitted trailing entry) means that BAR isn't implemented. |
| `io_bars` | `list[int]` (optional) | BAR indices (0-5) that are I/O-space rather than memory-space. Omit entirely if every BAR is memory-space — the common case outside legacy devices like virtio's own BAR0. |
| `interrupt_line` | `int` (optional) | The legacy ISA IRQ (1-15) this device's interrupt is wired to. `0` (the default) means "no interrupt" — both `write()`'s truthy return and `raise_irq()` then have nothing to pulse. Must actually be ACPI-routed to work under ACPI: a `--pci-device` slot outside the ranges `acpi/dsdt.asl`'s `_PRT` already covers (see [architecture.md](architecture.md)'s slot table) has no routing entry for whatever IRQ you pick — it still works with ACPI disabled (which trusts this value directly), but won't deliver under the default ACPI-enabled boot without adding a `_PRT` entry too. |
| `msi_capable` | `bool` (optional) | Set `True` to give this device a real PCI MSI capability (single message, 32-bit address — the simplest real form, not MSI-X). If a guest driver enables it, both `write()`'s truthy return and `raise_irq()` deliver via a real `KVM_SIGNAL_MSI` instead of pulsing `interrupt_line` — transparent to your device code either way. **Not useful for emulating virtio**: the real Linux virtio driver only ever requests MSI-X or falls back to plain INTx, never single-vector MSI, so a virtio-shaped device would never have this exercised by a real driver (hyperbug's own virtio devices never set it). It's for a custom device model with a real or hypothetical driver that genuinely requests plain MSI. |

## DMA confinement

An operator can bound what a specific plugin *instance's* `read_mem`/
`write_mem` may touch, independent of what the plugin's own code does:
the optional trailing `:<dma_base>:<dma_size>` on `--device`/
`--pci-device` and their `-sandboxed` variants (both hex, `0x`-prefix
optional), or `dma_range=(base, size)` on `DeviceSpec`/`PciDeviceSpec` in
Python. Omit it (the default) for unrestricted access — every shipped
`devices/*.py` example runs this way.

This is declared on the CLI/launch side, **never** read from a Python
attribute on the plugin itself — deliberately, since the plugin is exactly
the untrusted party such a restriction is meant to constrain, and a
malicious plugin could otherwise just declare "everything." A `read_mem`/
`write_mem` call outside the declared range raises `OSError`, the same
exception shape as an out-of-guest-RAM call, even for an address that is
otherwise perfectly valid guest memory the plugin would reach without the
restriction. See [security.md](security.md) for the trust model this
exists within.

## Sandboxed plugins (`--device-sandboxed` / `--pci-device-sandboxed`)

Exactly the same plugin file and class, no code changes — but running in
its own `python3` subprocess instead of hyperbug's embedded interpreter,
communicating over a small hex-encoded line protocol on stdin/stdout (see
`python/hyperbug/_sandbox_runner.py`'s module docstring for the full wire
format, and `src/pydevice_proc.rs` for the Rust side). `self.hyperbug`
inside a sandboxed plugin is a thin proxy (`_RemoteHyperbugCtx`) that
round-trips `read_mem`/`write_mem`/`raise_irq` to the parent process
exactly as if they were local calls — from the plugin author's side, this
is invisible.

What changes: a hung call (an infinite loop, a blocking call that never
returns) or a crash is caught by a 200ms reply timeout or a dead pipe,
respectively — the child is `SIGKILL`ed unconditionally, the device starts
answering like an unmapped one, and every access after that is a clean
no-op. The guest and every other device keep running regardless of what
the plugin was doing. The cost is a real IPC round trip (not a function
call) for every register access and DMA call — prefer plain `--device`/
`--pci-device` for a plugin you trust, and reserve the sandboxed form for
one you don't (third-party code, or something still being debugged).

## `import hyperbug` from a plugin file

Works automatically with no separate install step: hyperbug puts its own
`python/` directory on `sys.path` the first time any device is loaded. If
you're writing tooling that imports `hyperbug` *outside* of a plugin
context (e.g. a script using `hyperbug.VM`), install the package properly
instead: `pip install -e python/` from the repo root.

## The `hyperbug` Python package (launcher/control library)

`hyperbug.VM` is a thin wrapper around the compiled binary — there is no
in-process FFI binding; the binary owns the KVM fds, guest memory, and run
loop, so `VM` shells out and gives you a normal Python object instead of a
hand-built argv list.

```python
from hyperbug import VM

with VM("bzImage", mem_mb=512, disks=["disk.img"], net=True) as vm:
    exit_code = vm.wait()
```

### `VM` fields

| Field | Default | Meaning |
|---|---|---|
| `kernel` | required | Path to a bzImage. Still required even when `restore=` is set (unused in that mode). |
| `binary` | auto-detected | Path to the `hyperbug` executable; found on `$PATH` or as `target/release/hyperbug` next to a source checkout if omitted. |
| `initrd` | `None` | cpio.gz initramfs path. |
| `mem_mb` | `256` | Guest RAM in MB. |
| `cmdline` | `None` | Kernel command line (hyperbug's own default is used if omitted). |
| `devices` | `[]` | `list[DeviceSpec]` — `--device` entries. |
| `pci_devices` | `[]` | `list[PciDeviceSpec]` — `--pci-device` entries. |
| `sandboxed_devices` | `[]` | `list[DeviceSpec]` — `--device-sandboxed` entries. |
| `sandboxed_pci_devices` | `[]` | `list[PciDeviceSpec]` — `--pci-device-sandboxed` entries. |
| `disks` | `[]` | Backing files for virtio-blk (`--disk`, one per entry, in order). |
| `net` | `False` | `--net`. |
| `rng_modern` | `False` | `--rng-modern`. |
| `control_socket` | `None` | `--control-socket` path; required before `connect_control()`. |
| `smp` | `1` | `--smp`; real vCPU count. |
| `restore` | `None` | `--restore` path — boots from a snapshot instead of `kernel`/`initrd`. |

`DeviceSpec(path, class_name, base, size, dma_range=None)` and
`PciDeviceSpec(path, class_name, device_number, dma_range=None)` build the
corresponding CLI argument string (`.to_arg()`); `dma_range` is an
optional `(base, size)` tuple, matching the CLI's trailing
`:<dma_base>:<dma_size>`.

### Lifecycle

- `start(capture_output=False, **popen_kwargs)` — launches the process.
  With `capture_output=True`, stderr is piped so `wait()` can raise
  `HyperbugLaunchError` with hyperbug's own error message if it refuses to
  even start (a bad `--mem` value, a plugin that failed to load, ...);
  otherwise hyperbug's stdio is inherited and you see the guest's serial
  console live.
- `wait(timeout=None) -> int` — blocks for the process to exit, returns
  its exit code (or raises `HyperbugLaunchError`, per above).
- `poll() -> int | None` — non-blocking; `None` while still running.
- `stop(timeout=5.0)` — `SIGTERM`, then `SIGKILL` after `timeout`; a no-op
  if already exited.
- Used as a context manager, `VM` starts on `__enter__` and calls `stop()`
  on `__exit__`.

`ExitCode` (an `IntEnum`) documents what `wait()`'s return value means —
`CLEAN_SHUTDOWN`, `REQUESTED_REBOOT`, `TRIPLE_FAULT`, `HALTED` — including
the real ambiguity that a triple fault is the same underlying mechanism
Linux uses for a genuine crash, a `panic=1` auto-reboot, and (absent a
working ACPI reset path) a plain requested reboot; read its docstring
before assuming more than it can actually tell you.

### Live control (`--control-socket`)

```python
with VM("bzImage", control_socket="/tmp/hb.sock") as vm:
    with vm.connect_control() as ctl:
        data = ctl.read_mem(0x1000, 16)
        ctl.write_mem(0x1000, b"...")
        regs = ctl.regs()
        ctl.write_regs(rip=regs["rip"], rax=1)   # read-modify-write
```

`connect_control(timeout=5.0)` waits for the socket file to appear (it's
created shortly after `start()` returns, not necessarily before) and
returns a `ControlConnection`:

- `read_mem(addr, size) -> bytes` / `write_mem(addr, data) -> None` — live
  DMA against the running guest's physical memory. Raises `OSError` on an
  out-of-range address. There is nothing stopping a bad address from
  corrupting a running guest — that's the actual point of live control,
  the same responsibility a real debugger's memory-write command has.
- `regs() -> dict[str, int]` — a snapshot of every `kvm_regs` general-
  purpose field (`rip`, `rsp`, `rax`, ...) at the moment of the call, not
  a live view.
- `write_regs(**values: int) -> None` — read-modify-write; accepts exactly
  the field names `regs()` returns, so `ctl.write_regs(**ctl.regs())`
  round-trips. Raises `OSError` on an unknown name or a value KVM itself
  rejects (e.g. `rflags` with its always-set bit 1 cleared).
- `snapshot(path) -> None` — serializes the whole running guest to `path`
  (see "Snapshot/restore" below). Raises `OSError` on failure.

Several clients may connect to one control socket at once (up to 8); each
gets independent reads and commands execute one at a time, in order, on
the guest's own boot vCPU thread.

### Snapshot/restore

```python
with VM("bzImage", control_socket="/tmp/hb.sock") as vm:
    with vm.connect_control() as ctl:
        ctl.snapshot("/tmp/hb.snap")
# ... later, possibly a different process ...
with VM("bzImage", restore="/tmp/hb.snap") as vm:
    exit_code = vm.wait()
```

A snapshot captures vCPU register/FPU/MSR state, in-kernel PIC/PIT state,
guest memory, and hyperbug's own built-in device protocol state (serial,
PCI config space, both virtio PCI transports). It does **not** capture
`--device`/`--pci-device` Python plugin state, and is single-vCPU only —
both enforced at launch, not silently accepted. The rest of the launch
configuration (memory size, disks, net, PCI devices) must match what was
running when the snapshot was taken. See
[security.md](security.md#snapshotrestore-scope) for the two specific
known-open correctness gaps in this feature before relying on it.

## Reference plugins

- `devices/scratch.py` — the minimal contract: a plain register file, the
  truthy-`write()`-return interrupt style.
- `devices/dma_demo.py` — DMA (`read_mem`/`write_mem`), the spontaneous
  `raise_irq()` style, and `msi_capable = True`, combined in one small
  device that reverses a guest-supplied buffer.
- `devices/doorbell_demo.py` — `tick()`-driven asynchronous completion: a
  doorbell/status/result register set where a request completes several
  ticks after being submitted, proving out the register pattern a real
  bridged asynchronous transport (submit, then a completion interrupt
  arriving on its own schedule) needs.
