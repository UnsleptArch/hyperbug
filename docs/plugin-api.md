# Device plugin API reference

This is the authoritative reference for hyperbug's device-plugin contract
— the ABI a Python file implements to become a virtual device — and for
the `hyperbug` Python package used to launch and control a VM. If code and
this document disagree, treat it as a bug in one of them and check
`python/hyperbug/device.py`/`vm.py` and `src/pydevice.rs`/
`src/pydevice_proc.rs` directly.

## Versioning

`hyperbug.device.HYPERBUG_API_VERSION` (currently `1`) is the newest
plugin ABI version this build implements, bumped only for a *breaking*
change to the `Device`/`PciDevice` contract itself — a required method's
signature changing, or the meaning of an existing attribute changing.
Purely additive changes (like `tick()` was) never bump it, since they
can't break an existing plugin that doesn't use them.
`HYPERBUG_API_MIN_SUPPORTED` (also `1` today) is the oldest version a
plugin may declare and still be accepted — equal to `HYPERBUG_API_VERSION`
until a future build deliberately drops support for an old, numbered
contract, bumping both together.

A plugin that subclasses `Device`/`PciDevice` automatically declares
`hyperbug_api_version = HYPERBUG_API_VERSION` (of whatever `hyperbug`
package version it was written against). hyperbug's Rust side checks this
attribute once, at load, against the inclusive range
`[HYPERBUG_API_MIN_SUPPORTED, HYPERBUG_API_VERSION]`:

- **Declared higher than `HYPERBUG_API_VERSION`** — refused with "this
  plugin needs a newer hyperbug."
- **Declared lower than `HYPERBUG_API_MIN_SUPPORTED`** — refused with
  "the plugin needs updating for a breaking ABI change."
- **Anywhere in between** — loads normally.

Either failure is a clear, loud error at load time, never a silent
misbehavior against a `Device`/`PciDevice` shape the plugin never agreed
to. A plugin that doesn't declare the attribute at all — duck-typed,
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

### `reset(self) -> None` — optional

Same opt-in mechanism as `tick` (checked once at load via `HAS_RESET`,
zero cost if undefined), but a different purpose and a different
trigger:

```python
def reset(self) -> None:
    """Reinitialize this device's internal state, analogous to a real
    hardware reset line. Called only when an operator explicitly asks
    for it via the control socket — never automatically."""
```

Nothing in hyperbug calls `reset()` on its own — there's no in-guest
reset trigger modeled today (no PCI function-level reset, no guest-
driver-initiated reset). The only real caller is the live control
socket's `reset_device <mmio|pci> <selector>` command (see
[`hyperbug.vm.ControlConnection.reset_device`](#live-control---control-socket)
below), which calls it on the *current* running instance without
touching its code — for that, see "Hot-reload" next.

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
restriction. See [security.md](security/security.md) for the trust model this
exists within.

## Sandboxed plugins (`--device-sandboxed` / `--pci-device-sandboxed`)

Exactly the same plugin file and class, no code changes — but running in
its own `python3` subprocess instead of hyperbug's embedded interpreter,
communicating over a small binary, length-prefixed framed protocol on
stdin/stdout (see `python/hyperbug/_sandbox_runner.py`'s module docstring
for the full wire format, and `src/pydevice_proc.rs`'s `wire` module for
the Rust side) — a typed message with an explicit length header, not
hex-encoded text, so a device with real payload volume (not just
register-sized traffic) doesn't pay double for hex encoding and for
parsing it byte-pair by byte-pair. `self.hyperbug` inside a sandboxed
plugin is a thin proxy (`_RemoteHyperbugCtx`) that round-trips
`read_mem`/`write_mem`/`raise_irq` to the parent process exactly as if
they were local calls — from the plugin author's side, this is invisible.

What changes: a hung call (an infinite loop, a blocking call that never
returns) or a crash is caught by a 200ms reply timeout or a dead pipe,
respectively — the child is `SIGKILL`ed unconditionally, the device starts
answering like an unmapped one, and every access after that is a clean
no-op. The guest and every other device keep running regardless of what
the plugin was doing. The cost is a real IPC round trip (not a function
call) for every register access and DMA call — prefer plain `--device`/
`--pci-device` for a plugin you trust, and reserve the sandboxed form for
one you don't (third-party code, or something still being debugged).

The subprocess also runs under a real seccomp-bpf **deny-list**
(`src/seccomp.rs`), installed between `fork` and `exec`: a specific set
of syscalls with no legitimate use in a device plugin — `ptrace`,
`process_vm_readv`/`writev`, the mount/kernel-module/reboot family,
`bpf`, `perf_event_open`, and a few other privilege-escalation
primitives — are denied with `EPERM` instead of killing the process, so
a plugin that hits one gets an ordinary `OSError` it can report. This is
**not** an allow-list sandbox and does not drop the subprocess's own
user/filesystem/network privileges — see
[security.md](security/security.md) for the full trust model this sits
inside.

### Per-plugin resource limits

`--device-sandboxed`/`--pci-device-sandboxed`'s optional trailing
`mem=<mb>` and `cpu=<pct>` fields (either, both, or neither, independent
of whether a DMA range is also given — e.g.
`d.py:Cls:0x1000:0x100:mem=128`, no DMA range at all) apply a real
cgroups-v2 memory ceiling and/or CPU quota to that specific plugin
instance's subprocess. The child joins its cgroup from its own
`pre_exec` — before `exec` — so there's no window where it runs even
briefly outside the limit, once the cgroup exists.

This is **best-effort**, not a launch requirement: if cgroups v2 isn't
mounted, or this process isn't delegated permission to create a cgroup
(a common case outside systemd-managed/rootful setups), hyperbug logs a
one-time warning and the plugin loads and runs normally, just without
the ceiling enforced. Check the process's own stderr if you need to
confirm a limit actually took effect — a silent, successful load is not
proof it did.

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
- `reset_device(mmio_base=..., pci_device_number=...) -> None` — calls a
  live plugin's `reset()` method, if it defines one, without touching its
  code. Exactly one of the two keyword arguments; raises `OSError` if no
  matching device is attached. See "Hot-reload" below.
- `reload_device(mmio_base=..., pci_device_number=...) -> None` —
  re-reads a live plugin's file from disk and swaps in a fresh instance,
  in place, without restarting the guest. Same selection as
  `reset_device`. Raises `OSError` if no matching device is attached, or
  (PCI only) if the reloaded file's declared identity doesn't exactly
  match what's already registered. See "Hot-reload" below.

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
[security.md](security/security.md#snapshotrestore-scope) for the two specific
known-open correctness gaps in this feature before relying on it.

### Fork

```python
with VM("bzImage", control_socket="/tmp/hb.sock") as vm:
    with vm.connect_control() as ctl:
        child_pid = ctl.fork("/tmp/hb-child.sock")
        # the parent keeps running here, completely undisturbed

# elsewhere, connect to the child the same way as any control socket:
import socket
child_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
child_sock.connect("/tmp/hb-child.sock")
with ControlConnection(child_sock) as child_ctl:
    child_ctl.regs()
```

`fork(new_control_socket) -> int` clones the *live, running* guest into a
brand new, fully independent hyperbug process and returns its real PID.
Unlike `snapshot()` + `VM(restore=...)`, guest memory is never serialized
or copied — the child gets a real copy-on-write view of the exact same
mapping via `fork(2)`, so cloning a multi-gigabyte guest is essentially
free. The child's new control socket appears shortly after `fork()`
returns; connect to it the same way as any `--control-socket` launch.

**Scope, enforced on the Rust side, not just documented here**:
single-vCPU only, no `--device`/`--pci-device` plugin of any kind
(in-process, sandboxed, native, or WASM — none of their state, and for
in-process Python specifically none of the CPython interpreter/GIL
state, survives `fork()` safely), and not combinable with
`--record`/`--replay`/`--gdb-stub`/`--trace-file`. `fork()` raises
`OSError` if the running launch doesn't qualify. It also fails closed if
hyperbug's own background I/O thread can't be quiesced within 2 seconds
(a real, if unlikely, safety valve — forking while that thread might be
mid-lock would wedge the child forever with no way to recover) — see
`reactor::ReactorPause` on the Rust side for the mechanism.

This is the primitive behind "fork a running guest at a checkpoint,
mutate input, and diverge cheaply" workflows (fuzzing, exploring multiple
guest-state branches from one boot) — genuinely something not many VMMs
offer at the whole-VM level. Live migration between two hyperbug
processes (moving a running guest to a different host) is a related but
separate, larger, and not-yet-implemented feature.

### Live migration

```python
# destination: launched first, blocks until the source connects
dest = VM("bzImage", mem_mb=256, migrate_listen="127.0.0.1:9000", control_socket="/tmp/dest.sock")
dest.start()

# source: a normal, already-running guest
with VM("bzImage", mem_mb=256, control_socket="/tmp/src.sock") as vm:
    with vm.connect_control() as ctl:
        ctl.migrate("127.0.0.1:9000")
        # this process's guest is now retired — wait() returns
        # ExitCode.MIGRATED_AWAY
        vm.wait()

# elsewhere: connect to /tmp/dest.sock the same way as any control socket
```

`ControlConnection.migrate(dest_addr)` moves the *running* guest to a
separate hyperbug process launched ahead of time with
`VM(migrate_listen=dest_addr)` — vCPU state, guest memory, and device
state all travel over a plain TCP connection to it. Unlike `fork()`,
nothing is left running in the source process afterward: `wait()` there
returns `ExitCode.MIGRATED_AWAY`, not a crash and not a normal shutdown.

**Scope, enforced on the Rust side, not just documented here**: the same
restrictions `fork()` has (single-vCPU, no `devices`/`pci_devices` of any
kind, not combinable with `--record`/`--replay`/`--gdb-stub`/
`--trace-file`), checked before anything is captured or sent. The
destination's own configuration (`mem_mb`, `disks`, `net`, `rng_modern`)
must match the source's exactly — the same requirement file-based
`restore=` already has, since migration lands via the identical
`restore_vcpu`/`restore_device_state` path. `migrate()` raises `OSError`
if the launch doesn't qualify, the destination can't be reached, or the
reactor thread can't be quiesced in time (fails closed — never migrates a
guest whose background I/O thread might be mid-lock); a failed attempt
leaves the source guest running untouched, so it's always safe to retry.

**No encryption or authentication on the migration stream** — a plain,
unauthenticated TCP connection carrying a complete copy of guest memory
(which can hold real guest secrets). Fine on a private/trusted network,
the same threat model the control socket itself already documents (see
[security.md](security/security.md)); wrap it in your own tunnel (SSH, a
private VPC) for anything less trusted.

This is **stop-the-world migration, not pre-copy**: the guest is fully
paused for the entire capture-and-transfer, so downtime is roughly
"however long it takes to send guest memory over the network" — not the
millisecond-scale downtime a production hypervisor's iterative
dirty-page pre-copy achieves against a multi-gigabyte guest.

### Hot-reload

The actual answer to "I edited my device's Python file, now what" —
without a fresh boot:

```python
with VM("bzImage", control_socket="/tmp/hb.sock",
        devices=[DeviceSpec("my_device.py", "MyDevice", 0xd0000000, 0x1000)]) as vm:
    with vm.connect_control() as ctl:
        # ... edit my_device.py on disk ...
        ctl.reload_device(mmio_base=0xd0000000)   # or pci_device_number=<N>
```

`reload_device` re-reads the plugin file from disk (same path, same
class, same DMA range and resource limits it was originally launched
with — this is for picking up an edited *file*, not switching to a
different plugin) and swaps a freshly-instantiated copy into the exact
same running slot: same BAR/MMIO address, same `Arc` the bus already
holds, so the guest never needs to re-enumerate anything. A sandboxed
plugin's old subprocess is killed (and its cgroup, if any, cleaned up)
the moment the swap happens.

**One real constraint, enforced, not just documented**: a `--pci-device`
reload is refused outright — the running device left completely
untouched — if the reloaded file declares a different PCI identity
(`vendor_id`/`device_id`/`class_code`/`bar_sizes`/`interrupt_line`/
`msi_capable`). The PCI bus snapshots a device's identity once, at first
registration, and has no mechanism to notice it changed later — silently
accepting a mismatched reload would desync the guest's PCI config-space
view (what `lspci` or the driver sees) from the plugin code actually
answering behind it. Editing your device's `read`/`write`/`tick`/`reset`
logic is exactly the supported case; changing its declared PCI identity
requires a real relaunch instead. A plain MMIO (`--device`) plugin has no
such concern.

`reset_device` is the other half — see `reset(self)` above — calling a
live plugin's reset hook without reloading its code at all, for a plugin
that wants "reinitialize state" to be a distinct, cheaper operation than
"replace my entire instance."

## I2C target devices (`--i2c-device`)

`I2cDevice` (`python/hyperbug/device.py`) is a *separate*, smaller
contract from `Device`/`PciDevice`, for a target on hyperbug's single
virtual I2C bus:

```python
class I2cDevice(ABC):
    def i2c_write(self, data: bytes) -> None: ...
    def i2c_read(self, length: int) -> bytes: ...
```

Register with `--i2c-device <path>:<ClassName>:<addr>` (a 7-bit address,
`0x00`-`0x7f`). The guest reaches it through a real `virtio-i2c` adapter
(`VIRTIO_ID_I2C_ADAPTER`) — created automatically the moment any
`--i2c-device` is given, never otherwise — that a guest's own unmodified
`i2c-virtio` kernel driver binds to directly, no custom guest driver
needed.

**Deliberately not the same shape as `Device`.** There's no fixed
register-offset addressing (I2C messages are just address + direction + a
byte buffer, matching the guest's own `i2c_msg` abstraction) and no
`self.hyperbug` DMA context — a target only ever sees the bytes of
whichever message was addressed to it, never guest memory directly. There
is also no PCI identity to declare: the *adapter*, not each target, is
what the guest's PCI core sees.

Real I2C transactions very commonly chain a write (setting an internal
"register pointer") immediately followed by a read (returning data from
that pointer), with no bus release in between — the standard way almost
every real sensor works. hyperbug delivers `i2c_write`/`i2c_read` calls to
the *same* long-lived instance, strictly in the order the guest issued
them, which is enough to implement that idiom correctly with nothing more
than an instance attribute — see `devices/i2c_temp_sensor.py`. A
zero-length write (`i2cdetect`-style probing) never reaches either
method at all: hyperbug ACKs/NAKs it directly from whether a device is
registered at that address.

Currently in-process only (`--i2c-device`, no sandboxed/native/WASM I2C
transport yet), and not yet reachable from the control socket's
`reset_device`/`reload_device` (DEBTS.md item 57 has the detail).

## GPIO banks (`--gpio-device`)

`GpioBank` (`python/hyperbug/device.py`) is one virtual GPIO chip:

```python
class GpioBank(ABC):
    ngpio: int
    names: list[str] = []  # optional
    def get_direction(self, line: int) -> int: ...
    def set_direction(self, line: int, direction: int) -> None: ...
    def get_value(self, line: int) -> int: ...
    def set_value(self, line: int, value: int) -> None: ...
```

Register with `--gpio-device <path>:<ClassName>`. Unlike `I2cDevice` (many
targets sharing one bus), each bank gets its **own independent PCI slot**
and its own real `virtio-gpio` adapter (`VIRTIO_ID_GPIO`) — matching real
BMC hardware's typically several separate GPIO controllers rather than
one shared bus. Up to 4 banks (PCI slots 19-22, sharing GSI 14 the same
way virtio-blk's disks share one GSI).

Directions are `hyperbug.gpio.DIRECTION_NONE`/`DIRECTION_OUT`/
`DIRECTION_IN`. `self.hyperbug.raise_irq(line)` marks a line as having
spontaneously changed state — delivered to the guest as a real interrupt
only if that line currently has one armed (the guest's driver requested
edge/level detection on it) and enabled, otherwise dropped, matching a
real masked/disabled interrupt. This is real eventfd-backed and
thread-safe to call from anywhere, including your own background Python
thread (`threading.Timer`) — there's deliberately no per-iteration
`tick()` hook here, since a plain background thread already covers the
same need with no extra polling path. See `devices/gpio_button_bank.py`
for a worked example (a power button, a presence-detect line, and two
plain output control lines).

Currently in-process only, and — like I2C targets — not yet reachable
from the control socket's `reset_device`/`reload_device`.

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
- `devices/i2c_temp_sensor.py` — an `I2cDevice` target implementing the
  "write register pointer, then read its contents" idiom real I2C
  sensors use, with its own self-invented, vendor-neutral register map.
- `devices/gpio_button_bank.py` — a `GpioBank` with a power button,
  a presence-detect input, and two output control lines, plus a real
  worked example of `self.hyperbug.raise_irq()` from a background
  thread (`HYPERBUG_GPIO_DEMO_AUTOPRESS_MS`).
