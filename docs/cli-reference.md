# CLI reference

```
hyperbug --kernel <bzImage> [options]
```

`--kernel` is the only required flag. Every other flag is optional and may
be repeated where noted.

| Flag | Repeatable | Meaning |
|---|---|---|
| `--kernel <path>` | | Path to a bzImage kernel. Required (even when `--restore` is used — the parser still requires it, though it goes unused in that mode). |
| `--initrd <path>` | | cpio.gz initramfs. |
| `--mem <MB>` | | Guest RAM in MB. Default 256, minimum 32. Upper bound is computed at runtime from the host's low-memory page-table budget (see `gdt::max_identity_map()`), not a fixed constant. |
| `--cmdline <str>` | | Kernel command line. Default: `console=ttyS0 panic=1`. |
| `--smp <N>` | | Number of vCPUs. Default 1. Real multi-vCPU execution: vCPU 0 boots the kernel directly; vCPUs 1..N come up via a genuine INIT-SIPI-SIPI sequence through KVM's own in-kernel APIC, each on its own OS thread. Capped at whatever the host's KVM reports supporting. |
| `--disk <path>` | yes | Adds a virtio-blk device backed by this file. Up to 8 (PCI slots 4-11 are reserved for disks). |
| `--net` | | Adds a virtio-net device backed by a TAP interface hyperbug creates itself at runtime. Needs `CAP_NET_ADMIN` or root — see [dev-guide.md](dev-guide.md#playing-with-it-interactively) for a no-root option (`unshare --user --map-root-user --net`) and the real shell/job-control gotchas that come up running this by hand. |
| `--rng-modern` | | Attaches virtio-rng over the modern virtio 1.0 PCI transport (memory-mapped BARs via a real PCI capability list) instead of the legacy I/O-BAR transport every other virtio device here uses. No MSI-X yet — a real driver falls back to legacy INTx cleanly. |
| `--device <path.py>:<Class>:<base>:<size>[:<dma_base>:<dma_size>]` | yes | Loads a Python device plugin at a fixed MMIO address, in-process. `base`/`size` are hex (`0x` prefix optional). The optional trailing `<dma_base>:<dma_size>` confines this plugin's `self.hyperbug.read_mem`/`write_mem` to that guest-physical range — see [security.md](security/security.md#dma-confinement) and [plugin-api.md](plugin-api.md#dma-confinement). Omit it for unrestricted access (the default, and every shipped example's setting). |
| `--pci-device <path.py>:<Class>:<device_number>[:<dma_base>:<dma_size>]` | yes | Loads a Python device plugin on the PCI bus (function 0) at the given device number (0-31; slots 4-11/16/17 are reserved for hyperbug's own virtio devices and rejected as a config error). The plugin's own attributes declare its PCI identity — see [plugin-api.md](plugin-api.md#the-pcidevice-contract). Same optional DMA-range suffix as `--device`. |
| `--device-sandboxed <path.py>:<Class>:<base>:<size>[:<dma_base>:<dma_size>][:mem=<mb>][:cpu=<pct>]` | yes | Same spec syntax as `--device`, but the plugin runs in its own `python3` subprocess: a hung or crashed plugin is killed rather than stalling or crashing the guest. Optional trailing `mem=<mb>`/`cpu=<pct>` (either or both, in any combination, with or without the DMA range) apply a cgroups-v2 memory ceiling and/or CPU quota to this specific plugin instance — best-effort: silently unenforced (with a one-time warning) if cgroups v2 isn't available or delegated to this process. See [plugin-api.md](plugin-api.md#sandboxed-plugins---device-sandboxed--pci-device-sandboxed). |
| `--pci-device-sandboxed <path.py>:<Class>:<device_number>[:<dma_base>:<dma_size>][:mem=<mb>][:cpu=<pct>]` | yes | The `--pci-device` equivalent of `--device-sandboxed`, same optional `mem=`/`cpu=` suffix. |
| `--native-device <path.so>:<base>:<size>[:<dma_base>:<dma_size>]` | yes | Loads a `dlopen()`ed C-ABI device plugin (see [native-plugin-api.md](native-plugin-api.md)) at a fixed MMIO address, in-process. **No isolation at all** — full process privileges, no seccomp/cgroup/interpreter boundary; see [security.md](security/security.md#5-a-native-c-abi-plugin-is-fully-trusted--by-necessity-not-choice). Same optional DMA-range suffix as `--device`; no `mem=`/`cpu=` (rejected as a config error — there's no subprocess to limit). |
| `--native-pci-device <path.so>:<device_number>[:<dma_base>:<dma_size>]` | yes | The `--pci-device` equivalent of `--native-device`. The plugin's own `hyperbug_plugin_pci_identity` export declares its PCI identity. |
| `--wasm-device <path.wasm>:<base>:<size>[:<dma_base>:<dma_size>]` | yes | Loads a WASM module (see [wasm-plugin-api.md](wasm-plugin-api.md)) at a fixed MMIO address, executed in-process under `wasmtime`. Additive alongside the subprocess sandbox and native transports, not a replacement for either — real memory-safety isolation (a module can only touch its own linear memory; guest memory access goes through a checked host callback) at in-process speed, with a real enforced per-instance memory ceiling. Same optional DMA-range suffix as `--device`; no `mem=`/`cpu=` (rejected as a config error — there's no subprocess to limit). |
| `--wasm-pci-device <path.wasm>:<device_number>[:<dma_base>:<dma_size>]` | yes | The `--pci-device` equivalent of `--wasm-device`. The module's own `hyperbug_pci_identity` export declares its PCI identity. |
| `--i2c-device <path.py>:<Class>:<addr>` | yes | Attaches a Python `I2cDevice` target to hyperbug's single virtual I2C bus at a fixed 7-bit address (`0x00`-`0x7f`). A real `virtio-i2c` adapter (PCI slot 18, GSI 13) is created automatically the moment this is given at least once — no adapter at all otherwise. In-process only today. See [plugin-api.md](plugin-api.md#i2c-target-devices---i2c-device). |
| `--gpio-device <path.py>:<Class>` | yes | Attaches a Python `GpioBank` as its own independent virtual GPIO chip — a real `virtio-gpio` adapter, its own PCI slot (19-22, up to 4 banks) sharing GSI 14. Supports real interrupts (`self.hyperbug.raise_irq(line)`) via the guest's `eventq`, not just polled GET/SET_VALUE. In-process only today. See [plugin-api.md](plugin-api.md#gpio-banks---gpio-device). |
| `--uart2-log <path>` / `--uart3-log <path>` / `--uart4-log <path>` | | Attaches a real, additional ISA-convention 16550 UART (COM2/COM3/COM4 — `0x2F8`/`0x3E8`/`0x2E8`, sharing IRQ 3 or 4 with each other the same way real ISA hardware does) whose guest-transmitted bytes are captured to this host file. Output-only (no keyboard input, unlike COM1); real BMCs commonly need exactly this for debug-UART or SOL-capture logging. |
| `--vsock-uds <path>` | | Attaches a real `virtio-vsock` adapter. Every guest-initiated `AF_VSOCK` stream connection, regardless of destination port, bridges to this one host Unix domain socket — a clean host↔guest control channel, real credit-based flow control included. Guest-initiated only (no host-initiated connections). See [architecture.md](architecture.md). |
| `--control-socket <path>` | | Opens a Unix socket for live control of the running guest — memory/register peek/poke, triggering a snapshot, forking the guest into a brand new independent process, live-migrating it to a separate waiting process, and resetting/hot-reloading a `--device`/`--pci-device`/`--native-device`/`--wasm-device` plugin without restarting the guest. See [plugin-api.md](plugin-api.md#live-control---control-socket) and [security.md](security/security.md#4-the-live-control-socket-is-a-full-trust-local-interface) (it has no authentication of its own — restrict access via filesystem permissions on the socket path). Keep the path short: Unix sockets have an OS-level length limit (`SUN_LEN`, ~108 bytes on Linux). |
| `--restore <path>` | | Loads a snapshot written by the control socket's `snapshot <path>` command instead of booting `--kernel` normally. Single-vCPU only; not combinable with any `--device`/`--pci-device` (Python plugin state isn't part of a snapshot). See [plugin-api.md](plugin-api.md#snapshotrestore) and [security.md](security/security.md#snapshotrestore-scope). |
| `--migrate-listen <host:port>` | | Binds `host:port` and blocks until a *separate* hyperbug process's control socket runs `migrate <host:port>` against it, then resumes execution from exactly that process's live state — live migration's destination side. Same scope limits as `--restore` (single-vCPU, no `--device`/`--pci-device`), and mutually exclusive with it. `--kernel` still required but unused, same as `--restore`. See [plugin-api.md](plugin-api.md#live-migration). |
| `--gdb-stub <host:port>` | | Opens a real GDB/LLDB remote-serial-protocol TCP server and holds the BSP halted until a debugger connects (`target remote host:port`) — real breakpoints, single-stepping, register/memory access. BSP (vCPU 0) only; software breakpoints only. See [debugging.md](debugging.md#gdbllvm-remote-debugging). |
| `--trace-file <path>` | | Writes a Chrome Trace Event Format JSON file (`chrome://tracing`/Perfetto-loadable) covering every VM exit and interrupt injection. See [debugging.md](debugging.md#trace-export). |
| `--crash-dir <dir>` | | Where a triple-fault crash dump (full register state plus a short recent-VM-exit history) is written. Defaults to the current directory; a dump is always written on a triple fault regardless of whether this flag is given. See [debugging.md](debugging.md#crash-post-mortem-capture). |
| `--record <path>` | | Records real keyboard input, delivered TAP packets, and virtio-rng output, each tagged with a host branch-count position, to `path`. Single-vCPU only. Mutually exclusive with `--replay`. See [record-replay.md](record-replay.md). |
| `--replay <path>` | | Replays a recording written by `--record`: keyboard input and virtio-rng output are re-delivered from the recording; TAP packets are recorded but not replayed yet. Poll-granularity, not cycle-exact. Single-vCPU only. Mutually exclusive with `--record`. Real stdin is suppressed entirely — recorded input only. See [record-replay.md](record-replay.md). |

## Interactive console

The serial console (COM1) is a real two-way interactive terminal when run
from a real terminal: keystrokes go to the guest, guest output comes back,
and the host terminal is put into raw mode for the duration (restored on
exit, including via `libc::atexit` so a crash doesn't leave your shell in
raw mode). Since raw mode disables normal Ctrl-C handling, press **Ctrl-]**
to quit hyperbug at any time. An `acpi=off` guest has no other way to
self-terminate on halt; either use Ctrl-], or leave ACPI enabled (the
default) and run `poweroff` inside the guest for a clean shutdown.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean ACPI shutdown |
| 1 | Either hyperbug failed on this host (I/O, KVM, or a Python plugin load error) before or during the run, **or** the operator pressed Ctrl-] to quit — these share the same code by design, preserving a pre-existing exit code rather than changing externally-visible behavior in a refactor. Use `capture_output=True` with `hyperbug.VM` to get a real `HyperbugLaunchError` message distinguishing a launch failure instead of just the bare code. |
| 2 | Bad configuration: an out-of-range `--mem`/`--smp`/`--disk` value, a malformed `--device`/`--pci-device` spec, or a memory-layout constraint violated by the combination given — the guest never ran. |
| 10 | A requested reboot went through hyperbug's ACPI reset path. |
| 11 | Triple fault — ambiguous: this is also the mechanism behind a genuine kernel crash and (absent the ACPI reset path) any other reboot; hyperbug cannot distinguish these without parsing the guest's own kernel log. |
| 12 | Reserved, not currently produced: `HLT` is ordinary CPU idle once a guest is scheduling normally, not a terminal state — this code is kept numbered in `hyperbug.ExitCode` only for compatibility. |

`python/hyperbug/vm.py`'s `ExitCode` enum mirrors this table exactly; see
its docstring for the same caveats.
