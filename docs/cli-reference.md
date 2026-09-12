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
| `--net` | | Adds a virtio-net device backed by a TAP interface hyperbug creates itself at runtime. Needs `CAP_NET_ADMIN` or root. |
| `--rng-modern` | | Attaches virtio-rng over the modern virtio 1.0 PCI transport (memory-mapped BARs via a real PCI capability list) instead of the legacy I/O-BAR transport every other virtio device here uses. No MSI-X yet — a real driver falls back to legacy INTx cleanly. |
| `--device <path.py>:<Class>:<base>:<size>[:<dma_base>:<dma_size>]` | yes | Loads a Python device plugin at a fixed MMIO address, in-process. `base`/`size` are hex (`0x` prefix optional). The optional trailing `<dma_base>:<dma_size>` confines this plugin's `self.hyperbug.read_mem`/`write_mem` to that guest-physical range — see [security.md](security.md#dma-confinement) and [plugin-api.md](plugin-api.md#dma-confinement). Omit it for unrestricted access (the default, and every shipped example's setting). |
| `--pci-device <path.py>:<Class>:<device_number>[:<dma_base>:<dma_size>]` | yes | Loads a Python device plugin on the PCI bus (function 0) at the given device number (0-31; slots 4-11/16/17 are reserved for hyperbug's own virtio devices and rejected as a config error). The plugin's own attributes declare its PCI identity — see [plugin-api.md](plugin-api.md#the-pcidevice-contract). Same optional DMA-range suffix as `--device`. |
| `--device-sandboxed <path.py>:<Class>:<base>:<size>[:<dma_base>:<dma_size>]` | yes | Same spec syntax as `--device`, but the plugin runs in its own `python3` subprocess: a hung or crashed plugin is killed rather than stalling or crashing the guest. See [plugin-api.md](plugin-api.md#sandboxed-plugins---device-sandboxed--pci-device-sandboxed). |
| `--pci-device-sandboxed <path.py>:<Class>:<device_number>[:<dma_base>:<dma_size>]` | yes | The `--pci-device` equivalent of `--device-sandboxed`. |
| `--control-socket <path>` | | Opens a Unix socket for live control of the running guest — memory/register peek/poke, and triggering a snapshot. See [plugin-api.md](plugin-api.md#live-control---control-socket) and [security.md](security.md#4-the-live-control-socket-is-a-full-trust-local-interface) (it has no authentication of its own — restrict access via filesystem permissions on the socket path). Keep the path short: Unix sockets have an OS-level length limit (`SUN_LEN`, ~108 bytes on Linux). |
| `--restore <path>` | | Loads a snapshot written by the control socket's `snapshot <path>` command instead of booting `--kernel` normally. Single-vCPU only; not combinable with any `--device`/`--pci-device` (Python plugin state isn't part of a snapshot). See [plugin-api.md](plugin-api.md#snapshotrestore) and [security.md](security.md#snapshotrestore-scope). |

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
