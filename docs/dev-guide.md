# Developer guide

Building, testing, debugging, and contributing to hyperbug. For what the
code does, see [architecture.md](architecture.md). For the plugin ABI, see
[plugin-api.md](plugin-api.md).

## Requirements

| Tool | Needed for | Install |
|---|---|---|
| Rust (edition 2024 toolchain) | Building the VMM core | `rustup` or your distro's package |
| `/dev/kvm` | The real boot tests in `tests/boot.rs`, and running any guest at all | present on any Linux host with KVM enabled; check with `ls /dev/kvm` |
| `iasl` (from `acpica`) | Editing `acpi/dsdt.asl` — `build.rs` recompiles it and fails the build if the embedded `src/dsdt.aml` is out of sync. Silently skipped (with a warning) if not installed — not needed for an ordinary `cargo build`. | `pacman -S acpica` or your distro's equivalent |
| `busybox` | Building a minimal test initramfs for manual boot testing (not shipped in the repo — you build one yourself when you need to boot something by hand) | `pacman -S busybox` |
| Python 3.10+ | Writing/running device plugins, and the `hyperbug` package itself | usually already present |
| `CAP_NET_ADMIN` or root | Only if you pass `--net` — hyperbug creates its own TAP interface at runtime | run under `sudo`, `setcap cap_net_admin+ep` on the binary, **or** `unshare --user --map-root-user --net` — an *unprivileged* user namespace maps you to root inside a throwaway, isolated network namespace, which is real, sufficient `CAP_NET_ADMIN` with no actual root at all. Confirmed directly against this project's own dev host, not assumed. See "Playing with it interactively" below for the trade-off (an isolated netns is invisible to your already-open browser; plain `sudo` isn't). |
| `wasm32-unknown-unknown` Rust target | Building `devices/wasm_*.rs` reference plugins, and `wasm_plugin.rs`'s own tests (they compile these on the fly and skip cleanly if the target isn't installed) | `rustup target add wasm32-unknown-unknown` |
| A C compiler (`cc`/`gcc`) | Building `devices/native_*.c` reference plugins, and `native_plugin.rs`'s own tests (same skip-cleanly convention) | usually already present |

## Building

```sh
cargo build --release
```

That's the only hard requirement. Debug builds work too but are
noticeably slower for anything that boots a real guest.

## Testing

```sh
cargo test --release
cargo clippy --release --all-targets -- -D warnings
```

The unit test suite (110+ tests) needs nothing beyond the Rust toolchain
and runs in well under a second — it covers CLI parsing, PCI/virtio
protocol logic, ACPI table integrity (checksum verification always; a
real `iasl` round-trip additionally, if installed), snapshot format
round-trips, and the Python plugin bridge (both loaders), all without
`/dev/kvm`.

A subset of these are **property-based tests** (via the `proptest`
dev-dependency — no extra install needed, `cargo` fetches it like any
other crate) rather than hand-picked cases: `pci::tests::
arbitrary_config_space_traffic_never_panics`, `virtio::tests::
try_pop_never_returns_an_out_of_bounds_or_oversized_chain`, and a few
others in `mem.rs`/`virtio_net.rs`/`virtio_rng.rs`. Each runs hundreds of
generated inputs per `cargo test` invocation; a failure is saved to
`proptest-regressions/<file>.txt` and replayed first on the next run, so
check that file in if a genuine regression is ever found there. See
[security/defendmap.md](security/defendmap.md) for exactly which
guest-controlled-input surfaces have this kind of coverage and which
still only have hand-picked tests.

`tests/boot.rs` additionally runs **real boot tests against actual KVM
guests** — not mocked, not simulated. They need `/dev/kvm`, a kernel image
(found under `/boot` automatically, or point `HYPERBUG_TEST_KERNEL` at a
specific bzImage), and `busybox`; each one prints a reason and passes
trivially if a prerequisite is missing, rather than failing on a machine
that doesn't have them. What they actually verify, live:

- A guest boots with a disk attached and shuts down cleanly via ACPI, with
  no virtio-pci probe failures.
- A real interactive console over a real PTY: typed input reaches the
  guest, its computed response comes back, `poweroff` from inside the
  guest triggers a real ACPI shutdown — with PCI/ACPI both enabled at once
  (the historical console-vs-ACPI conflict this project spent several
  sessions root-causing; see [architecture.md](architecture.md)'s History
  section).
- Multiple vCPUs actually come online (`--smp`), via a real INIT-SIPI-SIPI
  sequence, not a faked count.
- A PCI capability list + MSI-capable `--pci-device` enumerates cleanly.
- A `--pci-device` DMA-range confinement launches and enumerates cleanly.
- virtio-rng over the modern virtio 1.0 PCI transport.
- The live control socket can peek/poke a running guest's memory and
  registers from a separate process.
- A live snapshot, taken through the control socket, resumes correctly in
  a fresh process via `--restore`.

Run the interactive/SMP/console tests several times in a row if you're
touching anything concurrency-adjacent — this project has been burned
twice by a change that passed once and failed intermittently under real
load (see the plugin-timeout and wakeup-ticker incidents in
[architecture.md](architecture.md)'s History section). A single green run
is not sufficient evidence for a concurrency-sensitive change.

### Testing a Python-side change

```sh
python3 -m venv /tmp/hb-venv && source /tmp/hb-venv/bin/activate
pip install -e python/
python3 -c "from hyperbug import VM, Device, PciDevice; print('ok')"
```

Prefer exercising a real launch over just checking imports when you
change `hyperbug.VM` or a `DeviceSpec`/`PciDeviceSpec` field — building
the argv list correctly is necessary but not sufficient; confirm the
binary actually accepts what gets built:

```python
from hyperbug.vm import VM
vm = VM(kernel="/boot/vmlinuz-...", ...)
print(vm._build_args())   # inspect before trusting
vm.start(capture_output=True)
vm.wait(timeout=10)
```

## Debugging techniques that have actually worked here

- **`HYPERBUG_SERIAL_TRACE=1`** — a zero-cost-when-unset env-gated trace
  of every COM1 register access. This is what root-caused the ACPI/serial
  IRQ conflict: it showed the guest's `MCR` write happening and then
  total silence on every subsequent register, before the guest's own
  `open()`/`write()` calls returned `EIO`.
- **Port 0xE9 as a raw debug channel** — wired straight to host stdout,
  the classic QEMU/Bochs debug-console convention. Useful for getting
  diagnostic output out of a guest when the thing you suspect is broken
  is the console path itself, so you can't trust the normal console to
  report on its own failure. Requires a real character-special
  `/dev/port` node in the guest (`mknod` it explicitly in a throwaway
  initramfs `init` if you're building one by hand — a leftover regular
  file at that path will silently swallow every write with no error).
- **kprobes/kretprobes on a real kernel function**, when you have a
  matching `vmlinux` with symbols (`/usr/lib/modules/*/build/vmlinux` on
  most distro kernels) — this is what pinned down the exact `-EINVAL`
  inside `uart_startup()` after register-level tracing alone had
  localized the problem to "somewhere before the descriptor lookup" but
  not further. Needs `CONFIG_FTRACE=y`/`CONFIG_KPROBES=y` in the guest
  kernel's actual config (check `/proc/config.gz`).
- **Never trust a remembered register/table layout for anything with
  real revision history.** ACPI structures, real PCI/USB/virtio device
  IDs, and CPU MSR/XSAVE layouts have all had at least one "remembered
  from training data, turned out wrong" incident in this project's
  history. Check the host's own kernel headers (`/usr/lib/modules/*/
  build/include/...`) or `hwdata`/`pci.ids` before trusting a specific
  numeric constant.
- **A throwaway kvm-ioctls program** to check what `KVM_GET_SUPPORTED_
  CPUID` (or any other host-queried KVM capability) actually reports on
  the machine you're running on, before writing code that assumes a
  specific value — this caught that an earlier CPUID "fix" (masking
  MWAIT) was inert on the host it was tested on, because KVM already
  reported it unsupported there for unrelated reasons.

## Playing with it interactively

`demo/build.sh` builds `demo/initramfs.cpio.gz` — a minimal busybox image
with real networking (virtio-net + `httpd` serving a one-line page) and a
shell — for exactly this: booting a real guest by hand instead of through
`tests/boot.rs`. `demo/` is gitignored, same as any other throwaway boot
image; re-run the script any time (e.g. after a kernel upgrade changes
where its modules live).

None of what follows is a hyperbug bug — every one of these is a real
shell/job-control/sandboxing interaction that will bite anyone running it
by hand for the first time, found (and worked through, painfully) in a
real session:

- **Backgrounding hyperbug (`hyperbug ... &`) without redirecting its
  stdin away from your terminal stops it outright.** Hyperbug always
  tries to configure its controlling terminal for the guest console; a
  backgrounded process that touches the terminal gets `SIGTTIN`/
  `SIGTTOU`'d by the shell's own job control, and the default disposition
  is to *stop* the process — `jobs` will show `Stopped`, silently, with
  no error from hyperbug at all. Fix: redirect stdin, e.g. `hyperbug ...
  < /dev/null &`.
  - **The trade-off, stated directly**: doing that makes the guest
    console *output-only* — real keyboard input to the guest is
    disabled (hyperbug logs this: `reactor: stdin isn't pollable`). If
    you actually want to type into the guest interactively, run it in
    the **foreground** instead (no `&`, no stdin redirect) — that's the
    only mode with a real interactive console.
  - **A real trap this causes**: with stdin redirected but stdout *not*
    redirected, the guest's own shell prompt still prints to your
    terminal, indistinguishable from a live prompt — but anything you
    type goes to *your* shell, not the guest (input is disabled, per
    above). Typing `poweroff -f` in that state runs *your host's own*
    `poweroff` command, not the guest's.
- **`sudo` needs a real terminal to prompt for your password.**
  Backgrounding `sudo hyperbug ... &` with stdin redirected starves that
  prompt the exact same way — `sudo` ends up permanently `Stopped`
  waiting for input it can never receive, and nothing after it (e.g. `ip
  addr add ... dev hyperbug0`) will work, since hyperbug itself never
  actually started. Fix: run `sudo -v` once, in the foreground, *before*
  backgrounding anything — it caches your credentials for a few minutes
  so the later backgrounded `sudo` never needs to touch the terminal:
  ```sh
  sudo -v
  sudo ./target/release/hyperbug --kernel $K --initrd demo/initramfs.cpio.gz \
      --net --mem 256 < /dev/null > /tmp/hb-net.log 2>&1 &
  sleep 3
  sudo ip addr add 10.250.0.1/24 dev hyperbug0
  ```
  With real `sudo` (rather than an isolated `unshare` netns), the TAP
  interface lands in your normal network namespace — reachable from a
  browser or any other tool you already have open, no extra steps.
- **An `unshare --user --map-root-user --net`-launched Chromium/Chrome
  needs `--no-sandbox`.** Chromium refuses to run its sandboxed renderer
  as root, and `--map-root-user` makes the process look exactly like
  root from inside that namespace. Firefox doesn't have this restriction.
  This only matters if you want a GUI browser to reach a `--net` guest
  *without* real `sudo` — the browser has to be launched **inside** the
  same `unshare` invocation, since an isolated network namespace's TAP
  interface is invisible to a browser already running in your normal
  session:
  ```sh
  unshare --user --map-root-user --net bash -c '
    ip link set lo up
    ./target/release/hyperbug --kernel $K --initrd demo/initramfs.cpio.gz \
        --net --mem 256 < /dev/null > /tmp/hb-net.log 2>&1 &
    for i in $(seq 1 100); do grep -q "network: eth0 up" /tmp/hb-net.log && break; sleep 0.1; done
    ip addr add 10.250.0.1/24 dev hyperbug0
    chromium --no-sandbox http://10.250.0.2:8080/
  '
  ```

## Writing a device plugin

See [plugin-api.md](plugin-api.md) for the full contract; the short
version:

```python
from hyperbug import Device

class MyDevice(Device):
    def __init__(self):
        self.regs = bytearray(16)

    def read(self, offset, size):
        return bytes(self.regs[offset:offset + size])

    def write(self, offset, data):
        self.regs[offset:offset + len(data)] = data
```

```sh
./target/release/hyperbug --kernel bzImage \
    --device path/to/my_device.py:MyDevice:0xd0000000:0x1000
```

Start from `devices/scratch.py` (plain register file), `devices/
dma_demo.py` (DMA + spontaneous interrupt + MSI), or `devices/
doorbell_demo.py` (`tick()`-driven async completion) depending on which
pattern is closest to what you're building.

## Project layout

```
src/
  main.rs / config.rs   CLI parsing (a pure, testable function — no
                         process::exit inside the parser itself)
  lib.rs                run(): validate, build the VM, load the kernel,
                         start the vCPU threads. Orchestration only.
  loader.rs / gdt.rs     what gets written into guest memory before the
  / acpi.rs              first instruction executes
  machine.rs            assembles the device model: buses, PCI slots,
                         IRQ assignment
  vcpu.rs                one vCPU's VM-exit loop
  reactor.rs             the epoll thread: stdin/TAP, ioeventfd-driven
                         virtio kicks, io_uring completions
  irq.rs                 irqfd-backed interrupt lines
  device.rs / pci.rs /   the devices themselves
  virtio*.rs / serial.rs
  plugin.rs              ScriptedDevice: the one Device/PciDevice impl
                         shared by all four plugin transports
  pydevice.rs /          the in-process (PyO3) and sandboxed (subprocess)
  pydevice_proc.rs       PluginTransport implementations
  native_plugin.rs       the C-ABI (dlopen) PluginTransport implementation
  wasm_plugin.rs          the WASM (wasmtime) PluginTransport implementation
  mem.rs                 guest RAM (huge-page-hinted, checked/unchecked
                         split for DMA)
  error.rs               how a run ends (Result-based, not process::exit)
  control.rs              the live control-socket protocol
  snapshot.rs             the snapshot/restore file format
  seccomp.rs              seccomp-bpf deny-list for the sandboxed-plugin
                         subprocess
  cgroup.rs               best-effort cgroups v2 memory/CPU limits for
                         the sandboxed-plugin subprocess
  tty.rs / cpuid.rs      terminal raw-mode handling; CPUID curation
devices/                 example/reference Python, native (C), and WASM
                         (Rust) device plugins — .so/.wasm files aren't
                         checked in, compile the .c/.rs sources yourself
include/                 hyperbug_plugin.h, the native plugin C ABI header
python/hyperbug/          the installable Python package
acpi/dsdt.asl             the one hand-authored AML source, compiled via
                         iasl into src/dsdt.aml at build time
tests/boot.rs             real KVM-backed integration tests
docs/security/            trust model, per-surface attack-surface map,
                         unsafe-block audit
```

## Design conventions worth preserving

- **`Result`, not `process::exit`, inside the library core.** `lib::run()`
  returns `Result<GuestExit, HyperbugError>`; only `main.rs` translates
  that into a process exit code. This makes hyperbug embeddable (a caller
  can build an `Args` and call `run()` directly) and testable (every
  launch-failure path has a real unit test asserting a clean `Err`, not a
  captured panic).
- **Guest-supplied values are always the untrusted-input side of a bounds
  check.** Any time a guest (or, for DMA, a device plugin acting on the
  guest's behalf) supplies an address, length, or count, look for the
  existing checked-path convention (`mem.rs`'s `*_checked` helpers,
  `virtio.rs`'s descriptor-chain validation) before adding a new one —
  don't reach for an unchecked write meant for hyperbug's own trusted
  boot-time offsets.
- **New host-facing I/O should be event-driven, not polled**, unless
  there's a specific, stated reason it can't be (the one existing
  exception — the 20ms SIGALRM — exists purely to bound exit-request
  latency during guest idle, not as a general I/O pattern to imitate).
- **Verify a concurrency-sensitive change under real load, more than
  once**, before trusting it. Two separate incidents in this project's
  history (an interpreter-internal plugin timeout, and a per-vCPU wakeup
  ticker) each passed cleanly in isolation and failed only under the full
  test suite or a real multi-vCPU boot.
- **Check a real source before trusting a remembered fact** for anything
  with revision history: kernel headers, `pci.ids`/`hwdata`, `vmlinux`
  symbols, `iasl` compilation — this project has a specific, paid-for
  history of "remembered from training data" turning out wrong for ACPI
  layouts, PCI/virtio device IDs, and MSR/XSAVE requirements.

## Contributing

Touch only what a change needs; match the surrounding file's existing
style. Add a unit test for new logic that doesn't require a live guest,
and a `tests/boot.rs` test (or an extension of an existing one) for
anything that only a real boot can actually confirm. Run the full
`cargo test --release` + `cargo clippy --release --all-targets -- -D
warnings` before calling a change done — this project has repeatedly
found real bugs exactly at that step, not before it.
