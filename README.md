<p align="center">
  <img src="docs/assets/hyperbug.png" alt="hyperbug" width="160">
</p>

<h1 align="center">hyperbug</h1>

<p align="center">
  <b>A KVM-backed VMM whose devices you write in Python, not Rust.</b><br>
  Real hardware-assisted virtualization. Real unmodified guest kernels. Real drivers.<br>
  Standing up a new virtual device is a matter of writing a Python file — not recompiling a hypervisor.
</p>

---

## Why hyperbug exists

Emulators like Unicorn are fantastic for running *code* in isolation — but the moment you need a real guest OS talking to a real driver over a real bus, with real interrupts and real DMA, you're out of their depth. Full hypervisors like QEMU give you that, but their device model lives deep in a huge C codebase you don't want to touch just to prototype one fake NIC.

hyperbug sits in between: a **small, hackable VMM built directly on Linux KVM**, with a Rust core just large enough to boot a guest and route memory/interrupts/PCI correctly — and every actual *device* is a scriptable plugin. Want to reverse-engineer how a driver probes a piece of hardware? Fuzz a management controller's attack surface? Bridge a real guest OS into an existing emulation harness? Write the device in ~20 lines of Python and boot a real kernel against it.

## What you actually get

- **Real KVM, not an emulator.** Hardware virtualization, long mode, the real Linux boot protocol, real ACPI + SMBIOS tables — no BIOS/firmware layer standing between you and the guest.
- **Devices as scripts.** A virtual PCI/MMIO device is a Python class with `read`/`write`. Real DMA against guest memory, spontaneous interrupts, PCI capability lists + MSI, hot-reload without rebooting the guest.
- **A real virtio device zoo.** Block (io_uring-backed), network (a real TAP interface), entropy, I2C, GPIO (with real guest-delivered interrupts), and vsock (a real host↔guest control channel bridged to a Unix socket) — every one verified against the guest's own unmodified upstream Linux driver, not a toy stand-in.
- **Real SMP.** Additional vCPUs come up through a genuine INIT-SIPI-SIPI sequence, the same way real silicon does — not a faked CPU count.
- **A choice of sandboxing, not a single trust level.** In-process Python for speed, a sandboxed subprocess when you don't trust the plugin, a native C ABI when Python's overhead is the bottleneck, or WebAssembly for real memory-safety isolation at near-native speed.
- **Debugging tools that outclass a plain emulator.** A real GDB/LLDB remote stub, live memory/register control over a socket while the guest runs, Chrome-trace VM-exit profiling, automatic crash postmortems, and poll-granularity **record-and-replay** for deterministic re-execution.
- **Snapshot, fork, and live migration.** Serialize a running guest to disk, clone one instantly via copy-on-write `fork()`, or migrate it live to another host process — the same primitives that make fuzzing a whole VM state-space tractable.
- **Verified against real boots, not just unit tests.** Every feature above is checked by an automated test that actually boots a real kernel under real KVM and drives it — not mocked, not assumed.

## Quick start

```sh
cargo build --release
./target/release/hyperbug --kernel /path/to/bzImage --initrd /path/to/initramfs.cpio.gz
```

The serial console is a real two-way interactive terminal — your keystrokes go to the guest, its output comes back. Press **Ctrl-]** to quit at any time.

```python
from hyperbug import VM

with VM("bzImage", mem_mb=512, disks=["disk.img"], net=True) as vm:
    exit_code = vm.wait()
```

## Write a device in five minutes

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

That's a real MMIO device a real guest driver can probe and talk to. Need DMA, spontaneous interrupts, a PCI identity, sandboxing, or hot-reload? See [docs/plugin-api.md](docs/plugin-api.md). Prefer C, Rust, or Wasm instead of Python? See [docs/native-plugin-api.md](docs/native-plugin-api.md) (no isolation — read the security note first) or [docs/wasm-plugin-api.md](docs/wasm-plugin-api.md) (real sandboxing, in-process speed).

## Status

Under active development; see [docs/status.md](docs/status.md) for an honest, current breakdown of what's verified against real KVM boots, what works but is narrower in scope than it looks, and what's explicitly not built yet.

## Documentation

| Doc | Covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | How hyperbug is put together internally: process/thread model, boot path, device model, design rationale, and hard-won lessons from past bugs. |
| [docs/plugin-api.md](docs/plugin-api.md) | The full `Device`/`PciDevice`/`I2cDevice`/`GpioBank` Python plugin ABIs, the `hyperbug` Python package (`VM`, live control, snapshot/restore, hot-reload), and reference plugins. |
| [docs/native-plugin-api.md](docs/native-plugin-api.md) | The C-ABI plugin contract for `--native-device`/`--native-pci-device` — for when Python's overhead genuinely matters. **No isolation at all**; read this before using it. |
| [docs/wasm-plugin-api.md](docs/wasm-plugin-api.md) | The WASM plugin contract for `--wasm-device`/`--wasm-pci-device` — real memory-safety sandboxing at in-process speed, additive alongside the subprocess and native transports. |
| [docs/debugging.md](docs/debugging.md) | The GDB/LLDB remote stub, Chrome-trace VM-exit profiling, and crash postmortems. |
| [docs/record-replay.md](docs/record-replay.md) | Deterministic record-and-replay: what's captured, what isn't, and the real limitations. |
| [docs/security/security.md](docs/security/security.md) | Trust boundaries, what's enforced against a hostile guest or an untrusted plugin, and what's explicitly out of scope today. |
| [docs/security/defendmap.md](docs/security/defendmap.md) | The concrete attack-surface map: every place untrusted bytes reach hyperbug's code, and whether that surface is defended, partially defended, or still held open. |
| [docs/security/unsafe-audit.md](docs/security/unsafe-audit.md) | A consolidated review of every `unsafe` block in the codebase, file by file. |
| [docs/dev-guide.md](docs/dev-guide.md) | Building, testing (including the real KVM-backed boot tests), debugging techniques, and contribution conventions. |
| [docs/cli-reference.md](docs/cli-reference.md) | Every CLI flag and exit code. |
| [docs/status.md](docs/status.md) | What's verified, what's narrower than it looks, what's not done. |

## Requirements

See [docs/dev-guide.md](docs/dev-guide.md#requirements) for the full table. In short: a Rust toolchain, `/dev/kvm` for anything that actually runs a guest, and Python 3.10+ for device plugins. `iasl`/`busybox` are only needed for specific workflows (editing the ACPI DSDT, building a test initramfs by hand).

## Project layout

```
src/            Rust VMM core
devices/        example/reference Python, native (C), and WASM (Rust) device plugins
include/        hyperbug_plugin.h, the native plugin C ABI header
python/hyperbug/ the installable Python package (device base classes, VM launcher)
acpi/dsdt.asl   hand-authored AML source, compiled via iasl at build time
tests/boot.rs   real KVM-backed integration tests
docs/           architecture, plugin APIs, security, dev guide, CLI reference, status
```

See [docs/dev-guide.md](docs/dev-guide.md#project-layout) for the per-file breakdown of `src/`.

## Contributing

This is a research/hobby project; expect rough edges. Read [docs/dev-guide.md](docs/dev-guide.md) before making a change — it covers the testing bar (`cargo test --release` including real boot tests, `cargo clippy -- -D warnings`) and a few design conventions worth preserving.

## License

Not yet declared. Do not assume permission to redistribute until a license file is added.
