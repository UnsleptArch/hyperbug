<p align="center">
  <img src="docs/assets/hyperbug.png" alt="hyperbug" width="160">
</p>

<h1 align="center">hyperbug</h1>

<p align="center">
  A VMM built on KVM where devices are Python scripts instead of Rust code.
</p>

---

hyperbug is a small virtual machine monitor built directly on Linux KVM. The core is Rust and stays small on purpose. It's just enough to boot a guest kernel and get memory, interrupts, and PCI right. Anything that would normally mean recompiling a hypervisor, like adding a new device, is instead a Python file.

Unicorn and friends are great for running code in isolation, but the moment you need an actual guest OS talking to an actual driver over an actual bus, they run out of road. QEMU gets you there, but its device model lives in a C codebase most people don't want to open just to fake one NIC. hyperbug is the middle ground. KVM does the heavy lifting and you write the device.

## What's in it

- **KVM, not emulation.** Long mode, the Linux boot protocol, ACPI and SMBIOS tables. No BIOS layer in the way.
- **Devices as Python.** A PCI or MMIO device is a class with `read`/`write`. DMA against guest memory, spontaneous interrupts, PCI capability lists and MSI, hot reload without rebooting the guest.
- **A decent virtio lineup.** Block using io_uring, network over TAP, entropy, I2C, GPIO with guest delivered interrupts, and vsock as a channel between host and guest bridged over a Unix socket. Each one is checked against the guest's own unmodified upstream driver.
- **SMP that isn't faked.** Extra vCPUs come up through an actual INIT SIPI SIPI sequence.
- **Pick your isolation level.** In process Python if you trust the plugin, a sandboxed subprocess if you don't, a C ABI if Python overhead is the problem, or WASM if you want memory safety without the subprocess round trip.
- **Debugging that doesn't suck.** A GDB or LLDB remote stub, live memory and register control over a socket while the guest runs, Chrome trace VM exit profiling, automatic crash dumps, and record and replay for deterministic reruns.
- **Snapshot, fork, migrate.** Dump a running guest to disk, clone one instantly with a copy on write `fork()`, or move it to another process live.
- **Tests that actually boot a kernel.** Every feature above has an automated test that boots real KVM and drives it. Nothing here is mocked.

## Quick start

```sh
cargo build --release
./target/release/hyperbug --kernel /path/to/bzImage --initrd /path/to/initramfs.cpio.gz
```

The serial console is a two way interactive terminal. Type into it and see the guest's output. Ctrl-] to quit.

```python
from hyperbug import VM

with VM("bzImage", mem_mb=512, disks=["disk.img"], net=True) as vm:
    exit_code = vm.wait()
```

## Write a device

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

That's a working MMIO device a guest driver can probe. For DMA, interrupts, a PCI identity, sandboxing, or hot reload, see [docs/plugin-api.md](docs/plugin-api.md). Want C, Rust, or Wasm instead of Python? Check [docs/native-plugin-api.md](docs/native-plugin-api.md) (no isolation, read the security note first) or [docs/wasm-plugin-api.md](docs/wasm-plugin-api.md) (sandboxed, in process speed).

## Status

Under active development. [docs/status.md](docs/status.md) has an honest breakdown of what's verified against real boots, what's narrower than it looks, and what isn't built yet.

## Documentation

| Doc | Covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Process/thread model, boot path, device model, and why things are built the way they are. |
| [docs/plugin-api.md](docs/plugin-api.md) | The `Device`/`PciDevice`/`I2cDevice`/`GpioBank` Python ABIs, the `hyperbug` package (`VM`, live control, snapshot/restore, hot reload), reference plugins. |
| [docs/native-plugin-api.md](docs/native-plugin-api.md) | The C ABI plugin contract. No isolation at all. Read this first. |
| [docs/wasm-plugin-api.md](docs/wasm-plugin-api.md) | The WASM plugin contract. Sandboxed, in process speed. |
| [docs/debugging.md](docs/debugging.md) | GDB/LLDB stub, trace export, crash postmortems. |
| [docs/record-replay.md](docs/record-replay.md) | What record/replay captures, what it doesn't, and the limits. |
| [docs/security/security.md](docs/security/security.md) | Trust boundaries and what's out of scope today. |
| [docs/security/defendmap.md](docs/security/defendmap.md) | Every place untrusted bytes reach hyperbug's code, and whether it's defended. |
| [docs/security/unsafe-audit.md](docs/security/unsafe-audit.md) | Every `unsafe` block, file by file. |
| [docs/dev-guide.md](docs/dev-guide.md) | Building, testing, debugging, contribution conventions. |
| [docs/cli-reference.md](docs/cli-reference.md) | Every CLI flag and exit code. |
| [docs/status.md](docs/status.md) | What's verified, what's not. |

## Requirements

Full table in [docs/dev-guide.md](docs/dev-guide.md#requirements). Short version, you need a Rust toolchain, `/dev/kvm` to run anything, and Python 3.10+ for plugins. `iasl` and `busybox` only matter if you're editing the ACPI DSDT or building a test initramfs by hand.

## Project layout

```
src/            Rust VMM core
devices/        example Python, native (C), and WASM (Rust) device plugins
include/        hyperbug_plugin.h, the native plugin C ABI header
python/hyperbug/ the installable Python package (device base classes, VM launcher)
acpi/dsdt.asl   AML source written by hand, compiled via iasl at build time
tests/boot.rs   integration tests that run against real KVM
docs/           architecture, plugin APIs, security, dev guide, CLI reference, status
```

File by file breakdown of `src/` is in [docs/dev-guide.md](docs/dev-guide.md#project-layout).

## Contributing

This is a research/hobby project, so expect rough edges. Read [docs/dev-guide.md](docs/dev-guide.md) before sending changes. It covers the testing bar (`cargo test --release`, including the real boot tests, and `cargo clippy -- -D warnings`) and a few conventions worth keeping.

## License

GPLv3. See [LICENSE](LICENSE).
