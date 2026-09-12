# hyperbug

A small, hackable virtual-machine monitor built directly on Linux **KVM**
(hardware-assisted virtualization, not software CPU emulation). The core
VMM is Rust; its **devices are Python plugins** — standing up a custom
virtual PCI/MMIO device is a matter of writing a Python file, not
recompiling a hypervisor.

hyperbug boots a real, unmodified guest kernel (long mode, the real Linux
boot protocol, real ACPI tables) with real interrupts, real DMA-shaped
memory sharing, real multi-vCPU SMP, and virtio-based block/network/
entropy devices — no BIOS or firmware layer involved.

## Status

Under active development; see [docs/status.md](docs/status.md) for an
honest, current breakdown of what's verified against real KVM boots, what
works but is narrower in scope than it looks, and what's explicitly not
built yet.

## Quick start

```sh
cargo build --release
./target/release/hyperbug --kernel /path/to/bzImage --initrd /path/to/initramfs.cpio.gz
```

The serial console is a real two-way interactive terminal — your
keystrokes go to the guest, its output comes back. Press **Ctrl-]** to
quit at any time.

```python
from hyperbug import VM

with VM("bzImage", mem_mb=512, disks=["disk.img"], net=True) as vm:
    exit_code = vm.wait()
```

## Documentation

| Doc | Covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | How hyperbug is put together internally: process/thread model, boot path, device model, design rationale, and hard-won lessons from past bugs. |
| [docs/plugin-api.md](docs/plugin-api.md) | The full `Device`/`PciDevice` plugin ABI, the `hyperbug` Python package (`VM`, live control, snapshot/restore), and reference plugins. |
| [docs/security/security.md](docs/security/security.md) | Trust boundaries, what's enforced against a hostile guest or an untrusted plugin, and what's explicitly out of scope today. |
| [docs/security/defendmap.md](docs/security/defendmap.md) | The concrete attack-surface map: every place untrusted bytes reach hyperbug's code, and whether that surface is defended, partially defended, or still held open. |
| [docs/security/unsafe-audit.md](docs/security/unsafe-audit.md) | A consolidated review of every `unsafe` block in the codebase, file by file. |
| [docs/dev-guide.md](docs/dev-guide.md) | Building, testing (including the real KVM-backed boot tests), debugging techniques, and contribution conventions. |
| [docs/cli-reference.md](docs/cli-reference.md) | Every CLI flag and exit code. |
| [docs/status.md](docs/status.md) | What's verified, what's narrower than it looks, what's not done. |

## Requirements

See [docs/dev-guide.md](docs/dev-guide.md#requirements) for the full
table. In short: a Rust toolchain, `/dev/kvm` for anything that actually
runs a guest, and Python 3.10+ for device plugins. `iasl`/`busybox` are
only needed for specific workflows (editing the ACPI DSDT, building a
test initramfs by hand).

## Writing a device plugin

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

Full contract, DMA/interrupt access, sandboxing, and PCI identity in
[docs/plugin-api.md](docs/plugin-api.md).

## Project layout

```
src/            Rust VMM core
devices/        example/reference Python device plugins
python/hyperbug/ the installable Python package (device base classes, VM launcher)
acpi/dsdt.asl   hand-authored AML source, compiled via iasl at build time
tests/boot.rs   real KVM-backed integration tests
docs/           architecture, plugin API, security, dev guide, CLI reference, status
```

See [docs/dev-guide.md](docs/dev-guide.md#project-layout) for the
per-file breakdown of `src/`.

## Contributing

This is a research/hobby project; expect rough edges. Read
[docs/dev-guide.md](docs/dev-guide.md) before making a change — it covers
the testing bar (`cargo test --release` including real boot tests,
`cargo clippy -- -D warnings`) and a few design conventions worth
preserving.

## License

Not yet declared. Do not assume permission to redistribute until a
license file is added.
