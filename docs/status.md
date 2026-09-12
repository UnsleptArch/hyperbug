# Project status

hyperbug is a research/hobby-grade VMM under active development. This
page is the honest, current summary of what's solid, what's real but
narrow in scope, and what's explicitly not done yet. It replaces relying
on commit history or an internal debt ledger to answer "can I depend on
this."

## What's verified, live, against real KVM

- Boots a real, unmodified guest kernel (the standard Linux 64-bit boot
  protocol; no BIOS/firmware layer) to a real interactive userspace shell
  over a from-scratch 16550 UART.
- Real ACPI: clean shutdown and reboot via real ACPI register writes, PCI
  BAR assignment via a real `_CRS`, correct interrupt routing via a real
  `_PRT`, with the console and PCI/ACPI working simultaneously (not
  mutually exclusive, as they once were — see
  [architecture.md](architecture.md)'s History section).
- Real multi-vCPU SMP: additional vCPUs come online via a genuine
  INIT-SIPI-SIPI sequence, not a faked CPU count.
- virtio-blk (legacy transport, real io_uring-backed async I/O),
  virtio-net (a real host TAP interface), virtio-rng (legacy and modern
  virtio 1.0 transports).
- A real interactive console over a real PTY, keystrokes delivered via a
  real epoll-driven reactor and irqfd, not a polling loop.
- Live control-socket access to a running guest's memory and registers
  from a separate process, and a real snapshot/restore round trip.
- Python device plugins, both in-process (PyO3) and sandboxed
  (subprocess-isolated), with real DMA, spontaneous interrupts, PCI
  identity/MSI, and an opt-in `tick()` hook — all exercised by both unit
  tests and, where it matters, real boot tests.

All of the above has at least one automated test that exercises it
against real `/dev/kvm` (`tests/boot.rs`), not just unit-level logic —
run `cargo test --release` to reproduce this yourself.

## What's real but narrower in scope than it might first appear

- **PCI**: a single flat bus, type-0 headers only — no bridges, no
  multi-function devices, no PCIe ECAM. A capability list and MSI exist,
  but only for a custom `--pci-device` plugin's own device model; virtio
  deliberately never uses plain MSI (the real Linux virtio driver never
  requests it).
- **Modern virtio 1.0**: implemented and wired to exactly one device
  (`--rng-modern`), as a vertical-slice proof rather than a full
  replacement for the legacy transport blk/net still use.
- **DMA confinement for Python plugins**: an operator-declared bound on
  what a specific plugin's `read_mem`/`write_mem` may reach — not a
  guest-facing IOMMU, and not a general privilege sandbox. See
  [security.md](security.md) for exactly what it does and doesn't cover.
- **Sandboxed plugins**: isolate a hang/crash from taking down the guest
  or VMM; not a privilege sandbox (no seccomp/namespace/capability drop).
- **CPUID curation**: a small number of specific, evidence-checked
  corrections (MONITOR/MWAIT, HTT/thread-count leakage, APIC ID/thread
  count in a couple of leaves) layered on raw host pass-through — not a
  from-scratch curated CPU model.
- **Snapshot/restore**: solid for a resumed *idle* guest; two known,
  specific correctness gaps remain open (see
  [security.md](security.md#snapshotrestore-scope)).

## What's explicitly not done

- No guest-facing IOMMU / DMA remapping.
- No seccomp/namespace/capability sandboxing of sandboxed-plugin
  subprocesses.
- No authentication or encryption on the live control socket (filesystem
  permissions on the socket path are the only access control).
- No PCI bridges, multi-function devices, or PCIe ECAM.
- No automated CI-triggered publishing/release process — `.github/
  workflows/ci.yml` runs build/clippy/test on every push, but there is no
  packaging or release pipeline beyond that.
- No formal API-stability guarantee beyond `HYPERBUG_API_VERSION`'s own
  breaking-change bump for the plugin ABI specifically; the CLI/Rust
  embedding surface (`Args`, `run()`) has no separate versioning scheme
  yet.

## Continuous integration

`.github/workflows/ci.yml` runs `cargo build`, `cargo clippy -- -D
warnings`, and the full test suite (including the real KVM-backed boot
tests — GitHub's Ubuntu runners provide `/dev/kvm`) on every push, after
installing `iasl` and `busybox`.
