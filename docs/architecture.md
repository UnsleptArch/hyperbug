# Architecture

This document describes how hyperbug is put together internally: the
process/thread model, the boot path, the device model, and the reasoning
behind the major design decisions. For the day-to-day "how do I build/test
this" workflow, see [dev-guide.md](dev-guide.md). For the plugin-facing
contract, see [plugin-api.md](plugin-api.md). For the trust model and known
attack surface, see [security.md](security/security.md).

## What hyperbug is

hyperbug is a virtual-machine monitor (VMM) built directly on Linux **KVM**
— hardware-assisted virtualization, not a CPU emulator. The VMM core is
Rust; devices are Python plugins loaded into the same process (or, for the
sandboxed variants, a child process) via [PyO3](https://pyo3.rs).

The design goal is to make it as cheap as possible to stand up a fully
custom, scriptable virtual device — a fake PCI card, a bridge into some
other tool, a research instrument — while still giving the guest a *real*
OS environment: real interrupts, real DMA-shaped memory sharing, a real
guest kernel booted through the actual Linux boot protocol, and (with
`--smp`) real multi-vCPU execution brought up via a genuine INIT-SIPI-SIPI
sequence, not a faked CPU count.

## Process and thread model

A single `hyperbug` process owns:

- One `/dev/kvm` file descriptor, one `KVM_CREATE_VM`, one in-kernel
  irqchip (PIC + IOAPIC + LAPIC) and PIT.
- One anonymous `mmap` backing all of guest RAM (`GuestMemory`, `mem.rs`),
  `MADV_HUGEPAGE`-hinted opportunistically.
- One OS thread per vCPU. vCPU 0 boots the kernel directly (its registers
  are set up by hand per the Linux 64-bit boot protocol); vCPUs 1..N start
  in `KVM_MP_STATE_UNINITIALIZED` and come up only once the guest's own
  bootstrap processor sends a real INIT-SIPI-SIPI sequence through its
  local APIC — handled entirely by KVM's in-kernel APIC emulation, with
  zero IPI-delivery code in this codebase.
- One reactor thread (`reactor.rs`) blocking in a real `epoll_wait` on
  stdin, the TAP fd (if `--net`), every virtio device's registered
  ioeventfd, and virtio-blk's io_uring completion eventfd. This is what
  delivers a keystroke or a network packet to the guest immediately,
  whether the guest is busy or fully halted in `HLT` — there is no
  polling loop and no fixed-latency tick for these paths.
- A shared device model (`SharedState`, built by `machine.rs`) behind one
  `Mutex`, used only long enough to look up which device an access belongs
  to — see "Locking" below.
- Optionally, one background thread per sandboxed Python plugin's IPC
  (reading replies from that plugin's subprocess) and one dedicated
  `python3` child process per sandboxed plugin.

There is **one exception to "no busy polling"**: a single process-wide
`SIGALRM` fires every 20ms (`tty::install_periodic_wakeup`) to reliably
interrupt a vCPU thread blocked inside `KVM_RUN`, so the main loop gets a
bounded-latency chance to notice a shared exit request even when the guest
is in a long NOHZ-idle `HLT`. This is deliberately *not* a per-thread
`pthread_kill` design — an earlier attempt at that stalled real SMP
bring-up by racing forced `EINTR`s against KVM's own INIT-SIPI-SIPI
handling (see the History section).

## Locking

Every device lives behind its own `Arc<Mutex<dyn Device>>`. `SharedState`
holds one lock for the buses (PCI config space, BAR routing, IRQ
assignment) and dispatch tables. The steady-state access pattern is:

1. Lock `SharedState` just long enough to find which device an address
   belongs to (`Bus::find_device`), clone the `Arc`, release the lock.
2. Lock only that device to actually call `read`/`write`/`tick`.

This means a slow device (a Python plugin doing real work, or a subprocess
round trip) blocks neither unrelated devices nor other vCPUs for the
duration of its own call — only whichever other caller happens to want
*that same* device at the same moment. Serial and PCI config-space access
are the one exception: both are fast, pure in-Rust register logic with no
device call inside, so they stay under the coarse lock rather than adding
lock-acquisition overhead for no isolation benefit.

## Boot path

1. `main.rs` parses `argv` into `config::Args` and calls `lib::run()`.
   Argument parsing is a pure, testable function — no `process::exit`
   inside it — so an embedder can build an `Args` directly without going
   through a CLI at all.
2. `lib::run()` validates arguments, opens `/dev/kvm`, creates the VM,
   irqchip and PIT, maps guest memory (`mem.rs`), and either:
   - loads a real bzImage kernel + optional initramfs via the Linux 64-bit
     boot protocol (`loader.rs`: zero-page/`boot_params`, e820 map,
     cmdline, identity-mapped page tables built by hand in `gdt.rs`, up to
     the dynamically-computed maximum guest RAM size the low-memory page
     table budget allows), or
   - restores a previously-saved snapshot (`snapshot.rs`) instead, skipping
     the boot path entirely and resuming from exactly where the snapshot
     was taken.
3. `machine.rs` builds the device model: buses, the fixed PCI slot/GSI
   layout (see below), ACPI tables (`acpi.rs`), and every device the
   arguments asked for (virtio-blk/net/rng, Python plugins, in-process or
   sandboxed).
4. `vcpu.rs` spawns one thread per vCPU and enters the VM-exit loop:
   dispatch on the reason (`IoIn`/`IoOut`/`MmioRead`/`MmioWrite`/`Hlt`/
   `Shutdown`/...), find the owning device, call into it, poll any pending
   Python `tick()`/spontaneous-interrupt state once per iteration.
5. On exit (clean shutdown, a requested reboot, a triple fault, or an
   error), `error::ExitSlot` records the first result — whichever vCPU or
   in-guest ACPI device gets there first — and `run()` returns a
   `Result<GuestExit, HyperbugError>` rather than calling
   `process::exit` itself; `main.rs` is the only place that translates
   that into a process exit code.

## Guest-visible hardware

- **CPU**: raw `KVM_GET_SUPPORTED_CPUID` pass-through, curated in
  `cpuid.rs` for a small number of confirmed, evidence-based
  corrections — MONITOR/MWAIT cleared (defense in depth; KVM/AMD hosts
  already report it absent), HTT and the logical-processor-count field
  corrected to match the single (or N, under `--smp`) vCPU actually
  modeled rather than leaking the host's real thread count, and the
  topology fields in leaf `0x0B` (x2APIC ID) and `0x80000008` (physical
  thread count) corrected per vCPU. Nothing else is touched — this is
  curation of specific known-bad leaks, not a from-scratch CPUID model.
- **Memory**: one flat identity-mapped region, long-mode 2 MiB pages, up
  to whatever the low-memory page-table budget allows before
  `KERNEL_START` (computed at runtime, not hardcoded — currently on the
  order of ~245 GiB of addressable guest RAM headroom on a typical layout).
  `MADV_HUGEPAGE`-hinted (opportunistic; failure is advisory-only, no host
  hugetlbfs reservation required).
- **Serial (COM1)**: a from-scratch 16550 UART (`serial.rs`) implementing
  enough of THR/LSR/IER/MSR/SCR/RBR for both the kernel's own polled
  printk console and a real userspace `write()`/interactive shell to work,
  including the IER-readback autoconfig probe every real 8250 driver
  performs before trusting the port. `HYPERBUG_SERIAL_TRACE=1` enables a
  zero-cost-when-unset register-level trace for debugging.
- **ACPI**: RSDP/RSDT/XSDT/FADT/MADT plus one small hand-authored DSDT
  (`acpi/dsdt.asl`, compiled via `iasl`) describing the PCI root bridge's
  `_CRS` (I/O/memory apertures for BAR assignment), `\_SB.PCI0`'s `_PRT`
  (interrupt routing for every fixed PCI slot), `\_SB.COM1` (so Linux's
  ACPI/PNP layer doesn't reserve IRQ4 out from under the serial port — see
  History), and a `\_S5` shutdown package plus a real `RESET_REG` for a
  clean, distinguishable reboot path. Uses ACPI's hardware-reduced model:
  every legacy PM1x/GPE register block is honestly zeroed rather than
  half-implemented, and shutdown/reset go through dedicated I/O-port
  devices (`acpi::SleepControl`/`ResetControl`) instead.
- **PCI**: generic CF8/CFC config-space mechanism (`pci.rs`), bus 0 only,
  type-0 headers, memory and I/O BAR sizing/assignment, a capability list
  with single-message 32-bit MSI (opt-in, for a custom device with a real
  driver that requests it — hyperbug's own virtio devices never do, since
  the real Linux virtio driver only ever requests MSI-X or falls back to
  INTx), and real `KVM_IOEVENTFD`-backed notification for virtio queue
  kicks (bound/rebound as a device's BAR is reprogrammed).
- **Storage**: virtio-blk over the legacy I/O-BAR virtio-PCI transport.
  IN/OUT requests submit through real `io_uring` (`IORING_OP_READV`/
  `WRITEV` directly against guest memory — no host staging buffer) and
  complete asynchronously via the reactor; FLUSH/DISCARD/WRITE_ZEROES stay
  synchronous (rare, not latency-sensitive). DISCARD/WRITE_ZEROES are real
  — a WRITE_ZEROES genuinely zeroes the requested byte range on the
  backing file, streamed through a fixed-size buffer rather than
  allocating a guest-controlled amount of memory.
- **Network**: virtio-net over the same legacy transport, backed by a TAP
  interface hyperbug creates itself at runtime (needs `CAP_NET_ADMIN` or
  root).
- **Entropy**: virtio-rng, either over the legacy transport (default) or
  the modern virtio 1.0 PCI transport (`--rng-modern` — the first vertical
  slice of that transport, not yet extended to blk/net), filled from real
  `getrandom(2)` output.
- **Fixed PCI slot/GSI layout** (`machine.rs`, kept static so
  `acpi/dsdt.asl`'s `_PRT` never has to change at runtime):

  | Slot | Device | GSI |
  |---|---|---|
  | 0 | host bridge stub | — |
  | 4-11 | up to 8 virtio-blk disks (`--disk`, one slot each) | 10 (shared) |
  | 16 | virtio-net (`--net`) | 11 |
  | 17 | virtio-rng | 12 |
  | 1-3, 18-31 | free for `--pci-device`/`--pci-device-sandboxed` | — |

  A `--pci-device` slot outside 4-11/16/17 has no matching `_PRT` entry —
  it works with ACPI disabled (which trusts the plugin's declared
  `interrupt_line` directly) but won't route an interrupt under ACPI
  without adding one.

## Python device plugins

See [plugin-api.md](plugin-api.md) for the full contract. In short:
hyperbug's Rust core knows nothing about any specific device's identity —
it exposes a generic MMIO/PCI-BAR-mapped register ABI (`read`/`write`,
optional `tick()`, optional PCI identity attributes) that a plugin
implements in Python, either loaded in-process via PyO3 (`pydevice.rs`) or
in its own subprocess (`pydevice_proc.rs`, `--*-sandboxed`) for isolation
from a plugin that hangs or crashes. A sandboxed plugin's subprocess is
additionally launched under a real seccomp-bpf deny-list (`seccomp.rs`,
installed via `Command::pre_exec` between `fork` and `exec`) blocking a
targeted set of privilege-escalation syscalls — see
[security.md](security/security.md) for exactly what it does and
doesn't cover.

## Snapshot/restore

`snapshot.rs` serializes vCPU register/FPU/MSR state, the in-kernel
PIC/PIT state, guest memory, and every built-in device's own protocol
state (serial, PCI config space, both virtio PCI transports) to a single
file, triggered live via the control socket's `snapshot <path>` command.
`--restore <path>` loads one instead of booting normally. Scope is
deliberately narrow: single-vCPU only, and no Python plugin state (a
plugin's own Python object graph isn't part of the format) — both checked
and refused at launch rather than silently producing a broken restore. See
[security.md](security/security.md) and the dev-guide's testing section for the
two known-open edge cases (a task woken immediately post-restore, and a
virtio-blk request genuinely in flight through io_uring at snapshot time).

## Why key decisions were made this way

- **Rust core, Python devices** — matches the project's other tooling
  conventions and keeps the trusted core small and memory-safe while
  making device authorship as cheap as writing a script.
- **PyO3 (embedded CPython) over an out-of-process device model by
  default** — proven across every device-scripting feature since; the
  out-of-process model exists too (`--*-sandboxed`), opt-in, for exactly
  the case embedding doesn't cover well: isolating a plugin you don't
  trust to behave.
- **KVM, not a CPU emulator** — the entire reason this project exists is
  giving a *real* guest OS and its *real*, unmodified drivers something to
  talk to (see the "Why hyperbug exists" section below); an emulator adds
  nothing to that goal and a great deal of complexity.
- **Legacy (I/O-BAR) virtio as the default transport, modern virtio 1.0 as
  an opt-in slice** — legacy needed nothing new from the PCI layer beyond
  I/O BARs and was the fastest path to a working virtio-blk/net/rng;
  modern was added once a genuine reason existed (proving the vertical
  slice), not spun up unconditionally.
- **No busy-spin anywhere except one 20ms process-wide timer** — every
  other host-facing I/O path (stdin, TAP, virtio kicks, io_uring
  completions) is real epoll-driven, event-triggered delivery. The one
  timer exists purely to guarantee a bounded-latency chance to notice a
  cross-thread exit request during a long guest idle period; it is not
  how any actual I/O gets delivered.
- **A single shared `Mutex` for bus/dispatch state, per-device locks for
  the device calls themselves** — narrower locking (e.g. splitting
  `PciBus`'s own internal state further) was considered and deliberately
  not done: PCI enumeration-time state is touched rarely, so there is no
  demonstrated contention there to justify the added complexity.

## Why hyperbug exists

hyperbug was built to close a specific gap in embedded-firmware
rehosting and dynamic-analysis work: a CPU-instruction emulator (Unicorn,
QEMU TCG, etc.) can execute real firmware faithfully, but it has no OS, no
real device drivers, and no real network stack around it. Some classes of
target — anything that matters because it's *reachable* from a real
operating system's real driver stack, or from a real network, rather than
because of what its own firmware does in isolation — need that reachable
surface to be real, not simulated. hyperbug supplies exactly that: a real
guest Linux kernel, booted through the real boot protocol, running real
unmodified drivers against devices defined in a few lines of Python, with
real interrupts, real DMA, real networking, and real multi-vCPU execution.
It is intentionally a general-purpose, vendor-neutral substrate — nothing
in hyperbug's own tree encodes any specific real vendor's hardware
identity; that belongs entirely in a `.py` plugin file loaded via
`--device`/`--pci-device`, owned wherever that device-specific work
actually lives.

## History and hard-won lessons

A few bugs were expensive enough to find that they're worth stating
directly, so a future change doesn't reintroduce them:

- **A minimal UART is not enough for real userspace I/O.** Implementing
  only THR/LSR (enough for the kernel's own polled printk) let the kernel
  boot but silently broke every real `write()` to the tty: Linux's 8250
  driver does an IER-register read-back probe (`autoconfig()`) to confirm
  real silicon, and a write-only IER fails that probe, leaving the port
  `PORT_UNKNOWN` and every later write returning `-EIO` with no log
  output explaining why. Beyond that, THRI's interrupt-enable bit must be
  treated as level-triggered and pulsed the moment it's armed — not only
  after a byte is written to THR — since the driver only pushes bytes to
  THR from inside the ISR that same IRQ triggers.
- **ACPI's IRQ reservation can silently starve a device that has no ACPI
  presence.** Once ACPI tables existed, the serial port's `uart_startup()`
  started failing with `-EINVAL` — traced (via a real kprobe on
  `request_threaded_irq`, checked against the actual running kernel's own
  `vmlinux` with symbols) to `IRQ_NOREQUEST` being set on IRQ4's
  descriptor, because Linux's ACPI/PNP layer defensively reserves any ISA
  IRQ nothing in the ACPI namespace claims. The fix was describing the
  serial port in the DSDT (`\_SB.COM1`, a real `_HID`/`_CRS`) — real
  hardware never hits this because a real BIOS always includes that
  device.
- **Two independent interpreter-internal plugin-timeout mechanisms both
  failed under real concurrent load, and both failures were only visible
  under load, not in isolation.** `PyErr_SetInterrupt()` targets whichever
  thread CPython considers "the main thread" — ambiguous once more than
  one thread touches the interpreter — and hung for 60+ seconds when the
  full test suite ran concurrently, despite passing cleanly alone.
  `PyThreadState_SetAsyncExc` (targeting a specific thread id) segfaulted
  under the same load instead. Both were reverted; the actual fix
  (`--*-sandboxed`) uses a real OS subprocess and `SIGKILL`, which cannot
  hang or corrupt the parent regardless of what the plugin was doing.
- **A background thread signaling every vCPU on a fixed cadence can race
  KVM's own SMP bring-up.** An attempt to replace the single process-wide
  `SIGALRM` with a dedicated ticker thread `pthread_kill`-ing every vCPU
  thread individually reproducibly stalled real `--smp` bring-up — forced
  `EINTR`s landing during the guest's own INIT-SIPI-SIPI sequence raced
  KVM's in-kernel APIC handling. Reverted to the single shared timer.
- **A saturating address-range end computation has an off-by-one at the
  literal top of the address space.** `addr < end` with `end` saturated to
  `u64::MAX` excludes address `u64::MAX` itself from a region that
  legitimately reaches it. Fixed by tracking an inclusive `last` address
  and comparing containment as a distance from `base`, not an endpoint.
- **Trust real source over memory for anything with revision history.**
  ACPI table layouts, real PCI/virtio device IDs (legacy virtio IDs do
  *not* follow the `0x1000 + type` formula a naive guess would produce),
  and MSR/XSAVE snapshot requirements were all confirmed against this
  host's own kernel headers or `vmlinux` symbols before being trusted,
  after at least one earlier session found a "remembered" value to be
  wrong.
