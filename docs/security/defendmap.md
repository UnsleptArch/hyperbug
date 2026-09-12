# Attack surface map

Every place guest-controlled, plugin-controlled, or network-controlled
bytes reach hyperbug's own parsing/dispatch code, what currently defends
it, and — where nothing does yet — a line saying so plainly. This is the
concrete counterpart to [security.md](security.md)'s trust-boundary
statement: that document says who's trusted, this one enumerates *where*
the untrusted side actually touches code and what stops it from doing
damage there.

**Status legend**: `DEFENDED` — a real, verified mitigation exists.
`PARTIAL` — some mitigation exists but with a stated gap. `HELD` — no
mitigation exists yet; do not treat this surface as safe against a
motivated adversary until it moves out of this state.

---

## 1. PCI configuration space (CF8/CFC)

**Attacker**: the guest (any code running in the VM, including
unprivileged userspace via a compromised or malicious driver stack).
**Reachable code**: `pci.rs`'s `io_out`/`io_in` handlers — config-space
reads/writes, BAR sizing/assignment, capability list walks, MSI
enable/address/data programming.

- **Bounds/overflow on BAR arithmetic** — DEFENDED. A BAR whose region
  reaches the literal top of the 64-bit address space is handled
  correctly (containment computed as a distance from a base address, not
  a saturated endpoint comparison — this was a real bug, fixed and
  covered by a unit test after being found during a merge).
- **Devfn/slot collisions** — DEFENDED. Registering two devices at one PCI
  slot is a `Result`-returned configuration error, not a panic.
- **Sub-dword config writes (e.g. enabling MSI via a 16-bit write to
  Message Control)** — DEFENDED. `config_write`'s `byte_offset` is used
  correctly; a prior version silently discarded it, which would have
  corrupted any write not aligned to a full dword.
- **Malformed/out-of-range config-space offsets from the guest** —
  PARTIAL. `pci::tests::arbitrary_config_space_traffic_never_panics`
  drives real `io_out`/`io_in` with hundreds of generated sequences of
  arbitrary devfn/register selections, writes (arbitrary byte offset
  within the real CF8/CFC 4-byte data window, arbitrary length/content),
  and reads against a real MSI-capable device — covering interleavings a
  hand-picked test wouldn't think to try (e.g. an MSI write landing
  mid-BAR-sizing-sequence). This is property-based testing with a fixed,
  in-repo strategy, not coverage-guided fuzzing (`cargo-fuzz`/AFL) — it
  won't discover a new code path the strategy itself doesn't already
  reach into, and it only checks "doesn't panic," not deeper semantic
  invariants (e.g. "the BAR sizing sequence's *result* is always
  correct" — that's still covered only by the hand-picked tests). Still
  HELD as far as genuine coverage-guided fuzzing goes.

## 2. Virtqueue descriptor chains (legacy and modern virtio)

**Attacker**: the guest, via any virtio driver (blk/net/rng) posting
descriptors in the shared ring.
**Reachable code**: `virtio.rs`'s `VirtQueue::try_pop` and the
per-device `process_chain` implementations in `virtio_blk.rs`/
`virtio_net.rs`/`virtio_rng.rs`.

- **A descriptor naming a buffer outside guest RAM** — DEFENDED. Rejected
  before any device code sees it.
- **A chain requesting more total bytes than guest RAM holds** —
  DEFENDED. Rejected as a whole, not truncated silently.
- **A cyclic descriptor chain (guest points a `next` index back into the
  chain already walked)** — DEFENDED, with a dedicated test: `try_pop`
  terminates instead of an infinite loop / unbounded host-side work.
- **A guest-controlled sector count driving unbounded host allocation**
  (virtio-blk WRITE_ZEROES/DISCARD) — DEFENDED. Streamed through a
  fixed-size buffer instead of `vec![0u8; guest_supplied_count]`.
- **A guest-controlled sector number past the end of the backing disk
  image** — DEFENDED. Range-checked before any seek/write.
- **Systematic adversarial/fuzzed descriptor-chain generation** —
  PARTIAL. `virtio::tests::try_pop_never_returns_an_out_of_bounds_or_
  oversized_chain` generalizes every hand-picked case above (cyclic
  chains, out-of-table indices, oversized buffers, oversized totals) into
  one property, generating whole descriptor tables (arbitrary
  addr/len/flags/next per slot) and asserting the two invariants every
  downstream device relies on: every returned buffer lies in guest RAM,
  and the chain's total length never exceeds it — plus a companion
  property confirming a genuinely well-formed chain is always accepted
  intact, so an over-strict regression would be caught too, not just an
  over-permissive one. `virtio_rng::tests::process_chain_never_panics_
  on_an_adversarial_chain` does the equivalent one level up, feeding a
  real device's `process_chain` adversarial buffer lists directly (via
  the new `DescChain::for_test` test helper). Same caveat as item 1:
  property-based with a fixed strategy, not coverage-guided fuzzing —
  `virtio_blk`/`virtio_net`'s own `process_chain` implementations don't
  yet have the equivalent property test extended to them.

## 3. ACPI

**Attacker**: none directly — hyperbug is the *author* of every ACPI
table the guest reads; there is currently no path where a guest or
external party supplies ACPI bytes hyperbug parses. This surface is
listed for completeness and to keep the map honest about which of the
Tier-2 hardening asks actually apply here.

- **Table checksum/structural integrity** — DEFENDED. Every table is
  checksum-verified in pure Rust; `iasl` round-trips the DSDT when
  installed. A `build.rs` check fails the build if the embedded compiled
  DSDT drifts from its source.
- **A future guest-facing ACPI *consumption* path** (e.g. if hyperbug ever
  parsed AML or ACPI data supplied by something other than itself) does
  not exist today — **HELD as an open design question**, not a current
  gap, since there is nothing to fuzz yet. Re-evaluate this entry if that
  ever changes.

## 4. Sandboxed-plugin IPC protocol

**Attacker**: a compromised, buggy, or actively malicious device plugin
running in its own subprocess (`--device-sandboxed`/
`--pci-device-sandboxed`), from the parent hyperbug process's point of
view — the child is explicitly not fully trusted, that's the entire
reason the subprocess boundary exists.
**Reachable code**: `pydevice_proc.rs`'s reply parser (parent side) and
`python/hyperbug/_sandbox_runner.py`'s command parser (child side).

- **A hung or crashed plugin** — DEFENDED. A 200ms reply timeout or a
  dead pipe results in an unconditional `SIGKILL` of the child and the
  device faulting to a clean no-op; verified directly with a plugin whose
  `write()` sleeps 60 seconds.
- **A malformed reply from the child (bad hex, wrong field count, an
  unexpected command)** — PARTIAL. The line-based text protocol is
  simple enough to review by reading it directly, and basic malformed
  input has hand-written coverage (hex round-trips, bad-input rejection
  in the equivalent `control.rs` protocol this mirrors), but the
  sandboxed-plugin protocol parser itself has no dedicated adversarial/
  fuzz coverage yet — **HELD** for that specific gap.
- **A plugin's DMA calls reaching guest memory outside an operator-
  declared confinement range** — DEFENDED (see `security.md`'s DMA
  confinement section) — enforced identically for in-process and
  sandboxed loaders via one shared check.
- **Privilege of the subprocess itself** — PARTIAL. `src/seccomp.rs`
  installs a real seccomp-bpf filter on the child (via `Command::
  pre_exec`, between `fork` and `exec`) — a **deny-list**, not a
  privilege-dropping sandbox: it blocks a specific set of syscalls with
  no legitimate use in a device plugin and a real ability to defeat the
  subprocess boundary or damage the host (`ptrace`, `process_vm_readv`/
  `writev`, the mount/kernel-module/reboot family, `bpf`,
  `perf_event_open`, clock/hostname changes, `personality`), denying each
  with `EPERM` rather than killing the process. Verified two ways: a unit
  test forks a child, installs the filter, and confirms `ptrace` fails
  with `EPERM` while an ordinary syscall (`getpid`) still works; the full
  `pydevice_proc` test suite (DMA, IRQ, `tick`, timeout-kill, API-version
  mismatch) and a real end-to-end guest boot with `--device-sandboxed`
  attached both still pass with the filter active. **Still not done**:
  the child still runs as the same user with the same filesystem/network
  access as the parent (no namespace, no capability drop, no UID
  change) — this filter narrows *which syscalls* are reachable, not
  *what the allowed ones can still do* as that user. The main VMM
  process's own steady-state loop (the other half of Tier-2 item 4) is
  untouched — it embeds a full CPython interpreter via PyO3 for
  in-process plugins, whose allocator/C-extension surface makes a safe
  syscall filter for that process a separate, larger piece of work than
  this one, deliberately not attempted alongside it.

## 5. Live control socket

**Attacker**: anything on the host that can connect to the socket path —
by design there is no protocol-level authentication, only filesystem
permissions on the path itself.
**Reachable code**: `control.rs`'s command dispatch (`read_mem`,
`write_mem`, `regs`, `write_regs`, `snapshot`).

- **Malformed hex/command input** — DEFENDED. Dedicated unit tests cover
  hex round-trips, rejecting bad input without panicking, and partial-
  write/EOF framing across multiple lines.
- **An out-of-bounds `read_mem`/`write_mem` address** — DEFENDED, same
  checked-memory path as everything else.
- **An unknown register name in `write_regs`** — DEFENDED, rejected with
  `OSError`/`ERR`, not silently ignored or panicking.
- **Anyone reaching the socket at all** — HELD, by design, as a policy
  matter rather than a code gap: this is documented in `security.md` as a
  full-trust local interface; the mitigation is operational (restrict who
  can reach the path), not code-level. Do not expose this socket across
  any trust boundary.

## 6. Guest-supplied DMA addresses (device plugin `read_mem`/`write_mem`, virtio buffers)

**Attacker**: the guest, indirectly — any address a guest driver hands a
device (via a virtio descriptor or a custom plugin's own register
protocol) that a plugin or built-in device then uses for DMA.

- **Bounds checking against guest RAM** — DEFENDED, via `mem.rs`'s
  `*_checked` helpers, used everywhere a guest-supplied address drives a
  memory access. `mem::tests` includes property tests checking
  `in_bounds`/`read_checked`/`write_checked` against an overflow-safe
  (`u128`-arithmetic) oracle across arbitrary `(addr, len)` pairs,
  including values at the `u64::MAX` boundary — the same class of
  overflow the address-space-containment bug (see
  [architecture.md](../architecture.md)'s History section) actually was.
- **A guest driving a *trusted* built-in device (virtio-blk/net/rng) to
  read/write anywhere in guest RAM** — this is expected and correct: a
  trusted built-in device legitimately needs full guest-RAM reach, same
  as real unprotected hardware. Not a gap; stated for completeness.
- **A guest-programmable IOMMU constraining what a *device* (not a
  plugin) may DMA to** — HELD. No DMAR/IVRS tables, no guest-facing
  translation. See `security.md` and Tier-1 item 5's scoping note: what
  exists is an *operator*-declared confinement on a *plugin's* own DMA
  calls, not a guest-facing IOMMU.

## 7. Network (`--net`, virtio-net + TAP)

**Attacker**: anything reachable over the TAP interface's network
segment, and the guest's own network stack from the other direction.

- **TAP interface flag manipulation** — DEFENDED. A real read-modify-
  write on the interface flags register, not a blind overwrite that would
  clear kernel-set flags.
- **Guest network stack exposure** — this is an ordinary Linux network
  namespace's worth of attack surface, no different from real hardware;
  hyperbug adds no additional filtering of its own. Not a hyperbug-level
  gap to close — it's the guest kernel's own responsibility, same as on
  real hardware. Listed here so it isn't silently assumed to be more
  contained than it is.

## 8. Host-side Rust `unsafe` code

**Attacker**: indirect — a bug here doesn't require malicious input, just
a latent memory-safety error in code the type system can't check.
**Reachable code**: 34 `unsafe` blocks across `mem.rs`, `reactor.rs`,
`virtio_net.rs`, `tty.rs`, `virtio_blk.rs`, `lib.rs`, `snapshot.rs`,
`pci.rs`, `virtio_rng.rs` (raw ioctls, `madvise`, raw file descriptors,
`iovec` construction for io_uring, TAP ioctl structs).

- **Per-block safety reasoning** — DEFENDED. A dedicated, consolidated
  audit pass (not spot checks made while writing the code) reviewed all
  34 blocks — see [unsafe-audit.md](unsafe-audit.md) for the full
  per-file writeup. One real finding: `lib.rs`'s `set_xsave` comment
  overstated its own guarantee for a `--restore`d snapshot file (fixed).
  A cross-file safety dependency in `virtio_blk.rs` (an `iovec`'s
  validity relies on an invariant enforced in `virtio.rs`, not
  re-checked locally) was flagged with a recommended debug-assert, not
  yet added. **Still PARTIAL** on the sanitizer half specifically: no
  ASAN/UBSAN or Miri run has actually been performed — most of these
  blocks call real syscalls Miri can't execute, but `snapshot.rs`'s two
  pure-memory-reinterpretation functions are a concrete, not-yet-taken
  Miri target.

---

## Summary: what's HELD or PARTIAL right now

Reading this list top to bottom:

1. **PARTIAL** — PCI config-space writes have real property-based
   coverage now (`arbitrary_config_space_traffic_never_panics`); genuine
   coverage-guided fuzzing (`cargo-fuzz`) is still HELD.
2. **PARTIAL** — virtqueue descriptor chains have real property-based
   coverage now (`try_pop_never_returns_an_out_of_bounds_or_oversized_
   chain` and the virtio-rng equivalent); coverage-guided fuzzing, and
   extending the property test to virtio-blk/net's own `process_chain`
   implementations, are still HELD.
3. **HELD** — systematic/fuzzed coverage of the sandboxed-plugin IPC
   protocol.
4. **PARTIAL** — a real seccomp-bpf deny-list is now installed on the
   sandboxed-plugin subprocess (`src/seccomp.rs`, applied via `pre_exec`);
   no namespace/capability-drop/UID change accompanies it, and the main
   VMM process's own steady-state loop (which embeds PyO3, a much harder
   syscall-filtering target) is untouched.
5. **PARTIAL** — the `unsafe`-block audit itself is done (see item 8
   above); a sanitizer/Miri pass on the one concrete target that permits
   it is still HELD.
6. A real guest-facing IOMMU / DMA remapping model (distinct from the
   existing operator-side plugin DMA confinement).

These map directly onto Tier 2's six items from the ongoing hardening
plan. As each is closed with real, verified work, update its entry above
from HELD to DEFENDED with what specifically closed it — the same
discipline the rest of this project's history holds itself to.
