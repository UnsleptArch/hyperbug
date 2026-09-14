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
**Reachable code**: `pydevice_proc.rs`'s `wire::read_frame` (parent side)
and `python/hyperbug/_sandbox_runner.py`'s `_read_frame`/`_dispatch`
(child side). Since a prior pass, the wire format itself changed from
hex-encoded text to a binary length-prefixed frame (`<u32 length><type
byte><payload>`) — adopted for payload-volume reasons (hex encoding and
per-byte-pair parsing cost double for a device with real bulk data), not
security ones, but worth noting the parser this entry describes is a
different, smaller one than before.

- **A hung or crashed plugin** — DEFENDED. A 200ms reply timeout or a
  dead pipe results in an unconditional `SIGKILL` of the child and the
  device faulting to a clean no-op; verified directly with a plugin whose
  `write()` sleeps 60 seconds.
- **A malformed reply from the child (a truncated frame, an unexpected
  message type, a length prefix past what's actually sent)** — PARTIAL.
  `read_frame` treats a short/truncated read the same as EOF (the
  device faults cleanly, same as a dead child), and an unrecognized
  message type is handled explicitly (mapped to an error string) rather
  than falling through to undefined behavior — but no dedicated
  adversarial/fuzz coverage exists yet for this specific parser
  (property-based coverage exists for PCI config space and virtqueue
  chains — see items 1/2 — not yet extended here). **HELD** for that
  specific gap.
- **A malicious child claiming a huge frame length to force a large
  host-side allocation** — DEFENDED. Found and fixed in the same pass
  that introduced the binary framing: `read_frame` now refuses any length
  above a 64 MiB ceiling (`MAX_FRAME_LEN`) before allocating a buffer for
  it, treating an oversized claim the same as a dead pipe. A related,
  narrower version of the same class of bug was also found and fixed in
  `handle_read_mem`'s `CB_READ_MEM` handling specifically: a plugin's own
  `self.hyperbug.read_mem(addr, size)` call carries its own `size` field
  (up to `u32::MAX`) inside a tiny 12-byte request — unrelated to the
  frame-length cap above — and the handler used to allocate a buffer
  sized from it *before* checking whether `addr`/`size` even fit in
  guest RAM. Fixed by checking bounds first. Both are covered by
  dedicated tests confirming the rejection is fast (no multi-gigabyte
  allocation actually attempted), not just checking the returned error.
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
- **A plugin exhausting host memory or CPU (a leak, a busy-loop, an
  intentional resource-exhaustion attempt)** — PARTIAL. `mem=`/`cpu=` on
  `--device-sandboxed`/`--pci-device-sandboxed` apply a real cgroups v2
  memory ceiling and/or CPU quota to that specific plugin's subprocess
  (`cgroup.rs`), joined by the child itself before `exec` so there's no
  window where it runs unconfined. Genuinely **best-effort**, not
  DEFENDED outright: silently unenforced (with a one-time stderr
  warning) if cgroups v2 isn't mounted or this process isn't delegated
  permission to create a cgroup — verified as the actual, common
  real-world case on this project's own dev host, which has cgroups v2
  mounted but no delegated write access for a non-root user. Opt-in
  (`None` by default, matching every plugin's behavior before this
  existed) and only ever applies to the sandboxed subprocess — an
  in-process plugin has no equivalent at all (see item 8's "no resource
  limits on in-process plugins" framing in `security.md`).

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
  Miri target. `native_plugin.rs`'s own FFI `unsafe` blocks (raw
  function-pointer calls, the `HostCtxData`/`CHostCtx` pointer plumbing)
  were reviewed as they were written, following the same discipline, but
  haven't yet been folded into a dedicated re-audit pass the way the
  original 34 were — worth doing next time this item is revisited.

## 9. Native (C ABI) plugin loading

**Attacker**: whatever loaded the `.so` in the first place — this
surface is unusual in that the "attack" is simply *using the feature at
all*, not a malformed-input case the way items 1-7 are. There is no
untrusted-input parsing to defend here; the whole mechanism is trust-by-
design, not trust-by-verification.
**Reachable code**: `native_plugin.rs`, `include/hyperbug_plugin.h`.

- **Isolating a native plugin from the rest of the process** — HELD, by
  explicit design, not oversight. A `--native-device`/
  `--native-pci-device` plugin is `dlopen()`ed directly into `hyperbug`
  and runs with full process privileges — no interpreter boundary, no
  subprocess, no seccomp, no cgroup. See `security.md`'s trust-tier 5 for
  the full statement. This will never become DEFENDED without a
  fundamentally different loading mechanism (e.g. a real out-of-process
  native plugin host, analogous to the sandboxed Python transport) —
  it's listed here for completeness, not as a bug to fix.
- **A plugin's DMA calls reaching guest memory outside an operator-
  declared confinement range** — DEFENDED. Enforced by the same shared
  `device::dma_range_allows` check the Python transports use, verified
  directly (no cross-language-boundary gap): a native plugin's
  `read_mem`/`write_mem` callbacks refuse an out-of-range or
  out-of-confinement call with `-1`, the same as the Python ABI's
  `OSError`.
- **A malicious or buggy `.so` claiming ABI compatibility it doesn't
  have** — DEFENDED for the version-mismatch case (checked once at load,
  refused with a clear "too new"/"too old" message, mirroring the Python
  ABI's range check) — but this is **not** a security boundary the way it
  might sound: nothing stops a plugin from simply returning a version
  number inside the supported range regardless of what it actually
  implements. The version check catches an honest-but-outdated plugin,
  not a hostile one.
- **A required export missing or having the wrong signature** — PARTIAL.
  A missing required export is refused at load with a clear message
  naming which one (verified with a real compiled `.so`). A present
  export with the *wrong signature* (e.g. `hyperbug_plugin_read` taking
  different arguments than the header declares) is **not** and cannot be
  detected — there is no way to verify a C ABI function's real signature
  from the dlopen side; calling it with the wrong signature is undefined
  behavior, caught by nothing. This is inherent to C ABI loading, not a
  gap specific to this implementation — the same is true of any
  `dlopen`/`dlsym`-based plugin system in any language.

## 10. WASM plugin loading

**Attacker**: an untrusted or buggy `.wasm` module — unlike item 9, this
surface *does* have a meaningful trust boundary to defend, since
`wasmtime`'s sandboxing is a real isolation mechanism, not "trust by
design."
**Reachable code**: `wasm_plugin.rs`.

- **Isolating a module's own code from the rest of the process's memory**
  — DEFENDED, by `wasmtime` itself. A module can only address its own
  linear memory (verified: the `a_wasm_plugin_handles_read_write_
  through_the_sandbox` test's out-of-register-file reads return zero
  rather than adjacent process memory) — there is no instruction in the
  WASM instruction set that reaches outside it.
- **A module growing its own memory without bound** — DEFENDED. A real,
  enforced ceiling (`wasmtime::StoreLimits`, 64 MiB) fails `memory.grow`
  cleanly inside the module rather than the host process actually
  allocating unbounded memory.
- **A module's DMA calls reaching guest memory outside an operator-
  declared confinement range** — DEFENDED. Same shared
  `device::dma_range_allows` check every other transport uses, enforced
  inside the `host_read_mem`/`host_write_mem` host functions before any
  guest memory is touched.
- **A module claiming a required export it doesn't actually have, or
  with the wrong signature** — DEFENDED, and a genuine improvement over
  the native transport's item 9 (PARTIAL there): `wasmtime`'s
  `get_typed_func` checks the *real* signature at load time (verified:
  `a_plugin_missing_a_required_export_fails_to_load_cleanly`) — there is
  no C-ABI-style "wrong signature is undefined behavior" gap here at all,
  since WASM's own type system carries real signature information, unlike
  a bare `dlsym` symbol.
- **A malicious or buggy module claiming ABI compatibility it doesn't
  have** — same PARTIAL as item 9's equivalent case: the version check
  (verified: `a_mismatched_abi_version_is_refused_at_load`) catches an
  honest-but-outdated module, not one that lies about its own version
  while implementing something else.
- **Isolating `wasmtime` itself (the JIT/runtime) from the rest of the
  process** — HELD, by necessity: no OS process boundary exists for this
  transport, unlike sandboxed Python. A `wasmtime`-level bug (not the
  loaded module's own code) is, in principle, still a risk to the whole
  `hyperbug` process. This is the honest trade the WASM transport makes
  in exchange for in-process speed — see `security.md`'s trust-tier 6.

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

Items 1-6 map directly onto Tier 2's six items from the ongoing hardening
plan. As each is closed with real, verified work, update its entry above
from HELD to DEFENDED with what specifically closed it — the same
discipline the rest of this project's history holds itself to.

Item 9 (native plugin isolation) is a **standing, by-design HELD** —
listed for honesty, not tracked as a bug to eventually close, since
closing it would mean building an entirely different loading mechanism
(an out-of-process native plugin host). Anyone loading a
`--native-device`/`--native-pci-device` plugin should treat that HELD as
permanent, not pending.

Item 10 (WASM plugin loading) is mostly DEFENDED — real, `wasmtime`-
enforced sandboxing of a module's own code, a genuine step up from item
9's native transport on several specific points (signature checking,
memory-growth bounds). Its one HELD sub-item (no OS process boundary
around `wasmtime` itself) is, like item 9's, a standing trade rather than
a bug: closing it would mean running `wasmtime` in a subprocess too, at
which point it's no longer offering in-process speed over the existing
sandboxed-Python transport.
