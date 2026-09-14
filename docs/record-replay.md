# Record-and-replay

**Status: Milestones 1-3 done. Keyboard and virtio-rng replay are real
and verified; TAP packet replay isn't implemented yet.** This page
describes the real design and honest current state, not an aspiration —
see [status.md](status.md) and `DEBTS.md` items 49-52 for the ledger
entries this was built under.

## The goal

Capture enough about a guest's run — every asynchronous input it received
(a keystroke, an RNG byte, a network packet, an interrupt) and *precisely
where in its own execution* each one landed — to replay the exact same
run later: same guest code path, same data, same timing relative to the
guest's own instructions. The payoff for a security-research-shaped tool
is real: reproduce "this exact packet sequence plus this exact RNG draw
triggers the bug," byte for byte, instead of "it happened once and I
can't get it back."

## Why this is hard specifically for a KVM-backed VMM

IntelCommander's Unicorn-based rehost can do this relatively easily
because Unicorn is a software CPU emulator with a hook on every
instruction — "replay" is just re-running the same instruction stream
with the same hooked inputs fed back in. **hyperbug runs guest code
directly on real hardware via KVM.** There is no instruction-level hook
between VM exits — that's the entire point of hardware virtualization
being fast. Real cycle-exact replay therefore needs the same trick
[Mozilla `rr`](https://rr-project.org/) uses for bare-metal process
record/replay: a hardware performance counter that lets you reconstruct
*exactly* how far into the instruction stream you are, so an async event
can be re-delivered at the exact same point on replay.

Nobody has documented doing this against a **guest's** execution before —
only bare-metal host processes. Building it for hyperbug is genuinely new
engineering, not adapting a known recipe.

## Vendor neutrality (a real course-correction, worth stating directly)

The first attempt at this investigated only this project's own dev
host's AMD hardware and started down an AMD-specific fix path without
designing for portability — caught directly by the user, and a real
instance of the same mistake this project's `CLAUDE.md` already has a
standing rule against (`src/heci.rs`'s reversion, for a guest-facing
device baking in one vendor's identity — the same principle applies to a
host-side mechanism just as much). The corrected design detects the host
CPU vendor via real CPUID and picks between two genuinely different
mechanisms:

- **Intel**: `BR_INST_RETIRED.CONDITIONAL` (raw PMU event `0xC4`, umask
  `0x00`), requested with PEBS precise sampling (`precise_ip=2`) — `rr`'s
  own primary, most reliable platform. **Implemented from documentation
  only — this project has no Intel hardware to test on, and this path is
  unverified.** Do not trust it without testing on real Intel hardware
  first.
- **AMD** (Zen / Family 17h+): "Retired Branch Instructions" (raw event
  `0xC2`) — real, tested, working on this project's own AMD dev host, but
  **not precise without a real fix**: see below.
- **Any other vendor**: refused outright.

## The AMD SpecLockMap finding

Measured directly against a real KVM guest on this project's own AMD
Ryzen host: a trivial busybox shell loop (`while true; do :; done`)
reported roughly **3.7 billion "retired branches" per second** — an
obviously inflated number for the CPU's actual clock speed. This matches
a documented AMD erratum: a hardware "SpecLockMap" speculative-execution
optimization causes this exact PMU event to overcount, which is exactly
why [`rr`'s own AMD Zen support](https://github.com/rr-debugger/rr/wiki/Zen)
requires a workaround before trusting it. The fix is a real, root-only
MSR write (`0xc0011020`, set bit 54, clear bit 10), applied system-wide.

`src/pmu.rs`'s `amd_speclockmap_workaround_applied()` **detects** whether
this fix is already in effect — it does not apply the fix itself. That's
deliberate: the fix is global CPU state affecting every process on the
host, not something a VMM should flip on its own initiative as a side
effect of one feature, and applying it needs root this process isn't
assumed to have. Without the fix confirmed, `BranchCounter::open_for_thread`
still opens and counts (useful for developing/testing this module, and
for whatever the recording side eventually does even at reduced
precision), but reports `precise = false` — callers must not treat that
count as exact.

To apply the fix yourself (root required): see `rr`'s
`scripts/zen_workaround.py`, or add `spec_store_bypass_disable=on` to
the kernel command line for a persistent fix that survives across the
SSB-mitigation resets that otherwise undo a one-shot `wrmsr`.

## What exists today (Milestone 1)

`src/pmu.rs`:

- `detect_host_vendor()` — real CPUID leaf 0, not `/proc/cpuinfo` text
  parsing.
- `BranchCounter::open_for_thread(tid)` — opens a guest-mode-only
  (`exclude_host`), ring-0-excluding (`exclude_kernel`) counter attached
  to a specific Linux thread ID, returning `(counter, precise)`.
- A hand-rolled `perf_event_attr`/`perf_event_open`/ioctl binding — the
  vendored `libc` crate has no `perf_event` support at all (confirmed by
  search, not assumed), so this is sized and laid out directly against
  this host's own `/usr/include/linux/perf_event.h`.
- `amd_speclockmap_workaround_applied()` — the detection check above.

Verified: a real unit test drives the raw plumbing (no KVM needed,
`exclude_host` turned off since a plain host thread never enters guest
mode); a real boot test (`tests/boot.rs::
guest_mode_branch_counter_counts_real_guest_execution`) attaches the
counter to a live guest's vCPU thread and confirms a real, nonzero count
from real guest execution — synchronized on the guest actually reaching
userspace via a console marker, not a guessed delay (an earlier version
of this test used a flat sleep and failed intermittently for exactly the
reason `exclude_kernel` implies: a guest is entirely ring-0 until its own
userspace code starts running, so measuring too early legitimately reads
zero).

## What exists today (Milestone 2): recording

```
hyperbug --kernel vmlinuz --record session.hbrr
```

`src/record.rs`'s `Recorder` runs for the whole guest lifetime (single-
vCPU only — `--record` requires `--smp 1`, same reasoning as `--restore`):
one `BranchCounter`, enabled once at startup and never reset, so every
recorded position is directly comparable to every other.

**What's recorded:**

- Real console keystrokes (`reactor.rs`'s `push_rx`).
- Real TAP network packets, but only ones actually delivered to the guest
  — a packet dropped for lack of a posted RX buffer never reached the
  guest and has nothing to replay, so it's correctly not recorded.
- Real virtio-rng output (`virtio_rng.rs`) — the exact random bytes
  returned to the guest, at the moment they're written to guest memory.
  Unlike the two above, an RNG request is synchronous from the guest's
  own point of view (the guest posts a buffer during a VM exit and the
  device fills it immediately, within that same exit), so the recorded
  branch-count position isn't meaningful as a replay *timing* target the
  way it is for keyboard/network events — but the *data* matters just as
  much: a real Linux guest derives real internal state (stack-protector
  canaries, ASLR slide values) from its first RNG reads, so a replay that
  handed the guest different random bytes than the recording did would
  diverge almost immediately, independent of how well interrupt timing is
  replayed. Contained entirely to `VirtioRng`'s own struct (an optional
  `Recorder` handle set at construction) rather than touching the generic
  `VirtioDeviceOps` trait every other virtio device also implements.

Each event is tagged with the host branch counter's value at the moment
of delivery, in a hand-rolled binary file format (magic + version +
`mem_size` + a precision flag, then a sequence of
`<kind><branch_count><len><data>` records) — matching this project's
standing convention of a small, exact-fit format over a serialization
dependency.

**What's still not recorded, and why:**

- **KVM's own in-kernel PIT/LAPIC/RTC timer interrupts.** A real,
  structural limitation of this architecture, not a missing feature:
  hyperbug uses KVM's in-kernel irqchip specifically so its own userspace
  code never has to model PIT/LAPIC/RTC timing, which also means there is
  no code path in this process that "delivers" one of those interrupts to
  record in the first place. They happen entirely inside the kernel,
  invisible to hyperbug. A guest whose behavior depends on exact timer
  interrupt timing cannot be replayed exactly by this design as it
  stands.

Verified with a real boot test
(`tests/boot.rs::record_flag_captures_real_typed_keystrokes_with_positions`):
types a known string through a real PTY into a live guest with
`--record` active, then reads the recording back and confirms it
reconstructs exactly what was typed, in order, with real non-decreasing
branch-count positions across the whole recording. The virtio-rng path is
verified at the unit level instead
(`virtio_rng::tests::a_recorder_captures_the_real_bytes_written_to_guest_memory`)
by calling `process_chain` directly and comparing the recorded event
against a direct read-back of guest memory — the existing test kernel's
initramfs has no `modprobe` support to load the real `virtio_rng` driver
module, the same pre-existing gap `boots_with_virtio_rng_over_the_modern_pci_transport`
already documents, so a real guest-driver round trip isn't exercisable
with this project's current test infrastructure.

## What exists today (Milestone 3): replay

```
hyperbug --kernel vmlinuz --replay session.hbrr
```

Poll-granularity, not cycle-exact — a deliberate choice, made because the
AMD precision fix is unconfirmed on the only hardware this was developed
against and there's no Intel hardware to verify that path either.
`Replayer` (`src/record.rs`) delivers:

- **Keyboard input**, from `vcpu.rs`'s own per-iteration poll (the same
  cadence as the existing control-socket/plugin poll) — pushed into the
  serial RX queue exactly as a real keystroke would be. Real stdin is
  suppressed entirely under `--replay` (`reactor.rs`) so no real typed
  input can mix with recorded input.
- **virtio-rng output**, consulted by `VirtioRng::process_chain` instead
  of `getrandom(2)`, consumed strictly in recorded order. Falls back to
  real `getrandom` (with a one-time warning) once the recording's RNG
  data is exhausted — a replay that outlives its own recording's RNG
  usage isn't reproducing the original run's random data at that point
  regardless, so hanging the guest to "stay faithful" wouldn't buy
  anything back.
- **TAP network packets are recorded but not replayed.** Stated directly
  — a `--replay` run logs how many recorded network events it's skipping.
  Replaying them needs the same net-device handles `reactor.rs` already
  holds, which `vcpu.rs`'s poll point doesn't have; and real end-to-end
  testing of either the recording or a replay path needs
  `CAP_NET_ADMIN`/root, unavailable in this project's own dev sandbox.

### A real reliability bug, found by running the real thing 8 times

A real end-to-end test — record a session with a genuine typed marker
through a real PTY, then launch a *completely separate* fresh hyperbug
process with `--replay` against that recording and confirm the same
marker gets echoed back — passed on its first attempt, then **failed 4 of
the next 7 runs**. The replayed guest reached its own idle shell prompt
and the recorded keystroke simply never arrived within a generous
20-second window.

Root cause, confirmed by inspecting the actual console output rather than
guessing: on this AMD host, without the SpecLockMap fix, the branch
counter's overcounting is **speculation-dependent noise, not a fixed
scale factor**. Once a guest goes idle (mostly `HLT`, almost no counted
execution), two separate real boots' counters can drift far enough apart
that a position reached in the recording is never reached by the
replay's own counter in any practical amount of time.

The fix: every `RecordedEvent` now also carries `elapsed_ms` (wall-clock
time since the `Recorder` started), and `Replayer::poll_keyboard`
delivers an event once **either** the branch count or the wall-clock
deadline is reached — whichever signal is actually still progressing.
This bounds the worst-case delay to roughly the same wall-clock gap the
original recording had, instead of an unbounded wait on a counter that
might never arrive. The recording format version was bumped (an old,
pre-fix recording is refused with a clear error, not silently misread).

Re-verified properly this time: the same end-to-end test run 16
consecutive times after the fix, all passing — chosen specifically
because 8 runs is what caught the bug in the first place, so 8 clean runs
afterward wouldn't have been convincing evidence of a real fix on their
own.

## What still doesn't exist

- **TAP packet replay** — see above.
- **True cycle-exact PMI-precise stopping.** `rr` itself handles counter
  skid with a "run close, then single-step the last few instructions
  precisely" dance — real engineering, still blocked on the AMD
  SpecLockMap precision question and the unverified Intel path. Revisit
  only once a host with the fix confirmed (or real Intel hardware) is
  available to actually test against — building this on an unverified
  precision foundation would mean shipping something impossible to
  confirm actually works, the same reasoning that picked poll-granularity
  over this in the first place.
- **TSC/RDTSC.** A guest reading the timestamp counter directly is a
  further, separate source of nondeterminism this design doesn't address
  at all. KVM currently passes `rdtsc`/`rdtscp` through to real hardware
  unintercepted. Trapping every guest TSC read needs VMX's "RDTSC exiting"
  execution control — **it's an open question whether this is reachable
  at all through the public `kvm-ioctls`/`kvm-bindings` surface this
  project depends on**, not yet confirmed either way.
- **SMP.** Real inter-vCPU races aren't addressed by branch-counting a
  single vCPU at all — multi-vCPU determinism is a substantially larger
  problem this design doesn't attempt to solve.
