# Debugging and observability

Tier 4 of the external review's roadmap ("this is where it should actually
out-do Unicorn's own tooling"). This page covers the three pieces that
exist today: a real GDB/LLDB remote-debugging stub, Chrome Trace Event
Format export, and automatic crash post-mortem capture. Structured,
leveled logging (`HYPERBUG_LOG`, replacing scattered `eprintln!`s) is
covered in-line in the source (`src/logging.rs`) rather than here.

Not done: a trace-export view of *device internals* beyond VM exits and
interrupts, and record-and-replay (deterministic re-execution) — both
deliberately deferred; see [status.md](status.md) and `DEBTS.md`.

## GDB/LLDB remote debugging

```
hyperbug --kernel vmlinuz --gdb-stub 127.0.0.1:1234
```

hyperbug blocks (the guest never executes a single instruction) until a
debugger connects, exactly like `qemu -s -S`. Then, in another terminal:

```
gdb
(gdb) set architecture i386:x86-64
(gdb) target remote 127.0.0.1:1234
(gdb) break *0xffffffff81000000
(gdb) continue
```

`set architecture` is needed because this stub doesn't implement
`qXfer:features:read` (a target-description XML reply) — GDB otherwise has
no way to know the remote is x86-64 before `g`'s first register read.
Point GDB at the guest's own kernel image (`gdb vmlinux`) before `target
remote` and it usually infers the architecture from the ELF instead, in
which case this step is unnecessary.

### What works

- Real breakpoints (`break`/`b`), inserted as an actual `0xCC` byte in
  guest memory and intercepted by KVM itself (`KVM_GUESTDBG_USE_SW_BP`) —
  not a polling watch on RIP.
- Single-stepping (`stepi`/`si`), via `KVM_GUESTDBG_SINGLESTEP`.
- `continue`/`c`.
- Full general-purpose register read/write (`info registers`, `set $rax
  = ...`), and memory read/write (`x/10i $rip`, `set {int}addr = ...`).
- Disassembly and memory dumps around a breakpoint show the *real*
  instruction bytes, not hyperbug's own `0xCC` patch — reads and writes
  through an active breakpoint's address are transparently shadowed.
- `detach` cleanly restores every breakpoint's original byte and disables
  guest-debug mode entirely; the guest then runs completely unmodified and
  untrapped, as if no debugger had ever attached.

### Scope, stated plainly (see `src/gdbstub.rs`'s own module doc comment
for the full detail)

- **BSP (vCPU 0) only.** With `--smp > 1`, every other vCPU keeps running
  freely and isn't stoppable or inspectable — the same limitation the
  control socket's own `regs` command already has, for the same reason (a
  live vCPU's register/debug state can only safely be touched from that
  vCPU's own thread).
- **Software breakpoints only.** Hardware watchpoints (`watch`, a data
  breakpoint) are refused outright (an empty RSP reply, the standard
  "unsupported" convention) — GDB falls back to single-stepping over the
  watched range instead, which works but is much slower.
- **No asynchronous break-into-a-running-target (Ctrl-C in GDB).**
  Commands are served synchronously, only while the guest is already
  stopped — set a breakpoint instead of relying on interrupting a free-
  running guest.
- **A real, unmodified kernel legitimately executes `int3` on its own** —
  Linux's boot-time `int3_selftest()`, and any later `ftrace`/live-
  patching trampoline swap. `KVM_GUESTDBG_USE_SW_BP` intercepts *every*
  `int3`, not just the ones this stub itself planted, so any trap that
  doesn't match one of this stub's own tracked breakpoints is re-injected
  into the guest exactly as real hardware would deliver it — the guest
  never sees a difference. This was a real bug caught by
  `tests/boot.rs::gdb_stub_serves_a_real_rsp_session_against_a_live_guest`
  hanging on its very first run against a real kernel (an entirely
  ordinary boot got silently stuck the moment the kernel's own self-test
  executed its first `int3`), not by any hand-written unit test.

## Trace export

```
hyperbug --kernel vmlinuz --trace-file trace.json
```

Produces a [Chrome Trace Event
Format](https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU)
JSON file — open it directly in `chrome://tracing`, or load it into
[Perfetto](https://ui.perfetto.dev). Every VM exit becomes a duration
("X") event named after its kind and address (`IoOut:0x3f8`,
`MmioWrite:0xd0000010`, ...), timed around hyperbug's own dispatch of it
(not wall-clock time spent blocked in `KVM_RUN` waiting for the *next*
exit — that would mostly measure "the guest was busy," not "hyperbug
spent this long handling it," which is the actually useful signal for
finding where time goes). Every interrupt injection becomes an instant
("i") event (`irq4`, ...). Each vCPU gets its own timeline (Chrome's
`tid` field).

Opt-in and deliberately hand-rolled (no dependency): `--trace-file` costs
one `Option` check per VM exit when absent, and one extra lock + a pair of
`Instant::elapsed()` calls per exit when present — real overhead, not
appropriate to leave on by default for every run.

The file is written incrementally (flushed after every event, inside a
`[ ... ]` array that's completed on a clean exit) rather than buffered and
written once at the end, so a crash or a `kill -9` loses at most the
in-flight event — Chrome's own tracing viewer tolerates a file missing its
closing `]`.

## Crash post-mortem capture

On a triple fault, hyperbug always writes
`<crash-dir>/hyperbug-crash-cpu<N>-<pid>.json` (`crash-dir` defaults to the
current directory; override with `--crash-dir`) — full register state
(`kvm_regs`, plus `cr0`/`cr2`/`cr3`/`cr4`/`efer`/`cs` from `kvm_sregs`) and
the last 32 VM exits leading up to the fault (kind + address, no
timestamps — see below), as JSON.

The 32-entry recent-exit ring buffer is **always kept**, independent of
`--trace-file` — a fixed-size, allocation-free array of `Copy` structs
pushed once per VM exit, cheap enough to run unconditionally so a
post-mortem has real context even on a run that never enabled full
tracing. It deliberately doesn't record each entry's `rip`: `VcpuExit`
borrows the vCPU's shared `kvm_run` page for as long as it's alive, so
nothing in the same scope may issue a fresh `KVM_GET_REGS` to fetch it —
the crash dump's own top-level `regs.rip` already gives the exact faulting
address; the history exists to show *what led there*, not to duplicate it.

Not yet extended to a per-device-plugin crash/fault ("plugin fault" in the
review's own phrasing) — `pydevice_proc.rs`'s existing rate-limited
logging on a faulted sandboxed device is the closest equivalent today, and
doesn't produce a structured dump file. A real, separate extension if it
turns out to matter in practice.
