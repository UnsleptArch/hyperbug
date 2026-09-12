# `unsafe` block audit

A dedicated pass over every `unsafe` block in the codebase — not spot
checks made while writing the code that introduced them, but a single
review pass reading each one cold, checking its `SAFETY` comment's claim
against what the surrounding code actually guarantees. Tier-2 hardening
item 2. Re-run this pass (or at least re-review any new/changed `unsafe`
block) whenever a change touches one of the files below.

## Method

`grep -rn "unsafe" src/*.rs` found 34 occurrences across 9 files. Each was
read in its full surrounding function, not just the line itself, and its
`SAFETY` comment's claim was checked against:

1. What guarantees the pointer/fd/buffer's validity at the point of use.
2. What guarantees its lifetime for the duration of the unsafe operation.
3. Whether any *cross-file* invariant is being relied on (the sharpest
   source of a false sense of safety — a comment can be locally correct
   and still wrong if the invariant it leans on lives somewhere else and
   changes later without anyone revisiting this comment).

Sanitizer/Miri notes: most of these blocks call real syscalls (`mmap`,
`ioctl`, `epoll_*`, `getrandom`, KVM ioctls via `kvm-ioctls`), which Miri
cannot execute and ASAN/UBSAN mostly just observe pass-through on rather
than meaningfully instrument. The two blocks that are pure memory
reinterpretation with no syscall involved — `snapshot.rs`'s
`struct_as_bytes`/`struct_from_bytes` — are exactly the kind of code Miri
*can* usefully check (raw pointer aliasing, alignment, uninitialized-read
rules), and are called out below as the concrete next step for that half
of this item.

## File-by-file findings

### `src/mem.rs` (8 blocks)

`mmap`/`madvise` at allocation, `munmap` in `Drop`, and four checked/
unchecked read-write helpers using `copy_nonoverlapping`/
`write_unaligned`. All sound: the checked paths (`read_checked`/
`write_checked`) verify `in_bounds` immediately before the unsafe op, with
no gap where the guest RAM mapping could change size between the check
and the use (the mapping is fixed-size for the process's lifetime — no
`mremap` anywhere). `unsafe impl Send for GuestMemory` is justified: the
mapping is only ever touched through the offset-based methods, never
exposed as a raw borrow that could outlive `self`, and concurrent access
across the vCPU/reactor threads is serialized by the `Mutex` every holder
wraps it in. **No finding.**

### `src/reactor.rs` (6 blocks)

`epoll_create1`/`epoll_ctl` (add/del)/`epoll_wait`/`close`, all through a
single `Epoll` struct that owns the fd for its entire lifetime and closes
it exactly once in `Drop` — the comment on the struct itself notes this
replaced an earlier version that could leak the fd on certain error
paths. Every return value that indicates failure is checked. **No
finding.**

### `src/virtio_net.rs` (6 blocks)

`ioctl(TUNSETIFF)`, `fcntl` (non-blocking), `socket`/`close`, and the two
`ioctl(SIOCGIFFLAGS/SIOCSIFFLAGS)` calls for bringing the TAP interface
up. The read-modify-write pattern for the interface flags is correct (a
blind `SIOCSIFFLAGS` would clobber flags the kernel set on the fresh
interface — this was a real bug caught by a dedicated isolated test
earlier in the project's history, not by this audit). Every socket/fd is
closed on every path. **No finding.**

### `src/tty.rs` (5 blocks)

Termios get/set (raw mode) with restoration via `libc::atexit` (correct,
since every real exit path is a bare `process::exit`, which skips Rust
destructors but still runs C atexit handlers), non-blocking bulk
`read`/`write` on stdin/stdout, and the `SIGALRM`/`setitimer` periodic
wakeup with a genuinely no-op, trivially async-signal-safe handler.
**No finding.**

### `src/lib.rs` (2 blocks)

- `set_user_memory_region` for guest RAM — sound; the mapping's size and
  lifetime are both correctly accounted for in the comment.
- `set_xsave` when restoring from a snapshot — **finding**: the existing
  comment claimed the XSAVE buffer "came from this same process's own
  `vcpu.get_xsave()`," which is true only for a snapshot this exact
  process produced. `--restore` actually loads *any* file matching the
  snapshot header/size format, which is operator-supplied input, not
  necessarily something this process wrote. This doesn't create a
  host-memory-safety issue — `struct_from_bytes` only ever reconstructs a
  fixed-size, pointer-free struct from exactly the right number of bytes,
  so a malformed or adversarial snapshot file can at worst hand KVM a
  syntactically-valid-but-semantically-garbage XSAVE area (which KVM/the
  guest's own FPU restore path would have to reject or fault on, not
  something that corrupts the host) — but the comment's own stated
  justification was inaccurate, which is exactly the kind of drift a
  dedicated audit pass exists to catch before it misleads whoever reads
  it next. **Fixed**: comment now states the real invariant (fixed size,
  no pointers, operator trusts the snapshot file same as any other launch
  input — kernel image, disk image — per `security.md`'s trust model),
  instead of the narrower and not-always-true claim about provenance.

### `src/snapshot.rs` (2 blocks)

`struct_as_bytes`/`struct_from_bytes` — reinterpreting a `kvm-bindings`
ioctl-argument struct (`kvm_regs`, `kvm_sregs`, `kvm_xsave`, etc.) as raw
bytes and back. Sound: every such struct is fixed-size integers/arrays
with no pointers, and `struct_from_bytes` only ever copies exactly
`size_of::<T>()` bytes (bounds-checked by `take` before the unsafe copy,
which errors cleanly on a truncated file rather than reading past the
buffer). **No finding**, but flagged as the concrete Miri target: unlike
every other unsafe block in this codebase, these two involve no syscalls
and are cheap to check under Miri directly. Not yet done — see "Next
steps" below.

### `src/pci.rs` (1 block, test-only)

`set_user_memory_region` inside a `#[cfg(test)]` function that opens a
real `/dev/kvm` VM to verify the raw `KVM_IOEVENTFD` mechanism in
isolation. Same reasoning as `lib.rs`'s equivalent call. **No finding.**

### `src/virtio_rng.rs` (1 block)

A single `libc::getrandom` call into a correctly-sized buffer slice.
**No finding.**

### `src/virtio_blk.rs` (3 blocks, counting the `unsafe impl`)

- `unsafe impl Send for IovecBox` — justified: `libc::iovec` isn't `Send`
  because it holds a raw pointer, but nothing in this process ever
  dereferences that pointer after submission (only the kernel reads it,
  asynchronously, until the completion CQE arrives), so moving the
  allocation between threads is sound regardless of which OS thread
  happens to submit vs. complete a given request.
- Building each `libc::iovec`'s `iov_base` via `mem.as_ptr().add(addr)` —
  this is the one place in the whole audit where the safety argument
  **crosses a file boundary**: the comment correctly states that
  `b.addr`/`b.len` are guaranteed to lie entirely within `mem`'s mapping,
  but that guarantee is enforced in `virtio.rs`'s `VirtQueue::try_pop`,
  not re-derived or re-checked here. This is a real, working invariant
  (covered by `virtio.rs`'s own dedicated tests for out-of-bounds/
  overlong descriptor chains), but it means a future change to
  `try_pop`'s bounds-checking logic could silently invalidate this
  `unsafe` block's soundness without anywhere near it flagging that.
  **Recommendation** (not yet done, low urgency): a debug-only assertion
  here (`debug_assert!(mem.in_bounds(b.addr, b.len as u64))`) would make
  this cross-file dependency self-checking in any debug/test build,
  rather than relying on a comment and a human remembering to check
  `virtio.rs` when either file changes.
- `self.ring.submission().push(&sqe)` — `io_uring`'s own unsafe API
  contract (the SQE's referenced memory must outlive the operation);
  satisfied by `IovecBox` being kept alive in `in_flight` until
  `poll_completions` sees the matching CQE. **No finding.**

## Next steps (not done in this pass)

1. **Miri on `snapshot.rs`'s `struct_as_bytes`/`struct_from_bytes`** — the
   one part of this audit item that's genuinely actionable as a sanitizer
   run rather than manual review. A small standalone test module isolating
   just these two functions (no KVM, no file I/O) could run under `cargo
   +nightly miri test` in CI as a permanent regression guard on this
   specific pair.
2. **The debug-assert suggested above** for `virtio_blk.rs`'s cross-file
   bounds invariant.
3. Everything else audited here has no open finding, but this is a
   point-in-time review — re-run it (or at minimum re-review the specific
   block) whenever code in these files changes, rather than treating this
   document as a permanent guarantee.
