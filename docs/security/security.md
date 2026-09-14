# Security model

This document states hyperbug's trust boundaries plainly: what runs
trusted, what's assumed hostile, what's enforced against it, and what
isn't. It is written for someone deciding whether to point hyperbug at a
guest, kernel, disk image, or device plugin they don't fully control.

For the concrete, per-surface counterpart to this — every place
untrusted bytes actually reach hyperbug's parsing/dispatch code, and
whether that specific surface is defended, partially defended, or held
open — see [defendmap.md](defendmap.md).

## Trust boundaries, in order of how much they're actually enforced

### 1. The host operator is fully trusted

Whoever launches `hyperbug` — chooses the CLI flags, picks which device
plugins load, decides whether `--net`/`--control-socket` are enabled —
is trusted completely. hyperbug does not defend against its own launch
configuration; it defends the *host* against what the *guest* (and,
partially, what a *device plugin*) might do once running.

### 2. The guest kernel/userspace is assumed hostile, and mostly contained by KVM itself

hyperbug runs the guest under real hardware-assisted virtualization —
guest code executes in a genuinely isolated VM context, not inside the
host's own address space or privilege level. The security properties KVM
itself provides (memory isolation, ring separation, trap-and-emulate for
privileged instructions) are inherited, not reimplemented. What hyperbug's
own code adds on top of that is:

- **Guest-supplied addresses are always bounds-checked before use.**
  Any DMA-shaped operation driven by a guest-controlled address or length
  — a virtio descriptor, a Python plugin's `read_mem`/`write_mem` call, a
  live-control-socket `read_mem`/`write_mem` — goes through a checked path
  (`mem.rs`'s `*_checked` helpers) distinct from hyperbug's own unchecked
  boot-time writes (which only ever use hyperbug's own trusted offsets).
  A chain requesting more bytes than guest RAM even holds, or naming a
  buffer address outside guest RAM entirely, is rejected before any device
  code sees it (`virtio.rs`'s `VirtQueue::try_pop`).
- **Guest-supplied lengths never drive unbounded host allocation.**
  virtio-blk's WRITE_ZEROES/DISCARD stream through a fixed-size buffer
  rather than `vec![0u8; guest_supplied_count]` — an earlier version of
  this code would have let a guest request a multi-terabyte allocation
  from a small integer field.
- **A malformed or cyclic virtqueue descriptor chain terminates instead of
  hanging.** `try_pop` has an explicit test exercising a deliberately
  cyclic chain to confirm this, not just a claim in a comment.
- **PCI BAR/address-space arithmetic doesn't wrap silently.** A BAR
  requesting a region up to and including the literal top of the 64-bit
  address space is handled correctly (containment is computed as a
  distance from a base address, not a saturated endpoint comparison —
  see [architecture.md](architecture.md)'s History section for the bug
  this fixes).

What KVM/hyperbug do **not** currently provide: a guest-programmable IOMMU
(no DMAR/IVRS tables, no guest-controlled address translation) — every
*trusted* built-in device (virtio-blk/net/rng) can address all of guest
RAM, same as real unprotected legacy hardware. There is a narrower,
*operator*-declared confinement mechanism for Python plugins specifically
— see below — but it is not a guest-facing IOMMU and does not change what
a built-in device can reach.

### 3. A Python device plugin is a third trust tier of its own

A `.py` file loaded via `--device`/`--pci-device` runs with the full
authority of whatever Python can do on the host — this is not a sandbox
by default. Two real, separate mechanisms exist for when a plugin isn't
fully trusted, and they solve *different* problems:

- **DMA confinement (`--device`/`--pci-device`'s optional trailing
  `:<dma_base>:<dma_size>`)** bounds what a plugin's `self.hyperbug.
  read_mem`/`write_mem` may touch, enforced host-side, invisible to the
  guest, and **declared by the operator at launch — never read from the
  plugin's own attributes**, since the plugin is exactly the party this
  is meant to constrain. It protects *guest memory outside the declared
  range* from a plugin that's memory-unsafe or malicious in what
  addresses it asks to touch. It does **not** sandbox the plugin's
  general Python execution — a confined plugin can still run arbitrary
  code, open files, make network connections, etc. on the host, subject
  only to the OS-level permissions the `hyperbug` process itself has.
- **Process isolation (`--device-sandboxed`/`--pci-device-sandboxed`)**
  runs the plugin in its own `python3` subprocess instead of hyperbug's
  embedded interpreter. This protects the **VMM process and the guest's
  liveness** from a plugin that hangs or crashes — a stuck or dead
  subprocess is `SIGKILL`ed and the device starts answering like an
  unmapped one, rather than wedging a vCPU thread forever or bringing down
  the whole process. On top of that, the subprocess is launched under a
  real seccomp-bpf **deny-list** (`src/seccomp.rs`, installed via
  `Command::pre_exec` between `fork` and `exec`): a specific set of
  syscalls with no legitimate use in a device plugin — `ptrace`,
  `process_vm_readv`/`writev`, the mount/kernel-module/reboot family,
  `bpf`, `perf_event_open`, and a few other classic privilege-escalation
  primitives — are denied with `EPERM`. This is deliberately **not** an
  allow-list sandbox: enumerating everything a full Python interpreter's
  normal operation legitimately needs (imports, its allocator, whatever
  I/O a legitimate plugin does) would be both far larger and more
  fragile across Python versions than a small, targeted deny-list. So the
  subprocess still runs as the same user, with the same filesystem and
  network access, as the parent, and with no namespace or capability
  drop — it solves availability/robustness fully, and closes off a
  specific, named set of privilege-escalation/boundary-crossing
  primitives, but is **not** full privilege containment.
- **Resource limits (`mem=`/`cpu=` on `--device-sandboxed`/
  `--pci-device-sandboxed`)** bound a specific plugin's memory and/or CPU
  via a cgroups v2 ceiling/quota, joined by the child itself before
  `exec` (`cgroup.rs`) — protects the **host** from a plugin that leaks
  memory or busy-loops, rather than the guest or the VMM process
  directly (those are already covered by the timeout/`SIGKILL` path
  above). Explicitly **best-effort**: silently unenforced, with a
  one-time warning, on a host without cgroups v2 or without delegated
  permission to create one — a common case outside a systemd-managed or
  rootful setup. Never assume a requested limit is actually active
  without checking hyperbug's own stderr for that warning.

**Combine all applicable mitigations when a plugin is genuinely
untrusted** (third-party code, something still being debugged):
`--device-sandboxed ...:<dma_base>:<dma_size>:mem=<mb>:cpu=<pct>` gets
you "a hang or crash can't take anything else down," "a bad memory
access can't reach guest RAM it has no business touching," "a small set
of privilege-escalation syscalls are denied outright," and "a runaway
memory leak or busy-loop is capped, if cgroups v2 is available." None of
these are a substitute for actually reviewing third-party plugin code
before running it — the child still runs as the same user with the same
filesystem/network access as the parent, with no namespace, capability
drop, or UID change.

### 4. The live control socket is a full-trust local interface

`--control-socket <path>` opens a Unix domain socket with **no
authentication of its own** — anything on the host that can connect to
the socket path can read and write the running guest's physical memory
and general-purpose registers, and can trigger a snapshot write to any
path the `hyperbug` process can write to. This is deliberately as
powerful as a live debugger attached to the guest, and should be treated
with the same care: restrict who can reach the socket path via normal
filesystem permissions (it's a plain Unix socket, so standard directory/
mode restrictions apply), and never expose it across a trust boundary
(e.g. bind-mounting it into a less-trusted container, or a path writable
by another user).

### 5. A native (C ABI) plugin is fully trusted — by necessity, not choice

`--native-device`/`--native-pci-device` (see
[native-plugin-api.md](../native-plugin-api.md)) `dlopen()` a shared
object directly into the `hyperbug` process. This is the **least
contained** of every device-loading mechanism hyperbug has: no
interpreter boundary (unlike in-process Python), no subprocess (unlike
sandboxed Python), no seccomp filter, no cgroup, nothing. The loaded code
runs with the full privileges of, and in the same address space as, the
VMM itself — a bug in a native plugin can corrupt or crash the whole
process, read or write arbitrary host memory, or do anything the
`hyperbug` process itself could do. There is no sandboxed equivalent of
this path, and none of `--device-sandboxed`'s mitigations (seccomp,
cgroups, subprocess-crash isolation) apply to it. The only mitigation
that *does* apply is DMA confinement — the same operator-declared
`<dma_base>:<dma_size>` bound the Python ABI offers, unrelated to and no
substitute for the process-level exposure above.

Use this path only for code you completely trust and control — treat a
`--native-device`/`--native-pci-device` argument with at least the same
level of trust you'd give a `--pci-device` in-process Python plugin, and
generally more: a memory-safety bug in native code has none of the
(limited but real) containment a Python exception gives you.

### 6. A WASM plugin is a fourth trust tier — genuine sandboxing, in-process, additive to the subprocess model

`--wasm-device`/`--wasm-pci-device` (see
[wasm-plugin-api.md](../wasm-plugin-api.md)) execute a WASM module
in-process under `wasmtime`. This is deliberately **not** a replacement
for sandboxed Python's subprocess isolation — it's a fourth option,
picked for a plugin that doesn't need arbitrary Python but does need
real throughput or wants isolation the native transport can't offer
without a subprocess's IPC cost.

Real, `wasmtime`-enforced properties: a module can only ever touch its
own linear memory directly (no ability to read/write arbitrary
`hyperbug` process memory, unlike the native transport); every access to
guest-physical memory goes through a checked host callback
(`host_read_mem`/`host_write_mem`/`host_raise_irq` — the module's only
way out of its own sandbox); a real, enforced per-instance memory
ceiling (`wasmtime::StoreLimits`, 64 MiB) that fails a `memory.grow`
cleanly rather than consuming unbounded host memory; and type-checked
exports (`get_typed_func` fails cleanly on a signature mismatch — no
C-ABI-style "wrong signature is undefined behavior" risk the native
transport has).

What it does *not* give you: a separate OS process. Unlike sandboxed
Python, a `wasmtime`-level bug (not the plugin module's own code) is
still, in principle, a risk to the whole `hyperbug` process — no process
boundary, no seccomp filter, no cgroup exists for this transport, because
none of those apply to what's already a language-level sandbox rather
than an OS-level one. Treat a WASM module the way you'd treat any
sandboxed code: genuine isolation for its own logic, but not equivalent
to a full subprocess boundary.

## Specific mechanisms, in more depth

### DMA confinement

Enforced identically across all four transports — in-process
(`pydevice.rs`'s `HyperbugCtx`), sandboxed (`pydevice_proc.rs`'s callback
handlers), native (`native_plugin.rs`'s `host_read_mem`/`host_write_mem`),
and WASM (`wasm_plugin.rs`'s imported `host_read_mem`/`host_write_mem`) —
via one shared check (`device::dma_range_allows`). A call outside the
declared range raises the same `OSError` shape (or, for native/WASM, the
same `-1` return) as an out-of-guest-RAM call, even for an address that
is otherwise valid guest memory. See
[plugin-api.md](plugin-api.md#dma-confinement) for the exact syntax.

Known scope limits, stated directly:

- It bounds `self.hyperbug.read_mem`/`write_mem` only — a plugin's own
  register `read`/`write` handlers, and anything else the plugin's Python
  code does, are unaffected.
- It is not visible to, or enforceable against, the guest — a real IOMMU
  changes what a *guest driver* can program a device to DMA to; this
  changes what a *plugin's own code* can reach regardless of what the
  guest asked for. They solve adjacent but distinct problems.

### Sandboxed plugin isolation

The wire protocol (`python/hyperbug/_sandbox_runner.py`'s module
docstring, `src/pydevice_proc.rs`) is plain hex-encoded text over stdin/
stdout — no serialization library, easy to audit by reading it directly.
A 200ms reply timeout and dead-pipe detection both result in an
unconditional `SIGKILL` of the child and the device faulting to a clean
no-op state; verified directly with a plugin whose `write()` sleeps 60
seconds (confirms the call returns in under 2 seconds, not that it
"should" per the code).

This mechanism exists specifically because two different in-process
interruption techniques were tried first and both failed under real
concurrent load — see [architecture.md](architecture.md)'s History
section for what was tried and why a subprocess-based design was chosen
instead. That history is relevant context for evaluating any future
proposal to interrupt a plugin call from inside the same process again.

### Snapshot/restore scope

A snapshot is a serialized dump of vCPU/device state and guest memory to
a plain file, restorable via `--restore`. Treat a snapshot file itself as
sensitive: it contains a full copy of guest physical memory (including
anything the guest had in RAM — secrets, keys, decrypted data) in a
straightforward, unencrypted, host-readable format. Two correctness gaps
are known and currently open, not just theoretical:

- Waking a specific blocked guest task via a post-restore interrupt (e.g.
  typing into a resumed interactive shell) can crash the guest — a kernel
  stack-guard-page hit during that task's FPU context switch. A resumed
  *idle* guest is solid and has a real boot test covering it; a guest that
  needs to schedule a woken task back in immediately after restore does
  not yet.
- A virtio-blk request genuinely in flight through the io_uring backend at
  the exact moment a snapshot is taken has no representation in the
  snapshot format — restoring silently drops it, and the guest hangs
  waiting on a completion that will never arrive.

Neither is a security vulnerability in the sense of granting unintended
access, but both are correctness/reliability gaps worth knowing about
before depending on snapshot/restore for anything you can't afford to
lose.

### Live migration scope

`migrate <host:port>` (`migrate.rs`) streams the exact same serialized
vCPU/device/memory state a snapshot file holds, over a plain TCP
connection, to a separate hyperbug process launched with
`--migrate-listen <host:port>`. **The stream itself has no encryption and
no authentication of any kind** — anyone who can reach `host:port` over
the network during the (typically brief) migration window can both read
a complete copy of guest memory as it crosses the wire and, in principle,
connect first and receive it themselves instead of the intended
destination (`TcpListener::accept()` only ever accepts one connection,
whichever arrives first). Treat the network path between source and
destination the way you'd treat an unencrypted snapshot file: restrict it
to a trusted network, or wrap it in your own tunnel (SSH, a private VPC)
before relying on it across anything less trusted. This mirrors the
snapshot file's own documented sensitivity above — migration is the same
data, sent over a socket instead of written to disk, with no additional
protection added.

### Network (`--net`)

hyperbug creates its own TAP interface at runtime (needs `CAP_NET_ADMIN`
or root) and brings it up via a real read-modify-write on the interface
flags register — a blind overwrite would have silently cleared flags the
kernel had already set on the fresh interface. The guest's network stack
is otherwise a completely ordinary Linux network namespace's worth of
attack surface: whatever the guest kernel and userspace would normally be
exposed to reaching them over that interface applies here exactly as it
would on real hardware. hyperbug does not add any additional network-level
filtering of its own.

### What is explicitly out of scope today

- No namespace/capability/UID sandboxing of sandboxed-plugin subprocesses
  (see above) — a seccomp *deny-list* now blocks a specific set of
  privilege-escalation syscalls, but the subprocess still runs as the
  same user with the same filesystem/network access as the parent.
- No syscall filtering of any kind on the main VMM process itself (only
  the sandboxed-plugin subprocess has one) — it embeds a full CPython
  interpreter via PyO3 for in-process plugins, which makes a safe filter
  for that process a separate, larger piece of work.
- No resource limits of any kind on an in-process (`--device`/
  `--pci-device`) plugin — it shares the whole VMM process's own memory/
  CPU budget by design. Sandboxed plugins can get a cgroup-enforced
  ceiling (`mem=`/`cpu=`), but only best-effort, dependent on cgroups v2
  being available and delegated to this process.
- No isolation of any kind for a native (`--native-device`/
  `--native-pci-device`) plugin — no interpreter boundary, no subprocess,
  no seccomp, no cgroup. It runs with full process privileges by design;
  DMA confinement is the only mitigation that applies to it.
- No process boundary for a WASM (`--wasm-device`/`--wasm-pci-device`)
  plugin — real `wasmtime`-enforced sandboxing of the module's own code
  (linear-memory isolation, a memory ceiling, type-checked exports), but
  no seccomp filter or cgroup, since neither concept applies to
  language-level sandboxing the way it does to a subprocess.
- No guest-facing IOMMU / DMA remapping for the built-in virtio devices.
- No authentication, encryption, or access control on the control socket
  beyond OS filesystem permissions on its path.
- No automatic PCI capability/topology hardening beyond what's needed for
  the devices hyperbug itself implements (single flat bus, no bridges, no
  PCIe ECAM).

If you're evaluating hyperbug for a use case with a genuinely adversarial
guest *and* untrusted third-party device plugins *and* a shared multi-
tenant host, treat all of the above as real, current gaps to account for
in your own deployment — not merely theoretical caveats.

## Reporting a security issue

This is a research/hobby project without a dedicated security contact or
disclosure process at this time. If you find a vulnerability, use
whatever contact channel the repository you obtained this from provides.
