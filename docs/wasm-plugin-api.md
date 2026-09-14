# WASM plugin reference

The fourth device-plugin transport, alongside in-process Python
([plugin-api.md](plugin-api.md)), sandboxed-subprocess Python (same doc,
`--*-sandboxed`), and the native C ABI
([native-plugin-api.md](native-plugin-api.md)). **This is additive, not a
replacement for any of the others** — pick it when a plugin doesn't need
arbitrary Python but does need real throughput, or wants stronger
isolation than the native (`dlopen`) path without paying a subprocess's
IPC round-trip cost.

A WASM plugin runs under [`wasmtime`](https://wasmtime.dev/) (Cranelift
JIT backend): real memory-safety isolation — a module can only ever touch
its own linear memory directly; every access to guest-physical memory
goes through a checked host callback, the same shape as the
sandboxed-subprocess transport's DMA calls — at in-process speed, no
interpreter and no IPC round trip.

## Trust model, compared to the other three transports

| | In-process Python | Sandboxed Python | Native (C ABI) | **WASM** |
|---|---|---|---|---|
| Isolation | none (shares the process) | real: separate OS process, seccomp deny-list, cgroup limits | **none at all** | real: sandboxed linear memory, enforced memory ceiling, no syscalls reachable |
| A plugin crash | takes down `hyperbug` | kills the subprocess only; the device faults cleanly | takes down `hyperbug` | traps cleanly inside `wasmtime`; the call returns an error, `hyperbug` keeps running |
| Cost per access | one interpreter call | one IPC round trip | one function call | one JIT-compiled function call |
| Type-checked exports | n/a (duck typing) | n/a | **no** — wrong signature is undefined behavior | **yes** — `get_typed_func` fails cleanly on a mismatch |
| Memory ceiling | none | none (whatever the OS/cgroup allows) | none | enforced by `wasmtime`'s `StoreLimits`, real and advisory-free |

The main thing WASM does *not* give you that the sandboxed-subprocess
transport does: no separate OS process, so a `wasmtime` bug (not this
plugin's own code) is still a `hyperbug`-process-wide risk in principle —
see [security.md](security/security.md) for the full picture. What it
gives you the native transport can't: a module literally cannot issue a
syscall, dereference a wild pointer into `hyperbug`'s address space, or
smash the stack — its only way out of its own sandbox is the three host
functions described below.

## The contract

A module must export:

```
memory                                  ;; the module's own linear memory
hyperbug_abi_version() -> i32
hyperbug_read(offset: i64, len: i32, _unused: i32)
hyperbug_write(offset: i64, _unused: i32, len: i32) -> i32
```

and may optionally export:

```
hyperbug_create()                            ;; called once, right after instantiation
hyperbug_tick()                              ;; called once per vCPU-loop iteration
hyperbug_reset()                             ;; called by the control socket's reset_device
hyperbug_pci_identity(probe: i32) -> i32      ;; --wasm-pci-device only
```

Missing a required export fails the load with a clear message naming
which one — `wasmtime`'s `get_typed_func` checks the exact signature too,
so a module exporting `hyperbug_read` with the wrong parameter types is
refused the same way, not run with corrupted arguments the way a
mismatched native C-ABI symbol would be.

And must import three host functions:

```
(import "env" "host_read_mem"  (func (param i64 i32 i32) (result i32)))
(import "env" "host_write_mem" (func (param i64 i32 i32) (result i32)))
(import "env" "host_raise_irq" (func))
```

A module with no other way to reach outside its own sandbox at all —
these three calls are it.

## The scratch region: how data crosses the sandbox boundary

`wasmtime` doesn't let host code pass a `&[u8]` into a WASM function
directly — both sides only ever exchange plain integers (i32/i64). Every
`read`/`write`/`pci_identity` call instead marshals its bytes through a
fixed **4 KiB scratch region at linear-memory offset 0**:

- **`hyperbug_read(offset, len, _unused)`**: called with nothing filled
  in; the module must write `len` bytes describing register `offset` to
  linear-memory address `0`. The host then copies those bytes out as the
  `read()` result.
- **`hyperbug_write(offset, _unused, len)`**: the host writes `len` bytes
  to address `0` *before* calling this; the module reads them from there.
  Return nonzero to request this device's configured interrupt be raised
  synchronously (same meaning as Python's truthy `write()` return).
- **`hyperbug_pci_identity(probe)`**: called once at load, first with
  `probe = 0` just to ask "do you have an identity at all" (return `0` for
  no); if nonzero, the module must have written the identity struct below
  to address `0` by the time it returns.

A module's *own* persistent state (register files, buffers) must live at
address 4096 or later — reserved so the marshaling writes above can never
clobber it. The simplest reliable way to guarantee that in Rust is to
grow linear memory for your own state (`core::arch::wasm32::memory_grow`)
rather than relying on where the compiler happens to place `static`
data — see `devices/wasm_dma_demo.rs`'s reference implementation.

**A sharp edge worth knowing if you write your own plugin in Rust:** a
raw pointer built from the integer literal `0` (`0usize as *mut u8`) has
no *provenance* over that memory as far as Rust's aliasing model is
concerned, even though address 0 is a perfectly ordinary, accessible
address in WASM linear memory. LLVM has been observed eliding a plain
store through such a pointer as dead-code cleanup for what it assumes is
unreachable undefined behavior. Use `core::ptr::write_volatile`/
`read_volatile` for scratch-region access — never removed by the
optimizer regardless of provenance. Both reference plugins in `devices/`
do this; it's not a hyperbug-specific requirement, just a real trap in
`wasm32-unknown-unknown` codegen worth flagging since nothing about it is
obvious from a compiler warning.

## Host functions: what a plugin gets

```
host_read_mem(addr: i64, buf_ptr: i32, size: i32) -> i32
host_write_mem(addr: i64, buf_ptr: i32, size: i32) -> i32
host_raise_irq()
```

- `host_read_mem`/`host_write_mem` — real, bounds-checked DMA against
  guest-physical memory (and this plugin's operator-declared
  DMA-confinement range, if one was given — see below). `buf_ptr` is an
  offset into the *module's own* linear memory (not the scratch region
  necessarily — any address the module owns); the host copies between
  guest RAM and that address. Returns `0` on success, `-1` on an
  out-of-range or out-of-confinement access. The same host-side rules
  Python's `self.hyperbug.read_mem`/`write_mem` and the native ABI's
  `read_mem`/`write_mem` follow.
- `host_raise_irq` — requests this device's configured interrupt (PCI
  plugins only) be raised as soon as hyperbug's vCPU loop next checks —
  spontaneous, independent of any `write()` call, exactly like Python's
  `self.hyperbug.raise_irq()`.

## Versioning

`hyperbug_abi_version()` must return a value in the same
`[PLUGIN_API_MIN_SUPPORTED, PLUGIN_API_VERSION]` range every other
transport's ABI check enforces — checked once at load, refusing a
mismatched module with a clear error (too new vs. too old) rather than
running it against a contract that's since changed underneath it.

## `hyperbug_pci_identity`: declaring a PCI device

Bytes written to the scratch region, `--wasm-pci-device` only, matching
`native-plugin-api.md`'s `struct hyperbug_pci_identity` layout exactly
(little-endian):

```
u16  vendor_id
u16  device_id
u32  class_code           (base<<16 | sub<<8 | progif)
u32  bar_sizes[6]         (0 = BAR not implemented)
u8   io_bars_mask         (bit i set: BAR i is I/O-space)
u8   interrupt_line       (legacy ISA IRQ, 0 = none)
u8   msi_capable          (0 or 1)
```

Read **once**, when the device is loaded (only for `--wasm-pci-device` —
a plain `--wasm-device` never calls this), and cached — the same as every
other transport's `PluginIdentity` snapshot. Changing what
`hyperbug_pci_identity` would return later has no effect once the device
is registered.

## Memory isolation

Every WASM instance gets a real, enforced 64 MiB linear-memory ceiling
(`wasmtime::StoreLimits`) — growing past it fails the `memory.grow`
instruction cleanly inside the module rather than actually consuming
unbounded host memory. This is a genuine advantage neither the
sandboxed-subprocess transport (bounded only by whatever the host/cgroup
allows) nor the native transport (no bound at all — it's the host
process's own heap) gets for free.

## DMA confinement, sandboxing, and resource limits — what does and doesn't apply

- **DMA confinement** (`--wasm-device`/`--wasm-pci-device`'s optional
  trailing `<dma_base>:<dma_size>`) works identically to every other
  transport: an operator-declared bound on what this plugin instance's
  `host_read_mem`/`host_write_mem` callbacks may touch, enforced
  host-side, checked before any guest memory is even read.
- **No `--wasm-device-sandboxed`.** WASM's own sandboxing is the
  isolation mechanism here — there's no separate subprocess to further
  isolate. `mem=`/`cpu=` resource-limit syntax (meaningful only for the
  sandboxed-subprocess transport's cgroup) is rejected as a config error
  for `--wasm-device`/`--wasm-pci-device`, same as for `--native-device`.
- **No seccomp filter, no cgroup** — WASM modules can't issue syscalls at
  all (no such instruction exists in the WASM instruction set reachable
  from inside the sandbox), so there's nothing for either of those
  mechanisms to additionally restrict.

## Hot-reload and `reset()`

Both work identically to every other transport —
`reset_device`/`reload_device` via the control socket (see
[plugin-api.md](plugin-api.md#hot-reload)) don't care which transport a
device uses. A reloaded WASM plugin's module is re-instantiated fresh
(a new `wasmtime::Store`/`Instance`, `hyperbug_create` called again if
exported) and swapped into the same running slot; a PCI plugin's reload
is refused if its declared identity changed, exactly like every other
transport.

## Reference plugins

- `devices/wasm_scratch.rs` — the minimal contract: a plain 16-byte
  register file, no PCI identity, no `tick`/`reset`. The WASM equivalent
  of `devices/scratch.py`/`devices/native_scratch.c`.
- `devices/wasm_dma_demo.rs` — the full contract in one file: PCI
  identity, real DMA (`host_read_mem`/`host_write_mem`), a spontaneous
  interrupt (`host_raise_irq`), and both `tick`/`reset`. The WASM
  equivalent of `devices/dma_demo.py`/`devices/native_dma_demo.c`.

Both are plain `#![no_std]` Rust source, compiled to WASM with no project
scaffolding beyond `rustc` itself and the `wasm32-unknown-unknown` target
(`rustup target add wasm32-unknown-unknown`):

```sh
rustc --target wasm32-unknown-unknown --crate-type=cdylib -O \
    -o devices/wasm_dma_demo.wasm devices/wasm_dma_demo.rs
```

```sh
./target/release/hyperbug --kernel bzImage \
    --wasm-pci-device devices/wasm_dma_demo.wasm:2
```

Nothing about the ABI is Rust-specific — any language with a
`wasm32-unknown-unknown`-equivalent target (C via `clang --target
wasm32`, Zig, hand-written WAT, etc.) works identically, as long as it
produces a module exporting `memory` plus the required functions above.

`.wasm` files are build artifacts, not checked into the repo — compile
them yourself from the `.rs` sources, the same way `native-plugin-api.md`
has you compile its `.c` sources.
