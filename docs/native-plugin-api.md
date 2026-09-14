# Native (C ABI) plugin reference

Python is the default, easy path for a device plugin (see
[plugin-api.md](plugin-api.md)). This is the other path: a plugin
written in C, Rust, or anything else that can produce a plain C-ABI
shared object, for the case where a plugin's own overhead — an embedded
interpreter, or a subprocess IPC round trip — genuinely matters, or a
plugin needs a language other than Python.

**Read [security.md](security/security.md) before using this.** A native
plugin is `dlopen()`ed directly into the `hyperbug` process: no
interpreter boundary, no seccomp filter, no cgroup, nothing. It runs with
the full privileges of, and in the same address space as, the VMM
itself. There is no sandboxed equivalent of this path — use it only for
code you completely trust and control.

## The contract

`include/hyperbug_plugin.h` is the authoritative header — read it
directly for the full byte-level layout. In short, a plugin shared
object exports these C symbols:

**Required** (load fails, naming which one, if any of these five is
missing):

```c
uint32_t hyperbug_plugin_abi_version(void);
void    *hyperbug_plugin_create(const struct hyperbug_host_ctx *ctx);
void     hyperbug_plugin_destroy(void *state);
void     hyperbug_plugin_read(void *state, uint64_t offset, uint8_t *data, size_t size);
int      hyperbug_plugin_write(void *state, uint64_t offset, const uint8_t *data, size_t size);
```

**Optional** (a plugin that omits one simply never gets it called —
checked once at load, exactly like Python's `tick`/`reset`/PCI-attribute
opt-in):

```c
void hyperbug_plugin_tick(void *state);
void hyperbug_plugin_reset(void *state);
int  hyperbug_plugin_pci_identity(void *state, struct hyperbug_pci_identity *out);
```

`hyperbug_plugin_write`'s return value: nonzero requests this device's
configured interrupt be raised synchronously (same meaning as Python's
truthy `write()` return). `hyperbug_plugin_pci_identity`'s return value:
nonzero means `out` was filled in and this is a PCI device; zero means
"no PCI identity" (a plain `--native-device`, or a `--native-pci-device`
plugin that chooses not to declare one — unusual, but not rejected).

## Versioning

`hyperbug_plugin_abi_version()` must return a value in the same
`[PLUGIN_API_MIN_SUPPORTED, PLUGIN_API_VERSION]` range the Python ABI's
`HYPERBUG_API_MIN_SUPPORTED`/`HYPERBUG_API_VERSION` check against —
checked once at load, refusing a mismatched plugin with a clear error
(too new vs. too old) rather than running it against a contract that's
since changed underneath it.

## `hyperbug_host_ctx`: what a plugin gets at `create()` time

```c
struct hyperbug_host_ctx {
    void *opaque;
    int  (*read_mem)(void *opaque, uint64_t addr, uint8_t *data, size_t size);
    int  (*write_mem)(void *opaque, uint64_t addr, const uint8_t *data, size_t size);
    void (*raise_irq)(void *opaque);
};
```

Passed to `hyperbug_plugin_create()` and valid for the plugin instance's
entire lifetime (not just during that one call) — hyperbug keeps the
struct and everything `opaque` points to alive until
`hyperbug_plugin_destroy()` runs. Always pass `opaque` back unchanged.

- `read_mem`/`write_mem` — real, bounds-checked DMA against guest
  physical memory (and this plugin's operator-declared DMA-confinement
  range, if one was given — see below). Returns `0` on success, `-1` on
  an out-of-range or out-of-confinement access. The same host-side rules
  Python's `self.hyperbug.read_mem`/`write_mem` follow.
- `raise_irq` — requests this device's configured interrupt (PCI plugins
  only) be raised as soon as hyperbug's vCPU loop next checks —
  spontaneous, independent of any `write()` call, exactly like Python's
  `self.hyperbug.raise_irq()`.

## `hyperbug_pci_identity`: declaring a PCI device

```c
struct hyperbug_pci_identity {
    uint16_t vendor_id;
    uint16_t device_id;
    uint32_t class_code;                  /* (base<<16 | sub<<8 | progif) */
    uint32_t bar_sizes[HYPERBUG_NUM_BARS]; /* 0 = BAR not implemented */
    uint8_t  io_bars_mask;                 /* bit i set: BAR i is I/O-space */
    uint8_t  interrupt_line;               /* legacy ISA IRQ, 0 = none */
    uint8_t  msi_capable;                  /* 0 or 1 */
};
```

Read **once**, when the device is loaded (only for `--native-pci-device`
— a plain `--native-device` never has this called), and cached — the
same as every other transport's `PluginIdentity` snapshot. Changing what
`hyperbug_plugin_pci_identity` would return later has no effect once the
device is registered.

## DMA confinement, sandboxing, and resource limits — what does and doesn't apply

- **DMA confinement** (`--native-device`/`--native-pci-device`'s optional
  trailing `<dma_base>:<dma_size>`) works identically to the Python ABI:
  an operator-declared bound on what this plugin instance's `read_mem`/
  `write_mem` callbacks may touch, enforced host-side.
- **No sandboxing.** There is no `--native-device-sandboxed`. A native
  plugin always runs in-process; process-level isolation (the seccomp
  deny-list, cgroup limits) that Python's `--*-sandboxed` variants get
  doesn't exist for this path at all, because there's no subprocess to
  apply it to.
- **No `mem=`/`cpu=` resource limits**, for the same reason — those are
  enforced via a cgroup the sandboxed *subprocess* joins; a native plugin
  shares the whole VMM process's own resource budget, same as an
  in-process Python plugin. `--native-device`/`--native-pci-device`
  reject `mem=`/`cpu=` as a config error rather than silently ignoring
  them.

## Hot-reload and `reset()`

Both work identically to the Python ABI — `reset_device`/`reload_device`
via the control socket (see
[plugin-api.md](plugin-api.md#hot-reload)) don't care which transport a
device uses. A reloaded native plugin's `.so` is `dlopen()`ed fresh (the
old one's `hyperbug_plugin_destroy()` is called first) and swapped into
the same running slot; a PCI plugin's reload is refused if its declared
identity changed, exactly like the Python case.

## Reference plugins

- `devices/native_scratch.c` — the minimal contract: a plain 16-byte
  register file, no PCI identity, no `tick`/`reset`. The C equivalent of
  `devices/scratch.py`.
- `devices/native_dma_demo.c` — the full contract in one file: PCI
  identity, real DMA (`read_mem`/`write_mem`), a spontaneous interrupt
  (`raise_irq`), and both `tick`/`reset`. The C equivalent of
  `devices/dma_demo.py` (plus a `tick`/`reset` example on top).

Build either with:

```sh
cc -shared -fPIC -Iinclude -o devices/native_scratch.so devices/native_scratch.c
```

```sh
./target/release/hyperbug --kernel bzImage \
    --native-device devices/native_scratch.so:0xd0000000:0x1000
```

`.so` files are build artifacts, not checked into the repo — compile
them yourself from the `.c` sources, the same way you'd compile any C
plugin you write.
