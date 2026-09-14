/* hyperbug native device plugin ABI — the C-ABI equivalent of the Python
 * Device/PciDevice contract (see docs/plugin-api.md), for a plugin
 * written in C, Rust (via #[no_mangle] extern "C"), or anything else
 * that can produce a shared object exporting a plain C ABI.
 *
 * SECURITY: a native plugin loaded via --native-device/--native-pci-device
 * is dlopen()ed directly into the hyperbug process. There is no
 * interpreter boundary, no seccomp filter, no cgroup, nothing — it runs
 * with the full privileges of, and in the same address space as, the
 * VMM itself. A bug in a native plugin can corrupt or crash the whole
 * process, or do anything the hyperbug process itself could do. Use this
 * ABI only for code you completely trust and control; there is no
 * sandboxed equivalent of this path (unlike Python's --*-sandboxed
 * variants) — see docs/security/security.md.
 *
 * Version: this header corresponds to HYPERBUG_PLUGIN_ABI_VERSION below.
 * A plugin exports hyperbug_plugin_abi_version() and hyperbug checks it
 * once at load against the range it currently supports (mirroring
 * hyperbug.device.HYPERBUG_API_VERSION/HYPERBUG_API_MIN_SUPPORTED on the
 * Python side) — a mismatch fails the load loudly instead of running the
 * plugin against a contract that's since changed.
 *
 * Required exports (load fails if any of these five is missing):
 *   uint32_t hyperbug_plugin_abi_version(void);
 *   void    *hyperbug_plugin_create(const struct hyperbug_host_ctx *ctx);
 *   void     hyperbug_plugin_destroy(void *state);
 *   void     hyperbug_plugin_read(void *state, uint64_t offset,
 *                                  uint8_t *data, size_t size);
 *   int      hyperbug_plugin_write(void *state, uint64_t offset,
 *                                   const uint8_t *data, size_t size);
 *
 * Optional exports (a plugin that omits one simply never gets it called,
 * exactly like Python's tick()/reset()/PCI-attribute opt-in):
 *   void hyperbug_plugin_tick(void *state);
 *   void hyperbug_plugin_reset(void *state);
 *   int  hyperbug_plugin_pci_identity(void *state,
 *                                      struct hyperbug_pci_identity *out);
 */

#ifndef HYPERBUG_PLUGIN_H
#define HYPERBUG_PLUGIN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYPERBUG_PLUGIN_ABI_VERSION 1u

/* Up to 6 BARs, matching real PCI and hyperbug's own NUM_BARS. */
#define HYPERBUG_NUM_BARS 6

/* A plugin's PCI identity, filled in by hyperbug_plugin_pci_identity().
 * Read once, at load — changing these fields later has no effect, the
 * same as the Python ABI's PciDevice attributes. */
struct hyperbug_pci_identity {
    uint16_t vendor_id;
    uint16_t device_id;
    uint32_t class_code;                       /* (base<<16 | sub<<8 | progif) */
    uint32_t bar_sizes[HYPERBUG_NUM_BARS];      /* 0 = BAR not implemented */
    uint8_t  io_bars_mask;                      /* bit i set: BAR i is I/O-space */
    uint8_t  interrupt_line;                    /* legacy ISA IRQ, 0 = none */
    uint8_t  msi_capable;                       /* 0 or 1 */
};

/* Host callbacks a plugin gets at hyperbug_plugin_create() time, valid
 * for the plugin instance's entire lifetime (until hyperbug_plugin_
 * destroy() is called). `opaque` must be passed back unchanged on every
 * call — it identifies which running guest/device this is.
 *
 * read_mem/write_mem: real, bounds-checked DMA against guest physical
 * memory (and, if the operator declared one, this plugin's DMA-
 * confinement range) — the same host-side rules the Python
 * self.hyperbug.read_mem/write_mem calls follow. Return 0 on success,
 * -1 on an out-of-range/out-of-confinement access.
 *
 * raise_irq: requests this device's configured interrupt (PCI plugins
 * only) be raised as soon as hyperbug's vCPU loop next checks —
 * spontaneous, not tied to a write() call, exactly like Python's
 * self.hyperbug.raise_irq(). */
struct hyperbug_host_ctx {
    void *opaque;
    int  (*read_mem)(void *opaque, uint64_t addr, uint8_t *data, size_t size);
    int  (*write_mem)(void *opaque, uint64_t addr, const uint8_t *data, size_t size);
    void (*raise_irq)(void *opaque);
};

#ifdef __cplusplus
}
#endif

#endif /* HYPERBUG_PLUGIN_H */
