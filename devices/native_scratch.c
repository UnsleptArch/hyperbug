/* A minimal native (C-ABI) device plugin — the C equivalent of
 * devices/scratch.py: a plain 16-byte register file, no PCI identity, no
 * tick/reset. See include/hyperbug_plugin.h for the full contract.
 *
 * Build: cc -shared -fPIC -Iinclude -o native_scratch.so devices/native_scratch.c
 * Use:   --native-device devices/native_scratch.so:0xd0000000:0x1000
 */

#include "hyperbug_plugin.h"
#include <string.h>
#include <stdlib.h>

struct scratch_state {
    unsigned char regs[16];
};

uint32_t hyperbug_plugin_abi_version(void) {
    return HYPERBUG_PLUGIN_ABI_VERSION;
}

void *hyperbug_plugin_create(const struct hyperbug_host_ctx *ctx) {
    (void)ctx; /* this device doesn't need DMA/IRQ, but a real one would stash ctx here */
    struct scratch_state *s = calloc(1, sizeof(*s));
    return s;
}

void hyperbug_plugin_destroy(void *state) {
    free(state);
}

void hyperbug_plugin_read(void *state, uint64_t offset, uint8_t *data, size_t size) {
    struct scratch_state *s = state;
    for (size_t i = 0; i < size; i++) {
        uint64_t off = offset + i;
        data[i] = (off < sizeof(s->regs)) ? s->regs[off] : 0;
    }
}

int hyperbug_plugin_write(void *state, uint64_t offset, const uint8_t *data, size_t size) {
    struct scratch_state *s = state;
    for (size_t i = 0; i < size; i++) {
        uint64_t off = offset + i;
        if (off < sizeof(s->regs)) {
            s->regs[off] = data[i];
        }
    }
    return 0; /* never requests an interrupt */
}
