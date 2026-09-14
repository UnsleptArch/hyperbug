/* A native (C-ABI) device plugin exercising the full contract: PCI
 * identity, real DMA (read_mem/write_mem), a spontaneous interrupt
 * (raise_irq), tick(), and reset() — the C equivalent of dma_demo.py
 * plus doorbell_demo.py's tick, in one file. See
 * include/hyperbug_plugin.h for the full contract.
 *
 * Register layout (offsets relative to BAR0, all little-endian):
 *   0x00  BUFFER_ADDR (write, u64): guest-physical address of the buffer
 *   0x08  BUFFER_LEN  (write, u32): how many bytes to reverse
 *   0x0c  CMD         (write, u8) : 1 = reverse the buffer via DMA now
 *
 * Build: cc -shared -fPIC -Iinclude -o native_dma_demo.so devices/native_dma_demo.c
 * Use:   --native-pci-device devices/native_dma_demo.so:<device_number>
 */

#include "hyperbug_plugin.h"
#include <stdlib.h>
#include <string.h>

struct dma_state {
    const struct hyperbug_host_ctx *ctx;
    uint64_t buffer_addr;
    uint32_t buffer_len;
    uint32_t tick_count;
};

uint32_t hyperbug_plugin_abi_version(void) {
    return HYPERBUG_PLUGIN_ABI_VERSION;
}

void *hyperbug_plugin_create(const struct hyperbug_host_ctx *ctx) {
    struct dma_state *s = calloc(1, sizeof(*s));
    s->ctx = ctx; /* `ctx` itself is kept alive by hyperbug for this device's whole lifetime */
    return s;
}

void hyperbug_plugin_destroy(void *state) {
    free(state);
}

void hyperbug_plugin_read(void *state, uint64_t offset, uint8_t *data, size_t size) {
    (void)state;
    (void)offset;
    memset(data, 0, size); /* write-only register file */
}

int hyperbug_plugin_write(void *state, uint64_t offset, const uint8_t *data, size_t size) {
    struct dma_state *s = state;
    if (offset == 0x00 && size == 8) {
        memcpy(&s->buffer_addr, data, 8);
    } else if (offset == 0x08 && size == 4) {
        memcpy(&s->buffer_len, data, 4);
    } else if (offset == 0x0c && size >= 1 && data[0] == 1) {
        /* Reverse the guest buffer in place via real DMA. */
        uint8_t buf[256];
        if (s->buffer_len > sizeof(buf)) {
            return 0;
        }
        if (s->ctx->read_mem(s->ctx->opaque, s->buffer_addr, buf, s->buffer_len) != 0) {
            return 0;
        }
        for (uint32_t i = 0; i < s->buffer_len / 2; i++) {
            uint8_t tmp = buf[i];
            buf[i] = buf[s->buffer_len - 1 - i];
            buf[s->buffer_len - 1 - i] = tmp;
        }
        s->ctx->write_mem(s->ctx->opaque, s->buffer_addr, buf, s->buffer_len);
        s->ctx->raise_irq(s->ctx->opaque);
    }
    return 0;
}

void hyperbug_plugin_tick(void *state) {
    struct dma_state *s = state;
    s->tick_count++;
}

void hyperbug_plugin_reset(void *state) {
    struct dma_state *s = state;
    s->buffer_addr = 0;
    s->buffer_len = 0;
    s->tick_count = 0;
}

int hyperbug_plugin_pci_identity(void *state, struct hyperbug_pci_identity *out) {
    (void)state;
    out->vendor_id = 0x1234;     /* not-real-silicon placeholder, matching dma_demo.py */
    out->device_id = 0x0002;
    out->class_code = 0xff0000;
    out->bar_sizes[0] = 0x10;
    for (int i = 1; i < HYPERBUG_NUM_BARS; i++) {
        out->bar_sizes[i] = 0;
    }
    out->io_bars_mask = 0;
    out->interrupt_line = 9;
    out->msi_capable = 1;
    return 1;
}
