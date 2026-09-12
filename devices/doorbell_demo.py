# Reference device demonstrating `tick()` (DEBTS.md item 32) driving a
# genuinely *asynchronous* completion — the register pattern a real
# doorbell + circular-buffer transport (host rings a doorbell, the far end
# processes the request on its own schedule, completion arrives via an
# interrupt sometime later, not synchronously inside the triggering write)
# needs. dma_demo.py already covers DMA + a *synchronous* raise_irq()
# inside write(); this is the other half — the one relevant to any future
# device that bridges to something answering on its own schedule instead
# of finishing before write() returns.
#
# hyperbug's own "no Intel/HECI/MEI-specific code" rule (see
# docs/architecture.md) applies here too: this models the *generic*
# register shape common to
# any bus-mastering ring-buffer transport (a host-facing doorbell/status/
# result window), not any specific real device's register layout or PCI
# identity — nothing here names or encodes real hardware.
#
# Register layout, all 32-bit little-endian, offsets relative to BAR0:
#
#   0x00  DOORBELL (write-only) : submit a request word. Queued, not
#                                 processed synchronously — see `tick()`
#                                 below. Multiple requests may be in
#                                 flight at once (a real circular buffer,
#                                 not a single-slot register).
#   0x04  STATUS    (read-only) : bit 0 (RESULT_READY) — a completed
#                                 response is waiting in RESULT.
#                                 bit 1 (BUSY) — at least one request is
#                                 still being processed.
#   0x08  RESULT    (read-only) : the oldest completed response still
#                                 queued. Reading it dequeues it and
#                                 updates STATUS (clearing RESULT_READY
#                                 once nothing is left).
#   0x0C  RESET     (write-only): write anything to drop all pending
#                                 requests/results and start clean —
#                                 real hardware doorbell/ring-buffer
#                                 transports always have a reset path,
#                                 not modeled by dma_demo.py.
#
# A request takes `LATENCY_TICKS` calls to `tick()` to complete — enough
# to prove the response genuinely arrives asynchronously (not on the same
# `write()` that submitted it), the way a real bridged transaction would.

from collections import deque

from hyperbug import PciDevice

STATUS_RESULT_READY = 0x1
STATUS_BUSY = 0x2

LATENCY_TICKS = 3


class DoorbellDemoDevice(PciDevice):
    # 0x1234: the same "not real silicon" placeholder vendor used
    # elsewhere in this repo (pci.rs's HostBridge, dma_demo.py) — this is
    # a demonstration device, not a real one. A different device_id from
    # dma_demo.py's so the two are distinguishable on the bus.
    vendor_id = 0x1234
    device_id = 0x0002
    class_code = 0xFF0000  # "unassigned class", matching virtio's own convention
    bar_sizes = [0x10]
    # See dma_demo.py's own comment on this — same reasoning, different
    # legacy IRQ so the two demo devices don't collide if both are loaded
    # at once.
    interrupt_line = 10
    msi_capable = True

    def __init__(self):
        # Each entry is [response_word, ticks_remaining]; `deque` because
        # requests complete in submission order, like a real ring buffer.
        self.in_flight = deque()
        self.completed = deque()

    def read(self, offset, size):
        if offset == 0x04:
            return self._status().to_bytes(4, "little")[:size]
        if offset == 0x08:
            value = self.completed.popleft() if self.completed else 0
            return value.to_bytes(4, "little")[:size]
        return bytes(size)

    def write(self, offset, data):
        if offset == 0x00:
            request = int.from_bytes(data, "little")
            self.in_flight.append([request, LATENCY_TICKS])
        elif offset == 0x0C:
            self.in_flight.clear()
            self.completed.clear()
        return False  # this device only ever raises its interrupt from tick()

    def tick(self):
        still_pending = []
        completed_this_tick = False
        for entry in self.in_flight:
            entry[1] -= 1
            if entry[1] <= 0:
                # The "processing": bitwise-complement the request word,
                # standing in for whatever a real bridged transaction
                # would actually compute.
                self.completed.append(entry[0] ^ 0xFFFFFFFF)
                completed_this_tick = True
            else:
                still_pending.append(entry)
        self.in_flight = deque(still_pending)
        if completed_this_tick:
            self.hyperbug.raise_irq()

    def _status(self):
        status = STATUS_BUSY if self.in_flight else 0
        status |= STATUS_RESULT_READY if self.completed else 0
        return status
