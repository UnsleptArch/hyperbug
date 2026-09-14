//! virtio-gpio: a real, standardized virtio device (`VIRTIO_ID_GPIO` = 41,
//! per this host's own `<linux/virtio_ids.h>`) that a guest's real,
//! unmodified `gpio-virtio` driver (`drivers/gpio/gpio-virtio.c`) binds to
//! directly. Wire format taken verbatim from this host's own
//! `<linux/virtio_gpio.h>` and cross-checked against the real driver
//! source (`torvalds/linux`), same discipline `virtio_i2c.rs` already
//! established for the sibling Tier-6 device.
//!
//! **Modern-transport only**, same reasoning as virtio-i2c: virtio-gpio
//! postdates the legacy PCI ID numbering scheme, so no legacy ID exists —
//! only ever wired through `VirtioModernPci`.
//!
//! **Two virtqueues, two different completion shapes.** `requestq`
//! (index 0) is a synchronous request/response protocol — GET/SET_
//! DIRECTION, GET/SET_VALUE, IRQ_TYPE, GET_NAMES — handled entirely
//! within one `process_chain` call, same as every other device in this
//! codebase. `eventq` (index 1) is fundamentally different: the guest
//! proactively posts one buffer *per GPIO line* to arm that line's
//! interrupt, and the buffer must **not** complete until a real event
//! actually happens on that line — potentially long after the kick that
//! posted it. This reuses the exact `ChainOutcome::Pending`/
//! `VirtioDeviceOps::poll_completions` machinery `virtio_blk.rs`'s
//! io_uring backend already established for "submitted now, completes
//! later" — just triggered by a Python plugin calling
//! `self.hyperbug.raise_irq(line)` instead of an io_uring completion
//! queue. `virtio.rs` gained `VirtioModernPci::drain_completions` (a copy
//! of the legacy transport's own) specifically so this device (the first
//! deferred-completion device on the modern transport) could reuse it
//! rather than needing a third variant.
//!
//! **A fired interrupt for a line nothing is listening on is dropped**,
//! not queued — `irq_enabled` tracks which lines currently have a
//! non-`NONE` `IRQ_TYPE` armed, and `poll_completions` only delivers a
//! fired line that's both enabled *and* has a live posted buffer
//! (`pending_arms`). This matches real hardware: an interrupt raised
//! while masked or with nobody polling is simply lost, not buffered
//! indefinitely.

use std::collections::HashMap;
use std::os::fd::RawFd;

use crate::gpio::{DIRECTION_IN, DIRECTION_NONE, DIRECTION_OUT, GpioBank};
use crate::mem::GuestMemory;
use crate::virtio::{ChainOutcome, CompletionResult, DescChain, VirtioDeviceOps, copy_config};

const REQUEST_QUEUE: u16 = 0;
const EVENT_QUEUE: u16 = 1;

/// `VIRTIO_GPIO_F_IRQ` (feature bit 0) — offered because this device
/// implements the event queue; a driver that doesn't negotiate it simply
/// never allocates `eventq` or registers guest IRQs, and every
/// GET/SET_DIRECTION/VALUE request still works either way.
const F_IRQ: u32 = 1 << 0;

const MSG_GET_NAMES: u16 = 0x0001;
const MSG_GET_DIRECTION: u16 = 0x0002;
const MSG_SET_DIRECTION: u16 = 0x0003;
const MSG_GET_VALUE: u16 = 0x0004;
const MSG_SET_VALUE: u16 = 0x0005;
const MSG_IRQ_TYPE: u16 = 0x0006;

const STATUS_OK: u8 = 0x0;
const STATUS_ERR: u8 = 0x1;

const IRQ_TYPE_NONE: u8 = 0x00;
const IRQ_STATUS_VALID: u8 = 0x1;

/// `struct virtio_gpio_request` is 8 bytes: `type` (u16 LE), `gpio` (u16
/// LE), `value` (u32 LE, only the low byte of which is ever meaningful).
const REQUEST_LEN: usize = 8;
/// `struct virtio_gpio_irq_request` is 2 bytes: `gpio` (u16 LE).
const IRQ_REQUEST_LEN: usize = 2;
/// `struct virtio_gpio_response`/`virtio_gpio_irq_response`'s common
/// prefix: a single status byte.
const RESPONSE_STATUS_LEN: usize = 1;

/// A guest-posted `eventq` buffer, armed for a specific line, not yet
/// completed because no real event has happened on it yet.
struct PendingArm {
    head_index: u16,
    status_buf_addr: u64,
}

pub struct VirtioGpio {
    bank: Box<dyn GpioBank>,
    ngpio: u16,
    /// `struct virtio_gpio_config`'s 8 bytes, built once at construction:
    /// `ngpio` (u16), 2 bytes padding, `gpio_names_size` (u32).
    config: [u8; 8],
    /// Every line's name, NUL-separated, back to back — `gpio_names_size`
    /// bytes exactly. Empty iff `bank.names()` was empty, in which case
    /// the real driver never issues `GET_NAMES` at all.
    names_blob: Vec<u8>,
    /// One entry per line currently armed on `eventq`, keyed by GPIO line
    /// number (at most one outstanding arm per line at a time, matching
    /// the real driver's own one-buffer-per-line convention).
    pending_arms: HashMap<u16, PendingArm>,
    /// Lines whose last `IRQ_TYPE` request set something other than
    /// `IRQ_TYPE_NONE` — a fired event for a line not in here is dropped,
    /// matching a masked/disabled real interrupt.
    irq_enabled: std::collections::HashSet<u16>,
}

impl VirtioGpio {
    pub fn new(bank: Box<dyn GpioBank>) -> Self {
        let ngpio = bank.ngpio();
        let names = bank.names();
        let names_blob: Vec<u8> = if names.is_empty() {
            Vec::new()
        } else {
            let mut blob = Vec::new();
            for name in &names {
                blob.extend_from_slice(name.as_bytes());
                blob.push(0);
            }
            blob
        };
        let mut config = [0u8; 8];
        config[0..2].copy_from_slice(&ngpio.to_le_bytes());
        config[4..8].copy_from_slice(&(names_blob.len() as u32).to_le_bytes());
        Self { bank, ngpio, config, names_blob, pending_arms: HashMap::new(), irq_enabled: std::collections::HashSet::new() }
    }

    fn handle_request(&mut self, mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome {
        if chain.buffers.len() != 2 {
            return ChainOutcome::Done(0);
        }
        let req_buf = &chain.buffers[0];
        let res_buf = &chain.buffers[1];
        if req_buf.device_writable || req_buf.len as usize != REQUEST_LEN || !res_buf.device_writable {
            return ChainOutcome::Done(0);
        }
        let mut req = [0u8; REQUEST_LEN];
        if !mem.read_checked(req_buf.addr, &mut req) {
            return ChainOutcome::Done(0);
        }
        let msg_type = u16::from_le_bytes([req[0], req[1]]);
        let gpio = u16::from_le_bytes([req[2], req[3]]);
        let value = req[4]; // only the low byte of the u32 ever matters

        if msg_type == MSG_GET_NAMES {
            let mut response = vec![0u8; RESPONSE_STATUS_LEN + self.names_blob.len()];
            response[0] = STATUS_OK;
            response[1..].copy_from_slice(&self.names_blob);
            let n = response.len().min(res_buf.len as usize);
            if !mem.write_checked(res_buf.addr, &response[..n]) {
                return ChainOutcome::Done(0);
            }
            return ChainOutcome::Done(n as u32);
        }

        let (status, out_value) = if gpio >= self.ngpio {
            (STATUS_ERR, 0u8)
        } else {
            match msg_type {
                MSG_GET_DIRECTION => (STATUS_OK, self.bank.get_direction(gpio)),
                MSG_SET_DIRECTION => match value {
                    DIRECTION_NONE | DIRECTION_OUT | DIRECTION_IN => {
                        self.bank.set_direction(gpio, value);
                        (STATUS_OK, 0)
                    }
                    _ => (STATUS_ERR, 0),
                },
                MSG_GET_VALUE => (STATUS_OK, self.bank.get_value(gpio) & 1),
                MSG_SET_VALUE => {
                    self.bank.set_value(gpio, value & 1);
                    (STATUS_OK, 0)
                }
                MSG_IRQ_TYPE => {
                    if value == IRQ_TYPE_NONE {
                        self.irq_enabled.remove(&gpio);
                    } else {
                        self.irq_enabled.insert(gpio);
                    }
                    (STATUS_OK, 0)
                }
                _ => (STATUS_ERR, 0),
            }
        };

        let response = [status, out_value];
        let n = response.len().min(res_buf.len as usize);
        if !mem.write_checked(res_buf.addr, &response[..n]) {
            return ChainOutcome::Done(0);
        }
        ChainOutcome::Done(n as u32)
    }

    fn handle_event_arm(&mut self, chain: &DescChain, mem: &mut GuestMemory) -> ChainOutcome {
        if chain.buffers.len() != 2 {
            return ChainOutcome::Done(0);
        }
        let req_buf = &chain.buffers[0];
        let res_buf = &chain.buffers[1];
        if req_buf.device_writable || req_buf.len as usize != IRQ_REQUEST_LEN || !res_buf.device_writable {
            return ChainOutcome::Done(0);
        }
        let mut req = [0u8; IRQ_REQUEST_LEN];
        if !mem.read_checked(req_buf.addr, &mut req) {
            return ChainOutcome::Done(0);
        }
        let gpio = u16::from_le_bytes(req);
        self.pending_arms.insert(gpio, PendingArm { head_index: chain.head_index(), status_buf_addr: res_buf.addr });
        ChainOutcome::Pending
    }
}

impl VirtioDeviceOps for VirtioGpio {
    fn legacy_pci_device_id(&self) -> u16 {
        // Never actually used — see this module's own doc comment: no
        // legacy virtio-gpio device exists in the real PCI ID registry,
        // and `machine.rs` only ever wires this through `VirtioModernPci`.
        0
    }

    fn virtio_device_type(&self) -> u16 {
        41 // VIRTIO_ID_GPIO, per this host's own <linux/virtio_ids.h>
    }

    fn pci_class_code(&self) -> u32 {
        0xff_00_00 // unclassified — no PCI class fits a GPIO controller cleanly
    }

    fn num_queues(&self) -> u16 {
        2 // requestq, eventq — real driver always looks for both by name
    }

    fn queue_size(&self, _queue: u16) -> u16 {
        64
    }

    fn host_features(&self) -> u32 {
        F_IRQ
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(&self.config, offset, data);
    }

    fn process_chain(&mut self, queue: u16, mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome {
        match queue {
            REQUEST_QUEUE => self.handle_request(mem, chain),
            EVENT_QUEUE => self.handle_event_arm(chain, mem),
            _ => ChainOutcome::Done(0),
        }
    }

    fn poll_completions(&mut self) -> Vec<CompletionResult> {
        let fired = self.bank.take_fired_irqs();
        let mut out = Vec::new();
        for line in fired {
            if !self.irq_enabled.contains(&line) {
                continue; // masked/disabled: matches a real interrupt simply being lost
            }
            if let Some(arm) = self.pending_arms.remove(&line) {
                out.push(CompletionResult {
                    queue_idx: EVENT_QUEUE,
                    head_index: arm.head_index,
                    written_len: 0, // the response is only the 1-byte status; drain_completions adds it
                    status_byte: IRQ_STATUS_VALID,
                    status_buf_addr: arm.status_buf_addr,
                });
            }
            // No pending arm: the guest hadn't (yet) posted a buffer for
            // this line when it fired — dropped, same as a real
            // interrupt with nothing currently polling for it.
        }
        out
    }

    fn completion_eventfd(&self) -> Option<RawFd> {
        self.bank.completion_eventfd()
    }
}
