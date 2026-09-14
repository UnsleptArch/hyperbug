//! A virtual I2C bus: a set of addressable target devices (0x00-0x7f) that
//! a `VirtioI2c` adapter (`virtio_i2c.rs`) dispatches messages to.
//!
//! **Deliberately message-level, not bit/byte/ACK-level.** Real I2C is a
//! two-wire, clocked, ACK-per-byte protocol; virtio-i2c itself already
//! abstracts all of that away into `i2c_msg`-shaped requests (address,
//! direction, a byte buffer) before it ever reaches a backend — the same
//! abstraction level the guest's own kernel `i2c_msg`/`i2c_transfer` API
//! uses. `I2cTargetDevice` mirrors that: `i2c_write`/`i2c_read` are called
//! once per message, in the order the guest issued them, against one
//! long-lived stateful target instance — which is exactly how a real
//! stateful I2C slave (a sensor with an internal register pointer, set by
//! a write and read back from on the next read) behaves from a bus
//! master's point of view, without hyperbug needing to model bus
//! arbitration, clock stretching, or repeated-start at the electrical
//! level. `virtio_i2c.rs`'s own module doc comment states this same
//! simplification from the adapter side.
//!
//! There is no bus-level NAK-vs-error distinction here: an access to an
//! address with no registered target simply reports `VIRTIO_I2C_MSG_ERR`
//! (mirroring a real NAK from an absent device), matching what
//! `i2cdetect`-style probing on the guest expects to see.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// One target device on the virtual I2C bus, addressed by its fixed 7-bit
/// address. `Send`: a device may be called from whichever thread is
/// draining the adapter's virtqueue (a vCPU thread synchronously, or the
/// reactor thread via ioeventfd — see `virtio.rs`'s `ioevent_entries`),
/// same reasoning as `device::Device`.
pub trait I2cTargetDevice: Send {
    /// Handle a write-direction message: `data` is exactly what the guest
    /// wrote in one `i2c_msg`. A stateful device typically uses this to
    /// set an internal register pointer (and/or write register contents),
    /// mirroring the extremely common "write register address[, then
    /// value]" idiom real I2C sensors use.
    fn i2c_write(&mut self, data: &[u8]);

    /// Handle a read-direction message: return up to `len` bytes for the
    /// adapter to write into the guest's buffer. Returning fewer than
    /// `len` bytes is safe (the remainder of the guest's buffer is left
    /// untouched, and the actual data-buffer length used for the message
    /// is what the guest itself specified — a real I2C read always
    /// transfers exactly the length the master clocked out); returning
    /// more than `len` is truncated.
    fn i2c_read(&mut self, len: usize) -> Vec<u8>;
}

/// Whether a 7-bit I2C address is representable at all (0x00-0x7f) —
/// `virtio_i2c`'s wire format only supports 7-bit addressing (see
/// `virtio_i2c_out_hdr`'s own doc comment in the real kernel header: "Only
/// 7-bit mode supported for this moment").
pub const MAX_I2C_ADDRESS: u8 = 0x7f;

/// The set of target devices attached to one virtual I2C bus, shared
/// between CLI wiring (`machine.rs`, which populates it from
/// `--i2c-device` specs before the adapter is even built) and the
/// `VirtioI2c` adapter that dispatches guest messages into it.
#[derive(Default)]
pub struct I2cBus {
    targets: HashMap<u8, Arc<Mutex<dyn I2cTargetDevice>>>,
}

impl I2cBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches `device` at `addr` (0x00-0x7f). Returns an error (rather
    /// than silently overwriting) if another device is already at that
    /// address — a real I2C bus can't have two chips answering the same
    /// address either.
    pub fn register(&mut self, addr: u8, device: Arc<Mutex<dyn I2cTargetDevice>>) -> Result<(), String> {
        if addr > MAX_I2C_ADDRESS {
            return Err(format!("I2C address {addr:#x} exceeds the 7-bit maximum {MAX_I2C_ADDRESS:#x}"));
        }
        if self.targets.contains_key(&addr) {
            return Err(format!("I2C address {addr:#x} is already occupied by another device"));
        }
        self.targets.insert(addr, device);
        Ok(())
    }

    /// The device at `addr`, if any — `None` mirrors a real bus's NAK from
    /// an address nothing is listening on.
    pub fn get(&self, addr: u8) -> Option<Arc<Mutex<dyn I2cTargetDevice>>> {
        self.targets.get(&addr).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoTarget {
        last_write: Vec<u8>,
    }

    impl I2cTargetDevice for EchoTarget {
        fn i2c_write(&mut self, data: &[u8]) {
            self.last_write = data.to_vec();
        }
        fn i2c_read(&mut self, len: usize) -> Vec<u8> {
            let mut out = self.last_write.clone();
            out.resize(len, 0xff);
            out
        }
    }

    #[test]
    fn a_registered_device_answers_at_its_address_and_nothing_answers_elsewhere() {
        let mut bus = I2cBus::new();
        bus.register(0x50, Arc::new(Mutex::new(EchoTarget { last_write: Vec::new() }))).unwrap();

        assert!(bus.get(0x50).is_some());
        assert!(bus.get(0x51).is_none(), "an unregistered address must NAK");

        let dev = bus.get(0x50).unwrap();
        dev.lock().unwrap().i2c_write(&[0xAB]);
        assert_eq!(dev.lock().unwrap().i2c_read(2), vec![0xAB, 0xff]);
    }

    #[test]
    fn registering_two_devices_at_the_same_address_is_refused() {
        let mut bus = I2cBus::new();
        bus.register(0x50, Arc::new(Mutex::new(EchoTarget { last_write: Vec::new() }))).unwrap();
        let err = bus
            .register(0x50, Arc::new(Mutex::new(EchoTarget { last_write: Vec::new() })))
            .expect_err("a second device at the same address must be refused");
        assert!(err.contains("already occupied"), "got: {err}");
    }

    #[test]
    fn an_address_past_the_7_bit_range_is_refused() {
        let mut bus = I2cBus::new();
        let err = bus
            .register(0x80, Arc::new(Mutex::new(EchoTarget { last_write: Vec::new() })))
            .expect_err("an 8-bit address must be refused");
        assert!(err.contains("7-bit"), "got: {err}");
    }
}
