//! virtio-i2c: a real, standardized virtio device (`VIRTIO_ID_I2C_ADAPTER`
//! = 34, per this host's own `<linux/virtio_ids.h>`) that a guest's real,
//! unmodified `i2c-virtio` driver (`drivers/i2c/busses/i2c-virtio.c`)
//! binds to directly — no custom guest-side driver needed, matching
//! hyperbug's whole "real drivers against devices you define" premise.
//! Wire format taken verbatim from this host's own
//! `<linux/virtio_i2c.h>` and cross-checked against the real driver
//! source (`torvalds/linux`, not reconstructed from the spec page alone —
//! the same "verify against a real source of truth" discipline `acpi.rs`
//! and `virtio.rs`'s modern-transport work already established).
//!
//! **Modern-transport only.** No legacy virtio-i2c PCI ID exists in the
//! real registry — virtio-i2c postdates the legacy numbering scheme
//! entirely (`VIRTIO_ID_I2C_ADAPTER` = 34 has no I/O-BAR transitional
//! form), so this is only ever wired up via `VirtioModernPci`, never
//! `VirtioLegacyPci`.
//!
//! **One virtqueue ("msg"), one descriptor chain per `i2c_msg`.** The real
//! driver's `virtio_i2c_xfer` calls `virtqueue_add_sgs` once per message
//! in a transfer (not once per whole transfer) before a single
//! `virtqueue_kick()` — so `process_chain` is called once per *message*,
//! which maps directly onto this codebase's existing per-descriptor-chain
//! `VirtioDeviceOps::process_chain` model with no special batching logic
//! needed.
//!
//! **`VIRTIO_I2C_FLAGS_FAIL_NEXT` (repeated-start grouping) is
//! deliberately not modeled as real bus arbitration.** The real flag lets
//! several messages in one transfer share a single START/STOP (a
//! repeated-start transaction — the standard "write register pointer,
//! then read its contents" idiom almost every real I2C sensor uses).
//! Since every message in such a group necessarily targets the same
//! `I2cTargetDevice` instance and hyperbug processes messages strictly in
//! the order the guest issued them, a stateful target sees exactly the
//! same *sequence* of `i2c_write`/`i2c_read` calls a repeated-start-aware
//! backend would deliver — it just doesn't need hyperbug to track START/
//! STOP boundaries explicitly to get that. `i2c.rs`'s own module doc
//! comment states this same simplification from the bus side.

use crate::i2c::I2cBus;
use crate::mem::GuestMemory;
use crate::virtio::{ChainOutcome, DescChain, VirtioDeviceOps};
use std::sync::{Arc, Mutex};

/// `VIRTIO_I2C_F_ZERO_LENGTH_REQUEST` (feature bit 0) — the real driver's
/// `virtio_i2c_probe` refuses to bind at all without it
/// (`dev_err_probe(..., "Zero-length request feature is mandatory\n")`),
/// since the driver's own `i2c_smbus_xfer`-shaped probing (`i2cdetect`)
/// relies on a zero-length write to test for a NAK/ACK with no data
/// buffer at all. Must always be offered.
const F_ZERO_LENGTH_REQUEST: u32 = 1 << 0;

/// Bit 0 of `virtio_i2c_out_hdr.flags`: groups this message with the next
/// one into one repeated-start transaction. See this module's own doc
/// comment for why hyperbug doesn't need to track this explicitly.
const FLAG_FAIL_NEXT: u32 = 1 << 0;
/// Bit 1: this message is a read (device -> host), not a write.
const FLAG_M_RD: u32 = 1 << 1;

const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;

/// `struct virtio_i2c_out_hdr` is 8 bytes: `addr` (u16 LE, the 7-bit
/// address shifted left by 1 — "only 7-bit mode supported", per the real
/// header), 2 bytes padding, `flags` (u32 LE).
const OUT_HDR_LEN: usize = 8;

pub struct VirtioI2c {
    bus: Arc<Mutex<I2cBus>>,
}

impl VirtioI2c {
    pub fn new(bus: Arc<Mutex<I2cBus>>) -> Self {
        Self { bus }
    }

}

impl VirtioDeviceOps for VirtioI2c {
    fn legacy_pci_device_id(&self) -> u16 {
        // Never actually used: no legacy virtio-i2c device exists in the
        // real PCI ID registry (virtio-i2c postdates the legacy transport
        // entirely), and `machine.rs` only ever wires this through
        // `VirtioModernPci`. See this module's own doc comment.
        0
    }

    fn virtio_device_type(&self) -> u16 {
        34 // VIRTIO_ID_I2C_ADAPTER, per this host's own <linux/virtio_ids.h>
    }

    fn pci_class_code(&self) -> u32 {
        // PCI class 0x0C (Serial Bus Controller), subclass 0x05 (SMBus) —
        // the closest real PCI classification to a generic I2C/SMBus
        // adapter; PCI has no dedicated "I2C" subclass of its own.
        0x0c_05_00
    }

    fn num_queues(&self) -> u16 {
        1 // "msg", per `virtio_i2c_setup_vqs`'s `virtio_find_single_vq`
    }

    fn queue_size(&self, _queue: u16) -> u16 {
        64
    }

    fn host_features(&self) -> u32 {
        F_ZERO_LENGTH_REQUEST
    }

    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        data.fill(0); // no device-specific config space defined for virtio-i2c
    }

    fn process_chain(&mut self, _queue: u16, mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome {
        // Real layout: out_hdr (device-readable) [, data (readable or
        // writable per FLAG_M_RD)] , in_hdr (device-writable, 1 byte
        // status) — 2 or 3 buffers total.
        if chain.buffers.len() != 2 && chain.buffers.len() != 3 {
            return ChainOutcome::Done(0); // malformed: wrong number of buffers
        }
        let hdr_buf = &chain.buffers[0];
        let status_buf = chain.buffers.last().unwrap();
        if hdr_buf.device_writable
            || hdr_buf.len as usize != OUT_HDR_LEN
            || !status_buf.device_writable
            || status_buf.len == 0
        {
            return ChainOutcome::Done(0); // malformed out_hdr/in_hdr
        }
        let mut hdr = [0u8; OUT_HDR_LEN];
        if !mem.read_checked(hdr_buf.addr, &mut hdr) {
            return ChainOutcome::Done(0);
        }
        let addr_field = u16::from_le_bytes([hdr[0], hdr[1]]);
        let flags = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let addr7 = (addr_field >> 1) as u8;
        let is_read = flags & FLAG_M_RD != 0;
        let _fail_next = flags & FLAG_FAIL_NEXT != 0; // see module doc comment

        let data_buf = if chain.buffers.len() == 3 { Some(&chain.buffers[1]) } else { None };

        let (status, written): (u8, u32) = match data_buf {
            None => {
                // Zero-length probe (mandatory per `F_ZERO_LENGTH_REQUEST`):
                // ACK iff a device answers this address, with no
                // `i2c_write`/`i2c_read` call at all — there's no data to
                // deliver either way.
                let ok = self.bus.lock().unwrap().get(addr7).is_some();
                (if ok { STATUS_OK } else { STATUS_ERR }, 0)
            }
            Some(buf) => match self.bus.lock().unwrap().get(addr7) {
                None => (STATUS_ERR, 0), // NAK: nothing at this address
                Some(target) => {
                    let mut target = target.lock().unwrap();
                    if is_read {
                        let want = buf.len as usize;
                        let bytes = target.i2c_read(want);
                        let n = bytes.len().min(want);
                        if n > 0 && !mem.write_checked(buf.addr, &bytes[..n]) {
                            (STATUS_ERR, 0)
                        } else {
                            (STATUS_OK, n as u32)
                        }
                    } else {
                        let mut data = vec![0u8; buf.len as usize];
                        if mem.read_checked(buf.addr, &mut data) {
                            let len = data.len() as u32;
                            target.i2c_write(&data);
                            (STATUS_OK, len)
                        } else {
                            (STATUS_ERR, 0)
                        }
                    }
                }
            },
        };

        mem.write_checked(status_buf.addr, &[status]);
        ChainOutcome::Done(1 + written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::DescBuffer;

    const MEM_SIZE: usize = 65536;
    const HDR_ADDR: u64 = 0x1000;
    const DATA_ADDR: u64 = 0x2000;
    const STATUS_ADDR: u64 = 0x3000;

    /// A stateful reference target mirroring the extremely common real
    /// I2C idiom: a write sets an internal register pointer (and,
    /// optionally, writes a byte there too); a read returns the byte at
    /// the current pointer and does *not* auto-advance it (matching a
    /// typical single-register-window sensor, not an auto-incrementing
    /// EEPROM — either is a valid real design, this test target picks one
    /// for determinism).
    struct RegisterTarget {
        registers: [u8; 4],
        pointer: usize,
    }

    impl crate::i2c::I2cTargetDevice for RegisterTarget {
        fn i2c_write(&mut self, data: &[u8]) {
            if data.is_empty() {
                return;
            }
            self.pointer = (data[0] as usize) % self.registers.len();
            if data.len() > 1 {
                self.registers[self.pointer] = data[1];
            }
        }
        fn i2c_read(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|i| self.registers[(self.pointer + i) % self.registers.len()]).collect()
        }
    }

    fn build_out_hdr(addr7: u8, flags: u32) -> [u8; OUT_HDR_LEN] {
        let mut hdr = [0u8; OUT_HDR_LEN];
        hdr[0..2].copy_from_slice(&((addr7 as u16) << 1).to_le_bytes());
        hdr[4..8].copy_from_slice(&flags.to_le_bytes());
        hdr
    }

    fn setup(target_addr: u8) -> (VirtioI2c, GuestMemory) {
        let mut bus = I2cBus::new();
        bus.register(target_addr, Arc::new(Mutex::new(RegisterTarget { registers: [0xAA, 0xBB, 0xCC, 0xDD], pointer: 0 })))
            .unwrap();
        (VirtioI2c::new(Arc::new(Mutex::new(bus))), GuestMemory::new(MEM_SIZE).unwrap())
    }

    #[test]
    fn a_write_then_read_message_pair_implements_the_register_pointer_idiom() {
        let (mut dev, mut mem) = setup(0x50);

        // Message 1: write [register=2] to set the pointer (a 1-byte
        // write — the real "select register" idiom).
        assert!(mem.write_checked(HDR_ADDR, &build_out_hdr(0x50, 0)));
        assert!(mem.write_checked(DATA_ADDR, &[2]));
        let write_chain = DescChain::for_test(vec![
            DescBuffer { addr: HDR_ADDR, len: OUT_HDR_LEN as u32, device_writable: false },
            DescBuffer { addr: DATA_ADDR, len: 1, device_writable: false },
            DescBuffer { addr: STATUS_ADDR, len: 1, device_writable: true },
        ]);
        let ChainOutcome::Done(_) = dev.process_chain(0, &mut mem, &write_chain) else {
            panic!("virtio-i2c never defers completion");
        };
        let mut status = [0u8; 1];
        mem.read_checked(STATUS_ADDR, &mut status);
        assert_eq!(status[0], STATUS_OK, "write to a real device must ACK");

        // Message 2: read 2 bytes back — should return registers[2..4].
        let read_chain = DescChain::for_test(vec![
            DescBuffer { addr: HDR_ADDR, len: OUT_HDR_LEN as u32, device_writable: false },
            DescBuffer { addr: DATA_ADDR, len: 2, device_writable: true },
            DescBuffer { addr: STATUS_ADDR, len: 1, device_writable: true },
        ]);
        assert!(mem.write_checked(HDR_ADDR, &build_out_hdr(0x50, FLAG_M_RD)));
        let ChainOutcome::Done(_) = dev.process_chain(0, &mut mem, &read_chain) else {
            panic!("virtio-i2c never defers completion");
        };
        mem.read_checked(STATUS_ADDR, &mut status);
        assert_eq!(status[0], STATUS_OK);
        let mut data = [0u8; 2];
        mem.read_checked(DATA_ADDR, &mut data);
        assert_eq!(data, [0xCC, 0xDD], "read must return the bytes at the pointer set by the prior write");
    }

    #[test]
    fn an_unoccupied_address_naks() {
        let (mut dev, mut mem) = setup(0x50);
        assert!(mem.write_checked(HDR_ADDR, &build_out_hdr(0x51, FLAG_M_RD)));
        let chain = DescChain::for_test(vec![
            DescBuffer { addr: HDR_ADDR, len: OUT_HDR_LEN as u32, device_writable: false },
            DescBuffer { addr: DATA_ADDR, len: 1, device_writable: true },
            DescBuffer { addr: STATUS_ADDR, len: 1, device_writable: true },
        ]);
        dev.process_chain(0, &mut mem, &chain);
        let mut status = [0u8; 1];
        mem.read_checked(STATUS_ADDR, &mut status);
        assert_eq!(status[0], STATUS_ERR, "no device at 0x51 must NAK");
    }

    #[test]
    fn a_zero_length_probe_acks_an_occupied_address_and_naks_an_empty_one() {
        let (mut dev, mut mem) = setup(0x50);
        let probe = |dev: &mut VirtioI2c, mem: &mut GuestMemory, addr7: u8| {
            assert!(mem.write_checked(HDR_ADDR, &build_out_hdr(addr7, 0)));
            let chain = DescChain::for_test(vec![
                DescBuffer { addr: HDR_ADDR, len: OUT_HDR_LEN as u32, device_writable: false },
                DescBuffer { addr: STATUS_ADDR, len: 1, device_writable: true },
            ]);
            dev.process_chain(0, mem, &chain);
            let mut status = [0u8; 1];
            mem.read_checked(STATUS_ADDR, &mut status);
            status[0]
        };
        assert_eq!(probe(&mut dev, &mut mem, 0x50), STATUS_OK, "a probe of an occupied address must ACK");
        assert_eq!(probe(&mut dev, &mut mem, 0x7f), STATUS_ERR, "a probe of an empty address must NAK");
    }

    #[test]
    fn host_features_advertises_the_mandatory_zero_length_request_bit() {
        let (dev, _mem) = setup(0x50);
        assert_eq!(
            dev.host_features() & F_ZERO_LENGTH_REQUEST,
            F_ZERO_LENGTH_REQUEST,
            "the real i2c-virtio driver refuses to probe without this feature bit"
        );
    }
}
