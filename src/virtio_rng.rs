//! virtio-rng: the simplest virtio device there is. One queue; the guest
//! posts empty device-writable buffers, and each one gets filled with real
//! randomness from the host kernel (`getrandom(2)`, not a userspace PRNG).
//! Exists because a real systemd/journald boot can stall for a long time
//! waiting on `/dev/random` entropy with no hardware RNG present.

use crate::mem::GuestMemory;
use crate::virtio::{ChainOutcome, DescChain, VirtioDeviceOps};

/// Entropy is generated in chunks through one reusable buffer rather than
/// a per-request allocation sized by the guest. A guest that posts a very
/// large buffer still gets it filled — just in passes, without the device
/// ever holding more than this much host memory.
const CHUNK: usize = 4096;

#[derive(Default)]
pub struct VirtioRng {
    buf: Vec<u8>,
}

impl VirtioRng {
    pub fn new() -> Self {
        Self::default()
    }
}

impl VirtioDeviceOps for VirtioRng {
    fn legacy_pci_device_id(&self) -> u16 {
        0x1005 // "Virtio RNG", per /usr/share/hwdata/pci.ids
    }

    fn pci_class_code(&self) -> u32 {
        0xff_00_00 // unclassified device — no well-defined PCI class fits an RNG
    }

    fn num_queues(&self) -> u16 {
        1
    }

    fn queue_size(&self, _queue: u16) -> u16 {
        64
    }

    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        data.fill(0); // no device-specific config space
    }

    fn process_chain(&mut self, _queue: u16, mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome {
        self.buf.resize(CHUNK, 0);
        let mut written = 0u32;
        for b in &chain.buffers {
            if !b.device_writable {
                continue; // malformed request; rng buffers are always device-writable
            }
            let mut remaining = b.len as usize;
            let mut addr = b.addr;
            while remaining > 0 {
                let want = remaining.min(CHUNK);
                // SAFETY: `self.buf` is a valid, initialized buffer of at
                // least `want` bytes; getrandom with flags=0 blocks only
                // before the kernel CSPRNG is first seeded, same as
                // reading /dev/urandom.
                let got = unsafe { libc::getrandom(self.buf.as_mut_ptr().cast(), want, 0) };
                if got <= 0 {
                    return ChainOutcome::Done(written); // no entropy available; report what we did fill
                }
                let got = got as usize;
                if !mem.write_checked(addr, &self.buf[..got]) {
                    return ChainOutcome::Done(written);
                }
                written += got as u32;
                addr += got as u64;
                remaining -= got;
            }
        }
        ChainOutcome::Done(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::DescBuffer;
    use proptest::prelude::*;

    const MEM_SIZE: u64 = 4096;

    /// Feeds `process_chain` a deliberately adversarial chain — buffers
    /// with arbitrary addresses/lengths (including out-of-guest-RAM and
    /// zero-length ones) and an arbitrary `device_writable` flag, the same
    /// shape a malformed or hostile descriptor chain would have if it ever
    /// reached this far. In real use `try_pop` already guarantees every
    /// buffer lies within guest RAM before a device ever sees it, so this
    /// test is deliberately *not* relying on that guarantee — it checks
    /// `process_chain` itself degrades safely (no panic, no reported
    /// `written` count exceeding what could actually have been written)
    /// even if that upstream guarantee were somehow bypassed.
    fn arbitrary_buffer() -> impl Strategy<Value = DescBuffer> {
        (any::<u64>(), any::<u32>(), any::<bool>())
            .prop_map(|(addr, len, device_writable)| DescBuffer { addr, len, device_writable })
    }

    proptest! {
        #[test]
        fn process_chain_never_panics_on_an_adversarial_chain(
            buffers in proptest::collection::vec(arbitrary_buffer(), 0..8),
        ) {
            let mut mem = GuestMemory::new(MEM_SIZE as usize).unwrap();
            let chain = DescChain::for_test(buffers);
            let mut rng = VirtioRng::new();

            let ChainOutcome::Done(written) = rng.process_chain(0, &mut mem, &chain) else {
                prop_assert!(false, "virtio-rng never defers completion");
                unreachable!();
            };

            // Every byte reported written had to have gone through a
            // successful `write_checked` into a device-writable buffer —
            // which is itself bounds-checked — so `written` can never
            // exceed the total length of the device-writable buffers in
            // the chain, adversarial or not.
            let max_possible: u64 = chain
                .buffers
                .iter()
                .filter(|b| b.device_writable)
                .map(|b| u64::from(b.len))
                .sum();
            prop_assert!(u64::from(written) <= max_possible);
        }

        /// A chain built entirely from in-bounds, device-writable buffers
        /// (the realistic case `try_pop` actually produces) gets fully
        /// filled: `written` equals the total requested length.
        #[test]
        fn a_well_formed_chain_is_filled_completely(
            addr in 0u64..(MEM_SIZE - 256),
            len in 1u32..256,
        ) {
            let mut mem = GuestMemory::new(MEM_SIZE as usize).unwrap();
            let chain = DescChain::for_test(vec![DescBuffer { addr, len, device_writable: true }]);
            let mut rng = VirtioRng::new();
            let ChainOutcome::Done(written) = rng.process_chain(0, &mut mem, &chain) else {
                prop_assert!(false, "virtio-rng never defers completion");
                unreachable!();
            };
            prop_assert_eq!(written, len);
        }
    }
}
