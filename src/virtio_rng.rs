//! virtio-rng: the simplest virtio device there is. One queue; the guest
//! posts empty device-writable buffers, and each one gets filled with real
//! randomness from the host kernel (`getrandom(2)`, not a userspace PRNG).
//! Exists because a real systemd/journald boot can stall for a long time
//! waiting on `/dev/random` entropy with no hardware RNG present.

use std::sync::{Arc, Mutex};

use crate::mem::GuestMemory;
use crate::record::{EventKind, Recorder, Replayer};
use crate::virtio::{ChainOutcome, DescChain, VirtioDeviceOps};

/// Entropy is generated in chunks through one reusable buffer rather than
/// a per-request allocation sized by the guest. A guest that posts a very
/// large buffer still gets it filled — just in passes, without the device
/// ever holding more than this much host memory.
const CHUNK: usize = 4096;

#[derive(Default)]
pub struct VirtioRng {
    buf: Vec<u8>,
    /// `Some` only when `--record` was given. Unlike keyboard/TAP input
    /// (`reactor.rs`), an RNG request is synchronous from the guest's own
    /// point of view — there's no delivery *timing* to capture, only the
    /// data — but recording it matters just as much for a future replay:
    /// a real Linux guest derives real internal state (stack-protector
    /// canaries, ASLR slide values) from its first RNG reads, so handing
    /// a replayed guest *different* random bytes than the recording did
    /// would make it diverge almost immediately, independent of how
    /// exactly interrupt timing is replayed.
    recorder: Option<Arc<Recorder>>,
    /// `Some` only when `--replay` was given (mutually exclusive with
    /// `recorder` — hyperbug never records and replays the same run).
    /// Consulted instead of `getrandom(2)` — see `Replayer::next_rng_bytes`.
    replayer: Option<Arc<Mutex<Replayer>>>,
}

impl VirtioRng {
    pub fn new(recorder: Option<Arc<Recorder>>, replayer: Option<Arc<Mutex<Replayer>>>) -> Self {
        Self { recorder, replayer, ..Self::default() }
    }

    /// Produces up to `want` bytes: from the recording under `--replay`
    /// (falling back to real `getrandom` only once that's exhausted — see
    /// `Replayer::next_rng_bytes`'s own doc comment for why), or real
    /// `getrandom(2)` otherwise. `None` means no entropy is available
    /// right now (matches `getrandom`'s own "would block" case).
    fn fill_random(&mut self, want: usize) -> Option<Vec<u8>> {
        if let Some(replayer) = &self.replayer
            && let Some(bytes) = replayer.lock().unwrap().next_rng_bytes(want)
        {
            return Some(bytes);
        }
        // SAFETY: `self.buf` was already resized to at least `CHUNK` >=
        // `want` bytes by `process_chain` before calling this; getrandom
        // with flags=0 blocks only before the kernel CSPRNG is first
        // seeded, same as reading /dev/urandom.
        let got = unsafe { libc::getrandom(self.buf.as_mut_ptr().cast(), want, 0) };
        if got <= 0 {
            return None;
        }
        Some(self.buf[..got as usize].to_vec())
    }
}

impl VirtioDeviceOps for VirtioRng {
    fn legacy_pci_device_id(&self) -> u16 {
        0x1005 // "Virtio RNG", per /usr/share/hwdata/pci.ids
    }

    fn virtio_device_type(&self) -> u16 {
        4 // VIRTIO_ID_RNG, per <linux/virtio_ids.h>
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
                let Some(bytes) = self.fill_random(want) else {
                    return ChainOutcome::Done(written); // no entropy available; report what we did fill
                };
                if !mem.write_checked(addr, &bytes) {
                    return ChainOutcome::Done(written);
                }
                if let Some(recorder) = &self.recorder {
                    recorder.record(EventKind::RngBytes, &bytes);
                }
                written += bytes.len() as u32;
                addr += bytes.len() as u64;
                remaining -= bytes.len();
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
            let mut rng = VirtioRng::new(None, None);

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
            let mut rng = VirtioRng::new(None, None);
            let ChainOutcome::Done(written) = rng.process_chain(0, &mut mem, &chain) else {
                prop_assert!(false, "virtio-rng never defers completion");
                unreachable!();
            };
            prop_assert_eq!(written, len);
        }
    }

    /// A real `Recorder` (Milestone 2, `record.rs`), attached to this
    /// test's own thread rather than a live guest's vCPU (no KVM needed
    /// for this one — `process_chain` is called directly): confirms
    /// `VirtioRng` actually records the *real* random bytes it wrote to
    /// guest memory, not a placeholder, by comparing the recorded event's
    /// data against what a direct read-back of guest memory shows.
    #[test]
    fn a_recorder_captures_the_real_bytes_written_to_guest_memory() {
        let path = std::env::temp_dir().join(format!("hyperbug-rng-record-test-{}.bin", std::process::id()));
        let path_str = path.to_str().unwrap().to_string();
        let recorder = match crate::record::Recorder::start(&path_str, std::process::id() as libc::pid_t, MEM_SIZE) {
            Ok(r) => std::sync::Arc::new(r),
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };

        let mut mem = GuestMemory::new(MEM_SIZE as usize).unwrap();
        let addr = 0x100u64;
        let len = 32u32;
        let chain = DescChain::for_test(vec![DescBuffer { addr, len, device_writable: true }]);
        let mut rng = VirtioRng::new(Some(recorder), None);
        let ChainOutcome::Done(written) = rng.process_chain(0, &mut mem, &chain) else {
            panic!("virtio-rng never defers completion");
        };
        assert_eq!(written, len);

        let mut actual = vec![0u8; len as usize];
        mem.read_checked(addr, &mut actual);

        let (_, events) = crate::record::read_all(&path_str).unwrap();
        assert_eq!(events.len(), 1, "exactly one RngBytes event should have been recorded");
        assert_eq!(events[0].kind, crate::record::EventKind::RngBytes);
        assert_eq!(events[0].data, actual, "the recorded bytes must match what was actually written to guest memory");

        std::fs::remove_file(&path_str).unwrap();
    }
}
