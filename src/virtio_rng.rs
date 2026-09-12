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
