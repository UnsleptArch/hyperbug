//! virtio-net device logic (raw Ethernet frames in/out) plus the host TAP
//! interface it's backed by. All the PCI/register/virtqueue plumbing lives
//! in `virtio.rs`.
//!
//! Unlike virtio-blk, receiving is not guest-triggered: a packet can
//! arrive from the host TAP interface at any time, not just in response to
//! a `QueueNotify`. `VirtioLegacyPci::try_deliver_rx` (in `virtio.rs`) is
//! the hook for that — `reactor.rs` blocks on the TAP fd in `epoll` and
//! pushes whatever arrives into the RX queue.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};

use crate::mem::GuestMemory;
use crate::virtio::{ChainOutcome, DescChain, VirtioDeviceOps, copy_config};

const IFNAMSIZ: usize = 16;

#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: i16,
    _pad: [u8; 22], // matches the kernel's struct ifreq size (40 bytes on x86_64)
}

impl IfReq {
    /// `name` is truncated to `IFNAMSIZ - 1` bytes, leaving the NUL the
    /// kernel expects. Also used for the `"hyperbug%d"` template form,
    /// where the kernel fills in `%d` and writes the result back.
    fn new(name: &str, flags: i16) -> Self {
        let mut ifr = Self { name: [0; IFNAMSIZ], flags, _pad: [0; 22] };
        let bytes = name.as_bytes();
        let n = bytes.len().min(IFNAMSIZ - 1);
        ifr.name[..n].copy_from_slice(&bytes[..n]);
        ifr
    }

    fn name_string(&self) -> String {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
        String::from_utf8_lossy(&self.name[..len]).into_owned()
    }
}


// Neither is exposed by the libc crate for glibc-linux targets, but both
// are stable, well-known Linux ABI constants (<linux/sockios.h>).
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

pub struct TapDevice {
    file: File,
    pub name: String,
}

impl TapDevice {
    /// Creates (or attaches to) a TAP interface and brings its link up.
    /// Requires `CAP_NET_ADMIN` (or root). `name_hint` is a template like
    /// `"hyperbug%d"` — the kernel fills in `%d` with the next free number.
    pub fn create(name_hint: &str) -> io::Result<Self> {
        let tun = std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;

        let mut ifr = IfReq::new(name_hint, (libc::IFF_TAP | libc::IFF_NO_PI) as i16);
        // SAFETY: ifr is a valid, correctly-sized buffer for TUNSETIFF; the
        // kernel only reads/writes within it.
        if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, &mut ifr) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let name = ifr.name_string();

        // Non-blocking: the reactor waits on this fd with `epoll` and then
        // drains it, rather than ever blocking a read on it.
        // SAFETY: plain fd flag manipulation on a fd this function owns.
        unsafe {
            let flags = libc::fcntl(tun.as_raw_fd(), libc::F_GETFL, 0);
            if flags >= 0 {
                libc::fcntl(tun.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        Self::bring_up(&name)?;
        Ok(Self { file: tun, name })
    }

    fn bring_up(name: &str) -> io::Result<()> {
        // SIOCSIFFLAGS/SIOCGIFFLAGS operate on any socket, conventionally a
        // throwaway AF_INET one, regardless of the interface's own address
        // family.
        // SAFETY: a plain socket(2); the fd is closed on every path below.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = Self::set_up_flag(sock, name);
        // SAFETY: `sock` is this function's own fd and is not used again.
        unsafe { libc::close(sock) };
        result
    }

    fn set_up_flag(sock: RawFd, name: &str) -> io::Result<()> {
        let mut ifr = IfReq::new(name, 0);
        // SIOCSIFFLAGS *replaces* the flags, so read the current ones
        // first and OR in IFF_UP rather than clobbering whatever the
        // kernel already set (IFF_BROADCAST, IFF_MULTICAST, ...) on the
        // freshly-created interface.
        // SAFETY: ifr is a valid, correctly-sized buffer for both ioctls.
        if unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &mut ifr) } < 0 {
            return Err(io::Error::last_os_error());
        }
        ifr.flags |= libc::IFF_UP as i16;
        // SAFETY: as above.
        if unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &ifr) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Non-blocking: `None` if nothing is available right now. A zero-byte
    /// read is reported as "nothing" too — it means EOF, not a real
    /// zero-length Ethernet frame, and passing it through would have the
    /// RX path consume a guest buffer to deliver no packet.
    pub fn try_read(&mut self, buf: &mut [u8]) -> Option<usize> {
        match self.file.read(buf) {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
            Err(e) => {
                eprintln!("[hyperbug] tap read error: {e}");
                None
            }
        }
    }

    pub fn write_frame(&mut self, frame: &[u8]) {
        if let Err(e) = self.file.write_all(frame) {
            eprintln!("[hyperbug] tap write error: {e}");
        }
    }
}

impl AsRawFd for TapDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_S_LINK_UP: u16 = 1;

/// `struct virtio_net_hdr` with none of the offload features negotiated —
/// ignored padding at the front of every frame in both directions.
pub const VNET_HDR_LEN: usize = 10;

/// virtio-net's fixed queue convention: rx is always queue 0, tx queue 1.
pub const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

pub struct VirtioNet {
    mac: [u8; 6],
    tap: TapDevice,
    /// Reassembly buffer for one outgoing frame, reused across
    /// transmissions rather than allocated per packet.
    tx_frame: Vec<u8>,
}

impl VirtioNet {
    pub fn new(mac: [u8; 6], tap: TapDevice) -> Self {
        Self { mac, tap, tx_frame: Vec::new() }
    }

    pub fn tap_mut(&mut self) -> &mut TapDevice {
        &mut self.tap
    }
}

impl VirtioDeviceOps for VirtioNet {
    fn legacy_pci_device_id(&self) -> u16 {
        0x1000 // "Virtio network device", per /usr/share/hwdata/pci.ids
    }

    fn pci_class_code(&self) -> u32 {
        0x02_00_00 // network controller, ethernet
    }

    fn num_queues(&self) -> u16 {
        2 // rx, tx (no control vq — this isn't multiqueue)
    }

    fn queue_size(&self, _queue: u16) -> u16 {
        256
    }

    fn host_features(&self) -> u32 {
        VIRTIO_NET_F_MAC
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // struct virtio_net_config { mac[6]; status u16; ... }
        let mut c = [0u8; 8];
        c[..6].copy_from_slice(&self.mac);
        c[6..8].copy_from_slice(&VIRTIO_NET_S_LINK_UP.to_le_bytes());
        copy_config(&c, offset, data);
    }

    fn process_chain(&mut self, queue: u16, mem: &mut GuestMemory, chain: &DescChain) -> ChainOutcome {
        if queue != TX_QUEUE {
            // RX buffers are posted, not filled, on notify — delivery
            // happens from try_deliver_rx instead, driven by the TAP fd.
            return ChainOutcome::Done(0);
        }
        // A TX chain is one or more device-readable buffers forming one
        // Ethernet frame, preceded by a virtio_net_hdr which — for our
        // negotiated feature set (none of the offload flags) — is just
        // ignored padding, per spec.
        self.tx_frame.clear();
        for buf in &chain.buffers {
            let start = self.tx_frame.len();
            self.tx_frame.resize(start + buf.len as usize, 0);
            if !mem.read_checked(buf.addr, &mut self.tx_frame[start..]) {
                return ChainOutcome::Done(0);
            }
        }
        if self.tx_frame.len() > VNET_HDR_LEN {
            self.tap.write_frame(&self.tx_frame[VNET_HDR_LEN..]);
        }
        ChainOutcome::Done(0)
    }
}
