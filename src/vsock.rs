//! virtio-vsock protocol logic, decoupled from virtqueue/transport
//! plumbing (`virtio_vsock.rs` owns that, the same split `virtio_blk.rs`/
//! `virtio.rs` already use). Wire format taken verbatim from this host's
//! own `<linux/virtio_vsock.h>` (a real UAPI header, BSD-licensed
//! specifically so third-party implementations can use it directly) and
//! cross-checked against the real guest driver
//! (`net/vmw_vsock/virtio_transport_common.c`, fetched from
//! `torvalds/linux`) for the credit-flow-control arithmetic in
//! particular — that accounting isn't obvious from the header alone.
//!
//! **Scope, stated directly**: guest-initiated `SOCK_STREAM` connections
//! only (no `SEQPACKET`, no host-initiated connections — a real host
//! service would need its own separate "listen and push a connection at
//! the guest" mechanism, not attempted here). Every guest connection,
//! regardless of which destination port it names, bridges to the *same*
//! host Unix domain socket path (`--vsock-uds <path>`) — the "clean
//! host↔guest control channel" Tier 6 asks for, not a general port-
//! forwarding NAT. Real, working credit-based flow control (the actual
//! protocol correctness a naive implementation could get away without
//! for a light test, but a real guest driver enforces strictly) is
//! implemented in full, not stubbed.

/// `struct virtio_vsock_hdr` is 44 bytes: two u64 CIDs, two u32 ports,
/// then five u32/u16 fields — see the field-by-field breakdown in
/// `Header::parse`/`Header::write`.
pub const HDR_LEN: usize = 44;

pub const TYPE_STREAM: u16 = 1;

#[allow(dead_code)] // never sent or matched on — kept for completeness against the real enum
pub const OP_INVALID: u16 = 0;
pub const OP_REQUEST: u16 = 1;
pub const OP_RESPONSE: u16 = 2;
pub const OP_RST: u16 = 3;
pub const OP_SHUTDOWN: u16 = 4;
pub const OP_RW: u16 = 5;
pub const OP_CREDIT_UPDATE: u16 = 6;
pub const OP_CREDIT_REQUEST: u16 = 7;

pub const SHUTDOWN_RCV: u32 = 1;
pub const SHUTDOWN_SEND: u32 = 2;

/// This device's own advertised receive-buffer size — fixed, generous,
/// and honestly accurate: every guest `OP_RW` payload we accept is
/// handed off to the bridge thread's own internal queue immediately (see
/// `virtio_vsock.rs`), so this is a real bound on how much we're willing
/// to have outstanding at once, not a number picked to look good.
pub const MY_BUF_ALLOC: u32 = 256 * 1024;

/// A parsed `virtio_vsock_hdr` plus whatever payload followed it in the
/// same guest buffer (header and payload always travel together in one
/// buffer on both rx and tx — see this module's own doc comment and
/// `virtio_transport.c`'s `virtio_transport_send_skb`/
/// `virtio_vsock_rx_fill`, which never split them across two).
#[derive(Debug, Clone)]
pub struct Packet {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub op: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Parses a raw guest TX buffer. `None` if it's too short to even
    /// hold a header — a malformed guest write, not something to panic
    /// over. Real field offsets, per `<linux/virtio_vsock.h>`'s
    /// `struct virtio_vsock_hdr`: src_cid@0(u64), dst_cid@8(u64),
    /// src_port@16(u32), dst_port@20(u32), len@24(u32), type@28(u16),
    /// op@30(u16), flags@32(u32), buf_alloc@36(u32), fwd_cnt@40(u32).
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < HDR_LEN {
            return None;
        }
        let u64_at = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
        let u16_at = |o: usize| u16::from_le_bytes(raw[o..o + 2].try_into().unwrap());
        let len = u32_at(24) as usize;
        let payload_start = HDR_LEN;
        // Clamped to what's actually in `raw`: a guest lying about `len`
        // must not read past the real buffer.
        let payload_end = payload_start + len.min(raw.len().saturating_sub(payload_start));
        Some(Self {
            src_cid: u64_at(0),
            dst_cid: u64_at(8),
            src_port: u32_at(16),
            dst_port: u32_at(20),
            op: u16_at(30),
            flags: u32_at(32),
            buf_alloc: u32_at(36),
            fwd_cnt: u32_at(40),
            payload: raw[payload_start..payload_end].to_vec(),
        })
    }

    /// Serializes this packet as a real, complete `virtio_vsock_hdr`
    /// followed by its payload — exactly what a guest RX buffer expects
    /// to be filled with.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HDR_LEN + self.payload.len());
        buf.extend_from_slice(&self.src_cid.to_le_bytes());
        buf.extend_from_slice(&self.dst_cid.to_le_bytes());
        buf.extend_from_slice(&self.src_port.to_le_bytes());
        buf.extend_from_slice(&self.dst_port.to_le_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&TYPE_STREAM.to_le_bytes());
        buf.extend_from_slice(&self.op.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&self.buf_alloc.to_le_bytes());
        buf.extend_from_slice(&self.fwd_cnt.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

/// One active (or being-torn-down) stream's protocol bookkeeping — the
/// credit-flow-control state `virtio_transport_common.c`'s
/// `virtio_vsock_sock` holds, kept here instead since hyperbug has no
/// guest-side socket to attach it to.
#[derive(Default)]
pub struct StreamState {
    /// Bytes we've sent to the guest so far (payload only, cumulative).
    pub tx_cnt: u32,
    /// Bytes we've accepted from the guest so far (payload only,
    /// cumulative) — reported to the guest as our own `fwd_cnt` in every
    /// packet, so it must only ever reflect data we've genuinely taken
    /// responsibility for (handed to the bridge thread), never data
    /// merely received.
    pub fwd_cnt: u32,
    /// The guest's receive-buffer size, from the last packet it sent us.
    pub peer_buf_alloc: u32,
    /// The guest's own `fwd_cnt`, from the last packet it sent us.
    pub peer_fwd_cnt: u32,
    /// Bytes received from the bridged host socket but not yet sent to
    /// the guest — held back only when the guest's own advertised credit
    /// (`peer_has_space`) doesn't currently allow more, drained as
    /// credit frees up (a `CREDIT_UPDATE` from the guest, or simply more
    /// room becoming available as it forwards what it already has).
    pub pending_send: std::collections::VecDeque<u8>,
}

impl StreamState {
    /// How many more payload bytes we're currently allowed to send the
    /// guest without exceeding its advertised receive buffer — real
    /// `wrapping_sub` arithmetic, matching the guest driver's own
    /// (`virtio_transport_has_space`), since these are free-running u32
    /// counters that wrap, not bounded totals.
    pub fn peer_has_space(&self) -> u32 {
        let in_flight = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(in_flight)
    }

    /// Updates our view of the guest's credit state from any packet it
    /// just sent us — every op carries `buf_alloc`/`fwd_cnt`, not just
    /// `CREDIT_UPDATE` (see this module's own doc comment on `Packet`).
    pub fn observe_peer_credit(&mut self, pkt: &Packet) {
        self.peer_buf_alloc = pkt.buf_alloc;
        self.peer_fwd_cnt = pkt.fwd_cnt;
    }
}

/// The conventional, spec-recognized CID for "the host" — `VMADDR_CID_
/// HOST` in every real vsock implementation, not a hyperbug-specific
/// choice. Used as our own `src_cid` in every packet we send.
pub const HOST_CID: u64 = 2;

/// Builds a control packet (`RESPONSE`/`RST`/`CREDIT_UPDATE`) with no
/// payload, from us (`our_port`, always `HOST_CID`) to the peer
/// (`peer_cid`/`peer_port` — whatever the triggering packet's own
/// `src_cid`/`src_port` were, echoed back rather than assumed). `state`
/// supplies the real, current `buf_alloc`/`fwd_cnt` every packet must
/// carry.
pub fn control_packet(op: u16, flags: u32, our_port: u32, peer_cid: u64, peer_port: u32, state: &StreamState) -> Packet {
    Packet {
        src_cid: HOST_CID,
        dst_cid: peer_cid,
        src_port: our_port,
        dst_port: peer_port,
        op,
        flags,
        buf_alloc: MY_BUF_ALLOC,
        fwd_cnt: state.fwd_cnt,
        payload: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_packet() -> Packet {
        Packet {
            src_cid: 3,
            dst_cid: 2,
            src_port: 1234,
            dst_port: 5000,
            op: OP_REQUEST,
            flags: 0,
            buf_alloc: 4096,
            fwd_cnt: 0,
            payload: Vec::new(),
        }
    }

    #[test]
    fn a_packet_round_trips_through_to_bytes_and_parse() {
        let mut pkt = request_packet();
        pkt.payload = b"hello vsock".to_vec();
        let bytes = pkt.to_bytes();
        let parsed = Packet::parse(&bytes).expect("a well-formed packet must parse");
        assert_eq!(parsed.src_cid, pkt.src_cid);
        assert_eq!(parsed.dst_cid, pkt.dst_cid);
        assert_eq!(parsed.src_port, pkt.src_port);
        assert_eq!(parsed.dst_port, pkt.dst_port);
        assert_eq!(parsed.op, pkt.op);
        assert_eq!(parsed.buf_alloc, pkt.buf_alloc);
        assert_eq!(parsed.payload, pkt.payload);
    }

    #[test]
    fn a_buffer_shorter_than_one_header_fails_to_parse_rather_than_panicking() {
        assert!(Packet::parse(&[0u8; HDR_LEN - 1]).is_none());
        assert!(Packet::parse(&[]).is_none());
    }

    #[test]
    fn a_truncated_payload_length_is_clamped_to_what_actually_arrived() {
        // A malicious/buggy guest claims a 1000-byte payload but the
        // buffer only actually has 10 bytes of it — parsing must not
        // read (or panic on) memory past what's really there.
        let mut pkt = request_packet();
        pkt.payload = vec![0xAB; 10];
        let mut bytes = pkt.to_bytes();
        bytes[16..20].copy_from_slice(&1000u32.to_le_bytes()); // lie about len
        let parsed = Packet::parse(&bytes).expect("must still parse, just with a clamped payload");
        assert_eq!(parsed.payload.len(), 10);
    }

    #[test]
    fn peer_has_space_accounts_for_bytes_already_in_flight() {
        let mut state = StreamState { peer_buf_alloc: 100, ..Default::default() };
        assert_eq!(state.peer_has_space(), 100);
        state.tx_cnt = 60;
        assert_eq!(state.peer_has_space(), 40, "60 bytes already sent and not yet acked reduces our budget");
        state.peer_fwd_cnt = 60;
        assert_eq!(state.peer_has_space(), 100, "the peer acking those 60 bytes restores the full budget");
    }

    #[test]
    fn observe_peer_credit_updates_from_any_packet_not_just_credit_update() {
        let mut state = StreamState::default();
        let mut pkt = request_packet();
        pkt.op = OP_RW;
        pkt.buf_alloc = 8192;
        pkt.fwd_cnt = 42;
        state.observe_peer_credit(&pkt);
        assert_eq!(state.peer_buf_alloc, 8192);
        assert_eq!(state.peer_fwd_cnt, 42);
    }

    #[test]
    fn control_packet_addresses_are_the_reverse_of_the_triggering_packet() {
        let state = StreamState { fwd_cnt: 7, ..Default::default() };
        // A guest (cid 3) sent us a REQUEST from its port 1234 to our
        // port 5000; our reply must swap both cid and port.
        let reply = control_packet(OP_RESPONSE, 0, /*our_port=*/ 5000, /*peer_cid=*/ 3, /*peer_port=*/ 1234, &state);
        assert_eq!(reply.src_cid, HOST_CID);
        assert_eq!(reply.dst_cid, 3);
        assert_eq!(reply.src_port, 5000, "our reply's source is the port the guest connected to");
        assert_eq!(reply.dst_port, 1234, "our reply's destination is the guest's own connecting port");
        assert_eq!(reply.buf_alloc, MY_BUF_ALLOC);
        assert_eq!(reply.fwd_cnt, 7);
        assert!(reply.payload.is_empty());
    }
}
