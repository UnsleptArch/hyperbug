//! Live VM control (DEBTS.md item 20): a Unix domain socket the running
//! VM listens on, so a Python script — or anything else — can inspect and
//! poke a *live* guest while it runs (peek/poke memory, read and write
//! vCPU registers), the way IntelCommander's `gdbstub.py`/`Rehost` already
//! let you do for a Unicorn-based rehost. Before this, `hyperbug.VM` was
//! launch/wait/stop only.
//!
//! Deliberately built with **zero new threads**: `ControlServer::poll` is
//! called once per vCPU-loop iteration on the BSP thread, and only ever
//! touches `GuestMemory`/`VcpuFd` from the one thread that already owns
//! them. This is a direct lesson from the same session's item 9 attempt (a
//! background-thread timeout mechanism for Python plugins that segfaulted
//! under real concurrent load) — and it's also why the control socket is
//! the one host-facing fd `reactor.rs` deliberately does *not* take over:
//! a live vCPU's registers can only be touched from that vCPU's own
//! thread, for writes every bit as much as for reads.
//!
//! Wire protocol: plain newline-terminated ASCII text, one command per
//! line, hex-encoded addresses/data — no serde dependency needed for
//! something this simple, and it's directly usable with `socat`/`nc` for
//! manual poking without any client library at all.
//!
//! - `read_mem <hex_addr> <len>` -> `OK <hex_bytes>` or `ERR <message>`
//! - `write_mem <hex_addr> <hex_bytes>` -> `OK` or `ERR <message>`
//! - `regs` -> `OK rip=<hex> rsp=<hex> rax=<hex> ... ` (every `kvm_regs`
//!   field) or `ERR <message>`
//! - `write_regs <field>=<hex> [<field>=<hex> ...]` -> `OK` or `ERR
//!   <message>`. Symmetric with `regs`: same field names, same `field=hex`
//!   spelling, so a `regs` reply can be edited and handed straight back.
//!   Read-modify-write — naming one field leaves the other seventeen
//!   alone.
//! - `snapshot <path>` -> `OK` or `ERR <message>`. Serializes the whole
//!   machine (DEBTS.md item 8, `snapshot.rs`) to `path` — vCPU state via
//!   this same `vcpu`, guest memory, and every snapshotted device's
//!   protocol state. See `snapshot.rs`'s module doc comment for exactly
//!   what's covered and what isn't (single vCPU, no Python device plugin
//!   state).
//! - anything else -> `ERR unknown command`
//!
//! Up to `MAX_CLIENTS` connections at once, each with its own line buffer
//! and its own independent reads. This started out deliberately
//! single-client; going multi-client turned out to be a genuinely small
//! change rather than a rearchitecture, because command handling
//! (`handle_command`) has never carried any per-connection state — the
//! only thing a connection owns is the bytes it hasn't finished a line
//! with yet. Commands are still served strictly one at a time on the BSP
//! thread, so two clients can't observe a half-applied `write_regs`.

use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use kvm_bindings::kvm_regs;
use kvm_ioctls::{VcpuFd, VmFd};

use crate::mem::GuestMemory;
use crate::pci::PciBus;
use crate::serial::Serial;
use crate::snapshot::Snapshot;

/// Longest command line accepted. A client that never sends a newline
/// would otherwise grow its buffer without bound; nothing legitimate comes
/// close (a `write_mem` of 64 KiB hex is ~128 KiB).
const MAX_LINE: usize = 1 << 20;

/// Largest `read_mem` response served in one go — bounds the reply buffer
/// against a client asking for the whole guest's RAM as hex.
const MAX_READ_LEN: usize = 1 << 20;

/// How many control connections may be attached at once. Every attached
/// client costs a buffer and a slot in the once-per-vCPU-loop poll, so
/// this is capped rather than unbounded; nothing realistic wants more than
/// a couple (a debugger script and a human with `socat`, say).
const MAX_CLIENTS: usize = 8;

/// One attached control connection: a socket plus whatever bytes it has
/// sent that don't yet form a complete line.
struct Client {
    stream: UnixStream,
    buf: Vec<u8>,
}

impl Client {
    fn new(stream: UnixStream) -> Self {
        Self { stream, buf: Vec::new() }
    }

    /// Drains whatever this client has sent into its own line buffer.
    /// Returns false if the connection ended (or misbehaved), in which
    /// case the caller drops it.
    fn fill(&mut self) -> bool {
        let mut chunk = [0u8; 4096];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => return false,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return false,
            }
            if self.buf.len() > MAX_LINE {
                eprintln!("[hyperbug] control client sent an over-long line; dropping it");
                return false;
            }
        }
        true
    }

    /// Pops the next complete (newline-terminated) command line, if the
    /// buffer holds one.
    fn next_line(&mut self) -> Option<String> {
        let pos = self.buf.iter().position(|&b| b == b'\n')?;
        let line = String::from_utf8_lossy(&self.buf[..pos]).into_owned();
        self.buf.drain(..=pos);
        Some(line)
    }

    /// Returns false if the reply couldn't be delivered (client gone).
    fn send(&mut self, reply: &str) -> bool {
        self.stream.write_all(reply.as_bytes()).is_ok()
    }
}

pub struct ControlServer {
    listener: UnixListener,
    clients: Vec<Client>,
    path: String,
    /// Reused reply buffer, so answering a command doesn't allocate. Only
    /// one command is ever in flight (single-threaded), so one buffer
    /// serves every client.
    reply: String,
}

impl ControlServer {
    pub fn bind(path: &str) -> std::io::Result<Self> {
        // A stale socket file from a previous run (crashed, killed -9)
        // left behind would otherwise make bind() fail with "address in
        // use" even though nothing is actually listening — remove it
        // first, same convention as most Unix-socket-serving daemons.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            clients: Vec::new(),
            path: path.to_string(),
            reply: String::new(),
        })
    }

    /// Call once per vCPU-loop iteration. Accepts any new clients, reads
    /// whatever each has available, and answers every complete
    /// (newline-terminated) command line found so far.
    pub fn poll(&mut self, vm: &VmFd, mem: &Arc<Mutex<GuestMemory>>, vcpu: &mut VcpuFd, snap: SnapshotDeps) {
        self.accept();
        let mut i = 0;
        while i < self.clients.len() {
            if self.serve_client(i, vm, mem, vcpu, snap) {
                i += 1;
            } else {
                self.clients.swap_remove(i);
            }
        }
    }

    fn accept(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    if self.clients.len() >= MAX_CLIENTS {
                        // Accept-then-drop rather than leave it unaccepted:
                        // a connection sitting in the listen backlog looks
                        // "connected" to its client and then hangs forever,
                        // whereas an immediate close is a clear answer.
                        eprintln!(
                            "[hyperbug] control socket: refusing connection, \
                             {MAX_CLIENTS} clients already attached"
                        );
                        continue;
                    }
                    let _ = stream.set_nonblocking(true);
                    self.clients.push(Client::new(stream));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("[hyperbug] control socket accept failed: {e}");
                    break;
                }
            }
        }
    }

    /// Serves every complete line one client has sent. Returns false when
    /// that client should be dropped.
    fn serve_client(
        &mut self,
        idx: usize,
        vm: &VmFd,
        mem: &Arc<Mutex<GuestMemory>>,
        vcpu: &mut VcpuFd,
        snap: SnapshotDeps,
    ) -> bool {
        if !self.clients[idx].fill() {
            return false;
        }
        loop {
            let Some(line) = self.clients[idx].next_line() else {
                return true;
            };
            // Move the shared reply buffer out for the duration of the
            // command, so `self.clients` can be borrowed mutably at the
            // same time without giving up the buffer reuse.
            let mut reply = std::mem::take(&mut self.reply);
            reply.clear();
            handle_command(&line, vm, mem, vcpu, snap, &mut reply);
            reply.push('\n');
            let alive = self.clients[idx].send(&reply);
            self.reply = reply;
            if !alive {
                return false;
            }
        }
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        // Leaving the socket file behind makes the *next* run's bind()
        // depend on its own stale-file cleanup; tidy up when we can.
        let _ = std::fs::remove_file(&self.path);
    }
}

fn parse_addr(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

/// The device state a `snapshot <path>` command needs to read — bundled so
/// `poll`/`serve_client`/`handle_command` don't each need one parameter
/// per device kind. Plain `&'a` references, so trivially `Copy`.
#[derive(Clone, Copy)]
pub struct SnapshotDeps<'a> {
    pub serial: &'a Serial,
    pub pci_bus: &'a PciBus,
    pub virtio: &'a [Arc<Mutex<dyn Snapshot>>],
}

fn handle_command(
    line: &str,
    vm: &VmFd,
    mem: &Arc<Mutex<GuestMemory>>,
    vcpu: &mut VcpuFd,
    snap: SnapshotDeps,
    out: &mut String,
) {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("read_mem") => {
            let (Some(addr), Some(len)) = (parts.next(), parts.next()) else {
                out.push_str("ERR usage: read_mem <hex_addr> <len>");
                return;
            };
            let (Some(addr), Ok(len)) = (parse_addr(addr), len.parse::<usize>()) else {
                out.push_str("ERR bad address or length");
                return;
            };
            if len > MAX_READ_LEN {
                let _ = write!(out, "ERR read_mem length {len} exceeds the {MAX_READ_LEN}-byte limit");
                return;
            }
            let mut data = vec![0u8; len];
            if !mem.lock().unwrap().read_checked(addr, &mut data) {
                let _ = write!(out, "ERR read_mem({addr:#x}, {len}) is out of bounds");
                return;
            }
            out.push_str("OK ");
            write_hex(&data, out);
        }
        Some("write_mem") => {
            let (Some(addr), Some(hex)) = (parts.next(), parts.next()) else {
                out.push_str("ERR usage: write_mem <hex_addr> <hex_bytes>");
                return;
            };
            let Some(addr) = parse_addr(addr) else {
                out.push_str("ERR bad address");
                return;
            };
            let Some(data) = from_hex(hex) else {
                out.push_str("ERR bad hex data");
                return;
            };
            if !mem.lock().unwrap().write_checked(addr, &data) {
                let _ = write!(out, "ERR write_mem({addr:#x}, {} bytes) is out of bounds", data.len());
                return;
            }
            out.push_str("OK");
        }
        Some("regs") => match vcpu.get_regs() {
            Ok(r) => {
                let _ = write!(
                    out,
                    "OK rip={:#x} rsp={:#x} rbp={:#x} rflags={:#x} rax={:#x} rbx={:#x} \
                     rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x} r8={:#x} r9={:#x} r10={:#x} \
                     r11={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                    r.rip, r.rsp, r.rbp, r.rflags, r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi,
                    r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15,
                );
            }
            Err(e) => {
                let _ = write!(out, "ERR KVM_GET_REGS failed: {e}");
            }
        },
        Some("write_regs") => {
            // Read-modify-write against the vCPU's current state, so a
            // client that only wants to move `rip` doesn't have to restate
            // the other seventeen registers (and can't zero them by
            // omission).
            let mut regs = match vcpu.get_regs() {
                Ok(r) => r,
                Err(e) => {
                    let _ = write!(out, "ERR KVM_GET_REGS failed: {e}");
                    return;
                }
            };
            if let Err(msg) = apply_reg_assignments(&mut regs, parts) {
                let _ = write!(out, "ERR {msg}");
                return;
            }
            // KVM validates what it's handed — an `rflags` value with the
            // always-set bit 1 cleared, for instance, is rejected here
            // rather than silently wedging the guest.
            match vcpu.set_regs(&regs) {
                Ok(()) => out.push_str("OK"),
                Err(e) => {
                    let _ = write!(out, "ERR KVM_SET_REGS failed: {e}");
                }
            }
        }
        Some("snapshot") => {
            let Some(path) = parts.next() else {
                out.push_str("ERR usage: snapshot <path>");
                return;
            };
            match crate::snapshot::save_to_file(path, vm, mem, vcpu, snap.serial, snap.pci_bus, snap.virtio) {
                Ok(()) => out.push_str("OK"),
                Err(msg) => {
                    let _ = write!(out, "ERR {msg}");
                }
            }
        }
        _ => out.push_str("ERR unknown command"),
    }
}

/// Applies `field=hex` assignments onto a register snapshot. Split out
/// from `handle_command` specifically so it's testable without a live
/// `VcpuFd`, and therefore without `/dev/kvm`.
///
/// All-or-nothing from the caller's point of view: it mutates a
/// caller-owned copy, and `handle_command` only pushes that copy to KVM
/// once every assignment has parsed cleanly.
fn apply_reg_assignments<'a>(
    regs: &mut kvm_regs,
    assignments: impl Iterator<Item = &'a str>,
) -> Result<(), String> {
    let mut any = false;
    for item in assignments {
        let Some((name, value)) = item.split_once('=') else {
            return Err(format!("expected <field>=<hex>, got {item:?}"));
        };
        let Some(parsed) = parse_addr(value) else {
            return Err(format!("bad hex value {value:?} for register {name:?}"));
        };
        let Some(slot) = reg_field_mut(regs, name) else {
            return Err(format!("unknown register {name:?}"));
        };
        *slot = parsed;
        any = true;
    }
    if !any {
        return Err("usage: write_regs <field>=<hex> [<field>=<hex> ...]".to_string());
    }
    Ok(())
}

/// The `kvm_regs` field a wire-protocol name refers to. Exactly the set
/// the `regs` reply prints, so the two directions stay symmetric.
fn reg_field_mut<'r>(regs: &'r mut kvm_regs, name: &str) -> Option<&'r mut u64> {
    Some(match name {
        "rip" => &mut regs.rip,
        "rsp" => &mut regs.rsp,
        "rbp" => &mut regs.rbp,
        "rflags" => &mut regs.rflags,
        "rax" => &mut regs.rax,
        "rbx" => &mut regs.rbx,
        "rcx" => &mut regs.rcx,
        "rdx" => &mut regs.rdx,
        "rsi" => &mut regs.rsi,
        "rdi" => &mut regs.rdi,
        "r8" => &mut regs.r8,
        "r9" => &mut regs.r9,
        "r10" => &mut regs.r10,
        "r11" => &mut regs.r11,
        "r12" => &mut regs.r12,
        "r13" => &mut regs.r13,
        "r14" => &mut regs.r14,
        "r15" => &mut regs.r15,
        _ => return None,
    })
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Appends `data` as lowercase hex. One pass, no per-byte `format!`
/// allocation (a 1 MiB `read_mem` used to do two million of them).
fn write_hex(data: &[u8], out: &mut String) {
    out.reserve(data.len() * 2);
    for &b in data {
        out.push(HEX_DIGITS[usize::from(b >> 4)] as char);
        out.push(HEX_DIGITS[usize::from(b & 0xf)] as char);
    }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes lowercase/uppercase hex. Operates on **bytes**, not `str`
/// slices: the previous `&s[i..i + 2]` form panicked outright on any input
/// whose byte pair straddled a multi-byte UTF-8 character (`"aéa"` was
/// enough), which a control client could send at will.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    // `as_chunks` yields the whole pairs and whatever odd byte is left
    // over, so the odd-length rejection falls out of the same pass.
    let (pairs, leftover) = s.as_bytes().as_chunks::<2>();
    if !leftover.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| Some(hex_value(pair[0])? << 4 | hex_value(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let data: Vec<u8> = (0..=255u8).collect();
        let mut hex = String::new();
        write_hex(&data, &mut hex);
        assert_eq!(hex.len(), 512);
        assert_eq!(from_hex(&hex).unwrap(), data);
        assert_eq!(from_hex("DEADbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn from_hex_rejects_bad_input_instead_of_panicking() {
        assert_eq!(from_hex("abc"), None, "odd length");
        assert_eq!(from_hex("zz"), None, "non-hex digits");
        // The real bug: a byte pair straddling a multi-byte UTF-8
        // character used to panic inside `&s[i..i + 2]`.
        assert_eq!(from_hex("aéa"), None);
        assert_eq!(from_hex("é"), None);
        assert_eq!(from_hex("ée"), None);
    }

    #[test]
    fn parse_addr_accepts_both_prefixed_and_bare_hex() {
        assert_eq!(parse_addr("0x1000"), Some(0x1000));
        assert_eq!(parse_addr("1000"), Some(0x1000));
        assert_eq!(parse_addr("nope"), None);
    }

    #[test]
    fn write_regs_touches_only_the_named_fields() {
        let mut regs = kvm_regs { rip: 0x1111, rax: 0x2222, rsp: 0x3333, ..Default::default() };
        apply_reg_assignments(&mut regs, ["rip=0xdead", "rax=beef"].into_iter()).unwrap();
        assert_eq!(regs.rip, 0xdead, "0x-prefixed value");
        assert_eq!(regs.rax, 0xbeef, "bare hex value");
        assert_eq!(regs.rsp, 0x3333, "an unnamed register must be left alone");
    }

    #[test]
    fn write_regs_covers_every_field_the_regs_reply_prints() {
        // The two directions have to stay symmetric: a `regs` reply should
        // be editable and handed straight back to `write_regs`.
        let names = [
            "rip", "rsp", "rbp", "rflags", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
            "r10", "r11", "r12", "r13", "r14", "r15",
        ];
        let mut regs = kvm_regs::default();
        for (i, name) in names.iter().enumerate() {
            let value = (i as u64) + 1;
            let assignment = format!("{name}={value:x}");
            apply_reg_assignments(&mut regs, std::iter::once(assignment.as_str()))
                .unwrap_or_else(|e| panic!("{name} should be writable: {e}"));
        }
        assert_eq!(regs.rip, 1);
        assert_eq!(regs.r15, 18);
    }

    #[test]
    fn write_regs_rejects_bad_input() {
        let mut regs = kvm_regs::default();
        assert!(apply_reg_assignments(&mut regs, ["rip"].into_iter()).is_err(), "no '='");
        assert!(
            apply_reg_assignments(&mut regs, ["cr3=0"].into_iter()).is_err(),
            "cr3 lives in kvm_sregs, not kvm_regs"
        );
        assert!(apply_reg_assignments(&mut regs, ["rip=zzz"].into_iter()).is_err(), "not hex");
        assert!(apply_reg_assignments(&mut regs, std::iter::empty()).is_err(), "no assignments");
    }

    #[test]
    fn client_frames_lines_across_partial_writes_and_notices_eof() {
        let (mut peer, server_side) = UnixStream::pair().unwrap();
        server_side.set_nonblocking(true).unwrap();
        let mut client = Client::new(server_side);

        peer.write_all(b"regs\nread_").unwrap();
        assert!(client.fill());
        assert_eq!(client.next_line().as_deref(), Some("regs"));
        assert_eq!(client.next_line(), None, "a partial line isn't served yet");

        peer.write_all(b"mem 0 4\n").unwrap();
        assert!(client.fill());
        assert_eq!(client.next_line().as_deref(), Some("read_mem 0 4"));

        drop(peer);
        assert!(!client.fill(), "EOF must mark the client dead");
    }

    #[test]
    fn accepts_several_clients_and_caps_the_rest() {
        // Short path on purpose: a Unix socket path is bounded by SUN_LEN
        // (~108 bytes), which a deep `target/` scratch directory has
        // overrun before (see the README's note on it).
        let path = format!("/tmp/hyperbug-ctl-test-{}", std::process::id());
        let mut server = ControlServer::bind(&path).unwrap();

        let attached: Vec<UnixStream> = (0..MAX_CLIENTS + 2)
            .map(|_| UnixStream::connect(&path).expect("connect"))
            .collect();
        server.accept();
        assert_eq!(
            server.clients.len(),
            MAX_CLIENTS,
            "excess connections are refused, not silently queued"
        );

        // Each attached client keeps its own line buffer, so a partial
        // line from one doesn't corrupt another's.
        // `Write` is implemented for `&UnixStream`, so a shared reference
        // into the vec is enough to send on one.
        let (mut first, mut second) = (&attached[0], &attached[1]);
        first.write_all(b"re").unwrap();
        second.write_all(b"regs\n").unwrap();
        assert!(server.clients[0].fill());
        assert!(server.clients[1].fill());
        assert_eq!(server.clients[0].next_line(), None);
        assert_eq!(server.clients[1].next_line().as_deref(), Some("regs"));

        // A disconnect is noticed rather than leaving a dead slot behind.
        drop(attached);
        assert!(!server.clients[0].fill());
    }
}
