//! A device plugin run in its own subprocess instead of in-process via
//! PyO3 — real OS-level isolation for a slow or buggy plugin. This is the
//! sandboxed transport for `ScriptedDevice` (`plugin.rs`); see that
//! module for everything shared with the in-process transport in
//! `pydevice.rs`.
//!
//! Two different in-process interruption mechanisms were already tried
//! and reverted before this: `PyErr_SetInterrupt` (ambiguous "main
//! thread" targeting, hung under real concurrent load) and
//! `PyThreadState_SetAsyncExc` (segfaulted). Neither failure mode is
//! possible here — a subprocess that stops responding to a `read`/`write`
//! within `timeout` gets `SIGKILL`ed, which cannot hang or corrupt this
//! process's own state, unlike an interpreter-internal interruption.
//!
//! The plugin-author-facing contract is unchanged: the same `Device`/
//! `PciDevice` base classes, the same `self.hyperbug.read_mem`/
//! `write_mem`/`raise_irq()`. `python/hyperbug/_sandbox_runner.py` is the
//! child-side half of this file and documents the wire protocol in full
//! in its own module docstring — the short version is `wire`'s frame
//! format below: a length-prefixed binary message, not hex-encoded text,
//! since a device with real payload volume (not just register-sized
//! traffic) would otherwise pay double for hex encoding and for parsing
//! it byte-pair by byte-pair. The child can nest a DMA/IRQ callback
//! *inside* handling a `read`/`write`, before replying to it.

use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::HyperbugError;
use crate::mem::GuestMemory;
use crate::pci::NUM_BARS;
use crate::plugin::{PluginIdentity, PluginTransport, ScriptedDevice};

/// How long a `read`/`write` round trip may take before the plugin is
/// considered faulted. Generous relative to any real register access
/// (which should be microseconds), but short enough that a genuinely
/// hung plugin doesn't visibly stall the guest for long.
const CALL_TIMEOUT: Duration = Duration::from_millis(200);
/// Plugin import + `__init__` can reasonably take longer than a single
/// register access (loading a large module, say).
const LOAD_TIMEOUT: Duration = Duration::from_secs(5);

/// The binary framed wire protocol shared with `_sandbox_runner.py` — see
/// that file's module docstring for the authoritative description of
/// every message and its payload layout. Every frame is `<u32 length,
/// little-endian><type byte><payload>`, where `length` counts the type
/// byte plus the payload.
mod wire {
    use std::io::{Read, Write};

    // Parent -> child requests.
    pub const MSG_IDENTITY: u8 = 1;
    pub const MSG_READ: u8 = 2;
    pub const MSG_WRITE: u8 = 3;
    pub const MSG_HAS_TICK: u8 = 4;
    pub const MSG_TICK: u8 = 5;
    pub const MSG_SHUTDOWN: u8 = 6;
    pub const MSG_HAS_RESET: u8 = 7;
    pub const MSG_RESET: u8 = 8;

    // Replies, either direction.
    pub const MSG_OK: u8 = 0x80;
    pub const MSG_OK_BYTES: u8 = 0x81;
    pub const MSG_OK_BOOL: u8 = 0x82;
    pub const MSG_OK_IDENTITY: u8 = 0x83;
    pub const MSG_ERR: u8 = 0xFF;

    // Child -> parent, nested callbacks.
    pub const MSG_CB_READ_MEM: u8 = 0x90;
    pub const MSG_CB_WRITE_MEM: u8 = 0x91;
    pub const MSG_CB_RAISE_IRQ: u8 = 0x92;

    /// A generous ceiling on a single frame's payload — comfortably above
    /// any real device register/DMA transfer this project's own devices
    /// perform, while refusing to let a compromised or malicious child
    /// process's length prefix drive an arbitrarily large host-side
    /// allocation. The child is untrusted by design (that's the entire
    /// reason the subprocess boundary exists); a length header is exactly
    /// as attacker-controlled as anything else it sends.
    const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;

    /// Writes one frame. `Err` means the pipe is gone (the child died) —
    /// the caller treats that the same as any other faulted-device path.
    pub fn write_frame<W: Write>(w: &mut W, msg_type: u8, payload: &[u8]) -> std::io::Result<()> {
        let len = (payload.len() + 1) as u32;
        w.write_all(&len.to_le_bytes())?;
        w.write_all(&[msg_type])?;
        w.write_all(payload)?;
        w.flush()
    }

    /// Reads one frame, or `None` on EOF, a malformed zero-length header,
    /// or a length past `MAX_FRAME_LEN` — all three are treated as "the
    /// child is gone/faulted," matching a dead pipe, rather than trying to
    /// honor an oversized length by allocating that much memory first.
    pub fn read_frame<R: Read>(r: &mut R) -> Option<(u8, Vec<u8>)> {
        let mut header = [0u8; 4];
        r.read_exact(&mut header).ok()?;
        let len = u32::from_le_bytes(header);
        if len == 0 || len > MAX_FRAME_LEN {
            return None;
        }
        let mut body = vec![0u8; len as usize];
        r.read_exact(&mut body).ok()?;
        Some((body[0], body[1..].to_vec()))
    }
}

impl PluginIdentity {
    /// Parses `OK_IDENTITY`'s payload (see `_sandbox_runner.py`'s
    /// `_identity_payload` and its own wire-protocol doc comment).
    /// Malformed input here means the runner script and this parser have
    /// drifted, not a guest-triggerable condition — falls back to an
    /// inert identity (every BAR absent) rather than failing the whole
    /// device load over one field.
    fn parse_sandboxed_reply(payload: &[u8]) -> Self {
        const HEADER_LEN: usize = 1 + 2 + 2 + 4 + NUM_BARS * 4 + 1 + 1 + 1;
        if payload.first() != Some(&1) || payload.len() < HEADER_LEN {
            return Self::default();
        }
        let vendor_id = u16::from_le_bytes(payload[1..3].try_into().unwrap());
        let device_id = u16::from_le_bytes(payload[3..5].try_into().unwrap());
        let class_code = u32::from_le_bytes(payload[5..9].try_into().unwrap());
        let mut bar_sizes = [0u32; NUM_BARS];
        for (i, slot) in bar_sizes.iter_mut().enumerate() {
            let off = 9 + i * 4;
            *slot = u32::from_le_bytes(payload[off..off + 4].try_into().unwrap());
        }
        let io_mask = payload[9 + NUM_BARS * 4];
        let mut bar_is_io = [false; NUM_BARS];
        for (i, flag) in bar_is_io.iter_mut().enumerate() {
            *flag = io_mask & (1 << i) != 0;
        }
        let interrupt_line = payload[9 + NUM_BARS * 4 + 1];
        let msi_capable = payload[9 + NUM_BARS * 4 + 2] != 0;
        Self { vendor_id, device_id, class_code, bar_sizes, bar_is_io, interrupt_line, msi_capable }
    }
}

/// The sandboxed half of `ScriptedDevice`: every `read`/`write`/`tick`
/// call is a real IPC round trip to a `python3` subprocess rather than a
/// direct function call — the only thing that distinguishes this from
/// `pydevice.rs`'s `InProcessTransport`.
struct SandboxedTransport {
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    replies: Receiver<(u8, Vec<u8>)>,
    /// Set once a `read`/`write` times out or the child dies; every
    /// access after that is a no-op (matching an unmapped device) rather
    /// than trying to talk to a process that's already been killed.
    faulted: Arc<AtomicBool>,
    /// Whether the plugin class defines `tick` at all, checked once at
    /// spawn via `HAS_TICK` — so a plugin that doesn't implement one never
    /// pays for a `TICK` round trip every vCPU-loop iteration.
    has_tick: bool,
    /// As `has_tick`, checked via `HAS_RESET` — see `Device::reset`'s doc
    /// comment for the real caller (the control socket's `reset_device`
    /// command; nothing in this codebase calls it automatically).
    has_reset: bool,
    /// Kept alive only so its `Drop` (best-effort cgroup removal) runs
    /// once this transport — and the process inside it — is actually
    /// gone; never read otherwise. `None` when no `mem=`/`cpu=` limits
    /// were requested, or cgroups v2 wasn't available to enforce them.
    _cgroup: Option<crate::cgroup::PluginCgroup>,
}

impl SandboxedTransport {
    /// `dma_range` optionally confines `self.hyperbug.read_mem`/
    /// `write_mem` to a sub-range of `guest_mem` — see
    /// `device::dma_range_allows`. `irq_pending` is the same `Arc` the
    /// caller will hand to `ScriptedDevice::new`: the reader thread
    /// spawned here sets it (via `CB_RAISE_IRQ`) from outside any
    /// `read`/`write`/`tick` call, and `ScriptedDevice::take_pending_irq`
    /// clears it — this struct itself never reads it back.
    fn spawn(
        path: &str,
        class_name: &str,
        want_pci: bool,
        guest_mem: Arc<Mutex<GuestMemory>>,
        dma_range: Option<(u64, u64)>,
        irq_pending: Arc<AtomicBool>,
        resource_limits: Option<crate::config::ResourceLimits>,
    ) -> Result<(Self, PluginIdentity), HyperbugError> {
        // Created (if requested and available) *before* spawning: the
        // child joins it from its own `pre_exec`, which needs the cgroup
        // to already exist.
        let cgroup = resource_limits.as_ref().and_then(crate::cgroup::PluginCgroup::create);

        let python_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/python");
        let mut command = Command::new("python3");
        command
            .args(["-m", "hyperbug._sandbox_runner", path, class_name])
            .env("PYTHONPATH", python_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // SAFETY: `pre_exec` runs in the freshly-forked child, before
        // `exec`, with exactly one thread alive — `install_subprocess_
        // filter` only issues a couple of syscalls (no allocation beyond
        // what already happened before `fork`, no locking), which is
        // exactly the kind of narrow, async-signal-safety-respecting work
        // `pre_exec`'s own safety contract requires. A filter-install
        // failure here aborts the exec with the returned `io::Error`
        // rather than silently running the plugin unconfined.
        unsafe {
            command.pre_exec(|| {
                crate::seccomp::install_subprocess_filter()
                    .map_err(std::io::Error::other)
            });
        }
        // A second, independent `pre_exec` hook (hooks run in the order
        // added): joins the cgroup created above, if any, by writing this
        // process's own pid — from inside the child itself, before exec,
        // so there is no window where the plugin runs even briefly
        // outside the requested limit. Unlike the seccomp hook above,
        // failure here is swallowed rather than propagated: a resource
        // ceiling is a best-effort convenience (see `cgroup.rs`'s module
        // doc comment), not a security boundary that must fail closed.
        if let Some(cg) = &cgroup {
            let procs_path = cg.procs_path();
            unsafe {
                command.pre_exec(move || {
                    let _ = std::fs::write(&procs_path, std::process::id().to_string());
                    Ok(())
                });
            }
        }
        let mut child = command
            .spawn()
            .map_err(|e| HyperbugError::Io(format!("spawning sandboxed device {path}: {e}")))?;

        let stdin = Arc::new(Mutex::new(child.stdin.take().expect("piped stdin")));
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = channel();
        spawn_reader(stdout, stdin.clone(), irq_pending, guest_mem, dma_range, tx);

        let mut transport = Self {
            child,
            stdin,
            _cgroup: cgroup,
            replies: rx,
            faulted: Arc::new(AtomicBool::new(false)),
            has_tick: false,
            has_reset: false,
        };

        match transport.replies.recv_timeout(LOAD_TIMEOUT) {
            Ok((wire::MSG_OK, _)) => {}
            Ok((wire::MSG_ERR, payload)) => {
                return Err(HyperbugError::Python(format!(
                    "loading sandboxed device {path} ({class_name}): {}",
                    String::from_utf8_lossy(&payload)
                )));
            }
            Ok((other, _)) => {
                return Err(HyperbugError::Python(format!(
                    "loading sandboxed device {path} ({class_name}): unexpected reply type {other:#x}"
                )));
            }
            Err(_) => {
                let _ = transport.child.kill();
                return Err(HyperbugError::Python(format!(
                    "sandboxed device {path} ({class_name}) didn't finish loading within {LOAD_TIMEOUT:?}"
                )));
            }
        }

        let mut identity = PluginIdentity::default();
        if want_pci {
            let (msg_type, payload) = transport.call(wire::MSG_IDENTITY, &[], LOAD_TIMEOUT).map_err(HyperbugError::Python)?;
            if msg_type == wire::MSG_OK_IDENTITY {
                identity = PluginIdentity::parse_sandboxed_reply(&payload);
            }
        }

        let (msg_type, payload) = transport.call(wire::MSG_HAS_TICK, &[], LOAD_TIMEOUT).map_err(HyperbugError::Python)?;
        transport.has_tick = msg_type == wire::MSG_OK_BOOL && payload.first() == Some(&1);

        let (msg_type, payload) = transport.call(wire::MSG_HAS_RESET, &[], LOAD_TIMEOUT).map_err(HyperbugError::Python)?;
        transport.has_reset = msg_type == wire::MSG_OK_BOOL && payload.first() == Some(&1);

        Ok((transport, identity))
    }

    /// Sends one request frame, waits up to `timeout` for the top-level
    /// reply frame. Faults the device (kills the child) on timeout or a
    /// dead pipe — this is the one place a genuinely stuck plugin gets
    /// dealt with.
    fn call(&mut self, msg_type: u8, payload: &[u8], timeout: Duration) -> Result<(u8, Vec<u8>), String> {
        if self.faulted.load(Ordering::Acquire) {
            return Err("device is faulted (a prior call timed out or crashed it)".to_string());
        }
        let write_failed = {
            let mut stdin = self.stdin.lock().unwrap();
            wire::write_frame(&mut *stdin, msg_type, payload).is_err()
        };
        if write_failed {
            self.fault();
            return Err("failed to write to sandboxed device's stdin".to_string());
        }
        match self.replies.recv_timeout(timeout) {
            Ok(reply) => Ok(reply),
            Err(RecvTimeoutError::Timeout) => {
                self.fault();
                Err(format!("sandboxed device didn't respond within {timeout:?}; killed"))
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.fault();
                Err("sandboxed device's process exited unexpectedly".to_string())
            }
        }
    }

    fn fault(&mut self) {
        if !self.faulted.swap(true, Ordering::AcqRel) {
            let _ = self.child.kill();
        }
    }
}

impl Drop for SandboxedTransport {
    fn drop(&mut self) {
        if !self.faulted.load(Ordering::Acquire) {
            let mut stdin = self.stdin.lock().unwrap();
            let _ = wire::write_frame(&mut *stdin, wire::MSG_SHUTDOWN, &[]);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl PluginTransport for SandboxedTransport {
    fn call_read(&mut self, offset: u64, data: &mut [u8]) -> Result<(), String> {
        let mut payload = Vec::with_capacity(12);
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
        let (msg_type, reply_payload) = self.call(wire::MSG_READ, &payload, CALL_TIMEOUT)?;
        match msg_type {
            wire::MSG_OK_BYTES => {
                if reply_payload.len() != data.len() {
                    return Err(format!(
                        "sandboxed device read() returned {} bytes, expected {}",
                        reply_payload.len(),
                        data.len()
                    ));
                }
                data.copy_from_slice(&reply_payload);
                Ok(())
            }
            wire::MSG_ERR => Err(String::from_utf8_lossy(&reply_payload).into_owned()),
            other => Err(format!("sandboxed device sent unexpected reply type {other:#x}")),
        }
    }

    fn call_write(&mut self, offset: u64, data: &[u8]) -> Result<bool, String> {
        let mut payload = Vec::with_capacity(8 + data.len());
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(data);
        let (msg_type, reply_payload) = self.call(wire::MSG_WRITE, &payload, CALL_TIMEOUT)?;
        match msg_type {
            wire::MSG_OK_BOOL => Ok(reply_payload.first().copied().unwrap_or(0) != 0),
            wire::MSG_ERR => Err(String::from_utf8_lossy(&reply_payload).into_owned()),
            other => Err(format!("sandboxed device sent unexpected reply type {other:#x}")),
        }
    }

    /// Sends `TICK`, but only if `HAS_TICK` reported the class actually
    /// implements one — otherwise a no-op, no round trip at all.
    fn call_tick(&mut self) -> Result<(), String> {
        if !self.has_tick {
            return Ok(());
        }
        let (msg_type, reply_payload) = self.call(wire::MSG_TICK, &[], CALL_TIMEOUT)?;
        match msg_type {
            wire::MSG_OK => Ok(()),
            wire::MSG_ERR => Err(String::from_utf8_lossy(&reply_payload).into_owned()),
            other => Err(format!("sandboxed device sent unexpected reply type {other:#x}")),
        }
    }

    fn has_tick(&self) -> bool {
        self.has_tick
    }

    /// Sends `RESET`, but only if `HAS_RESET` reported the class actually
    /// implements one — otherwise a no-op, no round trip at all. Never
    /// called by anything in this file automatically; see
    /// `Device::reset`'s doc comment for the real caller.
    fn call_reset(&mut self) -> Result<(), String> {
        if !self.has_reset {
            return Ok(());
        }
        let (msg_type, reply_payload) = self.call(wire::MSG_RESET, &[], CALL_TIMEOUT)?;
        match msg_type {
            wire::MSG_OK => Ok(()),
            wire::MSG_ERR => Err(String::from_utf8_lossy(&reply_payload).into_owned()),
            other => Err(format!("sandboxed device sent unexpected reply type {other:#x}")),
        }
    }

    fn has_reset(&self) -> bool {
        self.has_reset
    }
}

/// One background thread per sandboxed device, for its whole lifetime:
/// reads whatever the child sends and either services a nested DMA
/// callback immediately against `guest_mem` (replying on the same
/// `stdin` the main thread uses for top-level commands — safe without
/// further locking beyond `stdin`'s own `Mutex`, since by the wire
/// protocol a `CB_*` frame only ever arrives nested inside a top-level
/// `READ`/`WRITE` the main thread is currently blocked waiting on, except
/// `CB_RAISE_IRQ`, which needs no reply at all) or forwards a top-level
/// reply to the main thread's `call()`.
fn spawn_reader(
    stdout: std::process::ChildStdout,
    stdin: Arc<Mutex<ChildStdin>>,
    irq_pending: Arc<AtomicBool>,
    guest_mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    replies: Sender<(u8, Vec<u8>)>,
) {
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        loop {
            let Some((msg_type, payload)) = wire::read_frame(&mut reader) else { return };
            match msg_type {
                wire::MSG_CB_RAISE_IRQ => {
                    irq_pending.store(true, Ordering::Release);
                }
                wire::MSG_CB_READ_MEM => {
                    let (reply_type, reply_payload) = handle_read_mem(&payload, &guest_mem, dma_range);
                    let mut s = stdin.lock().unwrap();
                    let _ = wire::write_frame(&mut *s, reply_type, &reply_payload);
                }
                wire::MSG_CB_WRITE_MEM => {
                    let (reply_type, reply_payload) = handle_write_mem(&payload, &guest_mem, dma_range);
                    let mut s = stdin.lock().unwrap();
                    let _ = wire::write_frame(&mut *s, reply_type, &reply_payload);
                }
                _ => {
                    if replies.send((msg_type, payload)).is_err() {
                        return; // main thread gone
                    }
                }
            }
        }
    });
}

/// `<addr:u64><size:u32>` -> `(MSG_OK_BYTES, bytes)` or `(MSG_ERR, message)`.
fn handle_read_mem(payload: &[u8], guest_mem: &Arc<Mutex<GuestMemory>>, dma_range: Option<(u64, u64)>) -> (u8, Vec<u8>) {
    if payload.len() < 12 {
        return (wire::MSG_ERR, b"malformed CB_READ_MEM".to_vec());
    }
    let addr = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let size = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;
    if !crate::device::dma_range_allows(dma_range, addr, size as u64) {
        return (
            wire::MSG_ERR,
            format!("address {addr:#x}+{size:#x} is outside this device's declared DMA range").into_bytes(),
        );
    }
    // Bounds-check *before* allocating: `size` is a plugin-supplied u32
    // (up to ~4 GiB) that reaches here straight from the child's own
    // CB_READ_MEM request, unrelated to the wire frame's own length cap
    // (this whole request is only 12 bytes on the wire) — a hostile
    // plugin asking for a multi-gigabyte "read" must not get a
    // multi-gigabyte host allocation before this rejects it.
    let mem = guest_mem.lock().unwrap();
    if !mem.in_bounds(addr, size as u64) {
        return (wire::MSG_ERR, format!("address {addr:#x}+{size:#x} is outside guest memory").into_bytes());
    }
    let mut buf = vec![0u8; size];
    mem.read_checked(addr, &mut buf);
    (wire::MSG_OK_BYTES, buf)
}

/// `<addr:u64><data>` -> `(MSG_OK, [])` or `(MSG_ERR, message)`.
fn handle_write_mem(payload: &[u8], guest_mem: &Arc<Mutex<GuestMemory>>, dma_range: Option<(u64, u64)>) -> (u8, Vec<u8>) {
    if payload.len() < 8 {
        return (wire::MSG_ERR, b"malformed CB_WRITE_MEM".to_vec());
    }
    let addr = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let data = &payload[8..];
    if !crate::device::dma_range_allows(dma_range, addr, data.len() as u64) {
        return (
            wire::MSG_ERR,
            format!("address {addr:#x}+{:#x} is outside this device's declared DMA range", data.len()).into_bytes(),
        );
    }
    if guest_mem.lock().unwrap().write_checked(addr, data) {
        (wire::MSG_OK, Vec::new())
    } else {
        (wire::MSG_ERR, format!("address {addr:#x}+{:#x} is outside guest memory", data.len()).into_bytes())
    }
}

/// `dma_range` optionally confines `self.hyperbug.read_mem`/`write_mem`
/// to a sub-range of `guest_mem` — see `device::dma_range_allows`.
/// `resource_limits` optionally caps this specific plugin's memory/CPU
/// via a cgroup — see `cgroup.rs`; best-effort, never a load failure on
/// its own.
pub fn load(
    path: &str,
    class_name: &str,
    guest_mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    resource_limits: Option<crate::config::ResourceLimits>,
) -> Result<ScriptedDevice, HyperbugError> {
    spawn(path, class_name, false, guest_mem, dma_range, resource_limits)
}

pub fn load_pci(
    path: &str,
    class_name: &str,
    guest_mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    resource_limits: Option<crate::config::ResourceLimits>,
) -> Result<ScriptedDevice, HyperbugError> {
    spawn(path, class_name, true, guest_mem, dma_range, resource_limits)
}

fn spawn(
    path: &str,
    class_name: &str,
    want_pci: bool,
    guest_mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    resource_limits: Option<crate::config::ResourceLimits>,
) -> Result<ScriptedDevice, HyperbugError> {
    let irq_pending = Arc::new(AtomicBool::new(false));
    let (transport, identity) = SandboxedTransport::spawn(
        path,
        class_name,
        want_pci,
        guest_mem,
        dma_range,
        irq_pending.clone(),
        resource_limits,
    )?;
    Ok(ScriptedDevice::new(Box::new(transport), identity, irq_pending))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Device;

    fn require_python3() -> bool {
        Command::new("python3").arg("--version").output().is_ok()
    }

    fn write_plugin(dir: &std::path::Path, name: &str, source: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, source).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hyperbug-sandbox-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A well-formed frame within the size cap round-trips through
    /// `read_frame` exactly as written.
    #[test]
    fn read_frame_round_trips_a_well_formed_frame() {
        let mut buf = Vec::new();
        wire::write_frame(&mut buf, 0x42, b"hello").unwrap();
        let (msg_type, payload) = wire::read_frame(&mut buf.as_slice()).expect("a well-formed frame must parse");
        assert_eq!(msg_type, 0x42);
        assert_eq!(payload, b"hello");
    }

    /// A length prefix claiming more than `MAX_FRAME_LEN` is refused
    /// outright — `read_frame` returns `None` (the same as a dead pipe)
    /// instead of allocating a buffer sized from an untrusted child
    /// process's own claimed length.
    #[test]
    fn read_frame_refuses_a_length_past_the_cap_without_allocating_it() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_le_bytes()); // ~4 GiB claimed
        // No body needed: a real allocation attempt for a claimed length
        // this large would itself be the failure this test guards
        // against, so the cap must reject before ever trying to read it.
        let start = std::time::Instant::now();
        let result = wire::read_frame(&mut buf.as_slice());
        assert!(result.is_none(), "a length past MAX_FRAME_LEN must be refused, not honored");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// `handle_read_mem`/`handle_write_mem` are plain functions (no
    /// subprocess needed to exercise them directly) — checking the exact
    /// same confinement through the CB_READ_MEM/CB_WRITE_MEM wire-protocol
    /// handlers a real sandboxed plugin's `self.hyperbug.read_mem`/
    /// `write_mem` calls round-trip through.
    #[test]
    fn a_declared_dma_range_confines_the_cb_read_write_mem_handlers() {
        // 16 KiB, larger than the declared range, so an out-of-range
        // address used below is still real, in-bounds guest RAM — the
        // point is isolating the DMA-range check from the separate
        // out-of-guest-RAM check `dma_outside_guest_ram_...` already
        // covers.
        let mem = Arc::new(Mutex::new(GuestMemory::new(16384).unwrap()));
        let range = Some((0x1000u64, 0x1000u64)); // [0x1000, 0x2000)

        let mut read_payload = 0x1000u64.to_le_bytes().to_vec();
        read_payload.extend_from_slice(&0x10u32.to_le_bytes());
        let (msg_type, _) = handle_read_mem(&read_payload, &mem, range);
        assert_eq!(msg_type, wire::MSG_OK_BYTES, "the start of the declared range");

        let mut write_payload = 0x1ff0u64.to_le_bytes().to_vec();
        write_payload.extend_from_slice(&[0u8; 16]);
        let (msg_type, _) = handle_write_mem(&write_payload, &mem, range);
        assert_eq!(msg_type, wire::MSG_OK, "the end of the declared range");

        let mut read_payload = 0x0f00u64.to_le_bytes().to_vec();
        read_payload.extend_from_slice(&0x10u32.to_le_bytes());
        let (msg_type, err) = handle_read_mem(&read_payload, &mem, range);
        assert_eq!(msg_type, wire::MSG_ERR);
        assert!(
            String::from_utf8_lossy(&err).contains("DMA range"),
            "in guest RAM but outside the declared range must still be refused"
        );

        let mut write_payload = 0x1ff8u64.to_le_bytes().to_vec();
        write_payload.extend_from_slice(&[0u8; 16]);
        let (msg_type, err) = handle_write_mem(&write_payload, &mem, range);
        assert_eq!(msg_type, wire::MSG_ERR);
        assert!(
            String::from_utf8_lossy(&err).contains("DMA range"),
            "a write straddling past the declared range's end"
        );
    }

    /// A hostile plugin's `CB_READ_MEM` can claim any `size` up to
    /// `u32::MAX` in its 12-byte request — nothing about the wire
    /// frame's own length limits that value. `handle_read_mem` must
    /// reject an out-of-bounds request before allocating a host buffer
    /// sized from it, not after; this confirms the out-of-bounds error
    /// path completes quickly and without the process visibly ballooning
    /// its memory, for a size (a few GiB) that would be a real, painful
    /// allocation if attempted.
    #[test]
    fn a_huge_out_of_bounds_read_size_is_rejected_before_allocating() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut payload = 0u64.to_le_bytes().to_vec();
        payload.extend_from_slice(&0xF000_0000u32.to_le_bytes()); // ~3.75 GiB, well past guest RAM
        let start = std::time::Instant::now();
        let (msg_type, err) = handle_read_mem(&payload, &mem, None);
        assert_eq!(msg_type, wire::MSG_ERR);
        assert!(String::from_utf8_lossy(&err).contains("outside guest memory"));
        assert!(start.elapsed() < Duration::from_secs(1), "rejecting an oversized size must not allocate it first");
    }

    /// The actual point of this whole file: a plugin that hangs forever in
    /// `write()` must not stall the caller anywhere near that long. Neither
    /// of the two prior in-process interruption attempts tried before this
    /// file existed could make this guarantee (one hung under load, one
    /// segfaulted) — this is what a real subprocess boundary buys instead.
    #[test]
    fn a_hung_write_is_killed_instead_of_stalling_forever() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("hang");
        let path = write_plugin(
            &dir,
            "hang.py",
            "import time\n\
             class Hang:\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       time.sleep(60)\n\
            \x20       return False\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(&path, "Hang", mem, None, None).unwrap();

        let start = std::time::Instant::now();
        let wants_irq = device.write(0, &[1, 2, 3]);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "a hung plugin call should be killed within CALL_TIMEOUT, not actually waited out"
        );
        assert!(!wants_irq);

        // A faulted device answers like an unmapped one from here on,
        // without trying to talk to the now-dead process again.
        let mut buf = [0xffu8; 4];
        device.read(0, &mut buf);
        assert_eq!(buf, [0u8; 4], "a faulted device's read should be a zero-filled no-op");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The positive case: a real, well-behaved plugin doing genuine DMA
    /// (`read_mem`/`write_mem`) and a spontaneous `raise_irq()`, exactly
    /// the same worked example `pydevice.rs`'s in-process test drives —
    /// proving the whole subprocess round trip (spawn, IDENTITY handshake,
    /// READ/WRITE, nested CB_READ_MEM/CB_WRITE_MEM, CB_RAISE_IRQ) actually
    /// works end to end over the binary framed protocol, not just that a
    /// hung one gets killed.
    #[test]
    fn a_working_plugin_does_real_dma_and_raises_its_irq() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("dma");
        let path = write_plugin(
            &dir,
            "dma.py",
            "class Dma:\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       addr = int.from_bytes(data, 'little')\n\
            \x20       buf = bytearray(self.hyperbug.read_mem(addr, 4))\n\
            \x20       buf.reverse()\n\
            \x20       self.hyperbug.write_mem(addr, bytes(buf))\n\
            \x20       self.hyperbug.raise_irq()\n\
            \x20       return False\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let buffer_addr: u64 = 0x100;
        mem.lock().unwrap().write_checked(buffer_addr, &[1, 2, 3, 4]);

        let mut device = load(&path, "Dma", mem.clone(), None, None).unwrap();
        device.write(0, &buffer_addr.to_le_bytes()[..4]);

        let mut reversed = [0u8; 4];
        mem.lock().unwrap().read_checked(buffer_addr, &mut reversed);
        assert_eq!(reversed, [4, 3, 2, 1], "the plugin should have reversed the buffer via real DMA");

        // raise_irq() is asynchronous from the child's point of view (it
        // doesn't wait for an ack) — give the reader thread a moment to
        // have processed it.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !device.take_pending_irq() {
            assert!(std::time::Instant::now() < deadline, "raise_irq() should have set the pending flag");
            std::thread::sleep(Duration::from_millis(10));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A large-payload round trip — the actual point of moving off
    /// hex-encoded text: a real bulk transfer (well beyond register-sized
    /// traffic) through `read`/`write` and through DMA, confirming the
    /// binary framed protocol handles more than a few bytes per message
    /// without any length/boundary confusion.
    #[test]
    fn a_large_payload_round_trips_correctly_through_read_write_and_dma() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("bulk");
        let path = write_plugin(
            &dir,
            "bulk.py",
            "class Bulk:\n\
            \x20   def __init__(self):\n\
            \x20       self.buf = bytearray(65536)\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(self.buf[offset:offset + size])\n\
            \x20   def write(self, offset, data):\n\
            \x20       self.buf[offset:offset + len(data)] = data\n\
            \x20       return False\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(&path, "Bulk", mem, None, None).unwrap();

        let payload: Vec<u8> = (0..65536u32).map(|i| (i % 256) as u8).collect();
        device.write(0, &payload);
        let mut back = vec![0u8; payload.len()];
        device.read(0, &mut back);
        assert_eq!(back, payload, "a 64 KiB round trip must survive the framed protocol intact");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sandboxed equivalent of `pydevice::tests::
    /// tick_calls_the_plugins_tick_method_which_can_raise_its_own_irq` —
    /// same plugin logic, driven over the subprocess protocol's `HAS_TICK`/
    /// `TICK` commands instead of a direct PyO3 call.
    #[test]
    fn tick_round_trips_to_the_child_and_can_raise_its_own_irq() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("tick");
        let path = write_plugin(
            &dir,
            "ticker.py",
            "class Ticker:\n\
            \x20   def __init__(self):\n\
            \x20       self.count = 0\n\
            \x20   def read(self, offset, size):\n\
            \x20       return self.count.to_bytes(size, 'little')\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n\
            \x20   def tick(self):\n\
            \x20       self.count += 1\n\
            \x20       if self.count == 3:\n\
            \x20           self.hyperbug.raise_irq()\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(&path, "Ticker", mem, None, None).unwrap();

        for _ in 0..2 {
            device.tick();
            assert!(!device.take_pending_irq(), "should not raise before the third tick");
        }
        device.tick();
        assert!(device.take_pending_irq(), "the third tick should have raised the irq");

        let mut count = [0u8; 4];
        device.read(0, &mut count);
        assert_eq!(u32::from_le_bytes(count), 3, "tick() state should persist across calls");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sandboxed equivalent of `pydevice::tests::
    /// reset_calls_the_plugins_reset_method_when_it_defines_one` — driven
    /// over the subprocess protocol's `HAS_RESET`/`RESET` commands.
    #[test]
    fn reset_round_trips_to_the_child_and_restores_initial_state() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("reset");
        let path = write_plugin(
            &dir,
            "resettable.py",
            "class Resettable:\n\
            \x20   def __init__(self):\n\
            \x20       self.value = 1\n\
            \x20   def read(self, offset, size):\n\
            \x20       return self.value.to_bytes(size, 'little')\n\
            \x20   def write(self, offset, data):\n\
            \x20       self.value = int.from_bytes(data, 'little')\n\
            \x20       return False\n\
            \x20   def reset(self):\n\
            \x20       self.value = 1\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(&path, "Resettable", mem, None, None).unwrap();

        device.write(0, &42u32.to_le_bytes());
        let mut val = [0u8; 4];
        device.read(0, &mut val);
        assert_eq!(u32::from_le_bytes(val), 42, "sanity: the write took effect");

        device.reset();
        device.read(0, &mut val);
        assert_eq!(u32::from_le_bytes(val), 1, "reset() should have restored the initial value");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plugin with no `reset` method reports `HAS_RESET` as false at
    /// load, so `Device::reset()` never sends a `RESET` round trip.
    #[test]
    fn a_plugin_without_reset_reports_has_reset_false() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("noreset");
        let path = write_plugin(
            &dir,
            "noreset.py",
            "class NoReset:\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(&path, "NoReset", mem, None, None).unwrap();
        device.reset(); // must not hang or error

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plugin with no `tick` method reports `HAS_TICK` as false at load,
    /// so `Device::tick()` never sends a `TICK` round trip at all.
    #[test]
    fn a_plugin_without_tick_reports_has_tick_false() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("notick");
        let path = write_plugin(
            &dir,
            "notick.py",
            "class NoTick:\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(&path, "NoTick", mem, None, None).unwrap();
        device.tick(); // must not hang or error

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sandboxed equivalent of `pydevice::tests::
    /// a_mismatched_api_version_is_refused_at_load` — the version check
    /// lives in `_sandbox_runner.py`'s `_load_plugin`, so this exercises
    /// it through the real `LOAD_ERR` handshake path, not just unit-tests
    /// the Python function directly.
    #[test]
    fn a_mismatched_api_version_is_refused_at_load_in_the_sandbox_too() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("apiver");
        let path = write_plugin(
            &dir,
            "old.py",
            "class Old:\n\
            \x20   hyperbug_api_version = 999999\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match load(&path, "Old", mem, None, None) {
            Ok(_) => panic!("a mismatched hyperbug_api_version should refuse to load"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("hyperbug_api_version=999999"), "got: {msg}");
        assert!(msg.contains("needs a newer hyperbug"), "got: {msg}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sandboxed equivalent of `pydevice::tests::
    /// a_too_old_api_version_is_refused_at_load` — same "too old, not
    /// just mismatched" distinction, through the real `LOAD_ERR` handshake.
    #[test]
    fn a_too_old_api_version_is_refused_at_load_in_the_sandbox_too() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("apiver-old");
        let path = write_plugin(
            &dir,
            "ancient.py",
            "class Ancient:\n\
            \x20   hyperbug_api_version = 0\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        );
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match load(&path, "Ancient", mem, None, None) {
            Ok(_) => panic!("a too-old hyperbug_api_version should refuse to load"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("hyperbug_api_version=0"), "got: {msg}");
        assert!(msg.contains("needs updating"), "got: {msg}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plugin_that_fails_to_import_is_a_clean_error_not_a_hang() {
        if !require_python3() {
            eprintln!("skipping: python3 not found");
            return;
        }
        let dir = scratch_dir("badimport");
        let path = write_plugin(&dir, "bad.py", "import this_module_does_not_exist\n");
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match load(&path, "Whatever", mem, None, None) {
            Ok(_) => panic!("loading a plugin with a bad import should fail"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("this_module_does_not_exist"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
