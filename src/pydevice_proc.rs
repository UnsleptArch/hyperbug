//! A device plugin run in its own subprocess instead of in-process via
//! PyO3 — real OS-level isolation for a slow or buggy plugin.
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
//! child-side half of this file and documents the wire protocol in full;
//! the short version is a plain-text, newline-terminated, hex-encoded
//! protocol (matching `control.rs`'s own convention) where the child can
//! nest a DMA/IRQ callback *inside* handling a `read`/`write` before
//! replying to it.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::device::Device;
use crate::error::HyperbugError;
use crate::mem::GuestMemory;
use crate::pci::{NUM_BARS, PciDevice};

/// How long a `read`/`write` round trip may take before the plugin is
/// considered faulted. Generous relative to any real register access
/// (which should be microseconds), but short enough that a genuinely
/// hung plugin doesn't visibly stall the guest for long.
const CALL_TIMEOUT: Duration = Duration::from_millis(200);
/// Plugin import + `__init__` can reasonably take longer than a single
/// register access (loading a large module, say).
const LOAD_TIMEOUT: Duration = Duration::from_secs(5);

fn rate_limited_log(count: &mut u64, msg: &str) {
    *count += 1;
    if *count <= 5 || count.is_multiple_of(1000) {
        eprintln!("[hyperbug] {msg} (occurrence #{count})");
    }
}

#[derive(Default, Clone, Copy)]
struct PciIdentity {
    vendor_id: u16,
    device_id: u16,
    class_code: u32,
    bar_sizes: [u32; NUM_BARS],
    bar_is_io: [bool; NUM_BARS],
    interrupt_line: u8,
    msi_capable: bool,
}

impl PciIdentity {
    /// Parses the `IDENTITY` reply's `key=value` pairs (see
    /// `_sandbox_runner.py`'s wire-protocol doc comment). Malformed input
    /// here means the runner script and this parser have drifted, not a
    /// guest-triggerable condition — falls back to an inert identity
    /// (every BAR absent) rather than failing the whole device load over
    /// one field.
    fn parse(fields: &str) -> Self {
        let mut id = Self::default();
        for field in fields.split(' ') {
            let Some((key, value)) = field.split_once('=') else { continue };
            match key {
                "vendor" => id.vendor_id = u16::from_str_radix(value, 16).unwrap_or(0),
                "device" => id.device_id = u16::from_str_radix(value, 16).unwrap_or(0),
                "class" => id.class_code = u32::from_str_radix(value, 16).unwrap_or(0),
                "irq" => id.interrupt_line = u8::from_str_radix(value, 16).unwrap_or(0),
                "msi" => id.msi_capable = value == "1",
                "bars" => {
                    for (i, v) in value.split(',').enumerate().take(NUM_BARS) {
                        id.bar_sizes[i] = u32::from_str_radix(v, 16).unwrap_or(0);
                    }
                }
                "io_bars" => {
                    for v in value.split(',') {
                        if let Ok(i) = v.parse::<usize>()
                            && i < NUM_BARS
                        {
                            id.bar_is_io[i] = true;
                        }
                    }
                }
                _ => {}
            }
        }
        id
    }
}

pub struct SandboxedPyDevice {
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    replies: Receiver<String>,
    irq_pending: Arc<AtomicBool>,
    /// Set once a `read`/`write` times out or the child dies; every
    /// access after that is a no-op (matching an unmapped device) rather
    /// than trying to talk to a process that's already been killed.
    faulted: Arc<AtomicBool>,
    identity: Option<PciIdentity>,
    /// Whether the plugin class defines `tick` at all, checked once at
    /// spawn via `HAS_TICK` — so a plugin that doesn't implement one never
    /// pays for a `TICK` round trip every vCPU-loop iteration.
    has_tick: bool,
    read_error_count: u64,
    write_error_count: u64,
    tick_error_count: u64,
}

impl SandboxedPyDevice {
    /// `dma_range` optionally confines `self.hyperbug.read_mem`/
    /// `write_mem` to a sub-range of `guest_mem` — see
    /// `device::dma_range_allows`.
    pub fn load(
        path: &str,
        class_name: &str,
        guest_mem: Arc<Mutex<GuestMemory>>,
        dma_range: Option<(u64, u64)>,
    ) -> Result<Self, HyperbugError> {
        Self::spawn(path, class_name, false, guest_mem, dma_range)
    }

    pub fn load_pci(
        path: &str,
        class_name: &str,
        guest_mem: Arc<Mutex<GuestMemory>>,
        dma_range: Option<(u64, u64)>,
    ) -> Result<Self, HyperbugError> {
        Self::spawn(path, class_name, true, guest_mem, dma_range)
    }

    fn spawn(
        path: &str,
        class_name: &str,
        want_pci: bool,
        guest_mem: Arc<Mutex<GuestMemory>>,
        dma_range: Option<(u64, u64)>,
    ) -> Result<Self, HyperbugError> {
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
        let mut child = command
            .spawn()
            .map_err(|e| HyperbugError::Io(format!("spawning sandboxed device {path}: {e}")))?;

        let stdin = Arc::new(Mutex::new(child.stdin.take().expect("piped stdin")));
        let stdout = child.stdout.take().expect("piped stdout");
        let irq_pending = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        spawn_reader(stdout, stdin.clone(), irq_pending.clone(), guest_mem, dma_range, tx);

        let mut device = Self {
            child,
            stdin,
            replies: rx,
            irq_pending,
            faulted: Arc::new(AtomicBool::new(false)),
            identity: None,
            has_tick: false,
            read_error_count: 0,
            write_error_count: 0,
            tick_error_count: 0,
        };

        match device.replies.recv_timeout(LOAD_TIMEOUT) {
            Ok(line) if line == "LOAD_OK" => {}
            Ok(line) => {
                return Err(HyperbugError::Python(format!(
                    "loading sandboxed device {path} ({class_name}): {line}"
                )));
            }
            Err(_) => {
                let _ = device.child.kill();
                return Err(HyperbugError::Python(format!(
                    "sandboxed device {path} ({class_name}) didn't finish loading within {LOAD_TIMEOUT:?}"
                )));
            }
        }

        if want_pci {
            let reply = device.call("IDENTITY", LOAD_TIMEOUT).map_err(HyperbugError::Python)?;
            // "NONE" (no prefix match) means the class has no PCI attributes.
            device.identity = reply.strip_prefix("OK ").map(PciIdentity::parse);
        }

        let reply = device.call("HAS_TICK", LOAD_TIMEOUT).map_err(HyperbugError::Python)?;
        device.has_tick = reply.trim() == "OK 1";

        Ok(device)
    }

    /// Sends `command`, waits up to `timeout` for the top-level reply.
    /// Faults the device (kills the child) on timeout or a dead pipe —
    /// this is the one place a genuinely stuck plugin gets dealt with.
    fn call(&mut self, command: &str, timeout: Duration) -> Result<String, String> {
        if self.faulted.load(Ordering::Acquire) {
            return Err("device is faulted (a prior call timed out or crashed it)".to_string());
        }
        let write_failed = {
            let mut stdin = self.stdin.lock().unwrap();
            writeln!(stdin, "{command}").is_err()
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

impl Drop for SandboxedPyDevice {
    fn drop(&mut self) {
        if !self.faulted.load(Ordering::Acquire) {
            let mut stdin = self.stdin.lock().unwrap();
            let _ = writeln!(stdin, "SHUTDOWN");
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One background thread per sandboxed device, for its whole lifetime:
/// reads whatever the child sends and either services a nested DMA
/// callback immediately against `guest_mem` (replying on the same
/// `stdin` the main thread uses for top-level commands — safe without
/// further locking beyond `stdin`'s own `Mutex`, since by the wire
/// protocol a `CB_*` message only ever arrives nested inside a top-level
/// `READ`/`WRITE` the main thread is currently blocked waiting on, except
/// `CB_RAISE_IRQ`, which needs no reply at all) or forwards a top-level
/// reply to the main thread's `call()`.
fn spawn_reader(
    stdout: std::process::ChildStdout,
    stdin: Arc<Mutex<ChildStdin>>,
    irq_pending: Arc<AtomicBool>,
    guest_mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    replies: Sender<String>,
) {
    std::thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        while let Some(Ok(line)) = lines.next() {
            if line == "CB_RAISE_IRQ" {
                irq_pending.store(true, Ordering::Release);
                continue;
            }
            if let Some(rest) = line.strip_prefix("CB_READ_MEM ") {
                let reply = handle_read_mem(rest, &guest_mem, dma_range);
                let mut s = stdin.lock().unwrap();
                let _ = writeln!(s, "{reply}");
                continue;
            }
            if let Some(rest) = line.strip_prefix("CB_WRITE_MEM ") {
                let reply = handle_write_mem(rest, &guest_mem, dma_range);
                let mut s = stdin.lock().unwrap();
                let _ = writeln!(s, "{reply}");
                continue;
            }
            if replies.send(line).is_err() {
                return; // main thread gone
            }
        }
    });
}

/// `<addr_hex> <size_hex>` -> `OK <hex_bytes>` or `ERR <message>`.
fn handle_read_mem(args: &str, guest_mem: &Arc<Mutex<GuestMemory>>, dma_range: Option<(u64, u64)>) -> String {
    let Some((addr, size)) = args.split_once(' ') else {
        return "ERR malformed CB_READ_MEM".to_string();
    };
    let (Ok(addr), Ok(size)) = (u64::from_str_radix(addr, 16), usize::from_str_radix(size, 16)) else {
        return "ERR malformed CB_READ_MEM arguments".to_string();
    };
    if !crate::device::dma_range_allows(dma_range, addr, size as u64) {
        return format!("ERR address {addr:#x}+{size:#x} is outside this device's declared DMA range");
    }
    let mut buf = vec![0u8; size];
    if guest_mem.lock().unwrap().read_checked(addr, &mut buf) {
        format!("OK {}", hex_encode(&buf))
    } else {
        format!("ERR address {addr:#x}+{size:#x} is outside guest memory")
    }
}

/// `<addr_hex> <hex_bytes>` -> `OK` or `ERR <message>`.
fn handle_write_mem(args: &str, guest_mem: &Arc<Mutex<GuestMemory>>, dma_range: Option<(u64, u64)>) -> String {
    let Some((addr, hex)) = args.split_once(' ') else {
        return "ERR malformed CB_WRITE_MEM".to_string();
    };
    let Ok(addr) = u64::from_str_radix(addr, 16) else {
        return "ERR malformed CB_WRITE_MEM address".to_string();
    };
    let Some(data) = hex_decode(hex) else {
        return "ERR malformed CB_WRITE_MEM payload".to_string();
    };
    if !crate::device::dma_range_allows(dma_range, addr, data.len() as u64) {
        return format!(
            "ERR address {addr:#x}+{:#x} is outside this device's declared DMA range",
            data.len()
        );
    }
    if guest_mem.lock().unwrap().write_checked(addr, &data) {
        "OK".to_string()
    } else {
        format!("ERR address {addr:#x}+{:#x} is outside guest memory", data.len())
    }
}

impl Device for SandboxedPyDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        match self.call(&format!("READ {offset:x} {:x}", data.len()), CALL_TIMEOUT) {
            Ok(reply) => match reply.strip_prefix("OK ") {
                Some(hex) => match hex_decode(hex) {
                    Some(bytes) if bytes.len() == data.len() => data.copy_from_slice(&bytes),
                    Some(bytes) => rate_limited_log(
                        &mut self.read_error_count,
                        &format!("sandboxed device read() returned {} bytes, expected {}", bytes.len(), data.len()),
                    ),
                    None => rate_limited_log(&mut self.read_error_count, "sandboxed device sent malformed hex"),
                },
                None => rate_limited_log(&mut self.read_error_count, &format!("sandboxed device: {reply}")),
            },
            Err(msg) => rate_limited_log(&mut self.read_error_count, &msg),
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        let command = format!("WRITE {offset:x} {}", hex_encode(data));
        match self.call(&command, CALL_TIMEOUT) {
            Ok(reply) => match reply.strip_prefix("OK ") {
                Some(flag) => flag.trim() == "1",
                None => {
                    rate_limited_log(&mut self.write_error_count, &format!("sandboxed device: {reply}"));
                    false
                }
            },
            Err(msg) => {
                rate_limited_log(&mut self.write_error_count, &msg);
                false
            }
        }
    }

    /// A pending `hyperbug.raise_irq()` call from the plugin's own process,
    /// mirroring `PyDevice::take_pending_irq`; clears the flag either way.
    fn take_pending_irq(&self) -> bool {
        self.irq_pending.swap(false, Ordering::AcqRel)
    }

    /// Sends `TICK`, but only if `HAS_TICK` reported the class actually
    /// implements one — otherwise a no-op, no round trip at all.
    fn tick(&mut self) {
        if !self.has_tick {
            return;
        }
        match self.call("TICK", CALL_TIMEOUT) {
            Ok(reply) if reply == "OK" => {}
            Ok(reply) => rate_limited_log(&mut self.tick_error_count, &format!("sandboxed device: {reply}")),
            Err(msg) => rate_limited_log(&mut self.tick_error_count, &msg),
        }
    }
}

impl PciDevice for SandboxedPyDevice {
    fn vendor_id(&self) -> u16 {
        self.identity.map(|i| i.vendor_id).unwrap_or(0)
    }
    fn device_id(&self) -> u16 {
        self.identity.map(|i| i.device_id).unwrap_or(0)
    }
    fn class_code(&self) -> u32 {
        self.identity.map(|i| i.class_code).unwrap_or(0)
    }
    fn bar_sizes(&self) -> [u32; NUM_BARS] {
        self.identity.map(|i| i.bar_sizes).unwrap_or_default()
    }
    fn bar_is_io(&self, index: usize) -> bool {
        self.identity.is_some_and(|i| i.bar_is_io[index])
    }
    fn interrupt_line(&self) -> u8 {
        self.identity.map(|i| i.interrupt_line).unwrap_or(0)
    }
    fn msi_capable(&self) -> bool {
        self.identity.is_some_and(|i| i.msi_capable)
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let (pairs, leftover) = s.as_bytes().as_chunks::<2>();
    if !leftover.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi as u8) << 4 | lo as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// `handle_read_mem`/`handle_write_mem` are plain functions (no
    /// subprocess needed to exercise them directly) — the sandboxed
    /// mirror of `pydevice::tests::a_declared_dma_range_confines_
    /// read_mem_and_write_mem`, checking the exact same confinement
    /// through the CB_READ_MEM/CB_WRITE_MEM wire-protocol handlers a real
    /// sandboxed plugin's `self.hyperbug.read_mem`/`write_mem` calls
    /// round-trip through.
    #[test]
    fn a_declared_dma_range_confines_the_cb_read_write_mem_handlers() {
        // 16 KiB, larger than the declared range, so an out-of-range
        // address used below is still real, in-bounds guest RAM — the
        // point is isolating the DMA-range check from the separate
        // out-of-guest-RAM check `dma_outside_guest_ram_...` already
        // covers.
        let mem = Arc::new(Mutex::new(GuestMemory::new(16384).unwrap()));
        let range = Some((0x1000u64, 0x1000u64)); // [0x1000, 0x2000)

        let ok = handle_read_mem("1000 10", &mem, range);
        assert!(ok.starts_with("OK "), "the start of the declared range: {ok}");

        let ok = handle_write_mem("1ff0 00112233445566778899aabbccddeeff", &mem, range);
        assert_eq!(ok, "OK", "the end of the declared range: {ok}");

        let err = handle_read_mem("f00 10", &mem, range);
        assert!(
            err.starts_with("ERR") && err.contains("DMA range"),
            "in guest RAM but outside the declared range must still be refused: {err}"
        );

        let err = handle_write_mem("1ff8 00112233445566778899aabbccddeeff", &mem, range);
        assert!(
            err.starts_with("ERR") && err.contains("DMA range"),
            "a write straddling past the declared range's end: {err}"
        );
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
        let mut device = SandboxedPyDevice::load(&path, "Hang", mem, None).unwrap();

        let start = std::time::Instant::now();
        let wants_irq = device.write(0, &[1, 2, 3]);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "a hung plugin call should be killed within CALL_TIMEOUT, not actually waited out"
        );
        assert!(!wants_irq);
        assert!(device.faulted.load(Ordering::Acquire), "the device should be marked faulted");

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
    /// works end to end, not just that a hung one gets killed.
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

        let mut device = SandboxedPyDevice::load(&path, "Dma", mem.clone(), None).unwrap();
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
        let mut device = SandboxedPyDevice::load(&path, "Ticker", mem, None).unwrap();
        assert!(device.has_tick);

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
        let mut device = SandboxedPyDevice::load(&path, "NoTick", mem, None).unwrap();
        assert!(!device.has_tick);
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
        let err = match SandboxedPyDevice::load(&path, "Old", mem, None) {
            Ok(_) => panic!("a mismatched hyperbug_api_version should refuse to load"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("hyperbug_api_version=999999"), "got: {msg}");

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
        let err = match SandboxedPyDevice::load(&path, "Whatever", mem, None) {
            Ok(_) => panic!("loading a plugin with a bad import should fail"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("this_module_does_not_exist"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
