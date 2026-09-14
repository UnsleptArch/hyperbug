//! The transport-agnostic core of a scripted device plugin: one `Device`/
//! `PciDevice` implementation shared by both the in-process (PyO3,
//! `pydevice.rs`) and sandboxed (subprocess, `pydevice_proc.rs`) loaders,
//! instead of each hand-rolling its own copy of the same `read`/`write`/
//! `tick`/PCI-identity plumbing against a different transport underneath.
//!
//! `pydevice.rs` and `pydevice_proc.rs` each implement `PluginTransport`
//! (the one thing that actually differs — a direct PyO3 call vs. a
//! subprocess IPC round trip) and hand a boxed instance to
//! `ScriptedDevice::new`. Everything above that — error-rate-limited
//! logging, the PCI config-space identity snapshot, the spontaneous-IRQ
//! flag — lives here exactly once.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::device::Device;
use crate::pci::{NUM_BARS, PciDevice};

/// A device plugin's PCI identity, snapshotted once at load time (see
/// `ScriptedDevice::new`'s doc comment for why: real hardware's
/// config-space identity is fixed, and re-reading a Python attribute or
/// re-parsing an `IDENTITY` reply on every config-space access would mean
/// a full round trip — a PyO3 call or a subprocess IPC exchange — for
/// every dword the guest touches while enumerating the bus). Default (all
/// zero, no BARs) for a plain `--device` MMIO plugin, which never has its
/// `PciDevice` methods called.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct PluginIdentity {
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u32,
    pub bar_sizes: [u32; NUM_BARS],
    pub bar_is_io: [bool; NUM_BARS],
    pub interrupt_line: u8,
    pub msi_capable: bool,
}

/// The one thing that genuinely differs between an in-process and a
/// sandboxed plugin: how a `read`/`write`/`tick` call actually reaches the
/// plugin's Python code. Everything else (`ScriptedDevice`) is identical
/// either way.
pub trait PluginTransport: Send {
    /// Fills `data` with exactly `data.len()` bytes read from `offset`, or
    /// returns an error describing what went wrong (a Python exception, a
    /// malformed reply, a dead subprocess, ...) — the caller logs it and
    /// leaves `data` zeroed, it never propagates further, since a
    /// misbehaving plugin shouldn't take down the whole guest.
    fn call_read(&mut self, offset: u64, data: &mut [u8]) -> Result<(), String>;
    /// Writes `data` to `offset`; `Ok(true)` requests the device's
    /// configured interrupt be raised synchronously.
    fn call_write(&mut self, offset: u64, data: &[u8]) -> Result<bool, String>;
    /// Calls the plugin's `tick()`, if `has_tick()` says it defined one.
    /// Never called otherwise.
    fn call_tick(&mut self) -> Result<(), String>;
    /// Whether the plugin class defines a `tick` method at all, checked
    /// once at load — so a plugin without one costs nothing per
    /// vCPU-loop iteration, not even a round trip to find out again.
    fn has_tick(&self) -> bool;
    /// Calls the plugin's `reset()`, if `has_reset()` says it defined
    /// one. Never called automatically by anything in this codebase —
    /// see `Device::reset`'s own doc comment for the real callers
    /// (the control socket's `reset_device` command, and nothing else
    /// today).
    fn call_reset(&mut self) -> Result<(), String>;
    /// Whether the plugin class defines a `reset` method at all, checked
    /// once at load, mirroring `has_tick`.
    fn has_reset(&self) -> bool;
}

/// Rate-limited logging for a systematically-buggy plugin: log the first
/// few occurrences of a given error in full, then fall back to a
/// periodic count, so a device being polled in a tight loop can't flood
/// stderr or measurably slow the VM down just by always failing.
fn rate_limited_log(count: &mut u64, msg: &str) {
    *count += 1;
    if *count <= 5 || count.is_multiple_of(1000) {
        crate::log_warn!("{msg} (occurrence #{count})");
    }
}

/// A device plugin, in-process or sandboxed — see the module doc comment.
/// Exceptions/IPC errors from the plugin are logged (rate-limited) and
/// treated as a no-op (a failed `read` returns zeroed bytes, a failed
/// `write` requests no interrupt), the same policy both transports used
/// to implement separately before this existed.
pub struct ScriptedDevice {
    transport: Box<dyn PluginTransport>,
    identity: PluginIdentity,
    irq_pending: Arc<AtomicBool>,
    read_error_count: u64,
    write_error_count: u64,
    tick_error_count: u64,
    reset_error_count: u64,
}

impl ScriptedDevice {
    /// `irq_pending` is taken rather than created internally because both
    /// transports need to hand a clone of it to something that can set it
    /// asynchronously from *outside* a `read`/`write`/`tick` call (PyO3's
    /// `HyperbugCtx::raise_irq`, or the sandboxed reader thread's
    /// `CB_RAISE_IRQ` handling) — `ScriptedDevice` itself never sets it,
    /// only clears it in `take_pending_irq`.
    pub fn new(transport: Box<dyn PluginTransport>, identity: PluginIdentity, irq_pending: Arc<AtomicBool>) -> Self {
        Self {
            transport,
            identity,
            irq_pending,
            read_error_count: 0,
            write_error_count: 0,
            tick_error_count: 0,
            reset_error_count: 0,
        }
    }

    /// This device's PCI identity, as snapshotted at load — `Default` (all
    /// zero) for a plain MMIO device. Exposed for `machine.rs`'s
    /// `reload_device` support: a hot-reloaded PCI plugin's *new* identity
    /// is compared against this before swapping anything in, since
    /// `PciBus` itself caches a device's identity once at `register()`
    /// time and has no mechanism to notice it changed later (see
    /// `docs/plugin-api.md`'s hot-reload section for why this is a real,
    /// enforced constraint rather than a soft suggestion).
    pub fn identity(&self) -> PluginIdentity {
        self.identity
    }

    /// Replaces this device's current plugin instance entirely with
    /// `fresh` (a newly-loaded `ScriptedDevice`) — the actual mechanism
    /// behind hot-reload (`machine::reload_plugin`). Takes `fresh`'s
    /// `irq_pending` too, not just its transport/identity: the fresh
    /// transport (for a sandboxed plugin, its reader thread handling
    /// `CB_RAISE_IRQ`) was wired up against *that* flag at load time, not
    /// this device's original one — keeping the old flag while taking the
    /// new transport would silently discard every spontaneous interrupt
    /// the reloaded plugin ever raises, since nothing would still be
    /// reading the flag it's actually setting. `take_pending_irq` reads
    /// whatever `self.irq_pending` currently is, so this swap is
    /// transparent to callers. The old transport is dropped here, which
    /// for a sandboxed plugin means its subprocess is killed and its
    /// cgroup (if any) is cleaned up, the same as if the device had
    /// simply been dropped outright. Error counters reset to give the
    /// freshly-loaded plugin a clean slate rather than counting against
    /// the previous instance's failure history.
    pub fn reload(&mut self, fresh: ScriptedDevice) {
        self.transport = fresh.transport;
        self.identity = fresh.identity;
        self.irq_pending = fresh.irq_pending;
        self.read_error_count = 0;
        self.write_error_count = 0;
        self.tick_error_count = 0;
        self.reset_error_count = 0;
    }
}

impl Device for ScriptedDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        if let Err(msg) = self.transport.call_read(offset, data) {
            rate_limited_log(&mut self.read_error_count, &msg);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        match self.transport.call_write(offset, data) {
            Ok(wants_irq) => wants_irq,
            Err(msg) => {
                rate_limited_log(&mut self.write_error_count, &msg);
                false
            }
        }
    }

    fn take_pending_irq(&self) -> bool {
        self.irq_pending.swap(false, Ordering::AcqRel)
    }

    fn tick(&mut self) {
        if !self.transport.has_tick() {
            return;
        }
        if let Err(msg) = self.transport.call_tick() {
            rate_limited_log(&mut self.tick_error_count, &msg);
        }
    }

    fn reset(&mut self) {
        if !self.transport.has_reset() {
            return;
        }
        if let Err(msg) = self.transport.call_reset() {
            rate_limited_log(&mut self.reset_error_count, &msg);
        }
    }
}

impl PciDevice for ScriptedDevice {
    fn vendor_id(&self) -> u16 {
        self.identity.vendor_id
    }
    fn device_id(&self) -> u16 {
        self.identity.device_id
    }
    fn class_code(&self) -> u32 {
        self.identity.class_code
    }
    fn bar_sizes(&self) -> [u32; NUM_BARS] {
        self.identity.bar_sizes
    }
    fn bar_is_io(&self, index: usize) -> bool {
        self.identity.bar_is_io.get(index).copied().unwrap_or(false)
    }
    fn interrupt_line(&self) -> u8 {
        self.identity.interrupt_line
    }
    fn msi_capable(&self) -> bool {
        self.identity.msi_capable
    }
}
