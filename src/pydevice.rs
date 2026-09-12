//! Bridges a Python-scripted device into the Rust `Device` trait via PyO3.
//!
//! Contract for a device plugin file: define a class (any name, given to
//! `PyDevice::load`) with:
//!   - `__init__(self)`
//!   - `read(self, offset: int, size: int) -> bytes`   (len(result) == size)
//!   - `write(self, offset: int, data: bytes) -> bool | None` (a truthy
//!     return requests that the device's configured interrupt, if it has
//!     one — see `--pci-device` — be raised right now)
//!
//! Exceptions raised in either are logged to stderr and treated as a no-op
//! (reads return zeroes) rather than crashing the VMM — a misbehaving
//! device plugin shouldn't take down the whole guest.
//!
//! A device that also wants to sit behind a PCI BAR (rather than a fixed
//! MMIO address) additionally defines these attributes:
//!   - `vendor_id: int`, `device_id: int`
//!   - `class_code: int` (packed base/subclass/prog-if, as in the PCI spec)
//!   - `bar_sizes: list[int]` (up to 6 entries; BAR0 first, 0 = unimplemented)
//!   - `io_bars: list[int]` (optional; BAR indices that are I/O-space
//!     rather than memory-space — absent means all memory-space)
//!   - `interrupt_line: int` (optional), `msi_capable: bool` (optional)
//!
//! Those PCI attributes are read **once**, when the device is loaded
//! (`load_pci`), and cached on the Rust side — see `PyPciIdentity`. They
//! describe fixed config-space bytes on real hardware, and reading them
//! per access meant taking the GIL for every config-space dword the guest
//! touched while enumerating the bus.
//!
//! This is deliberately the *only* way hyperbug knows about any specific
//! PCI device identity — the core stays vendor-neutral; any real device's
//! identity (Intel, or anyone else's) lives entirely in the plugin file.

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::device::Device;
use crate::mem::GuestMemory;
use crate::pci::{NUM_BARS, PciDevice};

/// Given to every Python device instance as `self.hyperbug` (set right
/// after construction, so it isn't available inside `__init__` — a plugin
/// that needs it that early can just stash setup for a later `read`/
/// `write` call instead). This is what makes device scripting more than
/// "a register file with callbacks": a plugin can do real DMA against
/// guest RAM the same way a real device would (read a descriptor the
/// guest posted, write a response into guest-supplied buffers) and raise
/// its own interrupt spontaneously — a timer firing, an external event
/// arriving — not only synchronously from inside `write()`.
// Not `unsendable` (real multi-vCPU SMP means multiple OS threads can
// call into the same device plugin): `Arc<Mutex<...>>`/
// `Arc<AtomicBool>` are genuinely `Send`, so this can safely cross the
// per-vCPU threads that might call into the same device plugin — PyO3's
// GIL still serializes the actual Python execution regardless of which
// OS thread holds it, exactly as designed. This incidentally avoids a
// `RuntimeError: ... is unsendable, but is being dropped on another
// thread` that a prior `unsendable` version of this type hit in tests —
// that class of problem is specific to `unsendable` types, and this
// isn't one.
#[pyclass]
struct HyperbugCtx {
    mem: Arc<Mutex<GuestMemory>>,
    irq_pending: Arc<AtomicBool>,
    /// Host-side DMA confinement, from `--device`/`--pci-device`'s
    /// optional trailing `<dma_base>:<dma_size>` — see
    /// `device::dma_range_allows`'s doc comment. `None` (the default)
    /// means unrestricted, appropriate for a trusted first-party plugin.
    dma_range: Option<(u64, u64)>,
}

#[pymethods]
impl HyperbugCtx {
    /// Reads `size` bytes from guest physical address `addr`. Raises
    /// `OSError` if any part of the range falls outside guest RAM — a
    /// guest-supplied DMA address is untrusted input, unlike hyperbug's
    /// own boot-time addresses (see `mem.rs`'s `*_checked` helpers) — or
    /// outside this device's declared DMA range, if it has one.
    ///
    /// Fills the `bytes` object in place rather than staging through a
    /// `Vec` and copying: this is a device plugin's DMA hot path.
    fn read_mem(&self, py: Python<'_>, addr: u64, size: usize) -> PyResult<Py<PyBytes>> {
        if !crate::device::dma_range_allows(self.dma_range, addr, size as u64) {
            return Err(pyo3::exceptions::PyOSError::new_err(format!(
                "read_mem({addr:#x}, {size}) is outside this device's declared DMA range"
            )));
        }
        let mem = self.mem.lock().unwrap();
        if !mem.in_bounds(addr, size as u64) {
            return Err(pyo3::exceptions::PyOSError::new_err(format!(
                "read_mem({addr:#x}, {size}) is out of bounds"
            )));
        }
        let bytes = PyBytes::new_with(py, size, |dst| {
            mem.read_checked(addr, dst);
            Ok(())
        })?;
        Ok(bytes.unbind())
    }

    /// Writes `data` to guest physical address `addr`. Raises `OSError` on
    /// an out-of-bounds range or a range outside this device's declared
    /// DMA range, same reasoning as `read_mem`.
    fn write_mem(&self, addr: u64, data: &[u8]) -> PyResult<()> {
        if !crate::device::dma_range_allows(self.dma_range, addr, data.len() as u64) {
            return Err(pyo3::exceptions::PyOSError::new_err(format!(
                "write_mem({addr:#x}, {} bytes) is outside this device's declared DMA range",
                data.len()
            )));
        }
        if !self.mem.lock().unwrap().write_checked(addr, data) {
            return Err(pyo3::exceptions::PyOSError::new_err(format!(
                "write_mem({addr:#x}, {} bytes) is out of bounds",
                data.len()
            )));
        }
        Ok(())
    }

    /// Requests that this device's configured interrupt (PCI devices via
    /// `--pci-device` only, same as a truthy `write()` return) be raised
    /// as soon as hyperbug's vCPU loop next checks — i.e. spontaneously,
    /// not just synchronously from inside a register write.
    fn raise_irq(&self) {
        self.irq_pending.store(true, Ordering::Release);
    }
}

/// The PCI config-space identity of a `--pci-device` plugin, snapshotted
/// once at load (see the module doc comment). Default (all zero / no
/// BARs) for a plain `--device` MMIO plugin, whose PCI methods are never
/// called.
#[derive(Default)]
struct PyPciIdentity {
    vendor_id: u16,
    device_id: u16,
    class_code: u32,
    bar_sizes: [u32; NUM_BARS],
    bar_is_io: [bool; NUM_BARS],
    interrupt_line: u8,
    msi_capable: bool,
}

impl PyPciIdentity {
    fn snapshot(instance: &Bound<'_, PyAny>) -> Self {
        let required_u32 = |name: &str| -> u32 {
            match instance.getattr(name).and_then(|a| a.extract::<u32>()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[hyperbug] python PCI device missing/invalid `{name}`: {e}");
                    0
                }
            }
        };

        let mut bar_sizes = [0u32; NUM_BARS];
        match instance.getattr("bar_sizes").and_then(|a| a.extract::<Vec<u32>>()) {
            Ok(sizes) => {
                if sizes.len() > NUM_BARS {
                    eprintln!(
                        "[hyperbug] python PCI device's `bar_sizes` has {} entries, only \
                         {NUM_BARS} BARs exist; truncating",
                        sizes.len()
                    );
                }
                for (slot, size) in bar_sizes.iter_mut().zip(sizes) {
                    *slot = size;
                }
            }
            Err(e) => eprintln!("[hyperbug] python PCI device missing/invalid `bar_sizes`: {e}"),
        }

        // Optional; absent means "all memory-space", matching every
        // non-virtio device's real behavior.
        let mut bar_is_io = [false; NUM_BARS];
        if let Ok(attr) = instance.getattr("io_bars") {
            match attr.extract::<Vec<usize>>() {
                Ok(indices) => {
                    for i in indices {
                        match bar_is_io.get_mut(i) {
                            Some(flag) => *flag = true,
                            None => eprintln!("[hyperbug] python PCI device's `io_bars` names BAR {i}, which doesn't exist"),
                        }
                    }
                }
                Err(e) => eprintln!("[hyperbug] python PCI device's `io_bars` must be a list of ints: {e}"),
            }
        }

        Self {
            vendor_id: required_u32("vendor_id") as u16,
            device_id: required_u32("device_id") as u16,
            class_code: required_u32("class_code"),
            bar_sizes,
            bar_is_io,
            // Optional. Must be a legacy ISA IRQ (1-15) the guest's PIC
            // actually delivers; a `--pci-device` slot outside 4-11/16/17
            // has no matching `_PRT` entry in `acpi/dsdt.asl`, so it won't
            // route under ACPI without one being added there too.
            interrupt_line: instance
                .getattr("interrupt_line")
                .and_then(|a| a.extract::<u8>())
                .unwrap_or(0),
            // Optional; see `pci::PciDevice::msi_capable` for what opting
            // in means and when it's *not* useful.
            msi_capable: instance
                .getattr("msi_capable")
                .and_then(|a| a.extract::<bool>())
                .unwrap_or(false),
        }
    }
}

pub struct PyDevice {
    /// The plugin's bound `read`/`write` methods, resolved once at load.
    /// Every guest access to this device calls one of them, so looking the
    /// attribute up by name each time is pure per-MMIO-access overhead.
    /// (A bound method keeps the instance itself alive, so nothing else
    /// needs to hold it. A plugin that *rebinds* `self.read` after
    /// construction won't be picked up — devices declare their register
    /// handlers once, like real hardware.)
    read_fn: Py<PyAny>,
    write_fn: Py<PyAny>,
    /// The plugin's bound `tick` method, if it defined one — optional,
    /// unlike `read`/`write`: most devices only ever react to a guest
    /// access, so `None` here means `Device::tick` is a plain `Option`
    /// check and nothing else, not a GIL round trip. Called once per
    /// vCPU-loop iteration (see `vcpu::poll_host`) for logic that needs to
    /// run independent of any register access — e.g. a simulated timer, or
    /// an async transaction whose completion isn't driven by the guest
    /// touching a register at all.
    tick_fn: Option<Py<PyAny>>,
    pci: PyPciIdentity,
    irq_pending: Arc<AtomicBool>,
    read_error_count: u64,
    write_error_count: u64,
    tick_error_count: u64,
}

/// A systematically-buggy device (every call
/// raises) used to `eprintln!` unconditionally on every single guest
/// access — a driver polling that register in a tight loop could flood
/// stderr and measurably slow the VM. Logs the first few occurrences in
/// full, then falls back to a periodic count so the problem is still
/// visible without the flood. Doesn't address a plugin that hangs
/// outright rather than raising (an infinite loop or blocking call inside
/// a plugin still hangs its vCPU thread forever, unbounded, for this
/// in-process loader) — see `pydevice_proc.rs`'s sandboxed loader for the
/// real fix to that.
///
/// **A real per-call timeout was attempted and reverted — a verified
/// negative result, not just an untried idea, so a future session
/// doesn't repeat the same path.** First attempt used a watchdog thread
/// calling `PyErr_SetInterrupt()`; that targets whichever thread CPython
/// considers "the main thread" for signal purposes, which is ambiguous
/// once more than one thread ever touches the interpreter — it appeared
/// to work in isolated testing but **hung for over 60 seconds** when run
/// alongside the rest of this project's own test suite (caught by
/// actually running the full suite, not trusting the isolated pass).
/// Second attempt switched to `PyThreadState_SetAsyncExc`, which targets
/// a specific thread id directly rather than relying on "main thread"
/// semantics — this **segfaulted** the test binary under the same
/// concurrent load. Both attempts reverted. A future attempt should
/// likely look at a fundamentally different architecture (a subprocess
/// per device plugin, with a real OS-level kill as the timeout
/// mechanism, accepting IPC overhead) rather than another variant of
/// interpreter-internal interruption.
fn rate_limited_log(count: &mut u64, msg: &str) {
    *count += 1;
    if *count <= 5 || count.is_multiple_of(1000) {
        eprintln!("[hyperbug] {msg} (occurrence #{count})");
    }
}

/// Distinguishes `sys.modules` entries across multiple loaded device
/// instances (e.g. two devices loaded from files sharing a base name).
static NEXT_MODULE_ID: AtomicU64 = AtomicU64::new(0);

static ENSURE_PYTHONPATH: Once = Once::new();

/// Puts `python/` (the `hyperbug` package with `Device`/`PciDevice`/`VM`)
/// on `sys.path`, so a device plugin can `import hyperbug` without a
/// separate `pip install -e python/` step. Only meaningful for running
/// from a source checkout — a packaged/installed hyperbug would have
/// `hyperbug` on `sys.path` already via a normal pip install instead.
fn ensure_pythonpath(py: Python<'_>) {
    ENSURE_PYTHONPATH.call_once(|| {
        let python_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/python");
        if let Err(e) = (|| -> PyResult<()> {
            let sys_path = py.import("sys")?.getattr("path")?;
            sys_path.call_method1("insert", (0, python_dir))?;
            Ok(())
        })() {
            eprintln!("[hyperbug] couldn't add {python_dir} to sys.path: {e}");
        }
    });
}

/// A path or source file containing an interior NUL can't be handed to
/// CPython at all. Reported as a Python error rather than a panic: this is
/// reachable from a caller's `--device` argument, and `run()` is
/// embeddable (see `error.rs`).
fn to_cstring(what: &str, value: String) -> PyResult<CString> {
    CString::new(value)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{what} contains a NUL byte: {e}")))
}

/// Refuses to load a plugin that declares a `hyperbug_api_version` other
/// than what this build implements (`device::PLUGIN_API_VERSION`) — see
/// `python/hyperbug/device.py`'s `HYPERBUG_API_VERSION` for what the
/// number means and when it's bumped. A plugin with no such attribute at
/// all (duck-typed, not subclassing `Device`/`PciDevice` — explicitly
/// supported, see this module's doc comment) has nothing to check and
/// loads exactly as before this existed.
fn check_api_version(instance: &Bound<'_, PyAny>, path: &str) -> PyResult<()> {
    let Ok(attr) = instance.getattr("hyperbug_api_version") else { return Ok(()) };
    let declared: u32 = attr.extract()?;
    if declared != crate::device::PLUGIN_API_VERSION {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "{path} declares hyperbug_api_version={declared}, but this hyperbug build implements \
             version {} — the plugin may need updating for a breaking ABI change",
            crate::device::PLUGIN_API_VERSION
        )));
    }
    Ok(())
}

impl PyDevice {
    /// Loads the Python source at `path`, instantiates `class_name` with no
    /// arguments, and wraps it as a `Device`. `mem` backs the `read_mem`/
    /// `write_mem` DMA calls the instance gets via `self.hyperbug`;
    /// `dma_range` optionally confines those calls to a sub-range of it
    /// (`config::DeviceSpec`'s trailing `<dma_base>:<dma_size>` — see
    /// `device::dma_range_allows`).
    pub fn load(
        path: &str,
        class_name: &str,
        mem: Arc<Mutex<GuestMemory>>,
        dma_range: Option<(u64, u64)>,
    ) -> PyResult<Self> {
        Self::load_inner(path, class_name, mem, dma_range, false)
    }

    /// As `load`, but additionally snapshots the plugin's PCI config-space
    /// identity (`vendor_id`, `bar_sizes`, ...) — only `--pci-device`
    /// plugins declare those, so a plain MMIO device isn't warned about
    /// attributes it was never supposed to have.
    pub fn load_pci(
        path: &str,
        class_name: &str,
        mem: Arc<Mutex<GuestMemory>>,
        dma_range: Option<(u64, u64)>,
    ) -> PyResult<Self> {
        Self::load_inner(path, class_name, mem, dma_range, true)
    }

    fn load_inner(
        path: &str,
        class_name: &str,
        mem: Arc<Mutex<GuestMemory>>,
        dma_range: Option<(u64, u64)>,
        is_pci: bool,
    ) -> PyResult<Self> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("reading {path}: {e}")))?;
        let source = to_cstring("device source", source)?;
        let file_name = to_cstring("device path", path.to_string())?;
        let module_id = NEXT_MODULE_ID.fetch_add(1, Ordering::Relaxed);
        let module_name = to_cstring("module name", format!("hyperbug_device_{module_id}"))?;
        let irq_pending = Arc::new(AtomicBool::new(false));

        Python::attach(|py| {
            ensure_pythonpath(py);
            let module = PyModule::from_code(py, &source, &file_name, &module_name)?;
            let instance = module.getattr(class_name)?.call0()?;
            check_api_version(&instance, path)?;
            let ctx = HyperbugCtx { mem, irq_pending: irq_pending.clone(), dma_range };
            instance.setattr("hyperbug", Py::new(py, ctx)?)?;

            let pci = if is_pci { PyPciIdentity::snapshot(&instance) } else { PyPciIdentity::default() };
            // Optional: a plugin that doesn't define `tick` simply isn't
            // called back periodically, same as before this existed.
            let tick_fn = instance.getattr("tick").ok().map(|f| f.unbind());
            Ok(Self {
                read_fn: instance.getattr("read")?.unbind(),
                write_fn: instance.getattr("write")?.unbind(),
                tick_fn,
                pci,
                irq_pending,
                read_error_count: 0,
                write_error_count: 0,
                tick_error_count: 0,
            })
        })
    }
}

impl Device for PyDevice {
    /// A pending `hyperbug.raise_irq()` call from Python; clears the flag
    /// either way.
    #[inline]
    fn take_pending_irq(&self) -> bool {
        self.irq_pending.swap(false, Ordering::Acquire)
    }

    /// Calls the plugin's `tick()`, if it defined one. A no-op (no GIL
    /// attach at all) otherwise.
    fn tick(&mut self) {
        let Some(tick_fn) = &self.tick_fn else { return };
        let error = Python::attach(|py| match tick_fn.bind(py).call0() {
            Ok(_) => None,
            Err(e) => Some(format!("python device tick() raised: {e}")),
        });
        if let Some(msg) = error {
            rate_limited_log(&mut self.tick_error_count, &msg);
        }
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        data.fill(0);
        let error = Python::attach(|py| match self.read_fn.bind(py).call1((offset, data.len())) {
            Ok(val) => match val.cast::<PyBytes>() {
                Ok(bytes) => {
                    let b = bytes.as_bytes();
                    let n = b.len().min(data.len());
                    data[..n].copy_from_slice(&b[..n]);
                    (b.len() != data.len()).then(|| {
                        format!(
                            "python device read() returned {} bytes, expected {}",
                            b.len(),
                            data.len()
                        )
                    })
                }
                Err(_) => Some("python device read() must return bytes".to_string()),
            },
            Err(e) => Some(format!("python device read() raised: {e}")),
        });
        if let Some(msg) = error {
            rate_limited_log(&mut self.read_error_count, &msg);
        }
    }

    /// A truthy return from Python's `write()` requests that the device's
    /// configured interrupt (if any — see `Bus::register`) be raised.
    fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        let result = Python::attach(|py| {
            let bytes = PyBytes::new(py, data);
            match self.write_fn.bind(py).call1((offset, bytes)) {
                Ok(result) => Ok(result.is_truthy().unwrap_or(false)),
                Err(e) => Err(format!("python device write() raised: {e}")),
            }
        });
        match result {
            Ok(wants_irq) => wants_irq,
            Err(msg) => {
                rate_limited_log(&mut self.write_error_count, &msg);
                false
            }
        }
    }
}

// Only meaningful for a device registered on the PciBus via `load_pci`
// (see `PciDeviceSpec` in config.rs); a plain MMIO-only device reports the
// all-zero default and never has these consulted.
impl PciDevice for PyDevice {
    fn vendor_id(&self) -> u16 {
        self.pci.vendor_id
    }

    fn device_id(&self) -> u16 {
        self.pci.device_id
    }

    fn class_code(&self) -> u32 {
        self.pci.class_code
    }

    fn bar_sizes(&self) -> [u32; NUM_BARS] {
        self.pci.bar_sizes
    }

    fn bar_is_io(&self, index: usize) -> bool {
        self.pci.bar_is_io.get(index).copied().unwrap_or(false)
    }

    fn interrupt_line(&self) -> u8 {
        self.pci.interrupt_line
    }

    fn msi_capable(&self) -> bool {
        self.pci.msi_capable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_path() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/devices/dma_demo.py")
    }

    fn doorbell_demo_path() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/devices/doorbell_demo.py")
    }

    /// Exercises `devices/doorbell_demo.py` — the reference doorbell +
    /// ring-buffer device added alongside `tick()` to
    /// prove out the register pattern a real bridged async transport
    /// needs (submit, then a completion arriving on its own schedule via
    /// `raise_irq()`, not synchronously inside the triggering `write()`)
    /// before any such device gets written for real.
    #[test]
    fn doorbell_demo_completes_requests_asynchronously_in_order() {
        const STATUS: u64 = 0x04;
        const RESULT: u64 = 0x08;
        const DOORBELL: u64 = 0x00;

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = PyDevice::load_pci(doorbell_demo_path(), "DoorbellDemoDevice", mem, None)
            .expect("doorbell_demo.py should load");

        let mut status = [0u8; 4];
        Device::read(&mut device, STATUS, &mut status);
        assert_eq!(u32::from_le_bytes(status), 0, "nothing submitted yet");

        // Ring the doorbell twice, back to back — two requests in flight
        // at once, like a real circular buffer.
        Device::write(&mut device, DOORBELL, &0x1111_2222u32.to_le_bytes());
        Device::write(&mut device, DOORBELL, &0x3333_4444u32.to_le_bytes());

        Device::read(&mut device, STATUS, &mut status);
        let s = u32::from_le_bytes(status);
        assert_eq!(s & 0x2, 0x2, "BUSY should be set while a request is in flight");
        assert_eq!(s & 0x1, 0, "no completion yet — this is the point: not synchronous with write()");
        assert!(!device.take_pending_irq(), "no irq until tick() actually completes something");

        // LATENCY_TICKS - 1 ticks: still not done.
        Device::tick(&mut device);
        Device::tick(&mut device);
        assert!(!device.take_pending_irq(), "should not complete before the configured latency");

        // The tick that crosses the latency threshold.
        Device::tick(&mut device);
        assert!(device.take_pending_irq(), "both requests submitted on the same tick complete together");

        Device::read(&mut device, STATUS, &mut status);
        assert_eq!(u32::from_le_bytes(status) & 0x1, 0x1, "RESULT_READY should be set");

        let mut result = [0u8; 4];
        Device::read(&mut device, RESULT, &mut result);
        assert_eq!(u32::from_le_bytes(result), 0x1111_2222 ^ 0xFFFF_FFFF, "results complete in submission order");
        Device::read(&mut device, RESULT, &mut result);
        assert_eq!(u32::from_le_bytes(result), 0x3333_4444 ^ 0xFFFF_FFFF);

        Device::read(&mut device, STATUS, &mut status);
        assert_eq!(u32::from_le_bytes(status), 0, "draining both results should clear every status bit");
    }

    /// Exercises `devices/dma_demo.py` end-to-end, since `HyperbugCtx`'s
    /// `read_mem`/`write_mem`/`raise_irq` had once only been wired up and
    /// clean-building without ever actually being exercised by a real
    /// plugin. This drives the example device exactly the way a guest
    /// driver would (poke a buffer into "guest RAM", tell the device where
    /// it is via register writes, ask it to act, read the result back from
    /// the *other* end — through DMA, not by inspecting the device's own
    /// state) and checks the interrupt request fires too. No KVM/VM boot
    /// needed.
    #[test]
    fn dma_demo_reverses_a_buffer_via_dma_and_raises_its_irq() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let buffer_addr: u64 = 0x100;
        let payload = b"hyperbug";
        assert!(mem.lock().unwrap().write_checked(buffer_addr, payload));

        let mut device = PyDevice::load_pci(demo_path(), "DmaDemoDevice", mem.clone(), None)
            .expect("dma_demo.py should load");

        // A real guest driver would program these three registers, in this
        // order, exactly like this — offsets straight from the plugin's
        // own doc comment.
        Device::write(&mut device, 0x00, &buffer_addr.to_le_bytes());
        Device::write(&mut device, 0x08, &(payload.len() as u32).to_le_bytes());
        // The demo device calls `hyperbug.raise_irq()` (the *spontaneous*
        // path — see `HyperbugCtx`) rather than returning `True` from
        // `write()` (the older synchronous-only path scratch.py
        // demonstrates instead), so the interrupt request shows up via
        // `take_pending_irq()`, not `write()`'s own return value.
        Device::write(&mut device, 0x0c, &[1]); // CMD_REVERSE

        assert!(device.take_pending_irq(), "raise_irq() should have set the pending flag");
        assert!(!device.take_pending_irq(), "the flag should clear once taken");

        let mut result = [0u8; 8];
        assert!(mem.lock().unwrap().read_checked(buffer_addr, &mut result));
        assert_eq!(&result, b"gubrepyh", "the buffer should be reversed in place via DMA");
    }

    /// The identity a `--pci-device` plugin declares is read once at load
    /// and served from Rust after that — no GIL round trip per
    /// config-space dword during bus enumeration.
    #[test]
    fn pci_identity_is_snapshotted_from_the_plugins_attributes() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let device = PyDevice::load_pci(demo_path(), "DmaDemoDevice", mem, None)
            .expect("dma_demo.py should load");

        assert_eq!(device.vendor_id(), 0x1234);
        assert_eq!(device.device_id(), 0x0001);
        assert_eq!(device.class_code(), 0xff_00_00);
        assert_eq!(device.bar_sizes()[0], 0x10);
        assert_eq!(device.bar_sizes()[1], 0, "unlisted BARs are unimplemented");
        assert!(!device.bar_is_io(0), "no `io_bars` attribute means memory-space");
        assert_eq!(device.interrupt_line(), 9);
        assert!(device.msi_capable());
    }

    /// A plugin with no `tick` method pays nothing for it: `Device::tick`
    /// is a plain `Option` check, no GIL attach. Verified via the demo
    /// device, which doesn't define one.
    #[test]
    fn tick_is_a_no_op_for_a_plugin_that_does_not_define_it() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = PyDevice::load_pci(demo_path(), "DmaDemoDevice", mem, None).expect("dma_demo.py should load");
        assert!(device.tick_fn.is_none());
        Device::tick(&mut device); // must not panic or call anything
    }

    /// A plugin that *does* define `tick()` gets called once per
    /// `Device::tick()` — driven here the same way `vcpu::poll_host` drives
    /// it, once per (simulated) loop iteration — and can use it to raise
    /// its own interrupt independent of any register access — this is what
    /// makes it possible for a Python device to be called back into
    /// without the guest touching it first.
    #[test]
    fn tick_calls_the_plugins_tick_method_which_can_raise_its_own_irq() {
        let dir = std::env::temp_dir().join(format!("hyperbug-tick-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ticker.py");
        std::fs::write(
            &path,
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
        )
        .unwrap();

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = PyDevice::load(path.to_str().unwrap(), "Ticker", mem, None).expect("ticker.py should load");
        assert!(device.tick_fn.is_some());

        for _ in 0..2 {
            Device::tick(&mut device);
            assert!(!device.take_pending_irq(), "should not raise before the third tick");
        }
        Device::tick(&mut device);
        assert!(device.take_pending_irq(), "the third tick should have raised the irq");

        let mut count = [0u8; 4];
        Device::read(&mut device, 0, &mut count);
        assert_eq!(u32::from_le_bytes(count), 3, "tick() state should persist across calls");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plugin declaring a `hyperbug_api_version` other than what this
    /// build implements fails to load with a clear message, instead of
    /// silently running against a contract that's since changed.
    #[test]
    fn a_mismatched_api_version_is_refused_at_load() {
        let dir = std::env::temp_dir().join(format!("hyperbug-apiver-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.py");
        std::fs::write(
            &path,
            "class Old:\n\
            \x20   hyperbug_api_version = 999999\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        )
        .unwrap();

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match PyDevice::load(path.to_str().unwrap(), "Old", mem, None) {
            Ok(_) => panic!("a mismatched hyperbug_api_version should refuse to load"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("hyperbug_api_version=999999"), "got: {msg}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plugin that doesn't declare `hyperbug_api_version` at all (duck-
    /// typed, not subclassing `Device`) has nothing to check and loads
    /// exactly as before this existed.
    #[test]
    fn a_plugin_with_no_declared_api_version_loads_fine() {
        let dir = std::env::temp_dir().join(format!("hyperbug-apiver-duck-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("duck.py");
        std::fs::write(
            &path,
            "class Duck:\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        )
        .unwrap();

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        PyDevice::load(path.to_str().unwrap(), "Duck", mem, None).expect("a duck-typed plugin should still load");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An out-of-bounds DMA call is a Python-visible `OSError`, not a
    /// silent partial read — a plugin has to be able to tell.
    #[test]
    fn dma_outside_guest_ram_raises_rather_than_reading_garbage() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let ctx = HyperbugCtx { mem, irq_pending: Arc::new(AtomicBool::new(false)), dma_range: None };
        Python::attach(|py| {
            assert!(ctx.read_mem(py, 4090, 16).is_err());
            assert!(ctx.write_mem(4090, &[0u8; 16]).is_err());
            assert!(ctx.read_mem(py, 4080, 16).is_ok(), "an in-bounds range still works");
        });
    }

    /// The actual point of `dma_range` end to end (not just
    /// `device::tests::dma_range_allows_...`'s pure logic test): a plugin
    /// with a declared confinement gets a real `OSError` from
    /// `self.hyperbug.read_mem`/`write_mem` for anything outside it, even
    /// though the address is otherwise perfectly in-bounds guest RAM the
    /// plugin *would* be able to reach without the restriction.
    #[test]
    fn a_declared_dma_range_confines_read_mem_and_write_mem() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(8192).unwrap()));
        let ctx = HyperbugCtx {
            mem,
            irq_pending: Arc::new(AtomicBool::new(false)),
            dma_range: Some((0x1000, 0x1000)), // [0x1000, 0x2000)
        };
        Python::attach(|py| {
            assert!(ctx.read_mem(py, 0x1000, 16).is_ok(), "the start of the declared range");
            assert!(ctx.write_mem(0x1ff0, &[0u8; 16]).is_ok(), "the end of the declared range");
            assert!(
                ctx.read_mem(py, 0x0f00, 16).is_err(),
                "in guest RAM, but outside the declared range — must still be refused"
            );
            assert!(
                ctx.write_mem(0x1ff8, &[0u8; 16]).is_err(),
                "a write that would straddle past the declared range's end"
            );
        });
    }
}
