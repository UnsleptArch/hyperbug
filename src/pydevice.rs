//! Bridges a Python-scripted device into the Rust `Device` trait via PyO3
//! — the in-process transport for `ScriptedDevice` (`plugin.rs`); see
//! that module for everything that's shared with the sandboxed
//! (subprocess) transport in `pydevice_proc.rs`.
//!
//! Contract for a device plugin file: define a class (any name, given to
//! `load`) with:
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
//! (`load_pci`), and cached as a `PluginIdentity`. They describe fixed
//! config-space bytes on real hardware, and reading them per access meant
//! taking the GIL for every config-space dword the guest touched while
//! enumerating the bus.
//!
//! This is deliberately the *only* way hyperbug knows about any specific
//! PCI device identity — the core stays vendor-neutral; any real device's
//! identity (Intel, or anyone else's) lives entirely in the plugin file.

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vmm_sys_util::eventfd::EventFd;

use crate::mem::GuestMemory;
use crate::pci::NUM_BARS;
use crate::plugin::{PluginIdentity, PluginTransport, ScriptedDevice};

/// Given to every Python device instance as `self.hyperbug` (set right
/// after construction, so it isn't available inside `__init__` — a plugin
/// that needs it that early can just stash setup for a later `read`/
/// `write` call instead). This is what makes device scripting more than
/// "a register file with callbacks": a plugin can do real DMA against
/// guest RAM the same way a real device would (read a descriptor the
/// guest posted, write a response into guest-supplied buffers) and raise
/// its own interrupt spontaneously — a timer firing, an external event
/// arriving — not only synchronously from inside `write()`.
// Not `unsendable`: `Arc<Mutex<...>>`/`Arc<AtomicBool>` are genuinely
// `Send`, so this can safely cross the per-vCPU threads that might call
// into the same device plugin — PyO3's GIL still serializes the actual
// Python execution regardless of which OS thread holds it, exactly as
// designed.
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

impl PluginIdentity {
    fn snapshot(instance: &Bound<'_, PyAny>) -> Self {
        let required_u32 = |name: &str| -> u32 {
            match instance.getattr(name).and_then(|a| a.extract::<u32>()) {
                Ok(v) => v,
                Err(e) => {
                    crate::log_error!("python PCI device missing/invalid `{name}`: {e}");
                    0
                }
            }
        };

        let mut bar_sizes = [0u32; NUM_BARS];
        match instance.getattr("bar_sizes").and_then(|a| a.extract::<Vec<u32>>()) {
            Ok(sizes) => {
                if sizes.len() > NUM_BARS {
                    crate::log_warn!(
                        "python PCI device's `bar_sizes` has {} entries, only \
                         {NUM_BARS} BARs exist; truncating",
                        sizes.len()
                    );
                }
                for (slot, size) in bar_sizes.iter_mut().zip(sizes) {
                    *slot = size;
                }
            }
            Err(e) => crate::log_error!("python PCI device missing/invalid `bar_sizes`: {e}"),
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
                            None => crate::log_warn!("python PCI device's `io_bars` names BAR {i}, which doesn't exist"),
                        }
                    }
                }
                Err(e) => crate::log_error!("python PCI device's `io_bars` must be a list of ints: {e}"),
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

/// The in-process half of `ScriptedDevice`: a PyO3 call is a direct,
/// synchronous function invocation, not an IPC round trip — the only
/// thing that distinguishes this from `pydevice_proc.rs`'s
/// `SandboxedTransport`.
struct InProcessTransport {
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
    /// access, so `None` here means `has_tick()` is a plain check and
    /// nothing else, not a GIL round trip. Called once per vCPU-loop
    /// iteration (see `vcpu::poll_host`) for logic that needs to run
    /// independent of any register access — e.g. a simulated timer, or an
    /// async transaction whose completion isn't driven by the guest
    /// touching a register at all.
    tick_fn: Option<Py<PyAny>>,
    /// The plugin's bound `reset` method, if it defined one — optional,
    /// same reasoning as `tick_fn`. Never called by anything in this
    /// codebase automatically; see `Device::reset`'s doc comment for the
    /// real caller (the control socket's `reset_device` command).
    reset_fn: Option<Py<PyAny>>,
}

impl PluginTransport for InProcessTransport {
    fn call_read(&mut self, offset: u64, data: &mut [u8]) -> Result<(), String> {
        Python::attach(|py| match self.read_fn.bind(py).call1((offset, data.len())) {
            Ok(val) => match val.cast::<PyBytes>() {
                Ok(bytes) => {
                    let b = bytes.as_bytes();
                    let n = b.len().min(data.len());
                    data[..n].copy_from_slice(&b[..n]);
                    if b.len() != data.len() {
                        return Err(format!(
                            "python device read() returned {} bytes, expected {}",
                            b.len(),
                            data.len()
                        ));
                    }
                    Ok(())
                }
                Err(_) => Err("python device read() must return bytes".to_string()),
            },
            Err(e) => Err(format!("python device read() raised: {e}")),
        })
    }

    fn call_write(&mut self, offset: u64, data: &[u8]) -> Result<bool, String> {
        Python::attach(|py| {
            let bytes = PyBytes::new(py, data);
            match self.write_fn.bind(py).call1((offset, bytes)) {
                Ok(result) => Ok(result.is_truthy().unwrap_or(false)),
                Err(e) => Err(format!("python device write() raised: {e}")),
            }
        })
    }

    fn call_tick(&mut self) -> Result<(), String> {
        let Some(tick_fn) = &self.tick_fn else { return Ok(()) };
        Python::attach(|py| match tick_fn.bind(py).call0() {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("python device tick() raised: {e}")),
        })
    }

    fn has_tick(&self) -> bool {
        self.tick_fn.is_some()
    }

    fn call_reset(&mut self) -> Result<(), String> {
        let Some(reset_fn) = &self.reset_fn else { return Ok(()) };
        Python::attach(|py| match reset_fn.bind(py).call0() {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("python device reset() raised: {e}")),
        })
    }

    fn has_reset(&self) -> bool {
        self.reset_fn.is_some()
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
            crate::log_error!("couldn't add {python_dir} to sys.path: {e}");
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
    if declared > crate::device::PLUGIN_API_VERSION {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "{path} declares hyperbug_api_version={declared}, but this hyperbug build only \
             implements up to version {} — this plugin needs a newer hyperbug",
            crate::device::PLUGIN_API_VERSION
        )));
    }
    if declared < crate::device::PLUGIN_API_MIN_SUPPORTED {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "{path} declares hyperbug_api_version={declared}, but this hyperbug build no longer \
             supports anything older than version {} — the plugin needs updating for a breaking \
             ABI change",
            crate::device::PLUGIN_API_MIN_SUPPORTED
        )));
    }
    Ok(())
}

/// Loads the Python source at `path`, instantiates `class_name` with no
/// arguments, and wraps it as a `ScriptedDevice`. `mem` backs the
/// `read_mem`/`write_mem` DMA calls the instance gets via `self.hyperbug`;
/// `dma_range` optionally confines those calls to a sub-range of it
/// (`config::DeviceSpec`'s trailing `<dma_base>:<dma_size>` — see
/// `device::dma_range_allows`).
pub fn load(
    path: &str,
    class_name: &str,
    mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
) -> PyResult<ScriptedDevice> {
    load_inner(path, class_name, mem, dma_range, false)
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
) -> PyResult<ScriptedDevice> {
    load_inner(path, class_name, mem, dma_range, true)
}

fn load_inner(
    path: &str,
    class_name: &str,
    mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    is_pci: bool,
) -> PyResult<ScriptedDevice> {
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

        let identity = if is_pci { PluginIdentity::snapshot(&instance) } else { PluginIdentity::default() };
        // Optional: a plugin that doesn't define `tick`/`reset` simply
        // isn't called back for either, same as before `tick` existed.
        let tick_fn = instance.getattr("tick").ok().map(|f| f.unbind());
        let reset_fn = instance.getattr("reset").ok().map(|f| f.unbind());
        let transport = InProcessTransport {
            read_fn: instance.getattr("read")?.unbind(),
            write_fn: instance.getattr("write")?.unbind(),
            tick_fn,
            reset_fn,
        };
        Ok(ScriptedDevice::new(Box::new(transport), identity, irq_pending))
    })
}

/// The in-process bridge for an `--i2c-device` plugin: a Python
/// `I2cDevice` (see `python/hyperbug/device.py`) wrapped as
/// `i2c::I2cTargetDevice`. Deliberately much smaller than `ScriptedDevice`
/// — an I2C target has no `self.hyperbug` DMA context at all (it only
/// ever sees the bytes of the message addressed to it, never guest
/// memory directly — see `i2c.rs`'s own module doc comment), no `tick`/
/// `reset` hooks, and no PCI identity of its own (the bus's *adapter*,
/// not each target, is what the guest's PCI core sees).
pub struct PyI2cTarget {
    write_fn: Py<PyAny>,
    read_fn: Py<PyAny>,
}

impl crate::i2c::I2cTargetDevice for PyI2cTarget {
    fn i2c_write(&mut self, data: &[u8]) {
        Python::attach(|py| {
            let bytes = PyBytes::new(py, data);
            if let Err(e) = self.write_fn.bind(py).call1((bytes,)) {
                crate::log_error!("python I2C device i2c_write() raised: {e}");
            }
        });
    }

    fn i2c_read(&mut self, len: usize) -> Vec<u8> {
        Python::attach(|py| match self.read_fn.bind(py).call1((len,)) {
            Ok(val) => match val.cast::<PyBytes>() {
                Ok(bytes) => bytes.as_bytes().to_vec(),
                Err(_) => {
                    crate::log_error!("python I2C device i2c_read() must return bytes");
                    Vec::new()
                }
            },
            Err(e) => {
                crate::log_error!("python I2C device i2c_read() raised: {e}");
                Vec::new()
            }
        })
    }
}

/// Loads the Python source at `path`, instantiates `class_name` with no
/// arguments, and wraps it as an `i2c::I2cTargetDevice` — the loader
/// `machine.rs`'s `--i2c-device` handling calls, mirroring `load`/
/// `load_pci` above but for hyperbug's separate I2C target-device
/// contract (`i2c_write`/`i2c_read`, not `read`/`write`).
pub fn load_i2c(path: &str, class_name: &str) -> PyResult<PyI2cTarget> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("reading {path}: {e}")))?;
    let source = to_cstring("device source", source)?;
    let file_name = to_cstring("device path", path.to_string())?;
    let module_id = NEXT_MODULE_ID.fetch_add(1, Ordering::Relaxed);
    let module_name = to_cstring("module name", format!("hyperbug_i2c_device_{module_id}"))?;

    Python::attach(|py| {
        ensure_pythonpath(py);
        let module = PyModule::from_code(py, &source, &file_name, &module_name)?;
        let instance = module.getattr(class_name)?.call0()?;
        check_api_version(&instance, path)?;
        Ok(PyI2cTarget { write_fn: instance.getattr("i2c_write")?.unbind(), read_fn: instance.getattr("i2c_read")?.unbind() })
    })
}

/// Given to a `GpioBank` Python instance as `self.hyperbug` — the GPIO
/// equivalent of `HyperbugCtx`, much smaller: a GPIO bank has no DMA
/// context at all, only a way to signal a spontaneous per-line interrupt.
/// `fired`/`event_fd` are shared with `PyGpioBank` (the `GpioBank` trait
/// impl `virtio_gpio.rs` actually drives) so a call here is visible to
/// `VirtioGpio::poll_completions` on the other side — see `gpio.rs`'s own
/// module doc comment for why a plain thread-safe eventfd write, callable
/// from any thread including a plugin's own background one, is enough
/// with no per-iteration polling hook needed.
#[pyclass]
struct HyperbugGpioCtx {
    fired: Arc<Mutex<Vec<u16>>>,
    event_fd: Arc<EventFd>,
}

#[pymethods]
impl HyperbugGpioCtx {
    /// Marks `line` as having spontaneously changed state — delivered to
    /// the guest as a real interrupt only if that line is currently armed
    /// (the guest has posted an `eventq` buffer for it) and its
    /// `IRQ_TYPE` isn't `NONE`; otherwise dropped, matching a real masked/
    /// disabled interrupt.
    fn raise_irq(&self, line: u16) {
        self.fired.lock().unwrap().push(line);
        let _ = self.event_fd.write(1);
    }
}

/// The in-process bridge for a `--gpio-device` plugin: a Python
/// `GpioBank` (see `python/hyperbug/device.py`) wrapped as
/// `gpio::GpioBank`.
pub struct PyGpioBank {
    ngpio: u16,
    names: Vec<String>,
    get_direction_fn: Py<PyAny>,
    set_direction_fn: Py<PyAny>,
    get_value_fn: Py<PyAny>,
    set_value_fn: Py<PyAny>,
    fired: Arc<Mutex<Vec<u16>>>,
    event_fd: Arc<EventFd>,
}

impl crate::gpio::GpioBank for PyGpioBank {
    fn ngpio(&self) -> u16 {
        self.ngpio
    }

    fn names(&self) -> Vec<String> {
        self.names.clone()
    }

    fn get_direction(&mut self, line: u16) -> u8 {
        Python::attach(|py| match self.get_direction_fn.bind(py).call1((line,)) {
            Ok(val) => val.extract().unwrap_or(crate::gpio::DIRECTION_NONE),
            Err(e) => {
                crate::log_error!("python GPIO bank get_direction() raised: {e}");
                crate::gpio::DIRECTION_NONE
            }
        })
    }

    fn set_direction(&mut self, line: u16, direction: u8) {
        Python::attach(|py| {
            if let Err(e) = self.set_direction_fn.bind(py).call1((line, direction)) {
                crate::log_error!("python GPIO bank set_direction() raised: {e}");
            }
        });
    }

    fn get_value(&mut self, line: u16) -> u8 {
        Python::attach(|py| match self.get_value_fn.bind(py).call1((line,)) {
            Ok(val) => val.extract().unwrap_or(0),
            Err(e) => {
                crate::log_error!("python GPIO bank get_value() raised: {e}");
                0
            }
        })
    }

    fn set_value(&mut self, line: u16, value: u8) {
        Python::attach(|py| {
            if let Err(e) = self.set_value_fn.bind(py).call1((line, value)) {
                crate::log_error!("python GPIO bank set_value() raised: {e}");
            }
        });
    }

    fn take_fired_irqs(&mut self) -> Vec<u16> {
        std::mem::take(&mut *self.fired.lock().unwrap())
    }

    fn completion_eventfd(&self) -> Option<std::os::fd::RawFd> {
        Some(self.event_fd.as_raw_fd())
    }
}

/// Loads the Python source at `path`, instantiates `class_name` with no
/// arguments, and wraps it as a `gpio::GpioBank` — the loader
/// `machine.rs`'s `--gpio-device` handling calls.
pub fn load_gpio_bank(path: &str, class_name: &str) -> PyResult<PyGpioBank> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("reading {path}: {e}")))?;
    let source = to_cstring("device source", source)?;
    let file_name = to_cstring("device path", path.to_string())?;
    let module_id = NEXT_MODULE_ID.fetch_add(1, Ordering::Relaxed);
    let module_name = to_cstring("module name", format!("hyperbug_gpio_device_{module_id}"))?;
    let fired = Arc::new(Mutex::new(Vec::new()));
    let event_fd = Arc::new(
        EventFd::new(0).map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("creating GPIO completion eventfd: {e}")))?,
    );

    Python::attach(|py| {
        ensure_pythonpath(py);
        let module = PyModule::from_code(py, &source, &file_name, &module_name)?;
        let instance = module.getattr(class_name)?.call0()?;
        check_api_version(&instance, path)?;
        let ngpio: u16 = instance.getattr("ngpio")?.extract()?;
        if ngpio == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!("{path}'s ngpio can't be zero")));
        }
        let names: Vec<String> = instance.getattr("names").and_then(|a| a.extract()).unwrap_or_default();
        if !names.is_empty() && names.len() != usize::from(ngpio) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "{path}: `names` has {} entries but `ngpio` is {ngpio} — must match exactly, or be omitted entirely",
                names.len()
            )));
        }
        let ctx = HyperbugGpioCtx { fired: fired.clone(), event_fd: event_fd.clone() };
        instance.setattr("hyperbug", Py::new(py, ctx)?)?;
        Ok(PyGpioBank {
            ngpio,
            names,
            get_direction_fn: instance.getattr("get_direction")?.unbind(),
            set_direction_fn: instance.getattr("set_direction")?.unbind(),
            get_value_fn: instance.getattr("get_value")?.unbind(),
            set_value_fn: instance.getattr("set_value")?.unbind(),
            fired,
            event_fd,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Device;
    use crate::gpio::GpioBank;
    use crate::i2c::I2cTargetDevice;
    use crate::pci::PciDevice;

    fn i2c_temp_sensor_path() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/devices/i2c_temp_sensor.py")
    }

    /// Exercises `devices/i2c_temp_sensor.py` end to end through
    /// `load_i2c`: the real "write register pointer, then read its
    /// contents" idiom, driven exactly the way `virtio_i2c.rs`'s own
    /// `process_chain` would call into it.
    #[test]
    fn i2c_temp_sensor_demo_implements_the_register_pointer_idiom() {
        let mut sensor = load_i2c(i2c_temp_sensor_path(), "I2cTempSensor").expect("i2c_temp_sensor.py should load");

        // Register 0 (temperature) is selected by default with no write
        // at all.
        assert_eq!(sensor.i2c_read(2), vec![0x00, 0xeb], "23.5C as a big-endian tenths-of-a-degree i16 is 0x00eb");

        // Select register 1 (config) and write a value into it.
        sensor.i2c_write(&[1, 0x42]);
        assert_eq!(sensor.i2c_read(1), vec![0x42], "the config register should hold what was just written");

        // Switching back to register 0 must not have lost the earlier
        // temperature reading.
        sensor.i2c_write(&[0]);
        assert_eq!(sensor.i2c_read(2), vec![0x00, 0xeb]);
    }

    fn gpio_button_bank_path() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/devices/gpio_button_bank.py")
    }

    /// Exercises `devices/gpio_button_bank.py` end to end through
    /// `load_gpio_bank`: direction/value access via the `GpioBank` trait
    /// methods `virtio_gpio.rs`'s `process_chain` calls, and a real
    /// spontaneous interrupt via `self.hyperbug.raise_irq()`, verified
    /// through the same `take_fired_irqs`/`completion_eventfd` path the
    /// reactor actually drives.
    #[test]
    fn gpio_button_bank_demo_reports_direction_value_and_a_real_irq() {
        let mut bank = load_gpio_bank(gpio_button_bank_path(), "ButtonBank").expect("gpio_button_bank.py should load");

        assert_eq!(bank.ngpio(), 4);
        assert_eq!(bank.names(), vec!["power_button", "presence", "power_control", "reset_control"]);

        // Line 0 (power button) starts as input, idle high.
        assert_eq!(bank.get_direction(0), crate::gpio::DIRECTION_IN);
        assert_eq!(bank.get_value(0), 1);

        // Line 2 (power control) is an output the guest can drive.
        assert_eq!(bank.get_direction(2), crate::gpio::DIRECTION_OUT);
        bank.set_value(2, 1);
        assert_eq!(bank.get_value(2), 1, "a real write must persist");

        // A guest driver can also reconfigure a line's direction.
        bank.set_direction(3, crate::gpio::DIRECTION_IN);
        assert_eq!(bank.get_direction(3), crate::gpio::DIRECTION_IN);

        // No interrupt has fired yet, but a real completion eventfd
        // exists — the reactor's actual signal that `raise_irq()` was
        // called (see `HyperbugGpioCtx`'s own test just below for the
        // mechanism itself; the full guest-visible interrupt delivery is
        // exercised end to end by the real boot test).
        assert!(bank.take_fired_irqs().is_empty());
        assert!(bank.completion_eventfd().is_some(), "the bank must expose a real completion eventfd");
    }

    /// `HyperbugGpioCtx::raise_irq` (what `self.hyperbug.raise_irq(line)`
    /// calls into from Python) is what actually connects a plugin's
    /// spontaneous event to `VirtioGpio::poll_completions` on the other
    /// side — tested directly here, independent of any loaded plugin,
    /// the same way `dma_outside_guest_ram_raises_rather_than_reading_
    /// garbage` constructs a bare `HyperbugCtx` above.
    #[test]
    fn hyperbug_gpio_ctx_raise_irq_updates_shared_state_and_signals_the_eventfd() {
        let fired = Arc::new(Mutex::new(Vec::new()));
        let event_fd = Arc::new(EventFd::new(0).unwrap());
        let ctx = HyperbugGpioCtx { fired: fired.clone(), event_fd: event_fd.clone() };

        ctx.raise_irq(3);
        assert_eq!(*fired.lock().unwrap(), vec![3]);
        assert_eq!(event_fd.read().unwrap(), 1, "the eventfd must become readable exactly once");
    }

    fn demo_path() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/devices/dma_demo.py")
    }

    fn doorbell_demo_path() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/devices/doorbell_demo.py")
    }

    /// Exercises `devices/doorbell_demo.py` — the reference doorbell +
    /// ring-buffer device added alongside `tick()` to prove out the
    /// register pattern a real bridged async transport needs (submit,
    /// then a completion arriving on its own schedule via `raise_irq()`,
    /// not synchronously inside the triggering `write()`) before any such
    /// device gets written for real.
    #[test]
    fn doorbell_demo_completes_requests_asynchronously_in_order() {
        const STATUS: u64 = 0x04;
        const RESULT: u64 = 0x08;
        const DOORBELL: u64 = 0x00;

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load_pci(doorbell_demo_path(), "DoorbellDemoDevice", mem, None)
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

    /// Exercises `devices/dma_demo.py` end-to-end: drives the actual
    /// example device exactly the way a guest driver would (poke a buffer
    /// into "guest RAM", tell the device where it is via register writes,
    /// ask it to act, read the result back from the *other* end — through
    /// DMA, not by inspecting the device's own state) and checks the
    /// interrupt request fires too. No KVM/VM boot needed.
    #[test]
    fn dma_demo_reverses_a_buffer_via_dma_and_raises_its_irq() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let buffer_addr: u64 = 0x100;
        let payload = b"hyperbug";
        assert!(mem.lock().unwrap().write_checked(buffer_addr, payload));

        let mut device = load_pci(demo_path(), "DmaDemoDevice", mem.clone(), None)
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
        let device = load_pci(demo_path(), "DmaDemoDevice", mem, None)
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

    /// A plugin with no `tick` method pays nothing for it. Verified via
    /// the demo device, which doesn't define one.
    #[test]
    fn tick_is_a_no_op_for_a_plugin_that_does_not_define_it() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load_pci(demo_path(), "DmaDemoDevice", mem, None).expect("dma_demo.py should load");
        Device::tick(&mut device); // must not panic or call anything
    }

    /// A plugin that *does* define `tick()` gets called once per
    /// `Device::tick()` — driven here the same way `vcpu::poll_host` drives
    /// it, once per (simulated) loop iteration — and can use it to raise
    /// its own interrupt independent of any register access.
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
        let mut device = load(path.to_str().unwrap(), "Ticker", mem, None).expect("ticker.py should load");

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

    /// A plugin that defines `reset()` gets it called when
    /// `Device::reset()` is invoked (in real use, only ever via the
    /// control socket's `reset_device` command — see `Device::reset`'s
    /// doc comment) — and a plugin that doesn't define one is a
    /// no-op, exactly mirroring `tick`'s opt-in contract.
    #[test]
    fn reset_calls_the_plugins_reset_method_when_it_defines_one() {
        let dir = std::env::temp_dir().join(format!("hyperbug-reset-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("resettable.py");
        std::fs::write(
            &path,
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
        )
        .unwrap();

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(path.to_str().unwrap(), "Resettable", mem, None).expect("resettable.py should load");

        Device::write(&mut device, 0, &42u32.to_le_bytes());
        let mut val = [0u8; 4];
        Device::read(&mut device, 0, &mut val);
        assert_eq!(u32::from_le_bytes(val), 42, "sanity: the write took effect");

        Device::reset(&mut device);
        Device::read(&mut device, 0, &mut val);
        assert_eq!(u32::from_le_bytes(val), 1, "reset() should have restored the initial value");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plugin with no `reset` method pays nothing for it and doesn't
    /// error when `Device::reset()` is called anyway. Verified via the
    /// demo device, which doesn't define one.
    #[test]
    fn reset_is_a_no_op_for_a_plugin_that_does_not_define_it() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load_pci(demo_path(), "DmaDemoDevice", mem, None).expect("dma_demo.py should load");
        Device::reset(&mut device); // must not panic or call anything
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
        let err = match load(path.to_str().unwrap(), "Old", mem, None) {
            Ok(_) => panic!("a mismatched hyperbug_api_version should refuse to load"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("hyperbug_api_version=999999"), "got: {msg}");
        assert!(msg.contains("needs a newer hyperbug"), "got: {msg}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the supported range: a plugin declaring a
    /// version *older* than `PLUGIN_API_MIN_SUPPORTED` is refused too,
    /// with a message distinguishing "too old" from "too new" — not the
    /// same generic mismatch message either direction used to share.
    #[test]
    fn a_too_old_api_version_is_refused_at_load() {
        let dir = std::env::temp_dir().join(format!("hyperbug-apiver-old-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ancient.py");
        std::fs::write(
            &path,
            "class Ancient:\n\
            \x20   hyperbug_api_version = 0\n\
            \x20   def read(self, offset, size):\n\
            \x20       return bytes(size)\n\
            \x20   def write(self, offset, data):\n\
            \x20       return False\n",
        )
        .unwrap();

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match load(path.to_str().unwrap(), "Ancient", mem, None) {
            Ok(_) => panic!("a too-old hyperbug_api_version should refuse to load"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("hyperbug_api_version=0"), "got: {msg}");
        assert!(msg.contains("needs updating"), "got: {msg}");

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
        load(path.to_str().unwrap(), "Duck", mem, None).expect("a duck-typed plugin should still load");

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
