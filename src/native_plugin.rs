//! A device plugin written in C, Rust, or anything else that can produce
//! a C-ABI shared object — `dlopen()`ed directly into this process. See
//! `include/hyperbug_plugin.h` for the full contract this loads against.
//!
//! This is the third `PluginTransport` implementation (`plugin.rs`),
//! alongside `pydevice.rs`'s in-process PyO3 transport and
//! `pydevice_proc.rs`'s sandboxed-subprocess transport — the same
//! `ScriptedDevice` core (identity snapshot, spontaneous-IRQ flag,
//! rate-limited error logging) drives all three identically. Python
//! stays the default, easy path; this exists for the case where a
//! plugin's own overhead (an interpreter, a subprocess round trip)
//! genuinely matters, or a plugin needs to be written in something other
//! than Python.
//!
//! **No isolation of any kind.** Unlike either Python transport, a
//! native plugin runs with the full privileges of, and in the same
//! address space as, the VMM process itself — no seccomp filter, no
//! cgroup, no interpreter boundary catching a crash. A native plugin's
//! `read`/`write`/`tick`/`reset` calls also have no error-reporting
//! channel at all (no exception mechanism in a C ABI): a failure inside
//! one either does nothing observable or crashes the whole process,
//! there is no middle ground the way a caught Python exception gives
//! the Python transports. Use this only for code you completely trust
//! and control — see `docs/security/security.md`.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use libloading::{Library, Symbol};

use crate::error::HyperbugError;
use crate::mem::GuestMemory;
use crate::pci::NUM_BARS;
use crate::plugin::{PluginIdentity, PluginTransport, ScriptedDevice};

/// Mirrors `struct hyperbug_pci_identity` in `include/hyperbug_plugin.h`
/// exactly — field order and types must match, since this is read via a
/// raw C ABI call, not anything Rust's type system checks across the
/// boundary.
#[repr(C)]
struct CPciIdentity {
    vendor_id: u16,
    device_id: u16,
    class_code: u32,
    bar_sizes: [u32; NUM_BARS],
    io_bars_mask: u8,
    interrupt_line: u8,
    msi_capable: u8,
}

impl Default for CPciIdentity {
    fn default() -> Self {
        Self { vendor_id: 0, device_id: 0, class_code: 0, bar_sizes: [0; NUM_BARS], io_bars_mask: 0, interrupt_line: 0, msi_capable: 0 }
    }
}

/// Mirrors `struct hyperbug_host_ctx` in `include/hyperbug_plugin.h`
/// exactly.
#[repr(C)]
struct CHostCtx {
    opaque: *mut c_void,
    read_mem: unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> i32,
    write_mem: unsafe extern "C" fn(*mut c_void, u64, *const u8, usize) -> i32,
    raise_irq: unsafe extern "C" fn(*mut c_void),
}

/// What `CHostCtx.opaque` actually points to — boxed once at load and
/// kept alive for the plugin instance's entire lifetime (a plugin is
/// entitled to call these callbacks at any time up until
/// `hyperbug_plugin_destroy`, per the header's contract, not just during
/// `hyperbug_plugin_create`).
struct HostCtxData {
    mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    irq_pending: Arc<AtomicBool>,
}

/// # Safety
/// Called by a native plugin with the `opaque` pointer this module
/// itself set in `CHostCtx::opaque` — always a live `HostCtxData` for as
/// long as the plugin instance exists, and `data`/`size` are the
/// plugin's own claim about a buffer it owns for the duration of this
/// call (the same trust boundary any C callback API has).
unsafe extern "C" fn host_read_mem(opaque: *mut c_void, addr: u64, data: *mut u8, size: usize) -> i32 {
    let ctx = unsafe { &*opaque.cast::<HostCtxData>() };
    if !crate::device::dma_range_allows(ctx.dma_range, addr, size as u64) {
        return -1;
    }
    let mem = ctx.mem.lock().unwrap();
    if !mem.in_bounds(addr, size as u64) {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(data, size) };
    mem.read_checked(addr, buf);
    0
}

/// # Safety
/// See `host_read_mem`.
unsafe extern "C" fn host_write_mem(opaque: *mut c_void, addr: u64, data: *const u8, size: usize) -> i32 {
    let ctx = unsafe { &*opaque.cast::<HostCtxData>() };
    if !crate::device::dma_range_allows(ctx.dma_range, addr, size as u64) {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts(data, size) };
    if ctx.mem.lock().unwrap().write_checked(addr, buf) { 0 } else { -1 }
}

/// # Safety
/// See `host_read_mem`.
unsafe extern "C" fn host_raise_irq(opaque: *mut c_void) {
    let ctx = unsafe { &*opaque.cast::<HostCtxData>() };
    ctx.irq_pending.store(true, Ordering::Release);
}

type CreateFn = unsafe extern "C" fn(*const CHostCtx) -> *mut c_void;
type DestroyFn = unsafe extern "C" fn(*mut c_void);
type ReadFn = unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize);
type WriteFn = unsafe extern "C" fn(*mut c_void, u64, *const u8, usize) -> i32;
type TickFn = unsafe extern "C" fn(*mut c_void);
type ResetFn = unsafe extern "C" fn(*mut c_void);
type PciIdentityFn = unsafe extern "C" fn(*mut c_void, *mut CPciIdentity) -> i32;
type AbiVersionFn = unsafe extern "C" fn() -> u32;

/// The native half of `ScriptedDevice`: every `read`/`write`/`tick`/
/// `reset` call is a direct, in-process C ABI function call against
/// `dlopen()`ed code — no interpreter, no IPC, and (unlike either Python
/// transport) no error channel at all.
struct NativeTransport {
    state: *mut c_void,
    destroy_fn: DestroyFn,
    read_fn: ReadFn,
    write_fn: WriteFn,
    tick_fn: Option<TickFn>,
    reset_fn: Option<ResetFn>,
    /// Kept alive only so the `dlopen` handle and the boxed host-context
    /// data/struct outlive every call the plugin can make into either —
    /// never read directly. Drop order doesn't matter for soundness here
    /// (this struct's own `Drop` impl calls `destroy_fn` before any field
    /// drops at all, and everything below is a no-op to drop otherwise);
    /// grouped for clarity, not because ordering is load-bearing.
    _library: Library,
    _host_ctx_data: Box<HostCtxData>,
    _host_ctx_struct: Box<CHostCtx>,
}

// SAFETY: `state`/the function pointers are only ever touched through
// `&mut self` methods, which `ScriptedDevice`'s own `Arc<Mutex<...>>`
// wrapper already serializes to one caller at a time — the same
// reasoning `pydevice.rs`'s `HyperbugCtx` uses for its own `Send` impl.
// Whether the *native code itself* is actually thread-safe internally is
// the plugin author's own responsibility, same as any C library.
unsafe impl Send for NativeTransport {}

impl PluginTransport for NativeTransport {
    fn call_read(&mut self, offset: u64, data: &mut [u8]) -> Result<(), String> {
        // SAFETY: `read_fn` is this plugin's own declared entry point;
        // `state` is this instance's own opaque pointer, valid until
        // `destroy_fn` runs; `data` is a valid, exactly-`data.len()`-byte
        // buffer for the plugin to fill, per the header's contract.
        unsafe { (self.read_fn)(self.state, offset, data.as_mut_ptr(), data.len()) };
        Ok(())
    }

    fn call_write(&mut self, offset: u64, data: &[u8]) -> Result<bool, String> {
        // SAFETY: as `call_read`.
        let wants_irq = unsafe { (self.write_fn)(self.state, offset, data.as_ptr(), data.len()) };
        Ok(wants_irq != 0)
    }

    fn call_tick(&mut self) -> Result<(), String> {
        if let Some(f) = self.tick_fn {
            // SAFETY: as `call_read`.
            unsafe { f(self.state) };
        }
        Ok(())
    }

    fn has_tick(&self) -> bool {
        self.tick_fn.is_some()
    }

    fn call_reset(&mut self) -> Result<(), String> {
        if let Some(f) = self.reset_fn {
            // SAFETY: as `call_read`.
            unsafe { f(self.state) };
        }
        Ok(())
    }

    fn has_reset(&self) -> bool {
        self.reset_fn.is_some()
    }
}

impl Drop for NativeTransport {
    fn drop(&mut self) {
        // SAFETY: `state` was returned by this same library's own
        // `create_fn` and is destroyed exactly once, here; the library
        // and host-ctx boxes it may still call back into during this are
        // untouched until this function returns, so they're still alive.
        unsafe { (self.destroy_fn)(self.state) };
    }
}

/// Resolves a required export by name, as its raw function-pointer value
/// (copied out of the `Symbol` wrapper — safe and standard for a `Copy`
/// function-pointer type, and what decouples the pointer from `library`'s
/// borrow so it can be stored alongside `library` in the same struct).
fn required_symbol<T: Copy>(library: &Library, path: &str, name: &str) -> Result<T, HyperbugError> {
    let mut cname = name.as_bytes().to_vec();
    cname.push(0);
    // SAFETY: `cname` is a NUL-terminated byte string naming the symbol;
    // the caller is responsible for `T` matching that symbol's real
    // signature (there is no way to check this from the dlopen side —
    // the same trust boundary any C plugin ABI has).
    let sym: Symbol<T> = unsafe { library.get(&cname) }
        .map_err(|e| HyperbugError::Config(format!("{path}: missing required export {name}: {e}")))?;
    Ok(*sym)
}

/// As `required_symbol`, but a missing export is `None` rather than a
/// load failure — for the optional `tick`/`reset`/`pci_identity` hooks.
fn optional_symbol<T: Copy>(library: &Library, name: &str) -> Option<T> {
    let mut cname = name.as_bytes().to_vec();
    cname.push(0);
    // SAFETY: as `required_symbol`.
    unsafe { library.get::<T>(&cname) }.ok().map(|sym| *sym)
}

/// `dma_range` optionally confines this plugin's DMA callbacks to a
/// sub-range of `mem` — see `device::dma_range_allows`.
pub fn load(path: &str, mem: Arc<Mutex<GuestMemory>>, dma_range: Option<(u64, u64)>) -> Result<ScriptedDevice, HyperbugError> {
    spawn(path, mem, dma_range, false)
}

pub fn load_pci(path: &str, mem: Arc<Mutex<GuestMemory>>, dma_range: Option<(u64, u64)>) -> Result<ScriptedDevice, HyperbugError> {
    spawn(path, mem, dma_range, true)
}

fn spawn(
    path: &str,
    mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    want_pci: bool,
) -> Result<ScriptedDevice, HyperbugError> {
    // SAFETY: dlopen()s an operator-specified path. From this call
    // onward the loaded code runs with the full privileges of this
    // process — see this module's own doc comment; there is no
    // sandboxing for this path, by explicit scope, not oversight.
    let library = unsafe { Library::new(path) }
        .map_err(|e| HyperbugError::Io(format!("loading native plugin {path}: {e}")))?;

    let abi_version_fn: AbiVersionFn = required_symbol(&library, path, "hyperbug_plugin_abi_version")?;
    // SAFETY: a required, no-argument, `u32`-returning export the plugin
    // declared — the same trust boundary the rest of this file uses.
    let declared = unsafe { abi_version_fn() };
    if declared > crate::device::PLUGIN_API_VERSION || declared < crate::device::PLUGIN_API_MIN_SUPPORTED {
        return Err(HyperbugError::Config(format!(
            "{path} declares hyperbug_plugin_abi_version={declared}, but this hyperbug build supports \
             the range [{}, {}]",
            crate::device::PLUGIN_API_MIN_SUPPORTED,
            crate::device::PLUGIN_API_VERSION
        )));
    }

    let create_fn: CreateFn = required_symbol(&library, path, "hyperbug_plugin_create")?;
    let destroy_fn: DestroyFn = required_symbol(&library, path, "hyperbug_plugin_destroy")?;
    let read_fn: ReadFn = required_symbol(&library, path, "hyperbug_plugin_read")?;
    let write_fn: WriteFn = required_symbol(&library, path, "hyperbug_plugin_write")?;
    let tick_fn: Option<TickFn> = optional_symbol(&library, "hyperbug_plugin_tick");
    let reset_fn: Option<ResetFn> = optional_symbol(&library, "hyperbug_plugin_reset");
    let pci_identity_fn: Option<PciIdentityFn> = optional_symbol(&library, "hyperbug_plugin_pci_identity");

    let irq_pending = Arc::new(AtomicBool::new(false));
    let host_ctx_data = Box::new(HostCtxData { mem, dma_range, irq_pending: irq_pending.clone() });
    let host_ctx_struct = Box::new(CHostCtx {
        opaque: (&*host_ctx_data as *const HostCtxData).cast_mut().cast::<c_void>(),
        read_mem: host_read_mem,
        write_mem: host_write_mem,
        raise_irq: host_raise_irq,
    });

    // SAFETY: `create_fn` is the plugin's own declared entry point;
    // `host_ctx_struct` is heap-allocated and kept alive for this
    // device's entire lifetime (stored in the returned `NativeTransport`
    // below), so the pointer handed here stays valid for as long as the
    // plugin holds onto it, not just for the duration of this call.
    let state = unsafe { create_fn(&*host_ctx_struct) };

    let identity = if want_pci {
        pci_identity_fn
            .map(|f| {
                let mut c_identity = CPciIdentity::default();
                // SAFETY: `state` is this instance's own pointer, valid
                // until `destroy_fn` runs; `c_identity` is a valid,
                // correctly-sized out-param the plugin may fill in.
                let has_identity = unsafe { f(state, &mut c_identity) };
                if has_identity == 0 {
                    return PluginIdentity::default();
                }
                let mut bar_is_io = [false; NUM_BARS];
                for (i, flag) in bar_is_io.iter_mut().enumerate() {
                    *flag = c_identity.io_bars_mask & (1 << i) != 0;
                }
                PluginIdentity {
                    vendor_id: c_identity.vendor_id,
                    device_id: c_identity.device_id,
                    class_code: c_identity.class_code,
                    bar_sizes: c_identity.bar_sizes,
                    bar_is_io,
                    interrupt_line: c_identity.interrupt_line,
                    msi_capable: c_identity.msi_capable != 0,
                }
            })
            .unwrap_or_default()
    } else {
        PluginIdentity::default()
    };

    let transport = NativeTransport {
        state,
        destroy_fn,
        read_fn,
        write_fn,
        tick_fn,
        reset_fn,
        _library: library,
        _host_ctx_data: host_ctx_data,
        _host_ctx_struct: host_ctx_struct,
    };

    Ok(ScriptedDevice::new(Box::new(transport), identity, irq_pending))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Device;
    use crate::pci::PciDevice;

    /// `devices/native_scratch.so` — built from `devices/native_scratch.c`
    /// by the test itself (so this test is self-contained and doesn't
    /// depend on a stale checked-in `.so` matching the current source),
    /// requiring a C compiler; skips cleanly if none is found, the same
    /// convention `tests/boot.rs` uses for its own optional dependencies.
    fn compile_scratch() -> Option<std::path::PathBuf> {
        compile_plugin("native_scratch")
    }

    fn compile_dma_demo() -> Option<std::path::PathBuf> {
        compile_plugin("native_dma_demo")
    }

    fn compile_plugin(name: &str) -> Option<std::path::PathBuf> {
        let cc = if std::process::Command::new("cc").arg("--version").output().is_ok() { "cc" } else { "gcc" };
        if std::process::Command::new(cc).arg("--version").output().is_err() {
            return None;
        }
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let source = format!("{manifest_dir}/devices/{name}.c");
        let out = std::env::temp_dir().join(format!("hyperbug-native-test-{name}-{}.so", std::process::id()));
        let status = std::process::Command::new(cc)
            .args(["-shared", "-fPIC", "-I"])
            .arg(format!("{manifest_dir}/include"))
            .arg("-o")
            .arg(&out)
            .arg(&source)
            .status()
            .expect("failed to run cc");
        assert!(status.success(), "compiling {source} failed");
        Some(out)
    }

    /// The real point of this whole module: a plugin written in C, not
    /// Python, `dlopen()`ed and driven through the exact same
    /// `Device`/`PciDevice` trait calls every other transport goes
    /// through — read/write round trip, no PCI identity declared.
    #[test]
    fn a_native_plugin_handles_read_write_through_the_c_abi() {
        let Some(so_path) = compile_scratch() else {
            eprintln!("skipping: no C compiler found");
            return;
        };
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(so_path.to_str().unwrap(), mem, None).expect("native_scratch.so should load");

        Device::write(&mut device, 0, &[0xde, 0xad, 0xbe, 0xef]);
        let mut buf = [0u8; 4];
        Device::read(&mut device, 0, &mut buf);
        assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);

        // Offsets past the plugin's own 16-byte register file read as
        // zero and writes there are silently dropped, per how
        // native_scratch.c itself is written — not a hyperbug behavior,
        // but worth confirming the byte-for-byte marshaling across the
        // C ABI doesn't corrupt anything at the boundary.
        let mut past = [0xffu8; 4];
        Device::read(&mut device, 100, &mut past);
        assert_eq!(past, [0, 0, 0, 0]);

        let _ = std::fs::remove_file(&so_path);
    }

    /// The full contract in one plugin: PCI identity declared through
    /// `hyperbug_plugin_pci_identity`, real DMA via the host callbacks,
    /// a spontaneous interrupt via `raise_irq`, and `tick`/`reset` both
    /// actually called through the C ABI.
    #[test]
    fn a_native_pci_plugin_does_real_dma_raises_irq_ticks_and_resets() {
        let Some(so_path) = compile_dma_demo() else {
            eprintln!("skipping: no C compiler found");
            return;
        };
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let buffer_addr: u64 = 0x100;
        let payload = b"hyperbug";
        mem.lock().unwrap().write_checked(buffer_addr, payload);

        let mut device = load_pci(so_path.to_str().unwrap(), mem.clone(), None).expect("native_dma_demo.so should load");

        assert_eq!(device.vendor_id(), 0x1234);
        assert_eq!(device.device_id(), 0x0002);
        assert_eq!(device.class_code(), 0xff_00_00);
        assert_eq!(device.bar_sizes()[0], 0x10);
        assert_eq!(device.interrupt_line(), 9);
        assert!(device.msi_capable());

        Device::write(&mut device, 0x00, &buffer_addr.to_le_bytes());
        Device::write(&mut device, 0x08, &(payload.len() as u32).to_le_bytes());
        Device::write(&mut device, 0x0c, &[1]);

        assert!(device.take_pending_irq(), "raise_irq() through the C ABI should have set the pending flag");
        assert!(!device.take_pending_irq(), "the flag should clear once taken");

        let mut result = [0u8; 8];
        mem.lock().unwrap().read_checked(buffer_addr, &mut result);
        assert_eq!(&result, b"gubrepyh", "the buffer should be reversed in place via real DMA through the C ABI");

        Device::tick(&mut device);
        Device::tick(&mut device);
        // tick_count isn't guest-visible in this demo device, so this
        // just confirms tick() doesn't panic or hang through the C ABI —
        // the doorbell-style completion-after-N-ticks pattern is already
        // covered by the Python doorbell_demo.py equivalent.
        Device::reset(&mut device);

        let _ = std::fs::remove_file(&so_path);
    }

    /// A plugin missing a required export fails to load with a clear
    /// message naming which one, instead of a raw dlsym/segfault failure.
    #[test]
    fn a_plugin_missing_a_required_export_fails_to_load_cleanly() {
        let Some(cc) = (if std::process::Command::new("cc").arg("--version").output().is_ok() { Some("cc") } else { None })
        else {
            eprintln!("skipping: no C compiler found");
            return;
        };
        let dir = std::env::temp_dir().join(format!("hyperbug-native-badplugin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("incomplete.c");
        // Declares the ABI version and create/destroy, but never
        // `hyperbug_plugin_read`/`write` — a real, easy-to-make plugin
        // authoring mistake.
        std::fs::write(
            &source,
            "#include <stdint.h>\n\
             #include <stddef.h>\n\
             uint32_t hyperbug_plugin_abi_version(void) { return 1; }\n\
             void *hyperbug_plugin_create(const void *ctx) { (void)ctx; return (void*)1; }\n\
             void hyperbug_plugin_destroy(void *state) { (void)state; }\n",
        )
        .unwrap();
        let so_path = dir.join("incomplete.so");
        let status = std::process::Command::new(cc)
            .args(["-shared", "-fPIC", "-o"])
            .arg(&so_path)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success());

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match load(so_path.to_str().unwrap(), mem, None) {
            Ok(_) => panic!("a plugin missing hyperbug_plugin_read should fail to load"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("hyperbug_plugin_read"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plugin declaring an ABI version outside the supported range is
    /// refused at load, mirroring the Python-side check exactly.
    #[test]
    fn a_mismatched_abi_version_is_refused_at_load() {
        let Some(cc) = (if std::process::Command::new("cc").arg("--version").output().is_ok() { Some("cc") } else { None })
        else {
            eprintln!("skipping: no C compiler found");
            return;
        };
        let dir = std::env::temp_dir().join(format!("hyperbug-native-apiver-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("futureversion.c");
        std::fs::write(
            &source,
            "#include <stdint.h>\n\
             #include <stddef.h>\n\
             uint32_t hyperbug_plugin_abi_version(void) { return 999999; }\n\
             void *hyperbug_plugin_create(const void *ctx) { (void)ctx; return (void*)1; }\n\
             void hyperbug_plugin_destroy(void *state) { (void)state; }\n\
             void hyperbug_plugin_read(void *state, uint64_t offset, uint8_t *data, size_t size) { (void)state; (void)offset; (void)data; (void)size; }\n\
             int hyperbug_plugin_write(void *state, uint64_t offset, const uint8_t *data, size_t size) { (void)state; (void)offset; (void)data; (void)size; return 0; }\n",
        )
        .unwrap();
        let so_path = dir.join("futureversion.so");
        let status = std::process::Command::new(cc)
            .args(["-shared", "-fPIC", "-o"])
            .arg(&so_path)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success());

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match load(so_path.to_str().unwrap(), mem, None) {
            Ok(_) => panic!("a mismatched ABI version should refuse to load"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("999999"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
