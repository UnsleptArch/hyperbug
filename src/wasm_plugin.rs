//! A device plugin compiled to WebAssembly — an additional sandbox tier
//! alongside (not instead of) the subprocess model: real memory-safety
//! isolation (a WASM module can only ever touch its own linear memory
//! directly; every access to guest-physical memory goes through a
//! checked host callback, the same way the sandboxed-subprocess
//! transport's DMA calls do) at in-process speed — no interpreter, no
//! IPC round trip, and (via Cranelift) JIT-compiled to native code. For
//! a plugin that doesn't need arbitrary Python but does need real
//! throughput, or wants stronger isolation than the native (`dlopen`)
//! path offers without paying a subprocess's IPC cost.
//!
//! See `docs/wasm-plugin-api.md` for the full contract. In short: a
//! module exports `memory` plus `hyperbug_abi_version`/`hyperbug_read`/
//! `hyperbug_write` (required) and `hyperbug_create`/`hyperbug_tick`/
//! `hyperbug_reset`/`hyperbug_pci_identity` (optional), and imports three
//! host functions (`env.host_read_mem`/`host_write_mem`/`host_raise_irq`)
//! for touching guest memory and raising interrupts — a WASM module has
//! no other way to reach outside its own sandbox at all.
//!
//! This is the fourth `PluginTransport` implementation (`plugin.rs`),
//! alongside `pydevice.rs` (in-process Python), `pydevice_proc.rs`
//! (sandboxed Python subprocess), and `native_plugin.rs` (native C ABI,
//! zero isolation). Unlike the native transport, `wasmtime`'s own type
//! checking means a module's exports are verified against the exact
//! expected signature at load time (`get_typed_func` fails cleanly on a
//! mismatch) — there is no C-ABI-style "wrong signature is undefined
//! behavior" risk here, a real advantage of WASM's own type system.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use wasmtime::{Caller, Config, Engine, Instance, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc};

use crate::error::HyperbugError;
use crate::mem::GuestMemory;
use crate::pci::NUM_BARS;
use crate::plugin::{PluginIdentity, PluginTransport, ScriptedDevice};

/// Bytes of a module's own linear memory, starting at offset 0, that
/// hyperbug uses to marshal `read`/`write`/`pci_identity` data across
/// the WASM boundary — documented in `docs/wasm-plugin-api.md` as
/// reserved: a plugin's own state must live at this offset or later.
/// 4 KiB comfortably covers a real register-file-sized read/write (a
/// full PCI BAR's worth, in the shipped examples) without requiring a
/// module to export an allocator just to receive it.
const SCRATCH_SIZE: usize = 4096;

/// A generous per-instance linear-memory ceiling — real, enforced by
/// `wasmtime` itself (`StoreLimits`/`Store::limiter`), not just
/// advisory: growing past this fails the `memory.grow` instruction
/// cleanly rather than actually consuming host memory without bound.
/// This is a concrete, wasmtime-native answer to "stronger isolation"
/// neither the sandboxed-subprocess nor native transport gets for free.
const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;

/// Host-side state reachable from every imported host function via
/// `Caller::data()`/`data_mut()`.
struct HostState {
    mem: Arc<Mutex<GuestMemory>>,
    dma_range: Option<(u64, u64)>,
    irq_pending: Arc<AtomicBool>,
    /// Set once, right after instantiation (a module's own memory export
    /// isn't known until then) — every host function needs it to
    /// marshal data into/out of the module's sandboxed linear memory.
    memory: Option<Memory>,
    limits: StoreLimits,
}

fn build_linker(engine: &Engine) -> Result<Linker<HostState>, HyperbugError> {
    let mut linker = Linker::new(engine);

    linker
        .func_wrap("env", "host_read_mem", |mut caller: Caller<'_, HostState>, addr: i64, buf_ptr: i32, size: i32| -> i32 {
            let (dma_range, mem_arc, wasm_mem) = {
                let data = caller.data();
                (data.dma_range, data.mem.clone(), data.memory)
            };
            let (addr, size) = (addr as u64, size as u64);
            if !crate::device::dma_range_allows(dma_range, addr, size) {
                return -1;
            }
            let Some(wasm_mem) = wasm_mem else { return -1 };
            let mut buf = vec![0u8; size as usize];
            {
                let mem = mem_arc.lock().unwrap();
                if !mem.in_bounds(addr, size) {
                    return -1;
                }
                mem.read_checked(addr, &mut buf);
            }
            if wasm_mem.write(&mut caller, buf_ptr as usize, &buf).is_err() { -1 } else { 0 }
        })
        .map_err(|e| HyperbugError::Config(format!("registering host_read_mem: {e}")))?;

    linker
        .func_wrap("env", "host_write_mem", |caller: Caller<'_, HostState>, addr: i64, buf_ptr: i32, size: i32| -> i32 {
            let (dma_range, mem_arc, wasm_mem) = {
                let data = caller.data();
                (data.dma_range, data.mem.clone(), data.memory)
            };
            let (addr, size) = (addr as u64, size as u64);
            if !crate::device::dma_range_allows(dma_range, addr, size) {
                return -1;
            }
            let Some(wasm_mem) = wasm_mem else { return -1 };
            let mut buf = vec![0u8; size as usize];
            if wasm_mem.read(&caller, buf_ptr as usize, &mut buf).is_err() {
                return -1;
            }
            if mem_arc.lock().unwrap().write_checked(addr, &buf) { 0 } else { -1 }
        })
        .map_err(|e| HyperbugError::Config(format!("registering host_write_mem: {e}")))?;

    linker
        .func_wrap("env", "host_raise_irq", |caller: Caller<'_, HostState>| {
            caller.data().irq_pending.store(true, Ordering::Release);
        })
        .map_err(|e| HyperbugError::Config(format!("registering host_raise_irq: {e}")))?;

    Ok(linker)
}

/// The WASM half of `ScriptedDevice`: every `read`/`write`/`tick`/
/// `reset` call is a real, JIT-compiled function call into a sandboxed
/// WASM instance — no interpreter, no subprocess, and (unlike the native
/// transport) no ability to touch anything outside its own linear
/// memory except through the checked host callbacks above.
struct WasmTransport {
    store: Store<HostState>,
    memory: Memory,
    read_fn: TypedFunc<(i64, i32, i32), ()>,
    write_fn: TypedFunc<(i64, i32, i32), i32>,
    tick_fn: Option<TypedFunc<(), ()>>,
    reset_fn: Option<TypedFunc<(), ()>>,
}

// SAFETY: identical reasoning to `NativeTransport`'s `Send` impl —
// `ScriptedDevice`'s own `Arc<Mutex<...>>` wrapper already serializes
// every call to one caller at a time. `wasmtime`'s `Store`/`Instance`
// types are themselves `Send` when their stored data (`HostState`) is,
// which it is (only `Arc`/`Option<Memory>`/plain data).
unsafe impl Send for WasmTransport {}

impl PluginTransport for WasmTransport {
    fn call_read(&mut self, offset: u64, data: &mut [u8]) -> Result<(), String> {
        if data.len() > SCRATCH_SIZE {
            return Err(format!(
                "wasm plugin read() of {} bytes exceeds the {SCRATCH_SIZE}-byte scratch region",
                data.len()
            ));
        }
        self.read_fn
            .call(&mut self.store, (offset as i64, data.len() as i32, 0))
            .map_err(|e| format!("wasm hyperbug_read trapped: {e}"))?;
        self.memory
            .read(&self.store, 0, data)
            .map_err(|e| format!("reading wasm scratch memory after hyperbug_read: {e}"))
    }

    fn call_write(&mut self, offset: u64, data: &[u8]) -> Result<bool, String> {
        if data.len() > SCRATCH_SIZE {
            return Err(format!(
                "wasm plugin write() of {} bytes exceeds the {SCRATCH_SIZE}-byte scratch region",
                data.len()
            ));
        }
        self.memory
            .write(&mut self.store, 0, data)
            .map_err(|e| format!("writing wasm scratch memory before hyperbug_write: {e}"))?;
        let wants_irq = self
            .write_fn
            .call(&mut self.store, (offset as i64, 0, data.len() as i32))
            .map_err(|e| format!("wasm hyperbug_write trapped: {e}"))?;
        Ok(wants_irq != 0)
    }

    fn call_tick(&mut self) -> Result<(), String> {
        if let Some(f) = &self.tick_fn {
            f.call(&mut self.store, ()).map_err(|e| format!("wasm hyperbug_tick trapped: {e}"))?;
        }
        Ok(())
    }

    fn has_tick(&self) -> bool {
        self.tick_fn.is_some()
    }

    fn call_reset(&mut self) -> Result<(), String> {
        if let Some(f) = &self.reset_fn {
            f.call(&mut self.store, ()).map_err(|e| format!("wasm hyperbug_reset trapped: {e}"))?;
        }
        Ok(())
    }

    fn has_reset(&self) -> bool {
        self.reset_fn.is_some()
    }
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
    let config = Config::new();
    let engine = Engine::new(&config).map_err(|e| HyperbugError::Config(format!("wasmtime engine init: {e}")))?;
    let module = Module::from_file(&engine, path)
        .map_err(|e| HyperbugError::Config(format!("loading wasm plugin {path}: {e}")))?;
    let linker = build_linker(&engine)?;

    let irq_pending = Arc::new(AtomicBool::new(false));
    let limits = StoreLimitsBuilder::new().memory_size(MAX_MEMORY_BYTES).build();
    let host_state = HostState { mem, dma_range, irq_pending: irq_pending.clone(), memory: None, limits };
    let mut store = Store::new(&engine, host_state);
    store.limiter(|state| &mut state.limits);

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| HyperbugError::Config(format!("instantiating wasm plugin {path}: {e}")))?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| HyperbugError::Config(format!("{path}: missing required export `memory`")))?;
    store.data_mut().memory = Some(memory);

    let abi_version_fn: TypedFunc<(), i32> = required_export(&instance, &mut store, path, "hyperbug_abi_version")?;
    let declared = abi_version_fn
        .call(&mut store, ())
        .map_err(|e| HyperbugError::Config(format!("{path}: hyperbug_abi_version trapped: {e}")))?;
    if declared > crate::device::PLUGIN_API_VERSION as i32 || declared < crate::device::PLUGIN_API_MIN_SUPPORTED as i32 {
        return Err(HyperbugError::Config(format!(
            "{path} declares hyperbug_abi_version={declared}, but this hyperbug build supports the range \
             [{}, {}]",
            crate::device::PLUGIN_API_MIN_SUPPORTED,
            crate::device::PLUGIN_API_VERSION
        )));
    }

    let read_fn: TypedFunc<(i64, i32, i32), ()> = required_export(&instance, &mut store, path, "hyperbug_read")?;
    let write_fn: TypedFunc<(i64, i32, i32), i32> = required_export(&instance, &mut store, path, "hyperbug_write")?;
    let tick_fn: Option<TypedFunc<(), ()>> = instance.get_typed_func(&mut store, "hyperbug_tick").ok();
    let reset_fn: Option<TypedFunc<(), ()>> = instance.get_typed_func(&mut store, "hyperbug_reset").ok();
    let pci_identity_fn: Option<TypedFunc<i32, i32>> = instance.get_typed_func(&mut store, "hyperbug_pci_identity").ok();

    if let Ok(create_fn) = instance.get_typed_func::<(), ()>(&mut store, "hyperbug_create") {
        create_fn.call(&mut store, ()).map_err(|e| HyperbugError::Config(format!("{path}: hyperbug_create trapped: {e}")))?;
    }

    let identity = if want_pci {
        match pci_identity_fn {
            Some(f) => {
                let has_identity = f
                    .call(&mut store, 0)
                    .map_err(|e| HyperbugError::Config(format!("{path}: hyperbug_pci_identity trapped: {e}")))?;
                if has_identity == 0 {
                    PluginIdentity::default()
                } else {
                    let mut buf = [0u8; 2 + 2 + 4 + NUM_BARS * 4 + 1 + 1 + 1];
                    memory
                        .read(&store, 0, &mut buf)
                        .map_err(|e| HyperbugError::Config(format!("{path}: reading wasm PCI identity scratch: {e}")))?;
                    parse_pci_identity(&buf)
                }
            }
            None => PluginIdentity::default(),
        }
    } else {
        PluginIdentity::default()
    };

    let transport = WasmTransport { store, memory, read_fn, write_fn, tick_fn, reset_fn };
    Ok(ScriptedDevice::new(Box::new(transport), identity, irq_pending))
}

fn required_export<Params, Results>(
    instance: &Instance,
    mut store: impl wasmtime::AsContextMut,
    path: &str,
    name: &str,
) -> Result<TypedFunc<Params, Results>, HyperbugError>
where
    Params: wasmtime::WasmParams,
    Results: wasmtime::WasmResults,
{
    instance
        .get_typed_func(&mut store, name)
        .map_err(|e| HyperbugError::Config(format!("{path}: missing or mistyped required export {name}: {e}")))
}

/// Mirrors `native_plugin.rs`'s `CPciIdentity` byte layout exactly:
/// `<u16 vendor><u16 device><u32 class><6x u32 bar_sizes><u8 io_mask>
/// <u8 interrupt_line><u8 msi_capable>` — the same shape
/// `docs/wasm-plugin-api.md` documents for `hyperbug_pci_identity` to
/// write into its scratch region.
fn parse_pci_identity(buf: &[u8]) -> PluginIdentity {
    let vendor_id = u16::from_le_bytes(buf[0..2].try_into().unwrap());
    let device_id = u16::from_le_bytes(buf[2..4].try_into().unwrap());
    let class_code = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let mut bar_sizes = [0u32; NUM_BARS];
    for (i, slot) in bar_sizes.iter_mut().enumerate() {
        let off = 8 + i * 4;
        *slot = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
    }
    let io_mask = buf[8 + NUM_BARS * 4];
    let mut bar_is_io = [false; NUM_BARS];
    for (i, flag) in bar_is_io.iter_mut().enumerate() {
        *flag = io_mask & (1 << i) != 0;
    }
    let interrupt_line = buf[8 + NUM_BARS * 4 + 1];
    let msi_capable = buf[8 + NUM_BARS * 4 + 2] != 0;
    PluginIdentity { vendor_id, device_id, class_code, bar_sizes, bar_is_io, interrupt_line, msi_capable }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Device;
    use crate::pci::PciDevice;

    /// Compiles `devices/{name}.rs` to a real `.wasm` module via
    /// `rustc --target wasm32-unknown-unknown --crate-type=cdylib`, the
    /// same "compile the real reference plugin on the fly" convention
    /// `native_plugin.rs`'s tests use for its `.c` files — so this test is
    /// self-contained and doesn't depend on a stale checked-in `.wasm`.
    /// Skips cleanly if the `wasm32-unknown-unknown` target isn't
    /// installed.
    fn compile_plugin(name: &str) -> Option<std::path::PathBuf> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let source = format!("{manifest_dir}/devices/{name}.rs");
        let out = std::env::temp_dir().join(format!("hyperbug-wasm-test-{name}-{}.wasm", std::process::id()));
        let status = std::process::Command::new("rustc")
            .args(["--target", "wasm32-unknown-unknown", "--crate-type=cdylib", "-O", "-o"])
            .arg(&out)
            .arg(&source)
            .status()
            .expect("failed to run rustc");
        if !status.success() {
            return None;
        }
        Some(out)
    }

    fn compile_scratch() -> Option<std::path::PathBuf> {
        compile_plugin("wasm_scratch")
    }

    fn compile_dma_demo() -> Option<std::path::PathBuf> {
        compile_plugin("wasm_dma_demo")
    }

    /// The real point of this whole module: a plugin compiled to
    /// WebAssembly, not Python or a native `.so`, driven through the exact
    /// same `Device` trait calls every other transport goes through.
    #[test]
    fn a_wasm_plugin_handles_read_write_through_the_sandbox() {
        let Some(wasm_path) = compile_scratch() else {
            eprintln!("skipping: wasm32-unknown-unknown target not installed");
            return;
        };
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let mut device = load(wasm_path.to_str().unwrap(), mem, None).expect("wasm_scratch.wasm should load");

        Device::write(&mut device, 0, &[0xde, 0xad, 0xbe, 0xef]);
        let mut buf = [0u8; 4];
        Device::read(&mut device, 0, &mut buf);
        assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);

        // Offsets past the plugin's own 16-byte register file read as
        // zero and writes there are silently dropped, matching
        // `wasm_scratch.rs`'s own contract.
        let mut past = [0xffu8; 4];
        Device::read(&mut device, 100, &mut past);
        assert_eq!(past, [0, 0, 0, 0]);

        let _ = std::fs::remove_file(&wasm_path);
    }

    /// The full contract in one plugin: PCI identity via
    /// `hyperbug_pci_identity`, real DMA through the sandboxed
    /// `host_read_mem`/`host_write_mem` imports, a spontaneous interrupt
    /// via `host_raise_irq`, and `tick`/`reset` both actually called.
    #[test]
    fn a_wasm_pci_plugin_does_real_dma_raises_irq_ticks_and_resets() {
        let Some(wasm_path) = compile_dma_demo() else {
            eprintln!("skipping: wasm32-unknown-unknown target not installed");
            return;
        };
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let buffer_addr: u64 = 0x100;
        let payload = b"hyperbug";
        mem.lock().unwrap().write_checked(buffer_addr, payload);

        let mut device = load_pci(wasm_path.to_str().unwrap(), mem.clone(), None).expect("wasm_dma_demo.wasm should load");

        assert_eq!(device.vendor_id(), 0x1234);
        assert_eq!(device.device_id(), 0x0002);
        assert_eq!(device.class_code(), 0xff_00_00);
        assert_eq!(device.bar_sizes()[0], 0x10);
        assert_eq!(device.interrupt_line(), 9);
        assert!(device.msi_capable());

        Device::write(&mut device, 0x00, &buffer_addr.to_le_bytes());
        Device::write(&mut device, 0x08, &(payload.len() as u32).to_le_bytes());
        Device::write(&mut device, 0x0c, &[1]);

        assert!(device.take_pending_irq(), "raise_irq() through the wasm sandbox should have set the pending flag");
        assert!(!device.take_pending_irq(), "the flag should clear once taken");

        let mut result = [0u8; 8];
        mem.lock().unwrap().read_checked(buffer_addr, &mut result);
        assert_eq!(&result, b"gubrepyh", "the buffer should be reversed in place via real DMA through the wasm sandbox");

        Device::tick(&mut device);
        Device::tick(&mut device);
        Device::reset(&mut device);

        let _ = std::fs::remove_file(&wasm_path);
    }

    /// A plugin missing a required export fails to load with a clear
    /// message naming which one, instead of a raw wasmtime trap/panic.
    #[test]
    fn a_plugin_missing_a_required_export_fails_to_load_cleanly() {
        let dir = std::env::temp_dir().join(format!("hyperbug-wasm-badplugin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("incomplete.rs");
        // Declares the ABI version but never `hyperbug_read`/`hyperbug_write`.
        std::fs::write(
            &source,
            "#![no_std]\n\
             #[panic_handler]\n\
             fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }\n\
             #[no_mangle]\n\
             pub extern \"C\" fn hyperbug_abi_version() -> i32 { 1 }\n",
        )
        .unwrap();
        let out = dir.join("incomplete.wasm");
        let status = std::process::Command::new("rustc")
            .args(["--target", "wasm32-unknown-unknown", "--crate-type=cdylib", "-O", "-o"])
            .arg(&out)
            .arg(&source)
            .status()
            .expect("failed to run rustc");
        if !status.success() {
            eprintln!("skipping: wasm32-unknown-unknown target not installed");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match load(out.to_str().unwrap(), mem, None) {
            Ok(_) => panic!("should fail: missing hyperbug_read/hyperbug_write"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("hyperbug_read"), "error should name the missing export, got: {msg}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A module declaring an ABI version outside
    /// `[PLUGIN_API_MIN_SUPPORTED, PLUGIN_API_VERSION]` is refused at load
    /// with a clear message, not silently run against a stale contract.
    #[test]
    fn a_mismatched_abi_version_is_refused_at_load() {
        let dir = std::env::temp_dir().join(format!("hyperbug-wasm-badabi-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("badabi.rs");
        std::fs::write(
            &source,
            "#![no_std]\n\
             #[panic_handler]\n\
             fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }\n\
             #[no_mangle]\n\
             pub extern \"C\" fn hyperbug_abi_version() -> i32 { 999 }\n\
             #[no_mangle]\n\
             pub extern \"C\" fn hyperbug_read(_offset: i64, _len: i32, _u: i32) {}\n\
             #[no_mangle]\n\
             pub extern \"C\" fn hyperbug_write(_offset: i64, _u: i32, _len: i32) -> i32 { 0 }\n",
        )
        .unwrap();
        let out = dir.join("badabi.wasm");
        let status = std::process::Command::new("rustc")
            .args(["--target", "wasm32-unknown-unknown", "--crate-type=cdylib", "-O", "-o"])
            .arg(&out)
            .arg(&source)
            .status()
            .expect("failed to run rustc");
        if !status.success() {
            eprintln!("skipping: wasm32-unknown-unknown target not installed");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        let err = match load(out.to_str().unwrap(), mem, None) {
            Ok(_) => panic!("ABI version 999 should be refused"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("999"), "error should mention the declared version, got: {msg}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
