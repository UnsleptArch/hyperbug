// The WASM-transport analog of `native_scratch.c`: the simplest possible
// plugin, a 16-byte register file with no PCI identity and no DMA/IRQ/
// tick/reset. Compiled on the fly by `wasm_plugin.rs`'s own tests (via
// `rustc --target wasm32-unknown-unknown --crate-type=cdylib`) — see
// `docs/wasm-plugin-api.md` for the full ABI this implements.
#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

static mut REGS: [u8; 16] = [0; 16];

#[no_mangle]
pub extern "C" fn hyperbug_abi_version() -> i32 {
    1
}

/// Copies `len` bytes of the register file starting at `offset` into the
/// scratch region (linear-memory offset 0), where the host reads them.
///
/// Uses `write_volatile`/`read_volatile` rather than a plain dereference:
/// a pointer manufactured from the integer literal 0 has no provenance
/// over that memory as far as Rust's aliasing model is concerned, even
/// though address 0 is a perfectly ordinary, accessible address in wasm
/// linear memory — LLVM has been observed eliding a plain store through
/// such a pointer as unreachable-UB cleanup. Volatile access is never
/// removed by the optimizer regardless of provenance.
#[no_mangle]
pub extern "C" fn hyperbug_read(offset: i64, len: i32, _unused: i32) {
    let off = offset as usize;
    unsafe {
        let scratch = 0usize as *mut u8;
        let regs = &raw const REGS;
        for i in 0..(len as usize) {
            let src = off + i;
            let val = if src < (*regs).len() { (*regs)[src] } else { 0 };
            core::ptr::write_volatile(scratch.add(i), val);
        }
    }
}

/// Copies `len` bytes the host already placed in the scratch region into
/// the register file at `offset`. Bytes past the 16-byte register file are
/// silently dropped, matching `native_scratch.c`'s own behavior.
#[no_mangle]
pub extern "C" fn hyperbug_write(offset: i64, _unused: i32, len: i32) -> i32 {
    let off = offset as usize;
    unsafe {
        let scratch = 0usize as *const u8;
        let regs = &raw mut REGS;
        for i in 0..(len as usize) {
            let dst = off + i;
            if dst < (*regs).len() {
                (*regs)[dst] = core::ptr::read_volatile(scratch.add(i));
            }
        }
    }
    0
}
