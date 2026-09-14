// The WASM-transport analog of `native_dma_demo.c`: full contract exercise
// — PCI identity, DMA via the host `read_mem`/`write_mem` callbacks, a
// spontaneous interrupt, and `tick`/`reset`. Compiled on the fly by
// `wasm_plugin.rs`'s own tests. See `docs/wasm-plugin-api.md`.
//
// Register layout (matches `native_dma_demo.c` exactly, so both transports'
// tests can drive the same protocol):
//   0x00..0x08  u64 LE  guest-physical buffer address
//   0x08..0x0c  u32 LE  buffer length in bytes
//   0x0c        u8      write 1 to trigger: reverse the buffer via real
//                        DMA, then raise an interrupt
#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link(wasm_import_module = "env")]
extern "C" {
    fn host_read_mem(addr: i64, buf_ptr: i32, size: i32) -> i32;
    fn host_write_mem(addr: i64, buf_ptr: i32, size: i32) -> i32;
    fn host_raise_irq();
}

const MAX_BUFFER: usize = 256;

static mut BUFFER_ADDR: u64 = 0;
static mut BUFFER_LEN: u32 = 0;
static mut TICK_COUNT: u32 = 0;
static mut SCRATCH: [u8; MAX_BUFFER] = [0; MAX_BUFFER];

#[no_mangle]
pub extern "C" fn hyperbug_abi_version() -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn hyperbug_read(offset: i64, len: i32, _unused: i32) {
    unsafe {
        let mut buf = [0u8; 16];
        match offset {
            0x00 => buf[..8].copy_from_slice(&BUFFER_ADDR.to_le_bytes()),
            0x08 => buf[..4].copy_from_slice(&BUFFER_LEN.to_le_bytes()),
            _ => {}
        }
        // Volatile: see `wasm_scratch.rs`'s `hyperbug_read` doc comment —
        // a pointer built from the integer 0 needs volatile access or the
        // optimizer can (and has been observed to) elide the store.
        let scratch = 0usize as *mut u8;
        for i in 0..(len as usize).min(buf.len()) {
            core::ptr::write_volatile(scratch.add(i), buf[i]);
        }
    }
}

#[no_mangle]
pub extern "C" fn hyperbug_write(offset: i64, _unused: i32, len: i32) -> i32 {
    unsafe {
        let scratch = 0usize as *const u8;
        let mut buf = [0u8; 16];
        for i in 0..(len as usize).min(buf.len()) {
            buf[i] = core::ptr::read_volatile(scratch.add(i));
        }
        match offset {
            0x00 => {
                let mut addr_bytes = [0u8; 8];
                addr_bytes.copy_from_slice(&buf[..8]);
                BUFFER_ADDR = u64::from_le_bytes(addr_bytes);
            }
            0x08 => {
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&buf[..4]);
                BUFFER_LEN = u32::from_le_bytes(len_bytes);
            }
            0x0c => {
                if buf[0] != 0 {
                    reverse_buffer_via_dma();
                    host_raise_irq();
                }
            }
            _ => {}
        }
    }
    0
}

unsafe fn reverse_buffer_via_dma() {
    let len = (BUFFER_LEN as usize).min(MAX_BUFFER);
    let scratch = (&raw mut SCRATCH) as *mut u8;
    if host_read_mem(BUFFER_ADDR as i64, scratch as i32, len as i32) != 0 {
        return;
    }
    for i in 0..(len / 2) {
        let a = scratch.add(i);
        let b = scratch.add(len - 1 - i);
        core::ptr::swap(a, b);
    }
    host_write_mem(BUFFER_ADDR as i64, scratch as i32, len as i32);
}

#[no_mangle]
pub extern "C" fn hyperbug_tick() {
    unsafe {
        TICK_COUNT += 1;
    }
}

#[no_mangle]
pub extern "C" fn hyperbug_reset() {
    unsafe {
        BUFFER_ADDR = 0;
        BUFFER_LEN = 0;
        TICK_COUNT = 0;
    }
}

/// Called first with `has_identity_probe == 0` just to ask "do you have an
/// identity at all"; returns nonzero and writes the identity struct into
/// the scratch region if so. Layout mirrors `native_plugin.rs`'s
/// `CPciIdentity`: `<u16 vendor><u16 device><u32 class><6x u32 bar_sizes>
/// <u8 io_mask><u8 interrupt_line><u8 msi_capable>`.
#[no_mangle]
pub extern "C" fn hyperbug_pci_identity(_has_identity_probe: i32) -> i32 {
    unsafe {
        let scratch = 0usize as *mut u8;
        let mut off = 0usize;
        macro_rules! put {
            ($bytes:expr) => {{
                let b = $bytes;
                for byte in b {
                    core::ptr::write_volatile(scratch.add(off), byte);
                    off += 1;
                }
            }};
        }
        put!(0x1234u16.to_le_bytes());
        put!(0x0002u16.to_le_bytes());
        put!(0xff_00_00u32.to_le_bytes());
        put!(0x10u32.to_le_bytes());
        for _ in 1..6 {
            put!(0u32.to_le_bytes());
        }
        put!([0u8]); // io_mask: no I/O-space BARs
        put!([9u8]); // interrupt_line
        put!([1u8]); // msi_capable
    }
    1
}
