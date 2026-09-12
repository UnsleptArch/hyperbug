//! Linux x86_64 boot protocol: bzImage parsing, zero-page (boot_params)
//! construction, and initramfs/cmdline placement. Layout constants match
//! the well-known Firecracker/crosvm conventions.
//! Reference: Documentation/x86/boot.txt in the kernel source.
//!
//! The image is parsed exactly once, into a `BzImage`, rather than having
//! each step re-derive `setup_sects` from the raw bytes and re-validate
//! (or, as `build_zero_page` used to, not validate at all and index into
//! the slice on faith).

use std::fs;
use std::io;

use crate::mem::GuestMemory;

pub const KERNEL_START: u64 = 0x100000; // 1 MiB: protected-mode kernel load addr
pub const ZERO_PAGE_START: u64 = 0x7000; // occupies [0x7000, 0x8000)
pub const CMDLINE_START: u64 = 0x20000;
/// Initial boot stack top, one page below `CMDLINE_START`. Deliberately
/// isolated from every other low-memory structure (GDT at 0x500, zero page
/// at 0x7000, page tables at 0x9000+) so early pushes can't corrupt them.
pub const BOOT_STACK_TOP: u64 = CMDLINE_START - 0x1000;

// offsets within the real-mode kernel header / boot_params (setup_header)
const HDR_OFFSET: usize = 0x1f1;
const BOOT_FLAG_OFF: usize = 0x1fe;
const HEADER_MAGIC_OFF: usize = 0x202;
const XLOADFLAGS_OFF: usize = 0x236;
const TYPE_OF_LOADER_OFF: usize = 0x210;
const RAMDISK_IMAGE_OFF: usize = 0x218;
const RAMDISK_SIZE_OFF: usize = 0x21c;
const CMD_LINE_PTR_OFF: usize = 0x228;
const CMDLINE_SIZE_OFF: usize = 0x238;
const E820_ENTRIES_OFF: usize = 0x1e8;
const E820_TABLE_OFF: usize = 0x2d0;

/// Enough of the image to have read every header field above.
const MIN_HEADER_LEN: usize = 0x300;

const BOOT_FLAG_MAGIC: u16 = 0xaa55;
const HDRS_MAGIC: u32 = 0x5372_6448; // "HdrS" little-endian
const XLF_KERNEL_64: u16 = 1 << 0;

/// Command-line length a pre-2.06 kernel (no `cmdline_size` field) accepts.
const LEGACY_CMDLINE_MAX: u32 = 255;

const EBDA_START: u64 = 0x9_fc00;
const E820_RAM: u32 = 1;

/// The 32-bit `ramdisk_image`/`ramdisk_size` fields cap where an initramfs
/// can live. Rather than silently truncate the address for a guest with
/// more than 4 GiB of RAM (which is what happened before), placement is
/// simply confined below this line — the same thing every other loader
/// does absent the `ext_ramdisk_image` high-half fields.
const RAMDISK_ADDR_LIMIT: u64 = 1 << 32;

pub struct LoadedKernel {
    /// Guest-virtual (== guest-physical, identity mapped) 64-bit entry point.
    pub entry_point: u64,
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn read_u16(raw: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(raw[off..off + 2].try_into().unwrap())
}

fn read_u32(raw: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(raw[off..off + 4].try_into().unwrap())
}

/// A validated bzImage: the raw file plus the one derived value
/// (`setup_size`) every stage of loading needs.
pub struct BzImage {
    raw: Vec<u8>,
    /// Size of the real-mode setup area; the protected-mode kernel begins
    /// immediately after it.
    setup_size: usize,
}

impl BzImage {
    /// Reads and validates a bzImage. Every "is this really a 64-bit-boot
    /// bzImage" check lives here, once, rather than being spread over the
    /// individual loading steps.
    pub fn read(path: &str) -> io::Result<Self> {
        Self::parse(fs::read(path)?)
    }

    fn parse(raw: Vec<u8>) -> io::Result<Self> {
        if raw.len() < MIN_HEADER_LEN {
            return Err(bad("file too small to be a bzImage"));
        }
        if read_u16(&raw, BOOT_FLAG_OFF) != BOOT_FLAG_MAGIC {
            return Err(bad("missing 0xAA55 boot signature"));
        }
        if read_u32(&raw, HEADER_MAGIC_OFF) != HDRS_MAGIC {
            return Err(bad("missing \"HdrS\" header magic"));
        }
        if read_u16(&raw, XLOADFLAGS_OFF) & XLF_KERNEL_64 == 0 {
            return Err(bad("kernel does not support the 64-bit boot protocol"));
        }

        // setup_sects == 0 means the pre-historic default of 4, per the
        // boot protocol; the setup area is that many sectors plus the boot
        // sector itself.
        let setup_sects = match raw[HDR_OFFSET] {
            0 => 4usize,
            n => usize::from(n),
        };
        let setup_size = (setup_sects + 1) * 512;
        if raw.len() <= setup_size {
            return Err(bad("truncated bzImage: no protected-mode code past setup"));
        }
        Ok(Self { raw, setup_size })
    }

    /// The longest command line this kernel accepts, per its own header.
    fn cmdline_max(&self) -> u32 {
        match read_u32(&self.raw, CMDLINE_SIZE_OFF) {
            0 => LEGACY_CMDLINE_MAX, // pre-2.06: field doesn't exist
            n => n,
        }
    }

    /// Loads the protected-mode kernel at `KERNEL_START` and returns its
    /// 64-bit entry point.
    pub fn load(&self, mem: &mut GuestMemory, mem_size: u64) -> io::Result<LoadedKernel> {
        let code = &self.raw[self.setup_size..];
        if KERNEL_START + code.len() as u64 > mem_size {
            return Err(bad("guest memory too small to hold the kernel image"));
        }
        mem.write_slice_unchecked_boot_only(KERNEL_START, code);
        Ok(LoadedKernel { entry_point: KERNEL_START + 0x200 })
    }

    /// Writes the null-terminated kernel command line at `CMDLINE_START`,
    /// rejecting one longer than either this kernel's declared limit or
    /// the low-memory gap before the kernel image itself. Neither bound was
    /// checked before, so a long enough `--cmdline` would have scribbled
    /// over the kernel that was just loaded.
    pub fn write_cmdline(&self, mem: &mut GuestMemory, cmdline: &str) -> io::Result<()> {
        let with_nul = cmdline.len() as u64 + 1;
        let room = KERNEL_START - CMDLINE_START;
        let kernel_max = u64::from(self.cmdline_max());
        if with_nul > room || with_nul > kernel_max {
            return Err(bad(format!(
                "--cmdline is {} bytes; this kernel accepts at most {} and only {} bytes are \
                 reserved for it",
                cmdline.len(),
                kernel_max.saturating_sub(1),
                room - 1
            )));
        }
        mem.write_slice_unchecked_boot_only(CMDLINE_START, cmdline.as_bytes());
        mem.write_obj_unchecked_boot_only(CMDLINE_START + cmdline.len() as u64, 0u8);
        Ok(())
    }

    /// Builds the zero-page boot_params at `ZERO_PAGE_START`: the kernel's
    /// own setup_header (copied verbatim from the bzImage) patched with our
    /// loader-specific fields, plus an e820 memory map.
    pub fn build_zero_page(&self, mem: &mut GuestMemory, mem_size: u64, initramfs: Option<Initramfs>) {
        let mut zero_page = [0u8; 4096];
        // Copy the kernel's own real-mode header (setup_header) verbatim so
        // all fields we don't override (loadflags, version,
        // kernel_alignment, ...) stay exactly as the kernel build set them.
        // Only real header fields matter past this point; the rest of the
        // "setup" area is real-mode trampoline code the kernel never reads
        // out of boot_params, so capping at the zero page's size is safe
        // (and necessary).
        let header_end = self.setup_size.min(self.raw.len()).min(zero_page.len());
        let header = &self.raw[HDR_OFFSET..header_end];
        zero_page[HDR_OFFSET..HDR_OFFSET + header.len()].copy_from_slice(header);

        zero_page[TYPE_OF_LOADER_OFF] = 0xff; // undefined bootloader
        put_u32(&mut zero_page, CMD_LINE_PTR_OFF, CMDLINE_START as u32);

        if let Some(initramfs) = initramfs {
            // `Initramfs::load` guarantees both fit in 32 bits.
            put_u32(&mut zero_page, RAMDISK_IMAGE_OFF, initramfs.addr as u32);
            put_u32(&mut zero_page, RAMDISK_SIZE_OFF, initramfs.size as u32);
        }

        // e820: usable low memory below the EBDA, and usable memory from
        // 1 MiB up to the end of guest RAM (matches Firecracker's x86_64
        // layout). The BIOS-area gap between them is where `acpi.rs` puts
        // its tables — deliberately not advertised as RAM.
        let mut count = 0usize;
        let mut add_entry = |base: u64, len: u64| {
            let off = E820_TABLE_OFF + count * 20;
            zero_page[off..off + 8].copy_from_slice(&base.to_le_bytes());
            zero_page[off + 8..off + 16].copy_from_slice(&len.to_le_bytes());
            put_u32(&mut zero_page, off + 16, E820_RAM);
            count += 1;
        };
        add_entry(0, EBDA_START);
        if mem_size > KERNEL_START {
            add_entry(KERNEL_START, mem_size - KERNEL_START);
        }
        zero_page[E820_ENTRIES_OFF] = count as u8;

        mem.write_slice_unchecked_boot_only(ZERO_PAGE_START, &zero_page);
    }
}

fn put_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

/// Where an initramfs image ended up in guest memory.
#[derive(Clone, Copy)]
pub struct Initramfs {
    pub addr: u64,
    pub size: u64,
}

impl Initramfs {
    /// Loads an initramfs image as high in guest memory as it fits (page
    /// aligned, and below the 4 GiB `ramdisk_image` field's reach — see
    /// `RAMDISK_ADDR_LIMIT`).
    ///
    /// Every bound is checked *before* the placement arithmetic: the old
    /// order computed `mem_size - size` first and only then checked
    /// whether it had underflowed, which panics in a debug build and picks
    /// a wild address in a release one.
    pub fn load(mem: &mut GuestMemory, path: &str, mem_size: u64) -> io::Result<Self> {
        let raw = fs::read(path)?;
        let size = raw.len() as u64;
        let top = mem_size.min(RAMDISK_ADDR_LIMIT);
        if size == 0 {
            return Err(bad("initramfs is empty"));
        }
        if size > top.saturating_sub(KERNEL_START) {
            return Err(bad(format!(
                "initramfs of {size} bytes doesn't fit below {top:#x} in guest memory"
            )));
        }
        let addr = (top - size) & !0xfff; // page align, place near the top
        if addr < KERNEL_START {
            return Err(bad("initramfs too large for guest memory"));
        }
        mem.write_slice_unchecked_boot_only(addr, &raw);
        Ok(Self { addr, size })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal file with just enough valid header for `parse` to accept
    /// it, plus `code_len` bytes of "protected-mode kernel".
    fn fake_bzimage(code_len: usize) -> Vec<u8> {
        let setup_sects = 1u8;
        let setup_size = (usize::from(setup_sects) + 1) * 512;
        let mut raw = vec![0u8; setup_size + code_len];
        raw[HDR_OFFSET] = setup_sects;
        raw[BOOT_FLAG_OFF..BOOT_FLAG_OFF + 2].copy_from_slice(&BOOT_FLAG_MAGIC.to_le_bytes());
        raw[HEADER_MAGIC_OFF..HEADER_MAGIC_OFF + 4].copy_from_slice(&HDRS_MAGIC.to_le_bytes());
        raw[XLOADFLAGS_OFF..XLOADFLAGS_OFF + 2].copy_from_slice(&XLF_KERNEL_64.to_le_bytes());
        put_u32(&mut raw, CMDLINE_SIZE_OFF, 2047);
        raw
    }

    #[test]
    fn rejects_files_that_are_not_64_bit_bzimages() {
        assert!(BzImage::parse(vec![0u8; 16]).is_err(), "too small");

        let mut no_magic = fake_bzimage(512);
        no_magic[HEADER_MAGIC_OFF] ^= 0xff;
        assert!(BzImage::parse(no_magic).is_err(), "bad HdrS magic");

        let mut no_64bit = fake_bzimage(512);
        no_64bit[XLOADFLAGS_OFF] = 0;
        assert!(BzImage::parse(no_64bit).is_err(), "no 64-bit boot support");

        let truncated = fake_bzimage(0);
        assert!(BzImage::parse(truncated).is_err(), "no code past setup");
    }

    #[test]
    fn a_too_long_cmdline_is_rejected_instead_of_overwriting_the_kernel() {
        let image = BzImage::parse(fake_bzimage(512)).unwrap();
        let mut mem = GuestMemory::new(0x20_0000).unwrap();

        assert!(image.write_cmdline(&mut mem, "console=ttyS0").is_ok());
        assert!(
            image.write_cmdline(&mut mem, &"a".repeat(2047)).is_err(),
            "one byte past the kernel's own declared cmdline_size (with its NUL)"
        );
    }

    #[test]
    fn the_cmdline_is_written_null_terminated() {
        let image = BzImage::parse(fake_bzimage(512)).unwrap();
        let mut mem = GuestMemory::new(0x20_0000).unwrap();
        image.write_cmdline(&mut mem, "quiet").unwrap();

        let mut buf = [0u8; 6];
        assert!(mem.read_checked(CMDLINE_START, &mut buf));
        assert_eq!(&buf, b"quiet\0");
    }

    #[test]
    fn an_initramfs_larger_than_guest_ram_is_rejected_without_underflowing() {
        // The old code computed `mem_size - size` before checking, so this
        // case panicked in a debug build.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("hyperbug-initramfs-test-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 4 * 1024 * 1024]).unwrap();

        let mut mem = GuestMemory::new(0x20_0000).unwrap();
        let err = Initramfs::load(&mut mem, path.to_str().unwrap(), 0x20_0000);
        assert!(err.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_initramfs_stays_below_the_32_bit_ramdisk_field_limit() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("hyperbug-initramfs-hi-test-{}", std::process::id()));
        std::fs::write(&path, vec![0x5au8; 8192]).unwrap();

        // A mapping this large is virtual only (MAP_NORESERVE); nothing
        // beyond the placement address is ever touched.
        let mut mem = GuestMemory::new(6 * 1024 * 1024 * 1024).unwrap();
        let placed =
            Initramfs::load(&mut mem, path.to_str().unwrap(), 6 * 1024 * 1024 * 1024).unwrap();
        assert!(
            placed.addr + placed.size <= RAMDISK_ADDR_LIMIT,
            "placed at {:#x}, which a 32-bit ramdisk_image field can't express",
            placed.addr
        );
        assert_eq!(placed.size, 8192);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_zero_page_describes_low_ram_and_everything_above_1_mib() {
        let image = BzImage::parse(fake_bzimage(512)).unwrap();
        let mem_size = 0x20_0000;
        let mut mem = GuestMemory::new(mem_size as usize).unwrap();
        image.build_zero_page(&mut mem, mem_size, None);

        let mut entries = [0u8; 1];
        assert!(mem.read_checked(ZERO_PAGE_START + E820_ENTRIES_OFF as u64, &mut entries));
        assert_eq!(entries[0], 2);

        let table = ZERO_PAGE_START + E820_TABLE_OFF as u64;
        assert_eq!(mem.read_u64_checked(table).unwrap(), 0);
        assert_eq!(mem.read_u64_checked(table + 8).unwrap(), EBDA_START);
        assert_eq!(mem.read_u64_checked(table + 20).unwrap(), KERNEL_START);
        assert_eq!(mem.read_u64_checked(table + 28).unwrap(), mem_size - KERNEL_START);

        // The command-line pointer the kernel actually follows.
        assert_eq!(
            u64::from(mem.read_u32_checked(ZERO_PAGE_START + CMD_LINE_PTR_OFF as u64).unwrap()),
            CMDLINE_START
        );
    }
}
