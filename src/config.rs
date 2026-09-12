//! Everything that describes *what guest to run*, separate from the code
//! that runs it: `Args` plus the two device-plugin specs, and the CLI
//! parser that builds an `Args` from `argv`.
//!
//! The parser lives here rather than in `main.rs` so it's a plain,
//! testable function over an argument iterator (`Args::parse`) instead of
//! something entangled with `std::process::exit`. `main.rs` is left with
//! nothing but "parse, run, translate the result into an exit code"; an
//! embedder builds an `Args` directly and never goes through any of this.

/// A `--device <path>:<class>:<base>:<size>[:<dma_base>:<dma_size>]` spec:
/// a Python device mapped at a fixed MMIO address, with an optional
/// DMA-confinement range — see `dma_range`'s own doc comment below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSpec {
    pub path: String,
    pub class: String,
    pub base: u64,
    pub size: u64,
    pub dma_range: Option<(u64, u64)>,
}

fn parse_hex(s: &str, what: &str) -> Result<u64, String> {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(digits, 16).map_err(|e| format!("bad {what} {s:?}: {e}"))
}

/// Parses an optional trailing `<dma_base>:<dma_size>` pair (a host-side
/// vIOMMU-shaped restriction — see `device::dma_range_allows`'s doc
/// comment for what it enforces and why it's declared on the CLI rather
/// than trusted from the plugin's own Python attributes). `None` if
/// `rest` is empty — the default, unrestricted, matching every plugin's
/// behavior before this existed. A non-empty `rest` that isn't exactly
/// two hex fields is a config error, not silently ignored.
fn parse_dma_range(rest: &[&str], spec: &str) -> Result<Option<(u64, u64)>, String> {
    match rest {
        [] => Ok(None),
        [dma_base, dma_size] => {
            let dma_base = parse_hex(dma_base, "DMA range base")?;
            let dma_size = parse_hex(dma_size, "DMA range size")?;
            if dma_size == 0 {
                return Err(format!("{spec:?} has a zero-sized DMA range"));
            }
            if dma_base.checked_add(dma_size).is_none() {
                return Err(format!("{spec:?}'s DMA range wraps past the end of the address space"));
            }
            Ok(Some((dma_base, dma_size)))
        }
        _ => Err(format!("{spec:?} has a trailing DMA range that isn't exactly <dma_base>:<dma_size>")),
    }
}

impl DeviceSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let [path, class, base, size, rest @ ..] = parts.as_slice() else {
            return Err(format!(
                "expected --device <path>:<class>:<base>:<size>[:<dma_base>:<dma_size>], got {spec:?}"
            ));
        };
        let base = parse_hex(base, "base address")?;
        let size = parse_hex(size, "size")?;
        if size == 0 {
            return Err(format!("--device {spec:?} has a zero size"));
        }
        if base.checked_add(size).is_none() {
            return Err(format!("--device {spec:?} wraps past the end of the address space"));
        }
        let dma_range = parse_dma_range(rest, spec)?;
        Ok(Self { path: (*path).to_string(), class: (*class).to_string(), base, size, dma_range })
    }
}

/// A `--pci-device <path>:<class>:<device_number>[:<dma_base>:<dma_size>]`
/// spec: a Python device registered on the PCI bus (function 0), whose
/// identity (vendor/device ID, class code, BAR sizes) and BAR-mapped
/// address come from the Python object itself and PCI enumeration,
/// respectively — not from the CLI. This is the only way any specific PCI
/// device (HECI or otherwise) enters the picture: hyperbug's own code has
/// no opinion on what it is.
///
/// Slots 4-17 are reserved for hyperbug's own virtio devices (see
/// `machine.rs`) — picking one of those here is reported as a
/// configuration error rather than silently shadowing anything. Use 1-3 or
/// 18-31.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciDeviceSpec {
    pub path: String,
    pub class: String,
    pub device_number: u8,
    /// Optional DMA confinement, restricting `self.hyperbug.read_mem`/
    /// `write_mem` to this `(base, size)` range regardless of what the
    /// plugin's own Python code does — see `device::dma_range_allows`.
    /// Declared on the CLI, not read from a Python attribute: the plugin
    /// is exactly the party this is meant to constrain, so it can't be
    /// trusted to declare its own confinement (a malicious plugin would
    /// just declare "everything"). `None` (the default) is unrestricted,
    /// appropriate for a trusted first-party plugin — hyperbug's own
    /// `devices/*.py` examples included.
    pub dma_range: Option<(u64, u64)>,
}

/// The highest PCI device number a single bus has.
pub const MAX_PCI_DEVICE_NUMBER: u8 = 31;

impl PciDeviceSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let [path, class, devnum, rest @ ..] = parts.as_slice() else {
            return Err(format!(
                "expected --pci-device <path>:<class>:<device_number 0-{MAX_PCI_DEVICE_NUMBER}>\
                 [:<dma_base>:<dma_size>], got {spec:?}"
            ));
        };
        let device_number: u8 =
            devnum.parse().map_err(|e| format!("bad PCI device number {devnum:?}: {e}"))?;
        if device_number > MAX_PCI_DEVICE_NUMBER {
            return Err(format!(
                "PCI device number {device_number} must be 0-{MAX_PCI_DEVICE_NUMBER}"
            ));
        }
        let dma_range = parse_dma_range(rest, spec)?;
        Ok(Self { path: (*path).to_string(), class: (*class).to_string(), device_number, dma_range })
    }

    /// The PCI devfn (device number, function 0) this spec names.
    pub fn devfn(&self) -> u8 {
        self.device_number << 3
    }
}

pub const USAGE: &str = "usage: hyperbug --kernel <bzImage> [--initrd <cpio.gz>] [--mem <MB>] \
     [--cmdline <str>] [--device <path.py>:<class>:<base>:<size>[:<dma_base>:<dma_size>]]... \
     [--pci-device <path.py>:<class>:<device_number>[:<dma_base>:<dma_size>]]... \
     [--device-sandboxed <path.py>:<class>:<base>:<size>[:<dma_base>:<dma_size>]]... \
     [--pci-device-sandboxed <path.py>:<class>:<device_number>[:<dma_base>:<dma_size>]]... \
     [--disk <path>]... [--net] [--rng-modern] [--control-socket <path>] [--smp <N>] \
     [--restore <path>]";

/// The kernel command line used when `--cmdline` isn't given.
///
/// No explicit `reboot=` method: now that the FADT advertises a real
/// `RESET_REG` (`acpi.rs`), Linux's default reboot-method order tries ACPI
/// reset first, giving a real, distinguishable requested-reboot exit path
/// (see `acpi::exit_code`) instead of always falling back to the ambiguous
/// triple-fault trick `reboot=k` used to force.
pub const DEFAULT_CMDLINE: &str = "console=ttyS0 panic=1";

pub const DEFAULT_MEM_MB: u64 = 256;

pub struct Args {
    pub kernel: String,
    pub initrd: Option<String>,
    pub mem_mb: u64,
    pub cmdline: String,
    pub devices: Vec<DeviceSpec>,
    pub pci_devices: Vec<PciDeviceSpec>,
    /// `--device-sandboxed`: same spec syntax as `devices`, but the plugin
    /// runs in its own subprocess (DEBTS.md item 9) instead of in-process
    /// — a hung or crashed plugin gets killed rather than stalling or
    /// taking down the whole guest. See `pydevice_proc.rs`.
    pub sandboxed_devices: Vec<DeviceSpec>,
    /// `--pci-device-sandboxed`: the `--pci-device` equivalent.
    pub sandboxed_pci_devices: Vec<PciDeviceSpec>,
    pub disks: Vec<String>,
    pub net: bool,
    /// Attaches virtio-rng over the modern virtio 1.0 PCI transport
    /// (`VirtioModernPci`) instead of the legacy I/O-BAR one every other
    /// virtio device here still uses. Opt-in, on the same PCI slot/GSI as
    /// the legacy rng, rather than replacing it outright — this is the
    /// first real vertical slice of the modern transport, not yet
    /// extended to virtio-blk/virtio-net.
    pub rng_modern: bool,
    pub control_socket: Option<String>,
    pub smp: u8,
    /// `--restore`: instead of booting `kernel`/`initrd` normally, load a
    /// snapshot written by the control socket's `snapshot <path>` command
    /// (`src/snapshot.rs`) — guest memory, vCPU state, and every
    /// snapshotted device's protocol state — and resume execution from
    /// exactly that point. `kernel` is still required by the parser but
    /// unused in this mode (device wiring — disks/net/pci-devices — still
    /// comes from the rest of `Args`, and must match what was running
    /// when the snapshot was taken). DEBTS.md item 8 has the full scope
    /// and limitations (single-vCPU only, no Python device plugin state).
    pub restore: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            kernel: String::new(),
            initrd: None,
            mem_mb: DEFAULT_MEM_MB,
            cmdline: DEFAULT_CMDLINE.to_string(),
            devices: Vec::new(),
            pci_devices: Vec::new(),
            sandboxed_devices: Vec::new(),
            sandboxed_pci_devices: Vec::new(),
            disks: Vec::new(),
            net: false,
            rng_modern: false,
            control_socket: None,
            smp: 1,
            restore: None,
        }
    }
}

/// Takes the value that follows a flag, or reports which flag was missing
/// one — centralized so each parse arm below stays a single line.
fn next_value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires an argument"))
}

impl Args {
    /// Parses `argv` (without the program name). Every failure is a plain
    /// message the caller decides what to do with — unlike the previous
    /// version, which called `std::process::exit` from inside the parse
    /// loop and so couldn't be tested at all.
    pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Result<Self, String> {
        let mut args = Args::default();
        let mut kernel = None;
        let mut it = argv.into_iter();

        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--kernel" => kernel = Some(next_value(&mut it, &arg)?),
                "--initrd" => args.initrd = Some(next_value(&mut it, &arg)?),
                "--cmdline" => args.cmdline = next_value(&mut it, &arg)?,
                "--control-socket" => args.control_socket = Some(next_value(&mut it, &arg)?),
                "--disk" => args.disks.push(next_value(&mut it, &arg)?),
                "--net" => args.net = true,
                "--rng-modern" => args.rng_modern = true,
                "--restore" => args.restore = Some(next_value(&mut it, &arg)?),
                "--mem" => {
                    let v = next_value(&mut it, &arg)?;
                    args.mem_mb = v.parse().map_err(|e| format!("bad --mem {v:?}: {e}"))?;
                }
                "--smp" => {
                    let v = next_value(&mut it, &arg)?;
                    args.smp = v.parse().map_err(|e| format!("bad --smp {v:?}: {e}"))?;
                }
                "--device" => args.devices.push(DeviceSpec::parse(&next_value(&mut it, &arg)?)?),
                "--pci-device" => {
                    args.pci_devices.push(PciDeviceSpec::parse(&next_value(&mut it, &arg)?)?);
                }
                "--device-sandboxed" => {
                    args.sandboxed_devices.push(DeviceSpec::parse(&next_value(&mut it, &arg)?)?);
                }
                "--pci-device-sandboxed" => {
                    args.sandboxed_pci_devices.push(PciDeviceSpec::parse(&next_value(&mut it, &arg)?)?);
                }
                other => return Err(format!("unrecognized argument: {other}")),
            }
        }

        args.kernel = kernel.ok_or_else(|| format!("--kernel is required\n{USAGE}"))?;
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn a_minimal_command_line_uses_every_default() {
        let args = Args::parse(argv("--kernel vmlinuz")).unwrap();
        assert_eq!(args.kernel, "vmlinuz");
        assert_eq!(args.mem_mb, DEFAULT_MEM_MB);
        assert_eq!(args.cmdline, DEFAULT_CMDLINE);
        assert_eq!(args.smp, 1);
        assert!(!args.net);
        assert!(args.disks.is_empty());
    }

    #[test]
    fn repeated_flags_accumulate_in_order() {
        let args = Args::parse(argv("--kernel k --disk a --disk b")).unwrap();
        assert_eq!(args.disks, ["a", "b"]);
    }

    #[test]
    fn sandboxed_device_specs_are_kept_separate_from_in_process_ones() {
        let args = Args::parse(argv(
            "--kernel k --device d.py:A:0x1000:0x10 \
             --device-sandboxed s.py:B:0x2000:0x10 \
             --pci-device-sandboxed s.py:C:3",
        ))
        .unwrap();
        assert_eq!(args.devices.len(), 1);
        assert_eq!(args.devices[0].class, "A");
        assert_eq!(args.sandboxed_devices.len(), 1);
        assert_eq!(args.sandboxed_devices[0].class, "B");
        assert_eq!(args.sandboxed_pci_devices.len(), 1);
        assert_eq!(args.sandboxed_pci_devices[0].class, "C");
    }

    #[test]
    fn missing_values_and_unknown_flags_are_errors_not_silent_defaults() {
        assert!(Args::parse(argv("--kernel")).is_err(), "flag with no value");
        assert!(Args::parse(argv("--disk a")).is_err(), "no --kernel at all");
        assert!(Args::parse(argv("--kernel k --nope")).is_err(), "unknown flag");
        // The old parser silently kept the default here rather than
        // telling anyone the value was unusable.
        assert!(Args::parse(argv("--kernel k --mem banana")).is_err());
        assert!(Args::parse(argv("--kernel k --smp banana")).is_err());
    }

    #[test]
    fn device_specs_parse_hex_with_or_without_a_prefix() {
        let spec = DeviceSpec::parse("d.py:Cls:0xd0000000:1000").unwrap();
        assert_eq!(spec.path, "d.py");
        assert_eq!(spec.class, "Cls");
        assert_eq!(spec.base, 0xd000_0000);
        assert_eq!(spec.size, 0x1000);
    }

    #[test]
    fn malformed_device_specs_are_rejected() {
        assert!(DeviceSpec::parse("d.py:Cls:0x1000").is_err(), "too few fields");
        assert!(DeviceSpec::parse("d.py:Cls:nothex:1000").is_err());
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0").is_err(), "zero size maps nothing");
        assert!(
            DeviceSpec::parse("d.py:Cls:ffffffffffffffff:1000").is_err(),
            "a range that wraps the address space"
        );
    }

    #[test]
    fn pci_device_specs_bound_the_device_number() {
        assert_eq!(PciDeviceSpec::parse("d.py:Cls:3").unwrap().devfn(), 24);
        assert!(PciDeviceSpec::parse("d.py:Cls:32").is_err());
        assert!(PciDeviceSpec::parse("d.py:Cls:-1").is_err());
        assert!(PciDeviceSpec::parse("d.py:Cls").is_err());
    }

    #[test]
    fn an_optional_dma_range_is_parsed_for_both_device_and_pci_device_specs() {
        let spec = DeviceSpec::parse("d.py:Cls:0x1000:0x100:0x2000:0x1000").unwrap();
        assert_eq!(spec.dma_range, Some((0x2000, 0x1000)));
        assert_eq!(DeviceSpec::parse("d.py:Cls:0x1000:0x100").unwrap().dma_range, None, "no trailing fields");

        let spec = PciDeviceSpec::parse("d.py:Cls:3:0x2000:0x1000").unwrap();
        assert_eq!(spec.dma_range, Some((0x2000, 0x1000)));
        assert_eq!(PciDeviceSpec::parse("d.py:Cls:3").unwrap().dma_range, None, "no trailing fields");
    }

    #[test]
    fn a_malformed_dma_range_is_rejected_not_silently_dropped() {
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:onlyonefield").is_err());
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:notahex:0x1000").is_err());
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:0x2000:0").is_err(), "zero-sized DMA range");
        assert!(
            DeviceSpec::parse("d.py:Cls:0x1000:0x100:ffffffffffffffff:0x1000").is_err(),
            "a DMA range that wraps the address space"
        );
        assert!(PciDeviceSpec::parse("d.py:Cls:3:onlyonefield").is_err());
    }
}
