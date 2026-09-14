//! Everything that describes *what guest to run*, separate from the code
//! that runs it: `Args` plus the two device-plugin specs, and the CLI
//! parser that builds an `Args` from `argv`.
//!
//! The parser lives here rather than in `main.rs` so it's a plain,
//! testable function over an argument iterator (`Args::parse`) instead of
//! something entangled with `std::process::exit`. `main.rs` is left with
//! nothing but "parse, run, translate the result into an exit code"; an
//! embedder builds an `Args` directly and never goes through any of this.

/// A `--device <path>:<class>:<base>:<size>[:<dma_base>:<dma_size>]
/// [:mem=<mb>][:cpu=<pct>]` spec: a Python device mapped at a fixed MMIO
/// address, with an optional DMA-confinement range and (sandboxed loads
/// only) optional resource limits — see `dma_range`/`resource_limits`'s
/// own doc comments below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSpec {
    pub path: String,
    pub class: String,
    pub base: u64,
    pub size: u64,
    pub dma_range: Option<(u64, u64)>,
    pub resource_limits: Option<ResourceLimits>,
}

/// A cgroups-v2-enforced memory ceiling and/or CPU quota for exactly one
/// `--device-sandboxed`/`--pci-device-sandboxed` plugin instance — see
/// `cgroup.rs` for how this is actually applied (best-effort: silently
/// skipped, with a warning, if cgroups v2 isn't available or this process
/// lacks permission to create one). Meaningless for an in-process
/// (`--device`/`--pci-device`) plugin, which shares the whole VMM
/// process's own resource budget — `Args::parse` rejects a spec
/// declaring these outside a sandboxed flag rather than silently
/// ignoring them.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ResourceLimits {
    pub mem_limit_mb: Option<u64>,
    pub cpu_quota_percent: Option<u32>,
}

fn parse_hex(s: &str, what: &str) -> Result<u64, String> {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(digits, 16).map_err(|e| format!("bad {what} {s:?}: {e}"))
}

/// What follows the mandatory positional fields on a `--device`/
/// `--pci-device` spec — see `parse_trailing_options`.
struct TrailingOptions {
    dma_range: Option<(u64, u64)>,
    resource_limits: Option<ResourceLimits>,
}

/// Parses everything after the mandatory positional fields: an optional
/// `<dma_base>:<dma_size>` pair (a host-side vIOMMU-shaped restriction —
/// see `device::dma_range_allows`'s doc comment for what it enforces and
/// why it's declared on the CLI rather than trusted from the plugin's
/// own Python attributes), followed by zero or more `key=value` tokens
/// (`mem=<mb>`, `cpu=<pct>`) for per-plugin resource limits. The two
/// trailing fields are recognized as a DMA range only when *neither*
/// contains `=` — so `mem=256` alone (no DMA range at all) parses fine,
/// and existing `<dma_base>:<dma_size>` specs keep working unchanged.
fn parse_trailing_options(rest: &[&str], spec: &str) -> Result<TrailingOptions, String> {
    let (dma_part, kv_part) = match rest {
        [a, b, tail @ ..] if !a.contains('=') && !b.contains('=') => (&rest[..2], tail),
        _ => (&rest[..0], rest),
    };

    let dma_range = match dma_part {
        [] => None,
        [dma_base, dma_size] => {
            let dma_base = parse_hex(dma_base, "DMA range base")?;
            let dma_size = parse_hex(dma_size, "DMA range size")?;
            if dma_size == 0 {
                return Err(format!("{spec:?} has a zero-sized DMA range"));
            }
            if dma_base.checked_add(dma_size).is_none() {
                return Err(format!("{spec:?}'s DMA range wraps past the end of the address space"));
            }
            Some((dma_base, dma_size))
        }
        _ => unreachable!("dma_part is always [] or exactly two elements"),
    };

    let mut limits = ResourceLimits::default();
    for token in kv_part {
        let Some((key, value)) = token.split_once('=') else {
            return Err(format!("{spec:?} has an unrecognized trailing field {token:?} (expected key=value)"));
        };
        match key {
            "mem" => {
                let mb: u64 = value.parse().map_err(|e| format!("{spec:?}'s mem={value:?}: {e}"))?;
                if mb == 0 {
                    return Err(format!("{spec:?} has a zero mem= limit"));
                }
                limits.mem_limit_mb = Some(mb);
            }
            "cpu" => {
                let pct: u32 = value.parse().map_err(|e| format!("{spec:?}'s cpu={value:?}: {e}"))?;
                if pct == 0 || pct > 10_000 {
                    return Err(format!("{spec:?}'s cpu={pct} must be 1-10000 (percent of one CPU, >100 allowed for multi-core quotas)"));
                }
                limits.cpu_quota_percent = Some(pct);
            }
            other => return Err(format!("{spec:?} has an unrecognized trailing key {other:?} (expected mem or cpu)")),
        }
    }
    let resource_limits =
        (limits.mem_limit_mb.is_some() || limits.cpu_quota_percent.is_some()).then_some(limits);
    Ok(TrailingOptions { dma_range, resource_limits })
}

impl DeviceSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let [path, class, base, size, rest @ ..] = parts.as_slice() else {
            return Err(format!(
                "expected --device <path>:<class>:<base>:<size>[:<dma_base>:<dma_size>][:mem=<mb>][:cpu=<pct>], \
                 got {spec:?}"
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
        let TrailingOptions { dma_range, resource_limits } = parse_trailing_options(rest, spec)?;
        Ok(Self { path: (*path).to_string(), class: (*class).to_string(), base, size, dma_range, resource_limits })
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
/// Slots 4-23 are reserved for hyperbug's own virtio devices (see
/// `machine.rs`) — picking one of those here is reported as a
/// configuration error rather than silently shadowing anything. Use 1-3 or
/// 24-31.
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
    /// See `ResourceLimits`'s own doc comment — meaningful only for
    /// `--pci-device-sandboxed`.
    pub resource_limits: Option<ResourceLimits>,
}

/// The highest PCI device number a single bus has.
pub const MAX_PCI_DEVICE_NUMBER: u8 = 31;

/// A `--gpio-device <path>:<class>` spec: a Python `GpioBank` (see
/// `python/hyperbug/device.py`) attached as its own real `virtio-gpio`
/// adapter — unlike I2C targets (which share one bus), each GPIO bank
/// gets its own PCI slot, matching real BMC hardware's typically several
/// independent GPIO controllers. No address field: there's exactly one
/// bank per spec, not a bus of several.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpioDeviceSpec {
    pub path: String,
    pub class: String,
}

impl GpioDeviceSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let [path, class] = parts.as_slice() else {
            return Err(format!("expected --gpio-device <path>:<class>, got {spec:?}"));
        };
        Ok(Self { path: (*path).to_string(), class: (*class).to_string() })
    }
}

/// A `--i2c-device <path>:<class>:<addr>` spec: a Python I2C target device
/// (see `python/hyperbug/device.py`'s `I2cDevice`) attached to hyperbug's
/// single virtual I2C bus at 7-bit address `addr` (0x00-0x7f). Unlike
/// `DeviceSpec`/`PciDeviceSpec`, there's no DMA-confinement field — an I2C
/// target has no `self.hyperbug.read_mem`/`write_mem` at all (see
/// `i2c.rs`'s `I2cTargetDevice` trait: it only ever sees the bytes of the
/// message addressed to it, not guest memory).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I2cDeviceSpec {
    pub path: String,
    pub class: String,
    pub addr: u8,
}

impl I2cDeviceSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let [path, class, addr] = parts.as_slice() else {
            return Err(format!(
                "expected --i2c-device <path>:<class>:<addr 0x00-0x{:x}>, got {spec:?}",
                crate::i2c::MAX_I2C_ADDRESS
            ));
        };
        let addr = parse_hex(addr, "I2C address")?;
        if addr > u64::from(crate::i2c::MAX_I2C_ADDRESS) {
            return Err(format!(
                "--i2c-device {spec:?}: address {addr:#x} exceeds the 7-bit maximum {:#x}",
                crate::i2c::MAX_I2C_ADDRESS
            ));
        }
        Ok(Self { path: (*path).to_string(), class: (*class).to_string(), addr: addr as u8 })
    }
}

impl PciDeviceSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let [path, class, devnum, rest @ ..] = parts.as_slice() else {
            return Err(format!(
                "expected --pci-device <path>:<class>:<device_number 0-{MAX_PCI_DEVICE_NUMBER}>\
                 [:<dma_base>:<dma_size>][:mem=<mb>][:cpu=<pct>], got {spec:?}"
            ));
        };
        let device_number: u8 =
            devnum.parse().map_err(|e| format!("bad PCI device number {devnum:?}: {e}"))?;
        if device_number > MAX_PCI_DEVICE_NUMBER {
            return Err(format!(
                "PCI device number {device_number} must be 0-{MAX_PCI_DEVICE_NUMBER}"
            ));
        }
        let TrailingOptions { dma_range, resource_limits } = parse_trailing_options(rest, spec)?;
        Ok(Self { path: (*path).to_string(), class: (*class).to_string(), device_number, dma_range, resource_limits })
    }

    /// The PCI devfn (device number, function 0) this spec names.
    pub fn devfn(&self) -> u8 {
        self.device_number << 3
    }
}

/// A `<path>:<base>:<size>[:<dma_base>:<dma_size>]` spec shared by
/// `--native-device` (a `dlopen()`ed C-ABI plugin — see
/// `include/hyperbug_plugin.h`) and `--wasm-device` (a WASM module — see
/// `docs/wasm-plugin-api.md`) at a fixed MMIO address: both are
/// in-process, no-`class`-field transports (a shared object or WASM
/// module *is* the device — no equivalent of instantiating a named
/// Python class) with no `mem=`/`cpu=` (no subprocess to limit; both
/// share the whole VMM's own resource budget the same as an in-process
/// Python plugin — the WASM transport gets its own, different memory
/// ceiling instead, enforced by `wasmtime` itself, not this spec).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeDeviceSpec {
    pub path: String,
    pub base: u64,
    pub size: u64,
    pub dma_range: Option<(u64, u64)>,
}

impl NativeDeviceSpec {
    /// `flag` is the CLI flag this spec is being parsed for
    /// (`--native-device` or `--wasm-device`) — used only to make error
    /// messages name the flag the operator actually typed.
    pub fn parse(flag: &str, spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let [path, base, size, rest @ ..] = parts.as_slice() else {
            return Err(format!("expected {flag} <path>:<base>:<size>[:<dma_base>:<dma_size>], got {spec:?}"));
        };
        let base = parse_hex(base, "base address")?;
        let size = parse_hex(size, "size")?;
        if size == 0 {
            return Err(format!("{flag} {spec:?} has a zero size"));
        }
        if base.checked_add(size).is_none() {
            return Err(format!("{flag} {spec:?} wraps past the end of the address space"));
        }
        let TrailingOptions { dma_range, resource_limits } = parse_trailing_options(rest, spec)?;
        if resource_limits.is_some() {
            return Err(format!("{spec:?}: mem=/cpu= don't apply to {flag} plugins (no subprocess to limit)"));
        }
        Ok(Self { path: (*path).to_string(), base, size, dma_range })
    }
}

/// The PCI equivalent of `NativeDeviceSpec`, shared by `--native-pci-device`
/// and `--wasm-pci-device` — the plugin's identity comes from its own
/// `hyperbug_plugin_pci_identity`/`hyperbug_pci_identity` export, not the
/// CLI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePciDeviceSpec {
    pub path: String,
    pub device_number: u8,
    pub dma_range: Option<(u64, u64)>,
}

impl NativePciDeviceSpec {
    /// `flag` names the CLI flag being parsed for, as `NativeDeviceSpec::parse`.
    pub fn parse(flag: &str, spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let [path, devnum, rest @ ..] = parts.as_slice() else {
            return Err(format!(
                "expected {flag} <path>:<device_number 0-{MAX_PCI_DEVICE_NUMBER}>[:<dma_base>:<dma_size>], \
                 got {spec:?}"
            ));
        };
        let device_number: u8 =
            devnum.parse().map_err(|e| format!("bad PCI device number {devnum:?}: {e}"))?;
        if device_number > MAX_PCI_DEVICE_NUMBER {
            return Err(format!("PCI device number {device_number} must be 0-{MAX_PCI_DEVICE_NUMBER}"));
        }
        let TrailingOptions { dma_range, resource_limits } = parse_trailing_options(rest, spec)?;
        if resource_limits.is_some() {
            return Err(format!("{spec:?}: mem=/cpu= don't apply to {flag} plugins"));
        }
        Ok(Self { path: (*path).to_string(), device_number, dma_range })
    }

    /// The PCI devfn (device number, function 0) this spec names.
    pub fn devfn(&self) -> u8 {
        self.device_number << 3
    }
}

pub const USAGE: &str = "usage: hyperbug --kernel <bzImage> [--initrd <cpio.gz>] [--mem <MB>] \
     [--cmdline <str>] [--device <path.py>:<class>:<base>:<size>[:<dma_base>:<dma_size>]]... \
     [--pci-device <path.py>:<class>:<device_number>[:<dma_base>:<dma_size>]]... \
     [--device-sandboxed <path.py>:<class>:<base>:<size>[:<dma_base>:<dma_size>][:mem=<mb>][:cpu=<pct>]]... \
     [--pci-device-sandboxed <path.py>:<class>:<device_number>[:<dma_base>:<dma_size>][:mem=<mb>][:cpu=<pct>]]... \
     [--native-device <path.so>:<base>:<size>[:<dma_base>:<dma_size>]]... \
     [--native-pci-device <path.so>:<device_number>[:<dma_base>:<dma_size>]]... \
     [--wasm-device <path.wasm>:<base>:<size>[:<dma_base>:<dma_size>]]... \
     [--wasm-pci-device <path.wasm>:<device_number>[:<dma_base>:<dma_size>]]... \
     [--i2c-device <path.py>:<class>:<addr>]... \
     [--gpio-device <path.py>:<class>]... \
     [--uart2-log <path>] [--uart3-log <path>] [--uart4-log <path>] \
     [--vsock-uds <path>] \
     [--disk <path>]... [--net] [--rng-modern] [--control-socket <path>] [--smp <N>] \
     [--restore <path>] [--migrate-listen <host:port>] [--trace-file <path>] [--crash-dir <dir>] \
     [--gdb-stub <host:port>] [--record <path>] [--replay <path>]";

/// The kernel command line used when `--cmdline` isn't given.
///
/// No explicit `reboot=` method: now that the FADT advertises a real
/// `RESET_REG` (`acpi.rs`), Linux's default reboot-method order tries ACPI
/// reset first, giving a real, distinguishable requested-reboot exit path
/// (see `acpi::exit_code`) instead of always falling back to the ambiguous
/// triple-fault trick `reboot=k` used to force.
pub const DEFAULT_CMDLINE: &str = "console=ttyS0 panic=1";

pub const DEFAULT_MEM_MB: u64 = 256;

/// `Clone` specifically so `fork.rs` can build a forked child's own
/// `Args` (same configuration, `control_socket` overridden to the
/// child's new path, `restore`/`migrate_listen`/`record`/`replay`/
/// `gdb_stub`/`trace_file` cleared) from the parent's, without
/// re-parsing `argv`.
#[derive(Clone)]
pub struct Args {
    pub kernel: String,
    pub initrd: Option<String>,
    pub mem_mb: u64,
    pub cmdline: String,
    pub devices: Vec<DeviceSpec>,
    pub pci_devices: Vec<PciDeviceSpec>,
    /// `--device-sandboxed`: same spec syntax as `devices`, but the plugin
    /// runs in its own subprocess instead of in-process
    /// — a hung or crashed plugin gets killed rather than stalling or
    /// taking down the whole guest. See `pydevice_proc.rs`.
    pub sandboxed_devices: Vec<DeviceSpec>,
    /// `--pci-device-sandboxed`: the `--pci-device` equivalent.
    pub sandboxed_pci_devices: Vec<PciDeviceSpec>,
    /// `--native-device`: a `dlopen()`ed C-ABI plugin (see
    /// `include/hyperbug_plugin.h`) at a fixed MMIO address — no
    /// isolation at all, runs with full process privileges. See
    /// `native_plugin.rs`.
    pub native_devices: Vec<NativeDeviceSpec>,
    /// `--native-pci-device`: the `--pci-device` equivalent.
    pub native_pci_devices: Vec<NativePciDeviceSpec>,
    /// `--wasm-device`: a WASM module (see `docs/wasm-plugin-api.md`) at
    /// a fixed MMIO address — real memory-safety sandboxing (a module
    /// can only touch its own linear memory directly) at in-process,
    /// JIT-compiled speed. See `wasm_plugin.rs`.
    pub wasm_devices: Vec<NativeDeviceSpec>,
    /// `--wasm-pci-device`: the `--pci-device` equivalent.
    pub wasm_pci_devices: Vec<NativePciDeviceSpec>,
    /// `--i2c-device`: a Python target device on hyperbug's single virtual
    /// I2C bus (`virtio_i2c.rs`), attached to the guest via a real
    /// `virtio-i2c` adapter its own unmodified `i2c-virtio` driver binds
    /// to. The adapter itself only exists when at least one is given —
    /// see `machine.rs`.
    pub i2c_devices: Vec<I2cDeviceSpec>,
    /// `--gpio-device`: each spec attaches its own independent virtual
    /// GPIO bank (own PCI slot, real `virtio-gpio` adapter). Capped at
    /// `machine::slots::GPIO_MAX_BANKS`.
    pub gpio_devices: Vec<GpioDeviceSpec>,
    /// `--uart2-log`/`--uart3-log`/`--uart4-log`: attaches a real,
    /// additional ISA-convention 16550 UART (COM2/COM3/COM4) whose
    /// guest-transmitted bytes are captured to this host file — see
    /// `serial.rs`'s own module doc comment. `None` (the default) means
    /// that port doesn't exist at all.
    pub uart2_log: Option<String>,
    pub uart3_log: Option<String>,
    pub uart4_log: Option<String>,
    /// `--vsock-uds <path>`: attaches a real `virtio-vsock` adapter;
    /// every guest-initiated stream connection bridges to this one host
    /// Unix domain socket path, regardless of destination port — see
    /// `vsock.rs`'s own module doc comment for the full scope. `None`
    /// (the default) means no vsock adapter at all.
    pub vsock_uds: Option<String>,
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
    /// when the snapshot was taken). Single-vCPU only, and no Python
    /// device plugin state is captured — see `snapshot.rs` for the full
    /// scope and limitations.
    pub restore: Option<String>,
    /// `--migrate-listen <host:port>`: instead of booting `kernel`/
    /// `initrd` normally or loading a file-based `--restore` snapshot,
    /// binds `host:port` and blocks until a *separate* hyperbug process's
    /// control socket runs `migrate <host:port>` against it, then resumes
    /// execution from exactly the state that process sent — live
    /// migration's destination side (`migrate.rs`). `kernel` is still
    /// required by the parser but unused in this mode, same as
    /// `--restore`; the rest of `Args` (memory size, disks, net,
    /// rng-modern) must match the source guest's own configuration
    /// exactly, for the same reason `--restore` requires it. Single-vCPU
    /// only, no Python device plugin state — see `snapshot.rs`'s
    /// `validate_capturable` for the full scope, which the *source* side
    /// (`migrate <host:port>`) enforces before ever sending anything.
    pub migrate_listen: Option<String>,
    /// `--trace-file <path>`: writes a Chrome Trace Event Format JSON file
    /// covering every VM exit and interrupt injection — see `trace.rs`.
    /// `None` (the default) costs one branch per VM exit and nothing else.
    pub trace_file: Option<String>,
    /// `--crash-dir <dir>`: where a triple-fault crash dump is written
    /// (`crashdump.rs`). Defaults to the current directory when unset —
    /// a crash dump is always written on a triple fault, this only
    /// changes where.
    pub crash_dir: Option<String>,
    /// `--gdb-stub <host:port>`: opens a real GDB/LLDB remote-serial-
    /// protocol TCP server and holds the BSP halted until a debugger
    /// connects — see `gdbstub.rs` for the full scope (BSP-only, software
    /// breakpoints only).
    pub gdb_stub: Option<String>,
    /// `--record <path>`: records real async input (keyboard, TAP
    /// packets) tagged with a host branch-count position — Milestone 2 of
    /// record-and-replay (see `record.rs`, `docs/record-replay.md`).
    /// Single-vCPU only, same reason as `--restore`.
    pub record: Option<String>,
    /// `--replay <path>`: replays a recording written by `--record` —
    /// Milestone 3 of record-and-replay (see `record.rs`'s `Replayer`,
    /// `docs/record-replay.md`). Poll-granularity, not cycle-exact; TAP
    /// packets are recorded but not replayed. Mutually exclusive with
    /// `--record`; single-vCPU only, same reason as `--restore`.
    pub replay: Option<String>,
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
            native_devices: Vec::new(),
            native_pci_devices: Vec::new(),
            wasm_devices: Vec::new(),
            wasm_pci_devices: Vec::new(),
            i2c_devices: Vec::new(),
            gpio_devices: Vec::new(),
            uart2_log: None,
            uart3_log: None,
            uart4_log: None,
            vsock_uds: None,
            disks: Vec::new(),
            net: false,
            rng_modern: false,
            control_socket: None,
            smp: 1,
            restore: None,
            migrate_listen: None,
            trace_file: None,
            crash_dir: None,
            gdb_stub: None,
            record: None,
            replay: None,
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
                "--migrate-listen" => args.migrate_listen = Some(next_value(&mut it, &arg)?),
                "--trace-file" => args.trace_file = Some(next_value(&mut it, &arg)?),
                "--crash-dir" => args.crash_dir = Some(next_value(&mut it, &arg)?),
                "--gdb-stub" => args.gdb_stub = Some(next_value(&mut it, &arg)?),
                "--record" => args.record = Some(next_value(&mut it, &arg)?),
                "--replay" => args.replay = Some(next_value(&mut it, &arg)?),
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
                "--native-device" => {
                    args.native_devices.push(NativeDeviceSpec::parse(&arg, &next_value(&mut it, &arg)?)?);
                }
                "--native-pci-device" => {
                    args.native_pci_devices.push(NativePciDeviceSpec::parse(&arg, &next_value(&mut it, &arg)?)?);
                }
                "--wasm-device" => {
                    args.wasm_devices.push(NativeDeviceSpec::parse(&arg, &next_value(&mut it, &arg)?)?);
                }
                "--wasm-pci-device" => {
                    args.wasm_pci_devices.push(NativePciDeviceSpec::parse(&arg, &next_value(&mut it, &arg)?)?);
                }
                "--i2c-device" => {
                    args.i2c_devices.push(I2cDeviceSpec::parse(&next_value(&mut it, &arg)?)?);
                }
                "--gpio-device" => {
                    args.gpio_devices.push(GpioDeviceSpec::parse(&next_value(&mut it, &arg)?)?);
                }
                "--uart2-log" => args.uart2_log = Some(next_value(&mut it, &arg)?),
                "--uart3-log" => args.uart3_log = Some(next_value(&mut it, &arg)?),
                "--uart4-log" => args.uart4_log = Some(next_value(&mut it, &arg)?),
                "--vsock-uds" => args.vsock_uds = Some(next_value(&mut it, &arg)?),
                other => return Err(format!("unrecognized argument: {other}")),
            }
        }

        args.kernel = kernel.ok_or_else(|| format!("--kernel is required\n{USAGE}"))?;

        // Resource limits are enforced via a cgroup the sandboxed
        // subprocess joins before exec (see `cgroup.rs`) — an in-process
        // (`--device`/`--pci-device`) plugin shares the whole VMM
        // process's own resource budget, so declaring `mem=`/`cpu=`
        // there would either do nothing or (if ever wired up) throttle
        // the entire guest, neither of which is what an operator asking
        // for a per-*plugin* limit means. Rejected as a config error
        // rather than silently ignored.
        if args.devices.iter().any(|d| d.resource_limits.is_some())
            || args.pci_devices.iter().any(|d| d.resource_limits.is_some())
        {
            return Err(
                "mem=/cpu= resource limits only apply to --device-sandboxed/--pci-device-sandboxed \
                 (an in-process plugin shares the whole VMM's own resource budget)"
                    .to_string(),
            );
        }

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

    #[test]
    fn resource_limits_are_parsed_with_or_without_a_dma_range() {
        // mem=/cpu= alone, no DMA range at all.
        let spec = DeviceSpec::parse("d.py:Cls:0x1000:0x100:mem=128").unwrap();
        assert_eq!(spec.dma_range, None);
        assert_eq!(spec.resource_limits, Some(ResourceLimits { mem_limit_mb: Some(128), cpu_quota_percent: None }));

        let spec = DeviceSpec::parse("d.py:Cls:0x1000:0x100:cpu=50").unwrap();
        assert_eq!(spec.resource_limits.unwrap().cpu_quota_percent, Some(50));

        // Both a DMA range and resource limits together.
        let spec = DeviceSpec::parse("d.py:Cls:0x1000:0x100:0x2000:0x1000:mem=64:cpu=25").unwrap();
        assert_eq!(spec.dma_range, Some((0x2000, 0x1000)));
        assert_eq!(
            spec.resource_limits,
            Some(ResourceLimits { mem_limit_mb: Some(64), cpu_quota_percent: Some(25) })
        );

        // No trailing fields at all: neither is set (not `Some(default)`).
        assert_eq!(DeviceSpec::parse("d.py:Cls:0x1000:0x100").unwrap().resource_limits, None);

        let spec = PciDeviceSpec::parse("d.py:Cls:3:mem=256").unwrap();
        assert_eq!(spec.resource_limits.unwrap().mem_limit_mb, Some(256));
    }

    #[test]
    fn malformed_resource_limits_are_rejected() {
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:mem=0").is_err(), "zero mem limit");
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:mem=notanumber").is_err());
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:cpu=0").is_err(), "zero cpu quota");
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:cpu=20000").is_err(), "cpu quota out of range");
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:bogus=1").is_err(), "unrecognized key");
        assert!(DeviceSpec::parse("d.py:Cls:0x1000:0x100:notkeyvalue").is_err(), "not a key=value token at all");
    }

    #[test]
    fn resource_limits_are_rejected_on_non_sandboxed_device_flags() {
        let Err(err) = Args::parse(argv("--kernel k --device d.py:Cls:0x1000:0x100:mem=128")) else {
            panic!("expected a config error");
        };
        assert!(err.contains("--device-sandboxed"), "got: {err}");

        let Err(err) = Args::parse(argv("--kernel k --pci-device d.py:Cls:3:cpu=50")) else {
            panic!("expected a config error");
        };
        assert!(err.contains("--pci-device-sandboxed"), "got: {err}");

        // The same specs are fine on the sandboxed flags.
        assert!(Args::parse(argv("--kernel k --device-sandboxed d.py:Cls:0x1000:0x100:mem=128")).is_ok());
        assert!(Args::parse(argv("--kernel k --pci-device-sandboxed d.py:Cls:3:cpu=50")).is_ok());
    }
}
