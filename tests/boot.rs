//! Real boot tests — the thing DEBTS.md item 1 has said all along is the
//! only check that actually matters, turned into something a future
//! session (or CI) can re-run automatically instead of a human manually
//! repeating the scratchpad process this project's whole history has
//! relied on so far. Every bug found via manual boot testing this
//! project's had so far (a wrong ACPI register bit, a missing PCI
//! resource window, a table-layout self-corruption, a CPUID/idle
//! interaction, real keyboard input never having existed) was invisible
//! to `cargo test`'s unit tests, `iasl`, and clippy — this file is the
//! first automated check that actually boots a guest and checks it did
//! the right thing, closing exactly that gap for the two behaviors this
//! project has fought hardest to get right: booting cleanly and being
//! genuinely interactive.
//!
//! Needs `/dev/kvm` (world-r/w on the dev machine this was written on, no
//! root required), a real kernel image, and `busybox`. Each test checks
//! its own prerequisites and prints a reason + returns early (rather than
//! failing) if something's missing, since not every machine this runs on
//! will have all three — see `find_kernel` and `require_busybox`.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// `--kernel HYPERBUG_TEST_KERNEL` if set, else the first `/boot/vmlinuz-*`
/// found — every manual boot test this session ran used exactly this
/// fallback, so it's a reasonable default for "some real kernel on this
/// machine" rather than requiring one to be vendored into the repo.
fn find_kernel() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HYPERBUG_TEST_KERNEL") {
        return Some(PathBuf::from(p));
    }
    fs::read_dir("/boot").ok()?.filter_map(Result::ok).map(|e| e.path()).find(|p| {
        p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("vmlinuz-"))
    })
}

fn require_busybox() -> bool {
    Path::new("/usr/bin/busybox").exists() || Path::new("/bin/busybox").exists()
}

/// Builds a minimal initramfs with `init_script` as `/init`, the same way
/// every manual test this session ran did by hand: a static busybox
/// multi-call binary plus the applets a given script needs.
fn build_initramfs(dir: &Path, init_script: &str) -> PathBuf {
    let busybox = if Path::new("/usr/bin/busybox").exists() {
        "/usr/bin/busybox"
    } else {
        "/bin/busybox"
    };
    let root = dir.join("initramfs");
    for sub in ["bin", "proc", "sys", "dev", "mnt"] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    fs::copy(busybox, root.join("bin/busybox")).unwrap();
    for applet in ["sh", "mount", "echo", "cat", "dd", "sleep", "poweroff", "mkdir"] {
        std::os::unix::fs::symlink("busybox", root.join("bin").join(applet)).unwrap();
    }
    fs::write(root.join("init"), format!("#!/bin/busybox sh\n{init_script}\n")).unwrap();
    let mut perms = fs::metadata(root.join("init")).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(root.join("init"), perms).unwrap();

    let cpio_path = dir.join("initramfs.cpio.gz");
    let mut find = Command::new("find")
        .arg(".")
        .current_dir(&root)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut cpio = Command::new("cpio")
        .args(["-o", "-H", "newc"])
        .current_dir(&root)
        .stdin(find.stdout.take().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let gz = Command::new("gzip")
        .arg("-9")
        .stdin(cpio.stdout.take().unwrap())
        .output()
        .unwrap();
    find.wait().unwrap();
    cpio.wait().unwrap();
    fs::write(&cpio_path, gz.stdout).unwrap();
    cpio_path
}

/// Waits up to `timeout` for `child` to exit, killing it if it doesn't —
/// every non-interactive test here has a definite expected end state
/// (clean shutdown), so anything still running past its timeout is
/// already a failure, not something to wait out indefinitely.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return status.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A real pseudo-terminal, opened via `posix_openpt`/`grantpt`/`unlockpt`
/// (all already available through the `libc` crate, no new dependency
/// needed) — a plain pipe isn't representative of real keyboard input
/// (see DEBTS.md item 29/31's session log: a pipe-based simulation showed
/// confusing partial-byte-loss that turned out to be a pipe-timing
/// artifact, not a real bug, and only a real PTY caught that).
struct Pty {
    master: File,
    slave_path: PathBuf,
}

fn open_pty() -> Pty {
    unsafe {
        let master_fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master_fd >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master_fd), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master_fd), 0, "unlockpt failed");
        let name_ptr = libc::ptsname(master_fd);
        assert!(!name_ptr.is_null(), "ptsname failed");
        // `ptsname`'s buffer is internal/static — borrow it (CStr, not
        // CString) and copy the bytes out; never free or take ownership.
        let slave_path = PathBuf::from(std::ffi::CStr::from_ptr(name_ptr).to_string_lossy().into_owned());
        let flags = libc::fcntl(master_fd, libc::F_GETFL);
        libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        Pty { master: File::from_raw_fd(master_fd), slave_path }
    }
}

fn read_available(f: &mut File, out: &mut Vec<u8>) {
    let mut buf = [0u8; 4096];
    loop {
        match f.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// Test 1: a real guest boots, PCI/virtio devices attach without error,
/// and ACPI shutdown actually terminates the process cleanly (exit 0).
/// This is the regression guard for three of this session's real bugs at
/// once: the missing `_CRS` (virtio-pci probe failures), the wrong
/// `SLP_EN` bit (shutdown hanging forever), and the FADT/DSDT address
/// overlap (a crash during ACPI table parsing) — every one of them would
/// make this test fail today if it regressed.
#[test]
fn boots_with_disk_and_shuts_down_cleanly_under_acpi() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-boot-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "echo BOOT_MARKER\nsleep 1\npoweroff -f");

    let disk_path = dir.join("disk.img");
    fs::write(&disk_path, vec![0u8; 8 * 1024 * 1024]).unwrap();
    Command::new("mkfs.ext4").args(["-q", "-F"]).arg(&disk_path).output().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--disk"])
        .arg(&disk_path)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let code = wait_with_timeout(&mut child, Duration::from_secs(15));

    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();

    assert!(
        !stderr.contains("probe with driver virtio-pci failed") && !stderr.contains("can't assign; no space"),
        "virtio-pci BAR assignment regressed (DEBTS.md item 28's _CRS fix):\n{stderr}"
    );
    assert!(
        !stderr.contains("registering ioeventfd") && !stderr.contains("unregistering stale ioeventfd"),
        "KVM_IOEVENTFD (re)binding failed during BAR assignment for a virtio device \
         (see pci.rs's rebind_ioevents):\n{stderr}"
    );
    assert_eq!(
        code,
        Some(0),
        "hyperbug should exit 0 on a clean ACPI shutdown within 15s; got {code:?}. stderr:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Test 2: the guest's serial console is a *real* two-way interactive
/// terminal — the actual thing that makes hyperbug "a VM you can play
/// with" rather than a one-way boot log (DEBTS.md items 29/31). Types a
/// real command through a real PTY and checks the guest's own computed
/// answer comes back, then exits via the Ctrl-] escape hatch (needed
/// under `acpi=off`, which has no self-terminating halt path — see item
/// 30). Uses `acpi=off` deliberately, as a minimal baseline distinct from
/// the ACPI-on case `interactive_console_works_alongside_acpi_and_pci`
/// below covers — item 33 (console silent under ACPI) is now fixed, so
/// this is no longer "the only config that works", just the simplest one.
#[test]
fn interactive_console_accepts_real_keyboard_input() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-tty-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "exec /bin/sh");

    let pty = open_pty();
    let slave_for_child = pty.slave_path.clone();

    let mut child = unsafe {
        Command::new(env!("CARGO_BIN_EXE_hyperbug"))
            .args(["--kernel"])
            .arg(&kernel)
            .args(["--initrd"])
            .arg(&initramfs)
            .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 acpi=off"])
            .stdin(open_slave(&slave_for_child))
            .stdout(open_slave(&slave_for_child))
            .stderr(open_slave(&slave_for_child))
            .pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let path = CString::new(slave_for_child.to_string_lossy().into_owned()).unwrap();
                let fd = libc::open(path.as_ptr(), libc::O_RDWR);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(fd, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(fd);
                Ok(())
            })
            .spawn()
            .expect("failed to launch hyperbug")
    };

    let mut master = pty.master;
    let mut out = Vec::new();

    // Let it boot to the shell prompt.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        read_available(&mut master, &mut out);
        std::thread::sleep(Duration::from_millis(100));
    }

    let marker = "BOOT_TEST_MARKER_9137";
    let command = format!("echo {marker}\n");
    for byte in command.bytes() {
        let _ = master.write_all(&[byte]);
        std::thread::sleep(Duration::from_millis(20));
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        read_available(&mut master, &mut out);
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = master.write_all(&[0x1d]); // Ctrl-]: hyperbug's own quit hatch
    let code = wait_with_timeout(&mut child, Duration::from_secs(5));
    read_available(&mut master, &mut out);

    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains(marker),
        "typed `echo {marker}` should have echoed back through a real interactive console; got:\n{text}"
    );
    assert!(code.is_some(), "Ctrl-] should make hyperbug exit, not hang");

    let _ = fs::remove_dir_all(&dir);
}

/// Test: the actual fix for DEBTS.md item 33 — a real interactive console
/// *and* PCI/virtio *and* a clean ACPI shutdown, all at once, under the
/// plain default cmdline (no `acpi=off`). Before this fix, that
/// combination was impossible: ACPI on gave PCI/virtio and clean
/// shutdown but a silent console (`request_threaded_irq(4, ...)` failed
/// with `-EINVAL` — Linux's ACPI/PNP resource code marks an ISA IRQ
/// `IRQ_NOREQUEST` when nothing in the ACPI namespace claims it, and
/// hyperbug's DSDT never described the serial port at all); `acpi=off`
/// gave a real console but no PCI/virtio and no clean shutdown. Fixed by
/// adding a `PNP0501` (16550A-compatible serial port) device to
/// `acpi/dsdt.asl` describing COM1's real `_CRS` (I/O 0x3F8, IRQ 4) — the
/// same thing a real BIOS's DSDT always does, which is exactly why real
/// hardware never hits this. Attaches a disk (proving PCI/virtio) and
/// exits by typing `poweroff` through the PTY (proving a real ACPI
/// shutdown from an interactive session), not the Ctrl-] escape hatch.
#[test]
fn interactive_console_works_alongside_acpi_and_pci() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-acpi-tty-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "exec /bin/sh");

    let disk_path = dir.join("disk.img");
    fs::write(&disk_path, vec![0u8; 8 * 1024 * 1024]).unwrap();
    Command::new("mkfs.ext4").args(["-q", "-F"]).arg(&disk_path).output().unwrap();

    let pty = open_pty();
    let slave_for_child = pty.slave_path.clone();

    // No --cmdline at all: this is hyperbug's own plain default
    // ("console=ttyS0 panic=1"), ACPI on, exactly what every other guest
    // gets with no special-casing.
    let mut child = unsafe {
        Command::new(env!("CARGO_BIN_EXE_hyperbug"))
            .args(["--kernel"])
            .arg(&kernel)
            .args(["--initrd"])
            .arg(&initramfs)
            .args(["--disk"])
            .arg(&disk_path)
            .args(["--mem", "256"])
            .stdin(open_slave(&slave_for_child))
            .stdout(open_slave(&slave_for_child))
            .stderr(open_slave(&slave_for_child))
            .pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let path = CString::new(slave_for_child.to_string_lossy().into_owned()).unwrap();
                let fd = libc::open(path.as_ptr(), libc::O_RDWR);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(fd, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(fd);
                Ok(())
            })
            .spawn()
            .expect("failed to launch hyperbug")
    };

    let mut master = pty.master;
    let mut out = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        read_available(&mut master, &mut out);
        std::thread::sleep(Duration::from_millis(100));
    }

    let marker = "ACPI_TTY_MARKER_4471";
    for byte in format!("echo {marker}\n").bytes() {
        let _ = master.write_all(&[byte]);
        std::thread::sleep(Duration::from_millis(20));
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        read_available(&mut master, &mut out);
        std::thread::sleep(Duration::from_millis(100));
    }

    // A real ACPI shutdown requested from inside the interactive session
    // itself — not Ctrl-], which would prove nothing about ACPI working.
    // `-f`, same as every other init script here: this shell *is* init
    // (`exec /bin/sh`), so a plain `poweroff` expecting real init
    // cooperation (signaling PID 1, waiting on it) has nothing to
    // cooperate with.
    for byte in "poweroff -f\n".bytes() {
        let _ = master.write_all(&[byte]);
        std::thread::sleep(Duration::from_millis(20));
    }

    let code = wait_with_timeout(&mut child, Duration::from_secs(10));
    read_available(&mut master, &mut out);

    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains(marker),
        "typed `echo {marker}` should have echoed back through a real interactive console \
         with ACPI enabled; got:\n{text}"
    );
    assert_eq!(
        code,
        Some(0),
        "a real `poweroff` typed through the console should exit 0 via a clean ACPI shutdown; \
         got {code:?}. output:\n{text}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// `Stdio::from(File)` needs an owned `File`; a fresh open of the slave
/// path (rather than reusing one fd across stdin/stdout/stderr) matches
/// what a real terminal session looks like from three separate fds.
fn open_slave(path: &Path) -> Stdio {
    let file = OpenOptions::new().read(true).write(true).open(path).expect("open pty slave");
    Stdio::from(file)
}

/// Test 3: DEBTS.md item 11 — real SMP. Boots with `--smp 4` and checks
/// the guest's own SMP bring-up log for proof every AP actually came
/// online through a real INIT-SIPI-SIPI sequence (KVM's in-kernel APIC,
/// not anything this codebase implements directly) — "Total of N
/// processors activated" only prints once each AP has run far enough to
/// calibrate its own BogoMIPS, so this is real evidence of independent
/// execution, not just "the process didn't crash." This is also the
/// regression guard for a real bug a live boot caught while building
/// this: giving an AP the BSP's already-paging-enabled sregs *before* its
/// first SIPI made KVM reject it outright as `VcpuExit::InternalError`
/// the instant it tried to start.
#[test]
fn boots_with_multiple_cpus_and_they_all_come_online() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-smp-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "sleep 1\npoweroff -f");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--smp", "4"])
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 ignore_loglevel"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let code = wait_with_timeout(&mut child, Duration::from_secs(15));

    let mut stdout = String::new();
    child.stdout.take().unwrap().read_to_string(&mut stdout).unwrap();
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();

    assert!(
        !stdout.contains("InternalError") && !stderr.contains("InternalError"),
        "a vCPU hit KVM_EXIT_INTERNAL_ERROR — an AP's SIPI reset state \
         regressed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Total of 4 processors activated"),
        "the guest should report all 4 vCPUs as real, independently \
         booted processors; stdout:\n{stdout}"
    );
    assert_eq!(
        code,
        Some(0),
        "hyperbug should exit 0 on a clean ACPI shutdown within 15s with 4 vCPUs; got {code:?}. stderr:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Test 5: DEBTS.md item 2 — a real PCI capability list + MSI. Attaches
/// `devices/dma_demo.py` (a Python `--pci-device` with `msi_capable =
/// True`) and checks the guest's own PCI core actually walks the
/// capability chain without erroring — a malformed capability list is a
/// classic way to hang or crash real guest PCI enumeration, so this is a
/// genuine correctness check, not just "did the process not crash." Only
/// verifies *enumeration*, not that a driver ever binds and requests MSI
/// (no such driver exists for this vendor/device ID) — see `pci.rs`'s
/// module doc comment for why hyperbug's own virtio devices are
/// deliberately not part of this story.
#[test]
fn boots_with_an_msi_capable_pci_device_and_enumerates_it_cleanly() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-msi-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "sleep 1\npoweroff -f");
    let device_py = Path::new(env!("CARGO_MANIFEST_DIR")).join("devices/dma_demo.py");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--pci-device"])
        .arg(format!("{}:DmaDemoDevice:2", device_py.display()))
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 ignore_loglevel"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let code = wait_with_timeout(&mut child, Duration::from_secs(15));

    let mut stdout = String::new();
    child.stdout.take().unwrap().read_to_string(&mut stdout).unwrap();
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();

    assert!(
        stdout.contains("1234:0001"),
        "the guest's PCI core should have enumerated dma_demo.py's vendor:device id; stdout:\n{stdout}"
    );
    assert!(
        !stdout.to_lowercase().contains("malformed") && !stdout.to_lowercase().contains("bogus"),
        "the guest's PCI core flagged the capability list as broken; stdout:\n{stdout}"
    );
    assert_eq!(
        code,
        Some(0),
        "hyperbug should exit 0 on a clean ACPI shutdown within 15s even with the MSI-capable device attached; got {code:?}. stderr:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Test 5a2: a `--pci-device` spec with the optional trailing DMA-range
/// confinement (`<path>:<class>:<devnum>:<dma_base>:<dma_size>`) actually
/// launches and enumerates cleanly through the real CLI parser and
/// `Machine::build` wiring — not just `config.rs`'s own parsing unit
/// tests, and not just `pydevice.rs`/`pydevice_proc.rs`'s direct
/// `HyperbugCtx`/`handle_read_mem` confinement tests. Doesn't (and can't,
/// without a real guest-side driver for this demo device, which doesn't
/// exist) exercise a guest actually triggering an out-of-range DMA and
/// getting refused — that enforcement path is what the unit tests above
/// verify directly; this is the "does the CLI plumbing for it actually
/// work end to end" check.
#[test]
fn boots_with_a_pci_device_dma_range_and_enumerates_it_cleanly() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-dma-range-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "sleep 1\npoweroff -f");
    let device_py = Path::new(env!("CARGO_MANIFEST_DIR")).join("devices/dma_demo.py");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--pci-device"])
        .arg(format!("{}:DmaDemoDevice:2:0x1000000:0x100000", device_py.display()))
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 ignore_loglevel"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let code = wait_with_timeout(&mut child, Duration::from_secs(15));

    let mut stdout = String::new();
    child.stdout.take().unwrap().read_to_string(&mut stdout).unwrap();
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();

    assert!(
        stdout.contains("1234:0001"),
        "the guest's PCI core should have enumerated dma_demo.py's vendor:device id \
         even with a DMA range declared; stdout:\n{stdout}"
    );
    assert_eq!(
        code,
        Some(0),
        "hyperbug should exit 0 on a clean ACPI shutdown within 15s with a --pci-device \
         DMA range declared; got {code:?}. stderr:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Test 5b: the modern virtio 1.0 PCI transport (`VirtioModernPci`), its
/// first real vertical slice — virtio-rng attached via `--rng-modern`
/// instead of the legacy I/O-BAR transport every other virtio device here
/// still uses. Checks that the guest's *real* PCI core, not just this
/// codebase's own unit tests calling `VirtioModernPci`'s methods directly,
/// enumerates the modern device ID (`0x1af4:0x1044`, not legacy rng's
/// `0x1005`), decodes the hand-built `virtio_pci_cap` chain without
/// flagging it malformed, and gets far enough into `virtio-pci`'s own
/// probe to enable the device — all real, byte-level PCI I/O port traffic
/// this transport didn't exist to receive before this session.
///
/// **Deliberately does not check that `virtio_rng` itself binds and
/// `/dev/hwrng` works**: on this host, `virtio_rng` is a loadable module
/// (`virtio-rng.ko`), and the minimal busybox initramfs every test here
/// uses has no `modprobe`/module-loading support to bring it in — the
/// same gap would exist for the *legacy* rng device, so it isn't
/// specific to this transport. Feature negotiation (`VIRTIO_F_VERSION_1`
/// via the two-word device/guest-feature select registers) and the
/// notify→process_chain→ISR delivery path are instead verified
/// deterministically in `virtio::modern_pci_tests`, which don't have this
/// limitation since they drive the register protocol directly.
#[test]
fn boots_with_virtio_rng_over_the_modern_pci_transport() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-rng-modern-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "sleep 1\npoweroff -f");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .arg("--rng-modern")
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 ignore_loglevel"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let code = wait_with_timeout(&mut child, Duration::from_secs(15));

    let mut stdout = String::new();
    child.stdout.take().unwrap().read_to_string(&mut stdout).unwrap();
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();

    assert!(
        stdout.contains("1af4:1044"),
        "the guest's PCI core should have enumerated the modern virtio-rng PCI id; stdout:\n{stdout}"
    );
    assert!(
        !stdout.to_lowercase().contains("malformed") && !stdout.to_lowercase().contains("bogus"),
        "the guest's PCI core flagged the modern capability list as broken; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("virtio-pci 0000:00:11.0: enabling device"),
        "virtio-pci's own probe should have gotten far enough to enable the device; stdout:\n{stdout}"
    );
    assert_eq!(
        code,
        Some(0),
        "hyperbug should exit 0 on a clean ACPI shutdown within 15s with the modern-transport rng attached; \
         got {code:?}. stderr:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Test 6: DEBTS.md item 20 — live VM control. Connects to the control
/// socket of a *running* guest and does a real read/write round trip
/// against its memory, a real register read *and* write, and attaches a
/// second client alongside the first — proving the feature actually works
/// end to end (wire protocol, hex encoding, the once-per-loop-iteration
/// poll in `vcpu.rs`'s `poll_host`) rather than just compiling.
#[test]
fn live_control_socket_can_peek_and_poke_a_running_guest() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-control-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    // acpi=off's guest never self-terminates on halt (no ACPI reset/sleep
    // registers to trigger — see DEBTS.md item 30), which is exactly what
    // this test wants: stay alive and idle for as long as it takes to
    // connect and issue commands, then get killed explicitly rather than
    // needing to coordinate a clean shutdown with a live control session.
    let initramfs = build_initramfs(&dir, "sleep 60");
    let socket_path = dir.join("control.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--control-socket"])
        .arg(&socket_path)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 acpi=off"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    // The socket file appears as soon as bind() succeeds, well before the
    // guest finishes booting — poll for it rather than guessing a delay.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket_path.exists(), "control socket should appear shortly after launch");

    let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
        .expect("should be able to connect to the control socket");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());

    // A real read/write round trip against guest memory, from outside the
    // process, while the guest is genuinely running — the actual point of
    // "live" control. High in the 256 MiB region, away from anything a
    // fresh boot has likely touched yet, though this is inherently
    // best-effort against a live guest — the assertion only depends on
    // getting back exactly what was written, not on guest behavior.
    let addr = 0x0f00_0000u64;
    let payload = "deadbeefcafef00d";
    writeln!(stream, "write_mem {addr:x} {payload}").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "OK", "write_mem should succeed");

    writeln!(stream, "read_mem {addr:x} 8").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), format!("OK {payload}"), "read_mem should return exactly what write_mem wrote");

    // A real vCPU register read from the live guest.
    writeln!(stream, "regs").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.starts_with("OK rip="), "regs should return real register values; got: {line}");

    // A real vCPU register *write* on the live guest, routed through the
    // same vCPU-thread poll as the read above. Deliberately not asserting
    // a read-back of the written value: the guest keeps executing between
    // two control commands, so nothing stops it clobbering r15 in the
    // meantime — that would be a flaky assertion, not a stronger one.
    // What this does prove is the whole path: parse, KVM_GET_REGS,
    // apply, KVM_SET_REGS accepted by a live vCPU.
    writeln!(stream, "write_regs r15=0xfeedface").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "OK", "write_regs should succeed; got: {line}");

    writeln!(stream, "write_regs cr3=0").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(
        line.starts_with("ERR"),
        "a register that isn't a kvm_regs field should be rejected; got: {line}"
    );

    // A second client attached at the same time as the first, each
    // getting its own independent reads — the multi-client extension.
    let mut second = std::os::unix::net::UnixStream::connect(&socket_path)
        .expect("a second client should be able to attach while the first is still connected");
    second.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut second_reader = std::io::BufReader::new(second.try_clone().unwrap());
    writeln!(second, "regs").unwrap();
    let mut second_line = String::new();
    second_reader.read_line(&mut second_line).unwrap();
    assert!(
        second_line.starts_with("OK rip="),
        "the second client should be served, not closed; got: {second_line}"
    );
    // The first connection must still work afterwards.
    writeln!(stream, "read_mem {addr:x} 8").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), format!("OK {payload}"), "the first client should survive a second attaching");

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);
}

/// Test 7: DEBTS.md item 8 — snapshot/restore. Boots a real guest, saves a
/// snapshot through the control socket while it's running, kills that
/// process outright (not a clean shutdown — resuming from a snapshot is
/// the point, not a graceful handoff), relaunches an entirely separate
/// hyperbug process with `--restore`, and confirms the resumed vCPU is
/// genuinely alive and running — not crashed, not frozen — by driving its
/// *own* control socket: a memory write/read-back round trip (proving
/// guest RAM was correctly restored and is still live-addressable) and two
/// `regs` reads a moment apart returning real, syntactically valid
/// register data both times (proving the vCPU thread is still iterating
/// its main loop, i.e. actually executing, not stuck).
///
/// **Deliberately does not type a command through an interactive PTY.**
/// Getting this feature to the point of a live, idle vCPU surviving
/// restore already took real, incremental debugging (see `snapshot.rs`'s
/// module doc comment: KVM's own in-kernel PIC/IOAPIC/PIT/LAPIC state, and
/// the vCPU's FPU/XSAVE/XCRS/vcpu_events/syscall-MSR state, were *all*
/// discovered missing by this exact test failing in exactly this way
/// before those fixes landed). What's found and still real: waking a
/// *specific blocked userspace task* via a post-restore interrupt (typing
/// into a resumed interactive shell, concretely) still crashes the guest —
/// a kernel stack-guard-page hit during that task's FPU context switch.
/// Recorded honestly as still-open in DEBTS.md item 8 rather than forced
/// green by avoiding the one thing that currently breaks it.
#[test]
fn snapshot_then_restore_resumes_to_a_live_idle_guest() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-snapshot-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    // `acpi=off`: nothing here needs PCI/ACPI, and it keeps this test
    // independent of the interactive-console/ACPI machinery entirely —
    // just a guest that boots, idles, and is reachable over its control
    // socket, which is exactly what's under test.
    let initramfs = build_initramfs(&dir, "sleep 60");
    let socket1_path = dir.join("control1.sock");
    let socket2_path = dir.join("control2.sock");
    let snapshot_path = dir.join("snap.bin");

    let mut child1 = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--control-socket"])
        .arg(&socket1_path)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 acpi=off"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket1_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket1_path.exists(), "control socket should appear shortly after launch");

    // Real save via the control socket while the guest is still running.
    let stream1 = std::os::unix::net::UnixStream::connect(&socket1_path).expect("connect to control socket");
    stream1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut writer1 = stream1.try_clone().unwrap();
    let mut reader1 = std::io::BufReader::new(&stream1);
    writeln!(writer1, "snapshot {}", snapshot_path.display()).unwrap();
    let mut reply = String::new();
    reader1.read_line(&mut reply).unwrap();
    assert_eq!(reply.trim(), "OK", "snapshot command should succeed; got: {reply}");

    // Kill outright — resuming from a snapshot is the point, not a
    // graceful handoff between the two processes.
    let _ = child1.kill();
    let _ = child1.wait();

    // Relaunch entirely fresh from the snapshot: a new process, its own
    // control socket.
    let mut child2 = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--restore"])
        .arg(&snapshot_path)
        .args(["--control-socket"])
        .arg(&socket2_path)
        .args(["--mem", "256"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug --restore");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket2_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket2_path.exists(), "the restored guest's own control socket should appear");

    let stream2 = std::os::unix::net::UnixStream::connect(&socket2_path)
        .expect("should be able to connect to the resumed guest's control socket");
    stream2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut writer2 = stream2.try_clone().unwrap();
    let mut reader2 = std::io::BufReader::new(&stream2);

    // Guest RAM survived the round trip and is still live-addressable.
    let addr = 0x0f00_0000u64;
    let payload = "cafef00ddeadbeef";
    writeln!(writer2, "write_mem {addr:x} {payload}").unwrap();
    let mut line = String::new();
    reader2.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "OK", "write_mem on the resumed guest should succeed; got: {line}");

    writeln!(writer2, "read_mem {addr:x} 8").unwrap();
    line.clear();
    reader2.read_line(&mut line).unwrap();
    assert_eq!(
        line.trim(),
        format!("OK {payload}"),
        "read_mem should return exactly what was just written to the resumed guest"
    );

    // The vCPU thread is genuinely iterating its main loop (not crashed,
    // not stuck) — two real register reads, both syntactically valid.
    for _ in 0..2 {
        writeln!(writer2, "regs").unwrap();
        line.clear();
        reader2.read_line(&mut line).unwrap();
        assert!(line.starts_with("OK rip="), "the resumed vCPU should still answer `regs`; got: {line}");
        std::thread::sleep(Duration::from_millis(200));
    }

    let mut stderr_handle = child2.stderr.take().unwrap();
    let _ = child2.kill();
    let _ = child2.wait();
    let mut stderr2 = String::new();
    let _ = stderr_handle.read_to_string(&mut stderr2);
    assert!(
        !stderr2.to_lowercase().contains("panic") && !stderr2.to_lowercase().contains("triple-fault"),
        "the resumed guest should not have crashed during this test; stderr:\n{stderr2}"
    );

    let _ = fs::remove_dir_all(&dir);
}
