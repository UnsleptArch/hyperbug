//! Real boot tests — the only check that actually verifies this VMM
//! works, turned into something a future
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
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
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

/// The kernel release string (`uname -r`-shaped, e.g.
/// `6.18.38-2-cachyos-lts`) a given kernel image actually corresponds
/// to — needed to find that *exact* kernel's own loadable modules under
/// `/lib/modules/<release>/`. **Not** simply the `vmlinuz-<name>` filename
/// (a real, live bug this function's first draft had: this host's own
/// `/boot` has both `vmlinuz-linux-cachyos` and
/// `vmlinuz-linux-cachyos-lts`, and the latter's filename suffix,
/// `linux-cachyos-lts`, is not its real release string,
/// `6.18.38-2-cachyos-lts` — a distribution's boot-image package name and
/// its kernel release version are two different, independently-chosen
/// strings). The real version string is embedded in the bzImage itself
/// (the Linux boot protocol's own `kernel_version` field) — `file(1)`
/// already knows how to parse it out, the same "ask a real, authoritative
/// source instead of guessing from a filename convention" discipline this
/// project's own `loader.rs` bzImage handling follows.
fn kernel_release(kernel: &Path) -> Option<String> {
    let out = Command::new("file").arg(kernel).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let after = text.split_once("version ")?.1;
    after.split_whitespace().next().map(str::to_string)
}

/// Finds this exact kernel's own real, on-disk `virtio_net`/`net_failover`/
/// `failover` loadable modules (zstd-compressed, this host's own
/// distribution convention) — real evidence a Linux guest's own unmodified
/// virtio-net driver can actually bind to hyperbug's virtio-net device,
/// the thing `net_survives_a_real_ping_flood_after_the_rx_notify_fix`
/// below needs and no other test in this file exercises (every other
/// virtio device this project ships is either built directly into every
/// kernel this suite has used, `CONFIG_VIRTIO_BLK=y`, or — like
/// virtio-rng — has never had its own real driver binding verified for
/// the same "it's a loadable module this minimal initramfs doesn't load"
/// reason named honestly in `DEBTS.md` item 38). `None` (skip the test,
/// not fail it) if this host's kernel doesn't ship them as loadable
/// modules at all (built directly in, a real possibility on another
/// distribution) or under a path this function doesn't know to check.
fn find_virtio_net_modules(release: &str) -> Option<[PathBuf; 3]> {
    let base = PathBuf::from(format!("/lib/modules/{release}"));
    let names = [
        base.join("kernel/net/core/failover.ko.zst"),
        base.join("kernel/drivers/net/net_failover.ko.zst"),
        base.join("kernel/drivers/net/virtio_net.ko.zst"),
    ];
    names.iter().all(|p| p.exists()).then_some(names)
}

/// Whether `bin` runs at all (`--help`, ignoring its exit code — some
/// tools use a non-zero one for `--help`) — the same "check the real
/// prerequisite, skip cleanly if it's missing" discipline `find_kernel`/
/// `require_busybox` already established, extended to the extra host
/// tools `--net` testing needs (`unshare` for `CAP_NET_ADMIN` without
/// real root, `zstd` to decompress this host's `.ko.zst` modules, `ping`
/// to generate real traffic from the host side of the TAP interface).
fn have_tool(bin: &str) -> bool {
    Command::new(bin).arg("--help").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

/// Finds this exact kernel's own real, on-disk `i2c-virtio`/`i2c-dev`
/// loadable modules (zstd-compressed, matching `find_virtio_net_modules`'s
/// own layout convention) — real evidence a Linux guest's own unmodified
/// `i2c-virtio` driver binds to hyperbug's virtio-i2c adapter and a real
/// userspace `I2C_RDWR` ioctl round-trips through it, the thing
/// `i2c_adapter_answers_a_real_i2c_rdwr_ioctl_from_userspace` below needs.
/// `i2c-core` isn't required as a separate module — many distributions
/// (this host included) build it directly into the kernel
/// (`CONFIG_I2C=y`), so it's decompressed only if present. `None` (skip,
/// not fail) if the two mandatory modules aren't on disk as loadable
/// `.ko.zst` files.
fn find_i2c_modules(release: &str) -> Option<(PathBuf, PathBuf, Option<PathBuf>)> {
    let base = PathBuf::from(format!("/lib/modules/{release}"));
    let virtio = base.join("kernel/drivers/i2c/busses/i2c-virtio.ko.zst");
    let dev = base.join("kernel/drivers/i2c/i2c-dev.ko.zst");
    if !virtio.exists() || !dev.exists() {
        return None;
    }
    let core = base.join("kernel/drivers/i2c/i2c-core.ko.zst");
    Some((virtio, dev, core.exists().then_some(core)))
}

/// As `find_i2c_modules`, for `gpio-virtio.ko`. No `gpio-core` equivalent
/// to check for: GPIOLIB is virtually always built directly into the
/// kernel (`CONFIG_GPIOLIB=y`), never a loadable module on any real
/// distribution this project has seen.
fn find_gpio_module(release: &str) -> Option<PathBuf> {
    let path = PathBuf::from(format!("/lib/modules/{release}/kernel/drivers/gpio/gpio-virtio.ko.zst"));
    path.exists().then_some(path)
}

/// The three real modules a guest's `AF_VSOCK` stack needs:
/// `vsock.ko` (the address-family core), `vmw_vsock_virtio_transport_
/// common.ko` (the shared connection/credit state machine), and
/// `vmw_vsock_virtio_transport.ko` (the actual virtio binding). `None`
/// (skip, not fail) if this exact kernel doesn't ship all three as
/// loadable modules.
fn find_vsock_modules(release: &str) -> Option<[PathBuf; 3]> {
    let base = PathBuf::from(format!("/lib/modules/{release}/kernel/net/vmw_vsock"));
    let names = [
        base.join("vsock.ko.zst"),
        base.join("vmw_vsock_virtio_transport_common.ko.zst"),
        base.join("vmw_vsock_virtio_transport.ko.zst"),
    ];
    names.iter().all(|p| p.exists()).then_some(names)
}

/// A real `GPIO_V2` ioctl exerciser against `/dev/gpiochip0` — busybox has
/// no `gpiodetect`/`gpioget`/`gpioset` applets, same reasoning as the I2C
/// test's own statically-compiled C program. Requests line 2
/// (`power_control`, an output) and drives/reads it, then line 0
/// (`power_button`, an input armed for a falling-edge interrupt) and
/// waits for a real interrupt delivered by `devices/gpio_button_bank.py`'s
/// `HYPERBUG_GPIO_DEMO_AUTOPRESS_MS`-gated background-thread press.
const GPIO_TEST_C_SOURCE: &str = r#"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/gpio.h>
#include <poll.h>

static int request_line(int chip_fd, unsigned int offset, uint64_t flags, uint64_t val) {
    struct gpio_v2_line_request req;
    memset(&req, 0, sizeof(req));
    req.num_lines = 1;
    req.offsets[0] = offset;
    req.config.flags = flags;
    if (flags & GPIO_V2_LINE_FLAG_OUTPUT) {
        req.config.num_attrs = 1;
        req.config.attrs[0].mask = 1;
        req.config.attrs[0].attr.id = GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES;
        req.config.attrs[0].attr.values = val ? 1 : 0;
    }
    strncpy(req.consumer, "gpiotest", sizeof(req.consumer) - 1);
    if (ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, &req) < 0) { perror("GPIO_V2_GET_LINE_IOCTL"); return -1; }
    return req.fd;
}

static int get_value(int line_fd) {
    struct gpio_v2_line_values vals;
    memset(&vals, 0, sizeof(vals));
    vals.mask = 1;
    if (ioctl(line_fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &vals) < 0) { perror("GET_VALUES"); return -1; }
    return vals.bits & 1;
}

static int set_value(int line_fd, int v) {
    struct gpio_v2_line_values vals;
    memset(&vals, 0, sizeof(vals));
    vals.mask = 1;
    vals.bits = v ? 1 : 0;
    if (ioctl(line_fd, GPIO_V2_LINE_SET_VALUES_IOCTL, &vals) < 0) { perror("SET_VALUES"); return -1; }
    return 0;
}

int main(void) {
    int chip = open("/dev/gpiochip0", O_RDWR);
    if (chip < 0) { perror("open gpiochip0"); return 1; }

    int line2 = request_line(chip, 2, GPIO_V2_LINE_FLAG_OUTPUT, 1);
    if (line2 < 0) return 1;
    printf("POWER_CONTROL_INITIAL=%d\n", get_value(line2));
    set_value(line2, 0);
    printf("POWER_CONTROL_AFTER_CLEAR=%d\n", get_value(line2));

    int line0 = request_line(chip, 0, GPIO_V2_LINE_FLAG_INPUT | GPIO_V2_LINE_FLAG_EDGE_FALLING, 0);
    if (line0 < 0) return 1;
    printf("POWER_BUTTON_INITIAL=%d\n", get_value(line0));

    struct pollfd pfd = { .fd = line0, .events = POLLIN };
    int pr = poll(&pfd, 1, 10000);
    if (pr > 0 && (pfd.revents & POLLIN)) {
        struct gpio_v2_line_event ev;
        ssize_t n = read(line0, &ev, sizeof(ev));
        if (n == (ssize_t)sizeof(ev)) {
            printf("IRQ_RECEIVED offset=%u id=%llu\n", ev.offset, (unsigned long long)ev.id);
        } else {
            printf("IRQ_READ_SHORT n=%zd\n", n);
        }
    } else {
        printf("IRQ_TIMEOUT\n");
    }

    return 0;
}
"#;

/// Builds a `--gpio-device`-capable initramfs: the busybox base plus this
/// exact kernel's own decompressed `gpio-virtio` module and the
/// statically-compiled `GPIO_TEST_C_SOURCE` program, with a real
/// `devtmpfs` mount (same reasoning as `build_i2c_initramfs`'s own doc
/// comment — no udev, no device node otherwise).
fn build_gpio_initramfs(dir: &Path, gpio_ko: &Path) -> PathBuf {
    let busybox = if Path::new("/usr/bin/busybox").exists() { "/usr/bin/busybox" } else { "/bin/busybox" };
    let root = dir.join("initramfs");
    for sub in ["bin", "proc", "sys", "dev", "lib/modules"] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    fs::copy(busybox, root.join("bin/busybox")).unwrap();
    for applet in ["sh", "mount", "echo", "sleep", "insmod"] {
        std::os::unix::fs::symlink("busybox", root.join("bin").join(applet)).unwrap();
    }

    let out = Command::new("zstd")
        .args(["-d", "-f", "-q"])
        .arg(gpio_ko)
        .arg("-o")
        .arg(root.join("lib/modules/gpio-virtio.ko"))
        .status()
        .unwrap();
    assert!(out.success(), "decompressing {gpio_ko:?} failed");

    let c_src = dir.join("gpiotest.c");
    fs::write(&c_src, GPIO_TEST_C_SOURCE).unwrap();
    let out = Command::new("cc")
        .args(["-static", "-O2", "-o"])
        .arg(root.join("bin/gpiotest"))
        .arg(&c_src)
        .status()
        .unwrap();
    assert!(out.success(), "compiling the GPIO ioctl test program failed");

    let init_script = "\
        mount -t proc proc /proc\n\
        mount -t sysfs sysfs /sys\n\
        mount -t devtmpfs devtmpfs /dev\n\
        insmod /lib/modules/gpio-virtio.ko\n\
        /bin/gpiotest\n\
        echo GPIO_TEST_DONE\n\
        sleep 60\n\
    ";
    fs::write(root.join("init"), format!("#!/bin/busybox sh\n{init_script}\n")).unwrap();
    let mut perms = fs::metadata(root.join("init")).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(root.join("init"), perms).unwrap();

    let cpio_path = dir.join("gpio-initramfs.cpio.gz");
    let mut find = Command::new("find").arg(".").current_dir(&root).stdout(Stdio::piped()).spawn().unwrap();
    let mut cpio = Command::new("cpio")
        .args(["-o", "-H", "newc"])
        .current_dir(&root)
        .stdin(find.stdout.take().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let gz = Command::new("gzip").arg("-9").stdin(cpio.stdout.take().unwrap()).output().unwrap();
    find.wait().unwrap();
    cpio.wait().unwrap();
    fs::write(&cpio_path, gz.stdout).unwrap();
    cpio_path
}

/// A real `AF_VSOCK` client: connects to `VMADDR_CID_HOST`, writes a
/// known string, and reads back whatever comes back — busybox has no
/// vsock-aware applet at all, same reasoning as the I2C/GPIO tests' own
/// statically-compiled C programs.
const VSOCK_TEST_C_SOURCE: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>

int main(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_HOST;
    addr.svm_port = 5555;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        printf("CONNECT_FAILED\n");
        return 1;
    }
    printf("CONNECTED\n");

    const char *msg = "hello from vsock guest";
    write(fd, msg, strlen(msg));

    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        printf("ECHO_LEN=%zd DATA=%s\n", n, buf);
    } else {
        printf("READ_FAILED n=%zd\n", n);
    }

    close(fd);
    return 0;
}
"#;

/// Builds a `--vsock-uds`-capable initramfs: the busybox base plus this
/// exact kernel's own decompressed vsock modules and the statically-
/// compiled `VSOCK_TEST_C_SOURCE` program, with a real `devtmpfs` mount
/// (same reasoning as the I2C/GPIO tests' own initramfs builders).
fn build_vsock_initramfs(dir: &Path, modules: &[PathBuf; 3]) -> PathBuf {
    let busybox = if Path::new("/usr/bin/busybox").exists() { "/usr/bin/busybox" } else { "/bin/busybox" };
    let root = dir.join("initramfs");
    for sub in ["bin", "proc", "sys", "dev", "lib/modules"] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    fs::copy(busybox, root.join("bin/busybox")).unwrap();
    for applet in ["sh", "mount", "echo", "sleep", "insmod"] {
        std::os::unix::fs::symlink("busybox", root.join("bin").join(applet)).unwrap();
    }

    for (path, name) in
        modules.iter().zip(["vsock.ko", "vmw_vsock_virtio_transport_common.ko", "vmw_vsock_virtio_transport.ko"])
    {
        let out = Command::new("zstd")
            .args(["-d", "-f", "-q"])
            .arg(path)
            .arg("-o")
            .arg(root.join("lib/modules").join(name))
            .status()
            .unwrap();
        assert!(out.success(), "decompressing {path:?} failed");
    }

    let c_src = dir.join("vsocktest.c");
    fs::write(&c_src, VSOCK_TEST_C_SOURCE).unwrap();
    let out = Command::new("cc")
        .args(["-static", "-O2", "-o"])
        .arg(root.join("bin/vsocktest"))
        .arg(&c_src)
        .status()
        .unwrap();
    assert!(out.success(), "compiling the vsock test program failed");

    let init_script = "\
        mount -t proc proc /proc\n\
        mount -t sysfs sysfs /sys\n\
        mount -t devtmpfs devtmpfs /dev\n\
        insmod /lib/modules/vsock.ko\n\
        insmod /lib/modules/vmw_vsock_virtio_transport_common.ko\n\
        insmod /lib/modules/vmw_vsock_virtio_transport.ko\n\
        sleep 1\n\
        /bin/vsocktest\n\
        echo VSOCK_TEST_DONE\n\
        sleep 60\n\
    ";
    fs::write(root.join("init"), format!("#!/bin/busybox sh\n{init_script}\n")).unwrap();
    let mut perms = fs::metadata(root.join("init")).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(root.join("init"), perms).unwrap();

    let cpio_path = dir.join("vsock-initramfs.cpio.gz");
    let mut find = Command::new("find").arg(".").current_dir(&root).stdout(Stdio::piped()).spawn().unwrap();
    let mut cpio = Command::new("cpio")
        .args(["-o", "-H", "newc"])
        .current_dir(&root)
        .stdin(find.stdout.take().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let gz = Command::new("gzip").arg("-9").stdin(cpio.stdout.take().unwrap()).output().unwrap();
    find.wait().unwrap();
    cpio.wait().unwrap();
    fs::write(&cpio_path, gz.stdout).unwrap();
    cpio_path
}

/// A real, statically-linked I2C_RDWR ioctl exerciser against
/// `/dev/i2c-0` — the same shape as this project's earlier statically-
/// compiled port-0xE9 diagnostic tool (DEBTS.md item 33), used here
/// because busybox has no `i2cget`/`i2cdetect` applets at all. Writes the
/// exact "select register, then read" idiom `devices/i2c_temp_sensor.py`
/// implements, then a write+read round trip through its config register,
/// then a real probe of an address nothing answers at.
const I2C_TEST_C_SOURCE: &str = r#"
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

int main(void) {
    int fd = open("/dev/i2c-0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    uint8_t reg = 0x00;
    uint8_t rx[2] = {0, 0};
    struct i2c_msg msgs[2] = {
        { .addr = 0x48, .flags = 0, .len = 1, .buf = &reg },
        { .addr = 0x48, .flags = I2C_M_RD, .len = 2, .buf = rx },
    };
    struct i2c_rdwr_ioctl_data xfer = { .msgs = msgs, .nmsgs = 2 };
    if (ioctl(fd, I2C_RDWR, &xfer) != 2) { perror("I2C_RDWR temp"); return 1; }
    printf("TEMP_BYTES=%02x%02x\n", rx[0], rx[1]);

    uint8_t write_cfg[2] = { 0x01, 0x77 };
    struct i2c_msg wmsg = { .addr = 0x48, .flags = 0, .len = 2, .buf = write_cfg };
    struct i2c_rdwr_ioctl_data wxfer = { .msgs = &wmsg, .nmsgs = 1 };
    if (ioctl(fd, I2C_RDWR, &wxfer) != 1) { perror("I2C_RDWR write cfg"); return 1; }

    uint8_t reg2 = 0x01;
    uint8_t cfg = 0;
    struct i2c_msg rmsgs[2] = {
        { .addr = 0x48, .flags = 0, .len = 1, .buf = &reg2 },
        { .addr = 0x48, .flags = I2C_M_RD, .len = 1, .buf = &cfg },
    };
    struct i2c_rdwr_ioctl_data rxfer = { .msgs = rmsgs, .nmsgs = 2 };
    if (ioctl(fd, I2C_RDWR, &rxfer) != 2) { perror("I2C_RDWR read cfg"); return 1; }
    printf("CFG_BYTE=%02x\n", cfg);

    uint8_t probe_reg = 0x00;
    struct i2c_msg probe_msg = { .addr = 0x51, .flags = 0, .len = 0, .buf = &probe_reg };
    struct i2c_rdwr_ioctl_data probe_xfer = { .msgs = &probe_msg, .nmsgs = 1 };
    int probe_rc = ioctl(fd, I2C_RDWR, &probe_xfer);
    printf("PROBE_EMPTY_RC=%d\n", probe_rc);

    return 0;
}
"#;

/// Builds an `--i2c-device`-capable initramfs: the busybox base plus this
/// exact kernel's own decompressed `i2c-virtio`/`i2c-dev` modules and the
/// statically-compiled `I2C_TEST_C_SOURCE` program, with an init script
/// that mounts a real `devtmpfs` (needed for `/dev/i2c-0` to actually
/// appear with no udev around — the one real gap a first manual dry run
/// of this exact setup hit: `/sys/class/i2c-dev/i2c-0` existed with the
/// driver correctly bound the whole time, but no device *node* without
/// this), loads the modules, and runs the test program.
fn build_i2c_initramfs(dir: &Path, virtio_ko: &Path, dev_ko: &Path, core_ko: Option<&Path>) -> PathBuf {
    let busybox = if Path::new("/usr/bin/busybox").exists() { "/usr/bin/busybox" } else { "/bin/busybox" };
    let root = dir.join("initramfs");
    for sub in ["bin", "proc", "sys", "dev", "lib/modules"] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    fs::copy(busybox, root.join("bin/busybox")).unwrap();
    for applet in ["sh", "mount", "echo", "sleep", "insmod"] {
        std::os::unix::fs::symlink("busybox", root.join("bin").join(applet)).unwrap();
    }

    let mut insmods = String::new();
    if let Some(core) = core_ko {
        let out = Command::new("zstd")
            .args(["-d", "-f", "-q"])
            .arg(core)
            .arg("-o")
            .arg(root.join("lib/modules/i2c-core.ko"))
            .status()
            .unwrap();
        assert!(out.success(), "decompressing {core:?} failed");
        insmods.push_str("insmod /lib/modules/i2c-core.ko\n");
    }
    for (path, name) in [(virtio_ko, "i2c-virtio.ko"), (dev_ko, "i2c-dev.ko")] {
        let out = Command::new("zstd")
            .args(["-d", "-f", "-q"])
            .arg(path)
            .arg("-o")
            .arg(root.join("lib/modules").join(name))
            .status()
            .unwrap();
        assert!(out.success(), "decompressing {path:?} failed");
        insmods.push_str(&format!("insmod /lib/modules/{name}\n"));
    }

    let c_src = dir.join("i2ctest.c");
    fs::write(&c_src, I2C_TEST_C_SOURCE).unwrap();
    let out = Command::new("cc")
        .args(["-static", "-O2", "-o"])
        .arg(root.join("bin/i2ctest"))
        .arg(&c_src)
        .status()
        .unwrap();
    assert!(out.success(), "compiling the I2C ioctl test program failed");

    let init_script = format!(
        "\
        mount -t proc proc /proc\n\
        mount -t sysfs sysfs /sys\n\
        mount -t devtmpfs devtmpfs /dev\n\
        {insmods}\
        /bin/i2ctest\n\
        echo I2C_TEST_DONE\n\
        sleep 60\n\
    "
    );
    fs::write(root.join("init"), format!("#!/bin/busybox sh\n{init_script}\n")).unwrap();
    let mut perms = fs::metadata(root.join("init")).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(root.join("init"), perms).unwrap();

    let cpio_path = dir.join("i2c-initramfs.cpio.gz");
    let mut find = Command::new("find").arg(".").current_dir(&root).stdout(Stdio::piped()).spawn().unwrap();
    let mut cpio = Command::new("cpio")
        .args(["-o", "-H", "newc"])
        .current_dir(&root)
        .stdin(find.stdout.take().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let gz = Command::new("gzip").arg("-9").stdin(cpio.stdout.take().unwrap()).output().unwrap();
    find.wait().unwrap();
    cpio.wait().unwrap();
    fs::write(&cpio_path, gz.stdout).unwrap();
    cpio_path
}

/// Builds a `--net`-capable initramfs: the same busybox base
/// `build_initramfs` uses, plus the `ip`/`insmod` applets and this exact
/// kernel's own decompressed `failover`/`net_failover`/`virtio_net`
/// modules under `/lib/modules/`, with an init script that loads them,
/// brings up `eth0` at `10.250.0.2/24`, and prints `GUEST_NET_READY`
/// before idling — the real synchronization marker the test polls for
/// instead of a flat sleep (the exact race a flat sleep caused in item
/// 49's own boot test).
fn build_net_initramfs(dir: &Path, modules: &[PathBuf; 3]) -> PathBuf {
    let busybox = if Path::new("/usr/bin/busybox").exists() { "/usr/bin/busybox" } else { "/bin/busybox" };
    let root = dir.join("initramfs");
    for sub in ["bin", "proc", "sys", "dev", "mnt", "lib/modules"] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    fs::copy(busybox, root.join("bin/busybox")).unwrap();
    for applet in ["sh", "mount", "echo", "sleep", "insmod", "ip"] {
        std::os::unix::fs::symlink("busybox", root.join("bin").join(applet)).unwrap();
    }
    for (path, name) in modules.iter().zip(["failover.ko", "net_failover.ko", "virtio_net.ko"]) {
        let out = Command::new("zstd")
            .args(["-d", "-f", "-q"])
            .arg(path)
            .arg("-o")
            .arg(root.join("lib/modules").join(name))
            .status()
            .unwrap();
        assert!(out.success(), "decompressing {path:?} failed");
    }
    let init_script = "\
        insmod /lib/modules/failover.ko\n\
        insmod /lib/modules/net_failover.ko\n\
        insmod /lib/modules/virtio_net.ko\n\
        ip link set lo up\n\
        ip link set eth0 up\n\
        ip addr add 10.250.0.2/24 dev eth0\n\
        echo GUEST_NET_READY\n\
        sleep 60\n\
    ";
    fs::write(root.join("init"), format!("#!/bin/busybox sh\n{init_script}\n")).unwrap();
    let mut perms = fs::metadata(root.join("init")).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(root.join("init"), perms).unwrap();

    let cpio_path = dir.join("initramfs.cpio.gz");
    let mut find = Command::new("find").arg(".").current_dir(&root).stdout(Stdio::piped()).spawn().unwrap();
    let mut cpio = Command::new("cpio")
        .args(["-o", "-H", "newc"])
        .current_dir(&root)
        .stdin(find.stdout.take().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let gz = Command::new("gzip").arg("-9").stdin(cpio.stdout.take().unwrap()).output().unwrap();
    find.wait().unwrap();
    cpio.wait().unwrap();
    fs::write(&cpio_path, gz.stdout).unwrap();
    cpio_path
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
/// needed) — a plain pipe isn't representative of real keyboard input: an
/// earlier pipe-based simulation showed confusing partial-byte-loss that
/// turned out to be a pipe-timing artifact, not a real bug, and only a
/// real PTY caught that.
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
        "virtio-pci BAR assignment regressed (the ACPI _CRS fix that gives PCI a real \
         I/O/memory aperture to assign BARs from):\n{stderr}"
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
/// with" rather than a one-way boot log. Types a
/// real command through a real PTY and checks the guest's own computed
/// answer comes back, then exits via the Ctrl-] escape hatch (needed
/// under `acpi=off`, which has no self-terminating halt path). Uses
/// `acpi=off` deliberately, as a minimal baseline distinct from
/// the ACPI-on case `interactive_console_works_alongside_acpi_and_pci`
/// below covers — the console-silent-under-ACPI bug that once made this
/// the only config that worked is fixed, so this is now just the
/// simplest one.
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

/// Test: the actual fix for the console-silent-under-ACPI bug — a real
/// interactive console *and* PCI/virtio *and* a clean ACPI shutdown, all
/// at once, under the
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

/// Test 3: real SMP. Boots with `--smp 4` and checks
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

/// Test 5: a real PCI capability list + MSI. Attaches
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

/// Test 6: live VM control. Connects to the control
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
    // registers to trigger), which is exactly what
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

    // The socket appears as soon as bind() succeeds — well before the
    // kernel has finished its own boot-time memory setup (buddy allocator
    // init, page zeroing, etc.), which can still legitimately touch high
    // guest-physical addresses for a brief window after that. Found via a
    // real, reproducible flake: the write_mem/read_mem probe below (chosen
    // "high in the 256 MiB region, away from anything a fresh boot has
    // likely touched *yet*") would occasionally get overwritten by the
    // kernel's own continuing boot activity between the probe and a later
    // read-back. A short, fixed settle delay is cheaper and more direct
    // than trying to detect "boot finished" with no stdout to watch (this
    // test intentionally runs with `Stdio::null()`), and this kernel/
    // initramfs combination reaches a stable idle state well within it.
    std::thread::sleep(Duration::from_millis(500));

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

    // A second client attached at the same time as the first, each
    // getting its own independent reads — the multi-client extension.
    // Deliberately still before the register-write checks below: both of
    // these need the guest to still be alive and its memory unchanged,
    // and a `write_regs` against a live, arbitrary-context vCPU (see the
    // comment below) is exactly the kind of thing that can end that.
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

    // A real vCPU register *write* on the live guest, routed through the
    // same vCPU-thread poll as the read above — deliberately the *last*
    // thing this test does with the guest, not just "deliberately not
    // asserting a read-back": overwriting an arbitrary live register
    // (r15 here) can genuinely crash or hang whatever the guest happens
    // to be doing at that exact, unpredictable point in its own
    // execution (mid-syscall, mid-context-switch, anything a real vCPU
    // exit can land on) — this was found empirically, via exactly that
    // happening intermittently when this check used to run earlier and
    // something afterward depended on the guest staying alive. What this
    // still proves is the whole path: parse, KVM_GET_REGS, apply,
    // KVM_SET_REGS accepted by a live vCPU — it just no longer risks
    // taking anything else in this test down with it.
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

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);
}

/// Test 7: snapshot/restore. Boots a real guest, saves a
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
/// Recorded honestly as a still-open gap (see `docs/security/security.md`)
/// rather than forced green by avoiding the one thing that currently
/// breaks it.
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

/// A minimal RSP ("gdb remote serial protocol") client — just enough to
/// drive `gdbstub.rs` from the test's own process the way a real
/// `gdb`/`lldb` would, without depending on either actually being
/// installed on whatever machine runs this suite.
struct RspClient {
    stream: TcpStream,
}

impl RspClient {
    fn send(&mut self, data: &str) -> String {
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        write!(self.stream, "${data}#{checksum:02x}").unwrap();
        let mut ack = [0u8; 1];
        self.stream.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"+", "the stub should ack a well-formed packet");
        self.read_reply()
    }

    fn read_reply(&mut self) -> String {
        let mut byte = [0u8; 1];
        loop {
            self.stream.read_exact(&mut byte).unwrap();
            if byte[0] == b'$' {
                break;
            }
        }
        let mut data = Vec::new();
        loop {
            self.stream.read_exact(&mut byte).unwrap();
            if byte[0] == b'#' {
                break;
            }
            data.push(byte[0]);
        }
        let mut checksum = [0u8; 2];
        self.stream.read_exact(&mut checksum).unwrap();
        self.stream.write_all(b"+").unwrap(); // ack the stub's reply
        String::from_utf8(data).unwrap()
    }
}

/// A real GDB remote-serial-protocol session against a live guest: connects,
/// reads the full register set (`g`), sets and clears a software breakpoint
/// (`Z0`/`z0`) at a real guest-RAM address, then resumes (`c`) and lets the
/// guest boot and shut down normally — proving the whole protocol path
/// (accept, packet framing/checksums, `KVM_GET_REGS`, guest-memory
/// breakpoint patching, `KVM_SET_GUEST_DEBUG`, resuming a real `vcpu.run()`)
/// works end to end, not just that the packet parser's own unit tests pass.
#[test]
fn gdb_stub_serves_a_real_rsp_session_against_a_live_guest() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-gdb-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "poweroff -f");

    // Grab an ephemeral port, then release it immediately before handing
    // it to hyperbug — a small, accepted race (same pattern this file
    // doesn't otherwise need, since every other test uses a Unix socket
    // path instead of a TCP port).
    let addr = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--gdb-stub"])
        .arg(addr.to_string())
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    // `--gdb-stub` blocks the BSP (and therefore the whole boot) until a
    // debugger connects — poll for the listening port rather than
    // guessing a delay.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut client = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break RspClient { stream: s },
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("could not connect to the gdb stub: {e}"),
        }
    };
    client.stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // `?` — halt reason. The guest hasn't run a single instruction yet.
    assert_eq!(client.send("?"), "S05");

    // `g` — every register, in the fixed 164-byte layout `gdbstub.rs`
    // documents. Not a live boot's real entry-point value we can predict
    // exactly, but its *shape* (exactly 328 hex characters, valid hex) is
    // real, checkable evidence the read actually happened against a live
    // vCPU rather than returning something malformed or truncated.
    let regs = client.send("g");
    assert_eq!(regs.len(), 328, "the fixed amd64 register layout is 164 bytes = 328 hex chars; got: {regs}");
    assert!(regs.bytes().all(|b| b.is_ascii_hexdigit()), "got: {regs}");

    // `Z0`/`z0` — insert then remove a software breakpoint at a real
    // guest-RAM address well below the kernel (never actually reached by
    // `c` below, since it's removed before resuming) — proves the
    // breakpoint bookkeeping's guest-memory patch/restore round trip
    // works against real `GuestMemory`, not just the unit-tested logic.
    assert_eq!(client.send("Z0,8000,1"), "OK");
    assert_eq!(client.send("z0,8000,1"), "OK");

    // `c` — resume for real. No further stop is expected: the guest boots
    // and shuts down via ACPI on its own (the initramfs's `poweroff -f`),
    // same as every other non-interactive boot test in this file.
    write!(client.stream, "$c#63").unwrap(); // checksum of 'c' is 0x63
    let mut ack = [0u8; 1];
    client.stream.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"+");

    let code = wait_with_timeout(&mut child, Duration::from_secs(30));
    assert_eq!(code, Some(0), "the guest should have booted and shut down cleanly after `c`");

    let _ = fs::remove_dir_all(&dir);
}

/// `--trace-file` produces a real Chrome Trace Event Format JSON file from
/// an actual boot — a syntactically complete `[ ... ]` array with at least
/// one real VM-exit duration event in it, not just the hand-fed unit test
/// in `trace.rs`.
#[test]
fn trace_file_captures_real_vm_exits_from_a_live_boot() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-trace-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "poweroff -f");
    let trace_path = dir.join("trace.json");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--trace-file"])
        .arg(&trace_path)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let code = wait_with_timeout(&mut child, Duration::from_secs(30));
    assert_eq!(code, Some(0), "the guest should boot and shut down cleanly with tracing enabled");

    let contents = fs::read_to_string(&trace_path).expect("the trace file should exist");
    let trimmed = contents.trim();
    assert!(trimmed.starts_with('['), "got: {}", &trimmed[..trimmed.len().min(200)]);
    assert!(trimmed.ends_with(']'), "got: {}", &trimmed[trimmed.len().saturating_sub(200)..]);
    assert!(trimmed.contains("\"ph\":\"X\""), "should contain at least one real VM-exit duration event");
    assert!(trimmed.contains("\"cat\":\"vmexit\""));

    let _ = fs::remove_dir_all(&dir);
}

/// Reads the current `rip` off a live gdb-stub session's `g` reply — the
/// 17th 8-byte little-endian field (16 GPRs * 16 hex chars, then `rip` at
/// hex offset 256..272), per `gdbstub.rs`'s documented register layout.
fn rip_from_g_reply(regs: &str) -> u64 {
    let rip_hex = &regs[256..272];
    let bytes: Vec<u8> = (0..8).map(|i| u8::from_str_radix(&rip_hex[i * 2..i * 2 + 2], 16).unwrap()).collect();
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn connect_gdb_stub(addr: std::net::SocketAddr) -> RspClient {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                return RspClient { stream: s };
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("could not connect to the gdb stub: {e}"),
        }
    }
}

/// The test that actually exercises the path the earlier
/// `gdb_stub_serves_a_real_rsp_session_against_a_live_guest` test
/// deliberately didn't: setting a breakpoint at an address the guest
/// *will* actually execute (not one it's already sitting on), letting it
/// fire for real via normal execution, and then resuming past it with it
/// still armed.
///
/// This needs two separate launches, for a real reason, not caution for
/// its own sake: the first version of this test set a breakpoint at the
/// guest's *current* (not-yet-executed) `rip` and expected an immediate
/// stop on `c` — which never came, hanging the test. That guess was
/// itself wrong, not the code: real debuggers (this one included, and
/// correctly) treat "resuming from a position that already has one of
/// your own breakpoints planted on it" as a silent step-over-and-rearm,
/// the same standard `ptrace`/gdbserver convention used when you're
/// already stopped exactly on a breakpoint — no second "hit" is reported
/// for a location you're already sitting on. So this test needs the
/// breakpoint at an address that's genuinely *ahead* of where execution
/// currently is when `c` is issued, which needs a first, disposable
/// launch just to discover a real, guaranteed-to-be-executed downstream
/// address (via one real single step) before setting up the actual test
/// on a second, fresh launch.
///
/// This is the test that caught two real bugs on its very first run
/// (against the *original*, flawed single-launch design, before the
/// above correction): `pc` being off by one (every real breakpoint hit
/// was misclassified as "not ours" and forwarded to the guest instead of
/// reported), and resuming from an armed breakpoint with no step-over
/// logic at all re-trapping the same instruction forever. See
/// `gdbstub.rs`'s `handle_debug_exit`/`resume` doc comments for the full
/// root-cause writeups.
#[test]
fn gdb_stub_actually_hits_and_resumes_past_a_real_breakpoint() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-gdb-bp-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "poweroff -f");

    let launch = |kernel: &Path, initramfs: &Path| -> (Child, std::net::SocketAddr) {
        let addr = {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };
        let child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
            .args(["--kernel"])
            .arg(kernel)
            .args(["--initrd"])
            .arg(initramfs)
            .args(["--gdb-stub"])
            .arg(addr.to_string())
            .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to launch hyperbug");
        (child, addr)
    };

    // First, disposable launch: discover a real address the guest will
    // execute *after* its very first instruction, by single-stepping
    // exactly once. hyperbug's own loader always sets the same entry
    // point for the same kernel/args, so this address is exactly what a
    // fresh second launch will also reach.
    let (mut probe_child, probe_addr) = launch(&kernel, &initramfs);
    let mut probe = connect_gdb_stub(probe_addr);
    let entry_rip = rip_from_g_reply(&probe.send("g"));
    assert_ne!(entry_rip, 0, "the guest's real entry point should not be null");
    write!(probe.stream, "$s#73").unwrap(); // checksum of 's' is 0x73
    let mut ack = [0u8; 1];
    probe.stream.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"+");
    let stop = probe.read_reply();
    assert_eq!(stop, "S05", "the single step should complete and report a stop; got: {stop}");
    let second_rip = rip_from_g_reply(&probe.send("g"));
    assert_ne!(second_rip, entry_rip, "a real single step must have moved rip");
    let _ = probe_child.kill();
    let _ = probe_child.wait();

    // Second, real launch: fresh guest, halted again at `entry_rip`. Set
    // the breakpoint at `second_rip` — genuinely ahead of where execution
    // currently is — and continue for real.
    let (mut child, addr) = launch(&kernel, &initramfs);
    let mut client = connect_gdb_stub(addr);
    assert_eq!(rip_from_g_reply(&client.send("g")), entry_rip, "a fresh launch should reach the same entry point");
    assert_eq!(client.send(&format!("Z0,{second_rip:x},1")), "OK");
    write!(client.stream, "$c#63").unwrap(); // checksum of 'c' is 0x63
    client.stream.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"+");
    let stop = client.read_reply();
    assert_eq!(stop, "S05", "the breakpoint should have fired via real execution; got: {stop}");

    // The real point of this test: `rip` after the stop must be *exactly*
    // the breakpoint's own address, not off by one in either direction —
    // this is what the `pc`-without-minus-one fix guarantees.
    let stopped_rip = rip_from_g_reply(&client.send("g"));
    assert_eq!(stopped_rip, second_rip, "the guest must stop exactly at the breakpoint address, no off-by-one");

    // Resume with the breakpoint *still armed* — the step-over-and-rearm
    // path. If it's broken, the guest re-traps the same instruction
    // forever and this hangs; if it works, the guest boots and shuts down
    // normally (nothing else in this boot revisits this exact address).
    write!(client.stream, "$c#63").unwrap();
    client.stream.read_exact(&mut ack).unwrap();
    assert_eq!(&ack, b"+");

    let code = wait_with_timeout(&mut child, Duration::from_secs(30));
    assert_eq!(
        code,
        Some(0),
        "the guest should boot and shut down cleanly after resuming past an armed breakpoint"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Milestone 1 of record-and-replay (`src/pmu.rs`): confirms the real,
/// guest-mode-only branch counter actually counts real guest execution
/// against a live KVM guest — not just the plumbing-only host busy-loop
/// check `pmu.rs`'s own unit test does (which deliberately can't exercise
/// `exclude_host`, since a plain host thread never enters guest mode at
/// all). This is the test that reproduces, permanently and automatically,
/// the manual measurement that found this project's own AMD SpecLockMap
/// finding (`src/pmu.rs`'s module doc comment): a real, if likely
/// imprecise-without-the-MSR-fix, nonzero count from a real guest
/// actually running.
///
/// **Must synchronize on the guest actually reaching userspace, not
/// guess a delay.** The first version of this test used a flat 500ms
/// sleep before measuring, and failed intermittently with a real zero
/// count — not a counter bug: `exclude_kernel=1` filters *ring-0*
/// execution regardless of host or guest, so a guest still deep in
/// kernel-mode boot code (which is *all* of it, until the busybox init
/// script's own userspace code starts running) legitimately retires zero
/// *counted* branches. A flat sleep raced that boundary under real system
/// load (this was caught right after a `cargo` rebuild, when scheduling
/// latency was worse than usual) — the fix is watching the guest's own
/// console output for a real marker proving userspace was reached, the
/// same synchronization this project's other tests already use for
/// exactly this class of race (see `boots_with_disk_and_shuts_down_
/// cleanly_under_acpi`'s `BOOT_MARKER`).
#[test]
fn guest_mode_branch_counter_counts_real_guest_execution() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-pmu-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    // A real CPU-bound busy loop, not `sleep` — HLT retires no guest
    // branches at all, which would make this test meaningless. The marker
    // is `echo`ed (a shell builtin, no `exec`) right before the loop
    // starts, so seeing it on the console really does mean userspace
    // execution has begun.
    let initramfs = build_initramfs(&dir, "echo PMU_TEST_USERSPACE_READY\nwhile true; do :; done");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--mem", "128", "--cmdline", "console=ttyS0 panic=1 acpi=off"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    // `--smp` defaults to 1, so the BSP vCPU runs on the process's own
    // main thread — its Linux TID equals the process PID by convention.
    let vcpu_tid = child.id() as libc::pid_t;

    // Block on the real marker, with a generous timeout, instead of
    // guessing a delay. The read must be non-blocking — a plain blocking
    // read would hang past the deadline check entirely if the guest never
    // wrote anything at all, since the check only runs *between* reads.
    let mut stdout = child.stdout.take().unwrap();
    // SAFETY: `stdout`'s fd is valid for the duration of this call and
    // owned exclusively by this `ChildStdout` for as long as it's alive.
    unsafe {
        let flags = libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut seen = String::new();
    let mut byte = [0u8; 1];
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if seen.contains("PMU_TEST_USERSPACE_READY") {
            break;
        }
        assert!(Instant::now() < deadline, "guest never reached userspace; console so far: {seen}");
        match stdout.read(&mut byte) {
            Ok(1) => seen.push(byte[0] as char),
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }

    let (counter, precise) = match hyperbug::pmu::BranchCounter::open_for_thread(vcpu_tid) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skipping: {e}");
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&dir);
            return;
        }
    };
    eprintln!("branch counter opened against a live guest; precise = {precise}");
    counter.reset();
    counter.enable();
    std::thread::sleep(Duration::from_millis(500));
    counter.disable();
    let count = counter.read_count();
    eprintln!("guest-mode retired branches over ~500ms of a real busy loop: {count}");

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&dir);

    assert!(count > 0, "a real, CPU-bound guest busy loop should retire a nonzero number of branches");
}

/// Record-and-replay Milestone 2 (`src/record.rs`): `--record` actually
/// captures real, live-typed keystrokes — not synthetic data fed in some
/// other way — each tagged with a real host branch-count position, in
/// the same order they were typed. Still doesn't prove replay (Milestone
/// 3 doesn't exist), only that recording captures the real thing.
#[test]
fn record_flag_captures_real_typed_keystrokes_with_positions() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-record-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "exec /bin/sh");
    let record_path = dir.join("recording.bin");

    let pty = open_pty();
    let slave_for_child = pty.slave_path.clone();

    let mut child = unsafe {
        Command::new(env!("CARGO_BIN_EXE_hyperbug"))
            .args(["--kernel"])
            .arg(&kernel)
            .args(["--initrd"])
            .arg(&initramfs)
            .args(["--record"])
            .arg(&record_path)
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

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        read_available(&mut master, &mut out);
        std::thread::sleep(Duration::from_millis(100));
    }

    // A short, exactly-known sequence of real keystrokes.
    let typed = "echo RECORD_TEST\n";
    for byte in typed.bytes() {
        let _ = master.write_all(&[byte]);
        std::thread::sleep(Duration::from_millis(20));
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        read_available(&mut master, &mut out);
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = master.write_all(&[0x1d]); // Ctrl-]
    let code = wait_with_timeout(&mut child, Duration::from_secs(5));
    assert!(code.is_some(), "Ctrl-] should make hyperbug exit, not hang");

    let (header, events) = hyperbug::record::read_all(record_path.to_str().unwrap())
        .expect("a recording file should have been written");
    assert_eq!(header.mem_size, 256 * 1024 * 1024);
    eprintln!("recording precise = {}", header.precise);

    let keyboard_bytes: Vec<u8> = events
        .iter()
        .filter(|e| e.kind == hyperbug::record::EventKind::KeyboardRx)
        .flat_map(|e| e.data.iter().copied())
        .collect();
    let reconstructed = String::from_utf8_lossy(&keyboard_bytes);
    assert!(
        reconstructed.contains(typed),
        "the recording should reconstruct exactly what was typed; got: {reconstructed:?}"
    );

    // Positions must be real and non-decreasing across the whole
    // recording — a real, monotonically-advancing counter, not a
    // constant or garbage value.
    let mut last = 0u64;
    for event in &events {
        assert!(event.branch_count >= last, "branch_count must never go backwards");
        last = event.branch_count;
    }
    assert!(!events.is_empty(), "typing real keystrokes should have produced at least one recorded event");

    let _ = fs::remove_dir_all(&dir);
}

/// Record-and-replay Milestone 3 (`src/record.rs`'s `Replayer`): a real
/// end-to-end test — record a session where a marker is typed through a
/// real PTY, then launch a *completely separate, fresh* hyperbug process
/// with `--replay` against that recording (no PTY, no real keyboard input
/// at all — stdin is suppressed under `--replay`, see `reactor.rs`) and
/// confirm the replayed guest's own console shows the *same* marker
/// echoed back, delivered entirely by the recorded keystrokes being
/// re-injected at their recorded branch-count positions.
///
/// This is explicitly a poll-granularity check, not a cycle-exact one —
/// `docs/record-replay.md` states directly why this design doesn't (and,
/// on this AMD host without the SpecLockMap fix, currently can't) claim
/// cycle-exact timing. What this test actually proves: two independent
/// boots of the identical kernel/initramfs reach a similar-enough
/// execution position that recorded keyboard positions from one boot
/// still land correctly relative to the other — which is the real,
/// practical claim this milestone makes, not an exact-instruction-count
/// guarantee.
#[test]
fn replay_reproduces_a_recorded_session_on_a_completely_separate_boot() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-replay-e2e-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "exec /bin/sh");
    let record_path = dir.join("session.hbrr");

    // --- Record: a real PTY session, a real typed marker. ---
    {
        let pty = open_pty();
        let slave_for_child = pty.slave_path.clone();
        let mut child = unsafe {
            Command::new(env!("CARGO_BIN_EXE_hyperbug"))
                .args(["--kernel"])
                .arg(&kernel)
                .args(["--initrd"])
                .arg(&initramfs)
                .args(["--record"])
                .arg(&record_path)
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
                .expect("failed to launch hyperbug for recording")
        };

        let mut master = pty.master;
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            read_available(&mut master, &mut out);
            std::thread::sleep(Duration::from_millis(100));
        }

        let typed = "echo REPLAY_E2E_MARKER\n";
        for byte in typed.bytes() {
            let _ = master.write_all(&[byte]);
            std::thread::sleep(Duration::from_millis(20));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            read_available(&mut master, &mut out);
            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = master.write_all(&[0x1d]); // Ctrl-]
        let code = wait_with_timeout(&mut child, Duration::from_secs(5));
        assert!(code.is_some(), "the recording session should have exited cleanly");
        assert!(
            String::from_utf8_lossy(&out).contains("REPLAY_E2E_MARKER"),
            "sanity check: the recording session itself should have echoed the typed marker"
        );
    }

    // --- Replay: a completely separate process, no PTY, no real input at
    // all. Non-blocking plain pipe is enough — we only need to observe
    // the guest's own console output. ---
    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--replay"])
        .arg(&record_path)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 acpi=off"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug for replay");

    let mut stdout = child.stdout.take().unwrap();
    // SAFETY: `stdout`'s fd is valid and owned exclusively by this
    // `ChildStdout` for as long as it's alive.
    unsafe {
        let flags = libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut seen = String::new();
    let mut byte = [0u8; 1];
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !seen.contains("REPLAY_E2E_MARKER") {
        match stdout.read(&mut byte) {
            Ok(1) => seen.push(byte[0] as char),
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        seen.contains("REPLAY_E2E_MARKER"),
        "the replayed guest should have echoed the recorded marker, delivered from the \
         recording alone with no real keyboard input; console so far:\n{seen}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Fast fork-a-running-VM (Tier 5, `src/fork.rs`): a real, live guest, a
/// real `fork <path>` control-socket command, and confirmation that the
/// resulting child is a genuinely independent process — not sharing
/// memory with the parent, not sharing a control socket, and able to
/// keep running on its own after the parent is killed outright.
#[test]
fn fork_clones_a_live_guest_into_a_genuinely_independent_process() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-fork-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "sleep 60");
    let parent_socket = dir.join("parent.sock");
    let child_socket = dir.join("child.sock");

    let mut parent = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--control-socket"])
        .arg(&parent_socket)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 acpi=off"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !parent_socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(parent_socket.exists(), "parent control socket should appear shortly after launch");
    // Same settle rationale as the existing control-socket test: give the
    // kernel's own boot-time memory setup a moment to finish touching
    // high guest-physical addresses before probing them.
    std::thread::sleep(Duration::from_millis(500));

    let mut parent_stream =
        std::os::unix::net::UnixStream::connect(&parent_socket).expect("should connect to parent control socket");
    parent_stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut parent_reader = std::io::BufReader::new(parent_stream.try_clone().unwrap());

    // A real marker written into the parent's guest memory *before*
    // forking — this is what proves the child actually inherited memory
    // (via `fork()`'s own copy-on-write), not started from scratch.
    let addr = 0x0f00_0000u64;
    let before_fork = "cafebabe00000000";
    writeln!(parent_stream, "write_mem {addr:x} {before_fork}").unwrap();
    let mut line = String::new();
    parent_reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "OK", "write_mem before forking should succeed");

    // The actual fork.
    writeln!(parent_stream, "fork {}", child_socket.display()).unwrap();
    line.clear();
    parent_reader.read_line(&mut line).unwrap();
    assert!(line.starts_with("OK "), "fork should succeed; got: {line}");
    let child_pid: libc::pid_t = line.trim().strip_prefix("OK ").unwrap().parse().expect("fork reply should include a real pid");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !child_socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(child_socket.exists(), "child control socket should appear shortly after a successful fork");
    std::thread::sleep(Duration::from_millis(200));

    let mut child_stream =
        std::os::unix::net::UnixStream::connect(&child_socket).expect("should connect to the forked child's own control socket");
    child_stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut child_reader = std::io::BufReader::new(child_stream.try_clone().unwrap());

    // The child must have inherited the pre-fork memory contents exactly.
    writeln!(child_stream, "read_mem {addr:x} 8").unwrap();
    line.clear();
    child_reader.read_line(&mut line).unwrap();
    assert_eq!(
        line.trim(),
        format!("OK {before_fork}"),
        "the forked child should have inherited the parent's pre-fork memory"
    );

    // Now write *different* data into the child's own memory, and confirm
    // the parent's view is completely untouched — the actual point of
    // real copy-on-write divergence, not a shared mapping.
    let after_fork_child = "deadbeef11111111";
    writeln!(child_stream, "write_mem {addr:x} {after_fork_child}").unwrap();
    line.clear();
    child_reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "OK");

    writeln!(parent_stream, "read_mem {addr:x} 8").unwrap();
    line.clear();
    parent_reader.read_line(&mut line).unwrap();
    assert_eq!(
        line.trim(),
        format!("OK {before_fork}"),
        "the parent's memory must be completely unaffected by the child's own write"
    );

    // The child's vCPU must be genuinely alive and independently running
    // — a real register read through its own control socket.
    writeln!(child_stream, "regs").unwrap();
    line.clear();
    child_reader.read_line(&mut line).unwrap();
    assert!(line.starts_with("OK rip="), "the forked child's vCPU should be alive; got: {line}");

    // Kill the parent outright and confirm the child keeps running on its
    // own — proof it's a genuinely separate process, not something that
    // depends on the parent staying alive.
    let _ = parent.kill();
    let _ = parent.wait();
    std::thread::sleep(Duration::from_millis(200));
    writeln!(child_stream, "regs").unwrap();
    line.clear();
    child_reader.read_line(&mut line).unwrap();
    assert!(
        line.starts_with("OK rip="),
        "the forked child should survive the parent's death; got: {line}"
    );

    // The forked child was never spawned through this test's own
    // `Command` — it exists only because `fork()` happened *inside* the
    // (now-dead) parent process, so it was already reparented to init
    // once its real parent died. There's no `Child` handle here to call
    // `.kill()`/`.wait()` on (and no way for this process to `waitpid` a
    // process that was never its own child); just signal it to terminate
    // via the real pid the parent's own `fork` reply reported, and let
    // init reap it.
    drop(child_stream);
    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
    }

    let _ = fs::remove_dir_all(&dir);
}

/// Live migration (Tier 5's last item, `src/migrate.rs`): a real source
/// guest, a real `--migrate-listen` destination process waiting on a real
/// TCP port, and a real `migrate <host:port>` control-socket command —
/// confirming guest memory actually travels across the wire (not shared,
/// not assumed), the source guest retires with `GuestExit::MigratedAway`,
/// and the destination is a genuinely independent, live-addressable
/// process afterward.
#[test]
fn migrate_moves_a_live_guest_to_a_separate_waiting_process() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-migrate-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(&dir, "sleep 60");
    let source_socket = dir.join("source.sock");
    let dest_socket = dir.join("dest.sock");

    // Same ephemeral-port pattern the gdb-stub test already uses: grab a
    // free port, release it immediately, then race the destination
    // process to bind it — the destination is launched first and given
    // time to bind before the source ever connects, so the race is
    // narrow and one-directional (destination binds, then listens; the
    // source only ever connects after that).
    let migrate_addr = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    };

    // The destination: launched *before* the source migrates anything,
    // blocked in `TcpListener::accept()` (see `migrate::receive_and_wait`)
    // until the source connects. Same memory size and device
    // configuration as the source below — `--migrate-listen` shares
    // `--restore`'s own requirement that the rest of `Args` matches
    // exactly.
    let mut dest = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--migrate-listen"])
        .arg(migrate_addr.to_string())
        .args(["--control-socket"])
        .arg(&dest_socket)
        .args(["--mem", "256"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug --migrate-listen");

    // Deliberately *not* probed with a throwaway `TcpStream::connect`
    // here: `TcpListener::accept()` on the destination side
    // (`migrate::receive_and_wait`) only ever accepts *one* connection —
    // a probe that connects and then drops would be the one accepted,
    // starving the real migration attempt below and making the
    // destination process exit immediately on the resulting truncated
    // read. Instead, give the destination a brief moment to actually bind
    // (well under what a real process launch + arg parsing + `bind()`
    // takes) and let the migrate attempt below retry on its own if it's
    // still too early.
    std::thread::sleep(Duration::from_millis(300));

    // The source: a normal, fully-booted, independently-running guest —
    // `acpi=off` for the same reason `fork_clones_a_live_guest_...`
    // uses it, this test has nothing to do with ACPI/PCI.
    let mut source = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--control-socket"])
        .arg(&source_socket)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1 acpi=off"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !source_socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(source_socket.exists(), "source control socket should appear shortly after launch");
    std::thread::sleep(Duration::from_millis(500));

    let mut source_stream =
        std::os::unix::net::UnixStream::connect(&source_socket).expect("should connect to source control socket");
    source_stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut source_reader = std::io::BufReader::new(source_stream.try_clone().unwrap());

    // A real marker written into the source's guest memory *before*
    // migrating — this is what proves the destination actually received
    // real guest memory over the wire, not just a fresh boot.
    let addr = 0x0f00_0000u64;
    let marker = "f00dcafe12345678";
    writeln!(source_stream, "write_mem {addr:x} {marker}").unwrap();
    let mut line = String::new();
    source_reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "OK", "write_mem before migrating should succeed");

    // The actual migration — retried a few times in case the destination
    // hasn't quite finished binding yet (a failed attempt leaves the
    // source guest untouched and safe to retry, exactly as
    // `migrate.rs`'s own doc comment states).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        writeln!(source_stream, "migrate {migrate_addr}").unwrap();
        line.clear();
        source_reader.read_line(&mut line).unwrap();
        if line.trim() == "OK" {
            break;
        }
        assert!(Instant::now() < deadline, "migrate never succeeded; last reply: {line}");
        std::thread::sleep(Duration::from_millis(50));
    }

    // The source's own guest is now retired — `GuestExit::MigratedAway`
    // (exit code 13), not a crash and not a normal shutdown.
    let code = wait_with_timeout(&mut source, Duration::from_secs(10));
    assert_eq!(code, Some(13), "the source process should exit with the MigratedAway code");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !dest_socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(dest_socket.exists(), "destination control socket should appear once migration completes");
    std::thread::sleep(Duration::from_millis(200));

    let mut dest_stream = std::os::unix::net::UnixStream::connect(&dest_socket)
        .expect("should connect to the destination's own control socket");
    dest_stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut dest_reader = std::io::BufReader::new(dest_stream.try_clone().unwrap());

    // The destination must have received the exact pre-migration memory
    // contents — real bytes that crossed a real TCP connection.
    writeln!(dest_stream, "read_mem {addr:x} 8").unwrap();
    line.clear();
    dest_reader.read_line(&mut line).unwrap();
    assert_eq!(
        line.trim(),
        format!("OK {marker}"),
        "the destination should have received the source's pre-migration memory"
    );

    // The destination's vCPU must be genuinely alive and running on its
    // own, independent of the (now-exited) source process.
    writeln!(dest_stream, "regs").unwrap();
    line.clear();
    dest_reader.read_line(&mut line).unwrap();
    assert!(line.starts_with("OK rip="), "the destination's vCPU should be alive; got: {line}");

    let _ = dest.kill();
    let _ = dest.wait();
    let _ = fs::remove_dir_all(&dir);
}

/// The real regression guard for two real bugs found and fixed the same
/// session, both invisible to every other test in this file (none of
/// which drives a real guest network driver at all): (1) `pci.rs` never
/// implemented the PCI Subsystem Vendor/Device ID fields, which is what
/// `virtio_pci_legacy_dev.c` actually reads a legacy virtio device's type
/// from — every legacy virtio device (blk/net/rng) reported device id 0,
/// silently matching no real driver's `MODULE_DEVICE_TABLE`, for this
/// project's entire history; (2) `VirtioLegacyPci::drain_queue` treated
/// virtio-net's RX queue exactly like every other queue this codebase
/// has ("a kick means process it now"), but RX is the one queue where the
/// guest posts *empty* buffers for the device to fill *later* — draining
/// it on kick stole freshly-posted buffers before `try_deliver_rx` could
/// ever use them, causing majority (50-70%, measured) real packet loss
/// even at a light, non-adversarial ping rate. See `src/virtio.rs`'s
/// `VirtioDeviceOps::wants_queue_notify` and `src/pci.rs`'s
/// `PciDevice::subsystem_device_id` for the fixes' own doc comments.
///
/// Needs real `CAP_NET_ADMIN` to create a TAP interface. Rather than
/// needing real root (this project's long-standing blocker for testing
/// `--net` at all — see `DEBTS.md`), this test grants itself an isolated,
/// throwaway network namespace via `unshare --user --map-root-user
/// --net`: an *unprivileged* user namespace maps the calling (non-root)
/// user to root *inside* the new namespace, and `CAP_NET_ADMIN` inside an
/// unprivileged net namespace is real and sufficient to create a TAP
/// device — confirmed directly against this host before writing this
/// test, not assumed. Everything network-related (launching hyperbug,
/// configuring the host side of the TAP interface, running `ping`) has to
/// happen inside *one* such namespace to see the same interface, so it's
/// all one shell script run under one `unshare` invocation rather than
/// several cooperating processes.
#[test]
fn net_survives_a_real_ping_flood_after_the_rx_notify_fix() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }
    for tool in ["unshare", "zstd", "ping", "file"] {
        if !have_tool(tool) {
            eprintln!("skipping: `{tool}` not found on this host");
            return;
        }
    }
    let Some(release) = kernel_release(&kernel) else {
        eprintln!("skipping: couldn't determine the kernel's own release string");
        return;
    };
    let Some(modules) = find_virtio_net_modules(&release) else {
        eprintln!(
            "skipping: {release}'s own virtio-net modules not found under /lib/modules \
             (built directly into the kernel on this host, or a different distribution layout)"
        );
        return;
    };

    let dir = std::env::temp_dir().join(format!("hyperbug-net-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_net_initramfs(&dir, &modules);
    let guest_log = dir.join("guest.log");
    let hyperbug_bin = env!("CARGO_BIN_EXE_hyperbug");

    // One self-contained script, run inside one `unshare`-created
    // namespace: launch hyperbug with `--net` in the background, poll
    // its own log for the guest's `GUEST_NET_READY` marker (never a flat
    // sleep — see this project's own item 49 lesson about exactly that
    // race), configure the host side of the TAP interface, run a real
    // 50-packet ping flood, tear hyperbug down, and print ping's own
    // summary line last so the Rust side can parse it out of this
    // process's captured stdout.
    let script = format!(
        r#"
        set -e
        ip link set lo up
        {hyperbug_bin} --kernel {kernel} --initrd {initramfs} --net --mem 256 \
            > {guest_log} 2>&1 &
        HB_PID=$!
        for i in $(seq 1 100); do
            grep -q GUEST_NET_READY {guest_log} 2>/dev/null && break
            sleep 0.1
        done
        if ! grep -q GUEST_NET_READY {guest_log} 2>/dev/null; then
            echo "READY_TIMEOUT"
            kill $HB_PID 2>/dev/null || true
            exit 1
        fi
        ip addr add 10.250.0.1/24 dev hyperbug0
        ping -c 50 -i 0.02 -W 2 10.250.0.2
        kill $HB_PID 2>/dev/null || true
        wait $HB_PID 2>/dev/null || true
        "#,
        hyperbug_bin = hyperbug_bin,
        kernel = kernel.display(),
        initramfs = initramfs.display(),
        guest_log = guest_log.display(),
    );

    let output = Command::new("timeout")
        .args(["30", "unshare", "--user", "--map-root-user", "--net", "--", "bash", "-c", &script])
        .output()
        .expect("failed to run the unshare-wrapped test script");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stdout.contains("READY_TIMEOUT"),
        "the guest's own eth0 never came up (GUEST_NET_READY never printed) — \
         stdout:\n{stdout}\nstderr:\n{stderr}\nguest log:\n{}",
        fs::read_to_string(&guest_log).unwrap_or_default()
    );

    // Parses ping's own summary line ("50 packets transmitted, N
    // received, ...") rather than trusting the process's exit code alone
    // — `ping` exits non-zero on *any* loss, but this test's own
    // threshold (see below) is deliberately more lenient than "zero loss
    // ever" to avoid flakiness from ordinary host scheduling jitter.
    let summary_line = stdout
        .lines()
        .find(|l| l.contains("packets transmitted"))
        .unwrap_or_else(|| panic!("no ping summary line in output:\n{stdout}\nstderr:\n{stderr}"));
    let received: u32 = summary_line
        .split(',')
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("couldn't parse received count from: {summary_line}"));

    // The real bug this test guards against reproducibly caused 50-70%
    // loss even at this same light rate — 45/50 is comfortably above that
    // failure mode's own ceiling and comfortably below "flag on any
    // ordinary jitter."
    assert!(
        received >= 45,
        "expected at least 45/50 real pings to succeed, got {received}/50 — summary: {summary_line}\n\
         full output:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Real end-to-end verification of `--i2c-device`/`virtio_i2c.rs`: boots a
/// guest with the reference `devices/i2c_temp_sensor.py` target attached,
/// loads this exact kernel's own real, unmodified `i2c-virtio`/`i2c-dev`
/// drivers, and runs a real userspace `I2C_RDWR` ioctl against
/// `/dev/i2c-0` — the actual guest-facing surface this device exists to
/// provide, not just `process_chain` called directly (the unit tests in
/// `virtio_i2c.rs` already cover that in isolation). Checks: the real
/// "write register pointer, then read" idiom returns the sensor's
/// expected temperature bytes; a write-then-read round trip through the
/// config register actually persists; and probing an unoccupied address
/// gets a real NAK (fewer messages transferred than requested) rather
/// than being silently treated as present.
#[test]
fn i2c_adapter_answers_a_real_i2c_rdwr_ioctl_from_userspace() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }
    for tool in ["zstd", "cc", "file"] {
        if !have_tool(tool) {
            eprintln!("skipping: `{tool}` not found on this host");
            return;
        }
    }
    let Some(release) = kernel_release(&kernel) else {
        eprintln!("skipping: couldn't determine the kernel's own release string");
        return;
    };
    let Some((virtio_ko, dev_ko, core_ko)) = find_i2c_modules(&release) else {
        eprintln!(
            "skipping: {release}'s own i2c-virtio/i2c-dev modules not found under /lib/modules \
             (built directly into the kernel on this host, or a different distribution layout)"
        );
        return;
    };

    let dir = std::env::temp_dir().join(format!("hyperbug-i2c-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_i2c_initramfs(&dir, &virtio_ko, &dev_ko, core_ko.as_deref());
    let plugin = concat!(env!("CARGO_MANIFEST_DIR"), "/devices/i2c_temp_sensor.py");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--i2c-device", &format!("{plugin}:I2cTempSensor:0x48")])
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let mut stdout = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut out = child.stdout.take().unwrap();
    let mut buf = [0u8; 4096];
    loop {
        if stdout.contains("I2C_TEST_DONE") || Instant::now() >= deadline {
            break;
        }
        match out.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => stdout.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    let mut stderr = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut stderr);
    }

    assert!(
        stdout.contains("I2C_TEST_DONE"),
        "the guest never finished the real I2C_RDWR test within 20s — stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("TEMP_BYTES=00eb"),
        "expected the sensor's fixed 23.5C reading (0x00eb) via the real write-register-then-read \
         idiom over a genuine I2C_RDWR ioctl — stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("CFG_BYTE=77"),
        "a real write to the config register followed by a real read back must return what was \
         just written — stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("PROBE_EMPTY_RC=1"),
        "probing an address with no device attached must NAK (transfer fewer messages than \
         requested), not silently succeed — stdout:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Real end-to-end verification of `--gpio-device`/`virtio_gpio.rs`: boots
/// a guest with the reference `devices/gpio_button_bank.py` bank
/// attached, loads this exact kernel's own real, unmodified `gpio-virtio`
/// driver, and runs a real userspace `GPIO_V2` ioctl sequence against
/// `/dev/gpiochip0` — output line drive/read-back, then arming an input
/// line's falling-edge interrupt and receiving a **real** interrupt
/// delivered by the plugin's own background-thread `raise_irq()` call
/// (`HYPERBUG_GPIO_DEMO_AUTOPRESS_MS`), exercising the full
/// `ChainOutcome::Pending`/`poll_completions`/completion-eventfd path a
/// direct `process_chain` unit test can't reach.
#[test]
fn gpio_bank_answers_real_ioctls_and_delivers_a_real_interrupt() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }
    for tool in ["zstd", "cc", "file"] {
        if !have_tool(tool) {
            eprintln!("skipping: `{tool}` not found on this host");
            return;
        }
    }
    let Some(release) = kernel_release(&kernel) else {
        eprintln!("skipping: couldn't determine the kernel's own release string");
        return;
    };
    let Some(gpio_ko) = find_gpio_module(&release) else {
        eprintln!(
            "skipping: {release}'s own gpio-virtio module not found under /lib/modules \
             (built directly into the kernel on this host, or a different distribution layout)"
        );
        return;
    };

    let dir = std::env::temp_dir().join(format!("hyperbug-gpio-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_gpio_initramfs(&dir, &gpio_ko);
    let plugin = concat!(env!("CARGO_MANIFEST_DIR"), "/devices/gpio_button_bank.py");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--gpio-device", &format!("{plugin}:ButtonBank")])
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
        // A generous but bounded fixed delay before the plugin's own
        // background thread presses the button — there's no other
        // synchronization channel into a running plugin from outside the
        // guest (see `devices/gpio_button_bank.py`'s own doc comment).
        // Empirically, a real boot plus reaching the ioctl test in this
        // sandbox took a little over 2.5s once; 5s leaves comfortable
        // margin, and the guest's own `poll()` timeout (10s, compiled
        // into `GPIO_TEST_C_SOURCE`) comfortably outlasts it.
        .env("HYPERBUG_GPIO_DEMO_AUTOPRESS_MS", "5000")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let mut stdout = String::new();
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut out = child.stdout.take().unwrap();
    let mut buf = [0u8; 4096];
    loop {
        if stdout.contains("GPIO_TEST_DONE") || Instant::now() >= deadline {
            break;
        }
        match out.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => stdout.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    let mut stderr = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut stderr);
    }

    assert!(
        stdout.contains("GPIO_TEST_DONE"),
        "the guest never finished the real GPIO ioctl test within 25s — stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("POWER_CONTROL_INITIAL=1") && stdout.contains("POWER_CONTROL_AFTER_CLEAR=0"),
        "a real output line drive/read-back round trip must work — stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("POWER_BUTTON_INITIAL=1"),
        "the power button line must read its real idle-high value before being pressed — stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("IRQ_RECEIVED offset=0"),
        "a real falling-edge interrupt raised by the plugin's own background thread must reach a \
         real userspace GPIO_V2 line-event read — stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Real end-to-end verification of `smbios.rs`: boots a plain guest (no
/// special flags — SMBIOS tables are always present, like ACPI) and
/// checks the real, unmodified kernel's own DMI scanner
/// (`drivers/firmware/dmi_scan.c`) actually found and decoded them,
/// verified the only way that matters: reading real values back out of
/// `/sys/class/dmi/id/*`, the same interface real BMC/management
/// firmware or `dmidecode` would use. This is the regression guard for
/// the entry-point/table checksums and offsets — `smbios.rs`'s own unit
/// tests check the bytes are well-formed; this test checks a real,
/// unrelated kernel subsystem agrees.
#[test]
fn smbios_tables_are_found_and_decoded_by_the_real_kernel() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-smbios-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_initramfs(
        &dir,
        "mount -t sysfs sysfs /sys\n\
         echo SMBIOS_TEST_START\n\
         cat /sys/class/dmi/id/sys_vendor\n\
         cat /sys/class/dmi/id/product_name\n\
         cat /sys/class/dmi/id/product_serial\n\
         cat /sys/class/dmi/id/bios_vendor\n\
         cat /sys/class/dmi/id/bios_version\n\
         cat /sys/class/dmi/id/chassis_vendor\n\
         cat /sys/class/dmi/id/chassis_type\n\
         echo SMBIOS_TEST_DONE\n\
         poweroff -f",
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
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

    assert_eq!(code, Some(0), "hyperbug should exit 0 on a clean ACPI shutdown; got {code:?}. stderr:\n{stderr}");
    assert!(
        stdout.contains("SMBIOS_TEST_DONE"),
        "the guest never finished reading /sys/class/dmi/id — stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let dmi_section = stdout.split("SMBIOS_TEST_START").nth(1).unwrap_or("");
    for expected in [
        "hyperbug",       // sys_vendor
        "hyperbug-vm",    // product_name
        "HB-0000-0001",   // product_serial
        "1.0",            // bios_version
        "23",             // chassis_type (0x17 = Rack Mount Chassis)
    ] {
        assert!(
            dmi_section.contains(expected),
            "expected {expected:?} somewhere in the real DMI sysfs output — got:\n{dmi_section}\nfull stdout:\n{stdout}"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

/// Real end-to-end verification of `--uart2-log`/`serial.rs`'s
/// multi-UART support: boots a guest with a second UART attached and
/// confirms the real, unmodified 8250 driver binds `ttyS1` (COM2) and a
/// genuine userspace write to it is captured in the host log file — the
/// same load-bearing "THRI asserts the instant it's enabled" userspace-
/// tty-startup handshake this project's own Phase 2 history first had to
/// get right for COM1, now proven to work identically for a second,
/// independently-configured port sharing no state with it.
#[test]
fn a_second_uart_is_bound_by_the_real_driver_and_captures_real_output() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }

    let dir = std::env::temp_dir().join(format!("hyperbug-uart-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("com2.log");
    let initramfs = build_initramfs(
        &dir,
        "mount -t devtmpfs devtmpfs /dev\n\
         echo -n HELLO_FROM_COM2 > /dev/ttyS1\n\
         echo UART_TEST_DONE\n\
         poweroff -f",
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--uart2-log"])
        .arg(&log_path)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
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

    assert_eq!(code, Some(0), "hyperbug should exit 0 on a clean ACPI shutdown; got {code:?}. stderr:\n{stderr}");
    assert!(
        stdout.contains("UART_TEST_DONE"),
        "the guest never finished writing to ttyS1 — stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // `contains`, not exact equality: opening a tty device for shell
    // redirection can send a real, harmless leading control byte (a form
    // feed observed here) from the guest's own tty layer's default
    // termios/line-discipline settings on open — genuine guest behavior,
    // not something a device-level capture should filter out, but not
    // the actual property this test cares about either.
    let captured = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        captured.contains("HELLO_FROM_COM2"),
        "the real bytes a userspace write() sent to ttyS1 must land in the host log file \
         — got {captured:?}, stdout:\n{stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Real end-to-end verification of `--vsock-uds`/`virtio_vsock.rs`: boots
/// a guest, loads this exact kernel's own real, unmodified `AF_VSOCK`
/// stack (`vsock`/`vmw_vsock_virtio_transport[_common]`), and runs a real
/// `connect()`/`write()`/`read()` against a real `socat` echo server
/// bridged through the host Unix domain socket — the actual guest-facing
/// surface this device exists to provide. This is the regression guard
/// for a real, live-guest-caught bug (`VirtioDeviceOps::wants_queue_
/// notify` not overridden for the `rx` queue — see `virtio_vsock.rs`'s
/// own doc comment on it): every guest-posted `rx` buffer was silently
/// drained to nothing before this fix, so no reply could ever reach the
/// guest even though the device produced one correctly.
#[test]
fn vsock_bridges_a_real_guest_connection_to_a_real_host_unix_socket() {
    let Some(kernel) = find_kernel() else {
        eprintln!("skipping: no kernel found (set HYPERBUG_TEST_KERNEL)");
        return;
    };
    if !require_busybox() {
        eprintln!("skipping: busybox not found");
        return;
    }
    for tool in ["zstd", "cc", "file", "socat"] {
        if !have_tool(tool) {
            eprintln!("skipping: `{tool}` not found on this host");
            return;
        }
    }
    let Some(release) = kernel_release(&kernel) else {
        eprintln!("skipping: couldn't determine the kernel's own release string");
        return;
    };
    let Some(modules) = find_vsock_modules(&release) else {
        eprintln!(
            "skipping: {release}'s own vsock modules not found under /lib/modules \
             (built directly into the kernel on this host, or a different distribution layout)"
        );
        return;
    };

    let dir = std::env::temp_dir().join(format!("hyperbug-vsock-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let initramfs = build_vsock_initramfs(&dir, &modules);
    // Deliberately *not* under `dir` (which lives under a long
    // `std::env::temp_dir()`-based path): a Unix socket path has a real,
    // OS-level length limit (`SUN_LEN`), the exact thing a previous
    // session's live-control-socket work already hit once (DEBTS.md item
    // 20) — this test hit the identical limit itself while first being
    // written, confirming it's a real, recurring constraint worth a
    // short, fixed path here rather than nesting under `dir`.
    let uds_path = PathBuf::from(format!("/tmp/hyperbug-vsock-test-{}.sock", std::process::id()));
    let _ = fs::remove_file(&uds_path);

    let mut socat = Command::new("socat")
        .arg(format!("UNIX-LISTEN:{},fork", uds_path.display()))
        .arg("EXEC:cat")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to launch socat");
    // A real, if brief, wait for socat to actually bind and start
    // listening before hyperbug's guest tries to connect — matched by
    // the deadline below, which comfortably outlasts it.
    std::thread::sleep(Duration::from_millis(300));

    let mut child = Command::new(env!("CARGO_BIN_EXE_hyperbug"))
        .args(["--kernel"])
        .arg(&kernel)
        .args(["--initrd"])
        .arg(&initramfs)
        .args(["--vsock-uds"])
        .arg(&uds_path)
        .args(["--mem", "256", "--cmdline", "console=ttyS0 panic=1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch hyperbug");

    let mut stdout = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut out = child.stdout.take().unwrap();
    let mut buf = [0u8; 4096];
    loop {
        if stdout.contains("VSOCK_TEST_DONE") || Instant::now() >= deadline {
            break;
        }
        match out.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => stdout.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = socat.kill();
    let _ = socat.wait();

    let mut stderr = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut stderr);
    }

    assert!(
        stdout.contains("VSOCK_TEST_DONE"),
        "the guest never finished the real vsock test within 20s — stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("CONNECTED"),
        "a real guest AF_VSOCK connect() to VMADDR_CID_HOST must succeed — stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("ECHO_LEN=22 DATA=hello from vsock guest"),
        "the real bytes written by the guest must round-trip through the bridged host Unix socket \
         and back — stdout:\n{stdout}"
    );

    let _ = fs::remove_file(&uds_path);
    let _ = fs::remove_dir_all(&dir);
}
