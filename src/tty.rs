//! Host terminal handling so the guest's serial console is a real,
//! playable interactive session: puts the host's stdin into raw mode
//! (no line buffering, no local echo — the guest's own tty layer/login
//! shell does that, exactly like a real serial terminal) and non-blocking
//! (the reactor thread waits on it with `epoll` and drains it in bursts).
//!
//! Also owns the guest's console *output* path (`write_stdout`): a raw
//! `write(2)` straight to fd 1 rather than `std::io::Stdout`. Every
//! console byte is its own VM exit and has to be flushed immediately to
//! be useful, so `Stdout`'s `LineWriter` buffer is pure overhead on that
//! path — a lock, a buffer copy, and a separate flush call per byte.
//!
//! Restoration on exit is handled via `libc::atexit` rather than a Drop
//! guard: every exit path in `main.rs` is a bare `std::process::exit`,
//! which skips destructors but still runs the C runtime's atexit handlers.

use std::os::unix::io::RawFd;
use std::sync::OnceLock;

const STDIN_FD: RawFd = 0;
const STDOUT_FD: RawFd = 1;

static ORIGINAL_TERMIOS: OnceLock<libc::termios> = OnceLock::new();

extern "C" fn restore_termios() {
    if let Some(orig) = ORIGINAL_TERMIOS.get() {
        // SAFETY: `orig` is a termios this process read from this same fd.
        unsafe {
            libc::tcsetattr(STDIN_FD, libc::TCSANOW, orig);
        }
    }
}

/// Always sets stdin non-blocking (needed for the reactor's drain loop
/// regardless of what stdin is — a pipe feeding scripted input should work
/// too, not just a real terminal). The *raw* terminal attributes (no line
/// buffering, no local echo) only apply, and only make sense, when stdin
/// is an actual tty — e.g. piping a script's input into hyperbug shouldn't
/// try to raw-mode a pipe. Returns whether it's a real interactive
/// terminal (i.e. raw mode was applied), purely informational.
pub fn enable_raw_stdin() -> bool {
    // SAFETY: plain fd/termios syscalls on this process's own stdin; every
    // return value that matters is checked.
    unsafe {
        let flags = libc::fcntl(STDIN_FD, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(STDIN_FD, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        if libc::isatty(STDIN_FD) == 0 {
            return false;
        }

        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(STDIN_FD, &mut term) != 0 {
            return false;
        }
        let _ = ORIGINAL_TERMIOS.set(term);
        libc::atexit(restore_termios);

        let mut raw = term;
        libc::cfmakeraw(&mut raw);
        libc::tcsetattr(STDIN_FD, libc::TCSANOW, &raw) == 0
    }
}

/// Non-blocking bulk read from stdin into `buf`. `Some(n)` is how many
/// bytes were available right now (`Some(0)` meaning "nothing yet");
/// `None` means end of file — stdin is closed and will never produce
/// another byte.
///
/// That distinction matters: an EOF'd pipe stays permanently "ready" as
/// far as `epoll` is concerned, so a caller that treats EOF as "nothing
/// yet" spins at 100% CPU forever. See `reactor.rs`, which stops watching
/// stdin on `None`.
///
/// Bulk, not byte-at-a-time: fast typing or a paste used to cost one
/// `read(2)` per character because the caller looped over a single-byte
/// helper.
pub fn read_stdin(buf: &mut [u8]) -> Option<usize> {
    // SAFETY: `buf` is a valid, initialized slice of exactly `buf.len()`
    // bytes; `read` writes at most that many.
    let n = unsafe { libc::read(STDIN_FD, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    match n {
        0 => None,
        n if n > 0 => Some(n as usize),
        // EAGAIN/EWOULDBLOCK is the ordinary "nothing queued" case on a
        // non-blocking fd; EINTR is routine here thanks to the periodic
        // SIGALRM. Anything else is treated the same way — it isn't worth
        // ending a run over, and the fd stays watched.
        _ => Some(0),
    }
}

/// Writes `data` to the host's stdout, retrying short writes and `EINTR`
/// (which the periodic `SIGALRM` below makes routine). Used for both the
/// guest's serial console and the port-0xE9 debug channel.
pub fn write_stdout(data: &[u8]) {
    let mut written = 0;
    while written < data.len() {
        // SAFETY: `data[written..]` is a valid slice of the length passed.
        let n = unsafe {
            libc::write(
                STDOUT_FD,
                data[written..].as_ptr().cast::<libc::c_void>(),
                data.len() - written,
            )
        };
        if n > 0 {
            written += n as usize;
            continue;
        }
        // Retry an interrupted write; give up on any other error (a closed
        // or full stdout isn't worth ending an otherwise-fine run over).
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return;
    }
}

extern "C" fn noop_signal_handler(_: libc::c_int) {}

/// Arms a recurring `SIGALRM` every `interval_ms` milliseconds, with a
/// handler that does nothing except (by existing at all, with no
/// `SA_RESTART`) guarantee the signal actually interrupts a blocking
/// syscall with `EINTR` instead of the default action (process
/// termination) or a silent auto-restart. See its call site in `lib.rs`
/// for why the main VM loop needs this: a genuinely idle guest can leave
/// `vcpu.run()` blocked far longer than any interactive use can tolerate,
/// with no other mechanism to force it to return periodically and let the
/// loop poll the control socket and Python devices.
///
/// This is process-wide (a single `setitimer`/`ITIMER_REAL`), so its
/// `SIGALRM` lands on whichever *one* thread the kernel happens to pick
/// each tick, not every vCPU thread — fine for the BSP thread's own
/// control-socket responsiveness (the only thing that actually needs it),
/// but not a reliable way to force every AP thread to notice a shared exit
/// request promptly. A per-thread targeted-signal design was tried for
/// that and reverted: it introduced a real, reproducible SMP bring-up hang
/// (signaling every vCPU thread, including the BSP, on a fixed cadence
/// *during* the guest's own INIT-SIPI-SIPI sequence stalled bring-up
/// entirely) — a genuine race between forced `EINTR`s and KVM's in-kernel
/// APIC/SIPI handling that would need real investigation to fix safely,
/// out of scope for this pass. See `lib.rs::run`'s doc comment on why AP
/// threads are consequently *not* joined before `run` returns.
pub fn install_periodic_wakeup(interval_ms: i64) {
    // SAFETY: installs a no-op handler and a process-wide interval timer;
    // the handler itself does nothing at all, so it is trivially
    // async-signal-safe.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop_signal_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());

        let interval = libc::timeval {
            tv_sec: interval_ms / 1000,
            tv_usec: (interval_ms % 1000) * 1000,
        };
        let itimer = libc::itimerval { it_interval: interval, it_value: interval };
        libc::setitimer(libc::ITIMER_REAL, &itimer, std::ptr::null_mut());
    }
}
