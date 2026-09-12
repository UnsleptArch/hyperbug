//! A deny-list seccomp-bpf filter applied to the sandboxed device-plugin
//! subprocess (`python3 -m hyperbug._sandbox_runner`, spawned by
//! `pydevice_proc.rs`) — real defense-in-depth on top of that subprocess
//! boundary, not a replacement for it.
//!
//! Deliberately a **deny-list**, not an allow-list: a full Python
//! interpreter's own normal operation (module imports, its allocator,
//! whatever file/network I/O a legitimate plugin needs) uses a syscall
//! surface too wide, and too version/distro-dependent, to enumerate
//! safely as an allow-list without a real risk of unpredictably breaking
//! a legitimate plugin the next time Python's own internals change.
//! Instead this blocks a small, well-known set of syscalls that have no
//! legitimate use inside an ordinary device plugin and would either let
//! a hostile plugin defeat the whole point of running in a separate
//! process (attaching to or reading/writing the parent's memory
//! directly) or damage the host outright (mounting filesystems, loading
//! kernel modules, rebooting). Every denied syscall returns `EPERM`
//! rather than killing the process: a plugin that hits one gets an
//! ordinary Python `OSError` it can report, the same failure shape
//! `pydevice_proc.rs` already expects from a misbehaving plugin, not a
//! silent `SIGSYS` death that would look like an unrelated crash.
//!
//! Not currently applied to the main VMM process itself: it embeds a
//! full CPython interpreter via PyO3 for in-process (non-sandboxed)
//! device plugins, whose allocator and C-extension surface make a safe
//! syscall allow/deny-list for *that* process a much larger, separate
//! piece of work than this one — see `docs/security/defendmap.md` item
//! 8 / the Tier-2 hardening notes for the open item.

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

/// Syscalls with no legitimate use inside an ordinary Python device
/// plugin, chosen because each one either crosses back out of the
/// process-isolation boundary the sandboxed loader exists to establish
/// (`ptrace`, `process_vm_readv`/`writev`), or is a classic privilege-
/// escalation/host-damage primitive with nothing to do with emulating a
/// device (mount/kernel-module/reboot family, `bpf`, `perf_event_open`,
/// clock/hostname changes, `personality` — historically used to disable
/// ASLR as an exploit-mitigation bypass).
fn denied_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_personality,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
    ]
}

fn build_filter() -> Result<BpfProgram, String> {
    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| format!("unsupported architecture for seccomp: {}", std::env::consts::ARCH))?;

    let rules = denied_syscalls().into_iter().map(|sys| (sys, Vec::new())).collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,           // anything not explicitly listed: unaffected
        SeccompAction::Errno(libc::EPERM as u32), // a listed syscall: fails with EPERM
        arch,
    )
    .map_err(|e| format!("building seccomp filter: {e}"))?;
    filter.try_into().map_err(|e| format!("compiling seccomp filter to BPF: {e}"))
}

/// Installs the filter on the *calling thread only*. Meant to be called
/// from `Command::pre_exec`, in the freshly-forked child, after `fork()`
/// but before `exec()` — exactly one thread exists at that point, so
/// "calling thread" and "the whole process" are the same thing here.
/// Returns a plain `String` error rather than panicking: this runs in a
/// child process a moment before `exec`, where `pre_exec`'s own safety
/// contract already limits what's sound to do (async-signal-safety-like
/// constraints), and unwinding machinery is exactly the kind of
/// complexity not to lean on there.
pub fn install_subprocess_filter() -> Result<(), String> {
    let bpf = build_filter()?;
    seccompiler::apply_filter(&bpf).map_err(|e| format!("applying seccomp filter: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The filter itself builds and compiles to a real BPF program on
    /// this host's architecture — checked directly rather than only via
    /// the subprocess integration test, since a filter construction
    /// error would otherwise only surface as an opaque spawn failure.
    #[test]
    fn the_filter_builds_and_compiles_on_this_architecture() {
        let bpf = build_filter().expect("filter should build and compile");
        assert!(!bpf.is_empty(), "a real filter should never compile to zero BPF instructions");
    }

    /// Exercises the filter for real: forks a child, installs it via the
    /// same code path `pre_exec` uses, then confirms a denied syscall
    /// (`ptrace`, attempting to attach to the child's own parent — a
    /// concrete instance of the "escape the subprocess boundary" case
    /// this filter exists to block) fails with `EPERM` in the child
    /// while an ordinary, unlisted syscall (`getpid`) keeps working —
    /// i.e. this really is a deny-list, not an accidental allow-list of
    /// nothing.
    #[test]
    fn a_denied_syscall_fails_and_an_ordinary_one_still_works() {
        // SAFETY: the child performs only async-signal-safe operations
        // (syscalls and a single write to an already-open fd) before
        // exiting via `_exit`, never returning through `fork()`'s Rust
        // call frame into unrelated code.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            install_subprocess_filter().expect("filter should install");
            // A denied syscall must fail with EPERM now.
            let ptrace_result = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>()) };
            let ptrace_errno = std::io::Error::last_os_error().raw_os_error();
            // An ordinary, unlisted syscall must still work.
            let pid_ok = unsafe { libc::getpid() } > 0;

            let ok = ptrace_result == -1 && ptrace_errno == Some(libc::EPERM) && pid_ok;
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0i32;
        // SAFETY: `pid` is this process's own just-forked child; `waitpid`
        // is the ordinary, safe way to reap it.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "child reported a mismatch");
    }
}
