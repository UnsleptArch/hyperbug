//! Best-effort cgroups v2 resource limiting for a sandboxed-plugin
//! subprocess: an operator-declared memory ceiling and/or CPU quota
//! (`--device-sandboxed`/`--pci-device-sandboxed`'s optional trailing
//! `mem=`/`cpu=` fields — see `config::ResourceLimits`), enforced by the
//! kernel, not just advisory logging. Entirely optional and silently
//! skipped (with a one-time warning) if cgroups v2 isn't mounted or this
//! process lacks permission to create/delegate a cgroup — the same
//! "best effort, degrade gracefully" policy as `mem.rs`'s
//! `MADV_HUGEPAGE` hint or `virtio_net.rs`'s TAP bring-up, not a hard
//! requirement for launching a sandboxed plugin at all. Unlike the
//! seccomp filter (`seccomp.rs`, a real privilege boundary that must not
//! silently fail open), a resource ceiling is a convenience an operator
//! asked for, not a security guarantee this code can promise regardless
//! of the host's cgroup delegation setup.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::ResourceLimits;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const HYPERBUG_PARENT: &str = "hyperbug-plugins";

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// A cgroup created for exactly one sandboxed plugin instance. The
/// plugin's own subprocess joins it by writing its own pid to
/// `procs_path()` from inside `Command::pre_exec` (see
/// `pydevice_proc.rs`) — before `exec`, so there is no window where the
/// plugin runs even briefly outside the limit, the same reasoning that
/// puts the seccomp filter install in `pre_exec` too.
pub struct PluginCgroup {
    path: PathBuf,
}

impl PluginCgroup {
    /// Creates a fresh cgroup under `hyperbug-plugins/` and writes
    /// whatever limits `limits` specifies. Returns `None` (not an error)
    /// if cgroups v2 isn't available, the parent cgroup can't be
    /// created, or a limit can't be written — logged once per failure
    /// mode, with the plugin still loading, just without the requested
    /// ceiling enforced. Returns `None` without logging anything if
    /// `limits` asks for nothing (both fields absent).
    pub fn create(limits: &ResourceLimits) -> Option<Self> {
        if limits.mem_limit_mb.is_none() && limits.cpu_quota_percent.is_none() {
            return None;
        }
        let root = Path::new(CGROUP_ROOT);
        if !root.join("cgroup.controllers").exists() {
            crate::log_warn_once!(
                "cgroups v2 not available at {CGROUP_ROOT} (or not mounted); \
                 this plugin's mem=/cpu= limits will not be enforced"
            );
            return None;
        }
        let parent = root.join(HYPERBUG_PARENT);
        if let Err(e) = std::fs::create_dir_all(&parent) {
            crate::log_warn!(
                "couldn't create {parent:?} for plugin resource limits ({e}); \
                 this plugin's mem=/cpu= limits will not be enforced"
            );
            return None;
        }
        // Best-effort: enabling a controller that's already enabled, or
        // one this process isn't delegated permission to enable, just
        // means the per-plugin `memory.max`/`cpu.max` write below fails
        // instead — caught there, with its own specific warning.
        let _ = std::fs::write(root.join("cgroup.subtree_control"), "+memory +cpu");
        let _ = std::fs::write(parent.join("cgroup.subtree_control"), "+memory +cpu");

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("plugin-{}-{id}", std::process::id()));
        if let Err(e) = std::fs::create_dir(&path) {
            crate::log_warn!(
                "couldn't create plugin cgroup {path:?} ({e}); \
                 this plugin's mem=/cpu= limits will not be enforced"
            );
            return None;
        }

        if let Some(mb) = limits.mem_limit_mb {
            let bytes = mb.saturating_mul(1024 * 1024);
            if let Err(e) = std::fs::write(path.join("memory.max"), bytes.to_string()) {
                crate::log_warn!("couldn't set memory.max={bytes} on {path:?}: {e}");
            }
        }
        if let Some(pct) = limits.cpu_quota_percent {
            // cpu.max is "<quota> <period>", both in microseconds: the
            // process may run for up to `quota` out of every `period`.
            // A 100ms period is the kernel's own default and gives a
            // reasonable granularity without excessive scheduling
            // overhead; `pct` may exceed 100 to request more than one
            // CPU's worth of quota, matching cgroups v2's own semantics.
            const PERIOD_US: u64 = 100_000;
            let quota = PERIOD_US.saturating_mul(u64::from(pct)) / 100;
            if let Err(e) = std::fs::write(path.join("cpu.max"), format!("{quota} {PERIOD_US}")) {
                crate::log_warn!("couldn't set cpu.max={quota} {PERIOD_US} on {path:?}: {e}");
            }
        }

        Some(Self { path })
    }

    /// The path a process joins by writing its own pid to it — see the
    /// struct doc comment for why that happens from `pre_exec` rather
    /// than from this process after `spawn()` returns.
    pub fn procs_path(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }
}

impl Drop for PluginCgroup {
    fn drop(&mut self) {
        // Best-effort, silent: removing a cgroup the kernel hasn't yet
        // noticed is empty (the child was just killed and not fully
        // reaped, or reaping raced this drop) fails harmlessly and isn't
        // retried — a leftover empty-eventually cgroup directory is
        // cosmetic, not a resource leak, since nothing stays charged to
        // an empty cgroup.
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `create` is a real no-op (no filesystem touched, no warning
    /// printed) when nothing was actually requested — every plugin
    /// launched without `mem=`/`cpu=` must not pay for or notice this
    /// module existing at all.
    #[test]
    fn create_is_a_no_op_when_no_limits_are_requested() {
        assert!(PluginCgroup::create(&ResourceLimits::default()).is_none());
    }

    /// On a host without cgroups v2 (or without permission to use it),
    /// `create` degrades to `None` instead of panicking or returning an
    /// error the caller would have to handle specially — this is the
    /// actual environment this test suite runs in whenever cgroup
    /// delegation isn't set up, so it's exercising the real fallback
    /// path, not a hypothetical one.
    #[test]
    fn create_degrades_to_none_rather_than_panicking_when_unavailable_or_denied() {
        let limits = ResourceLimits { mem_limit_mb: Some(64), cpu_quota_percent: Some(50) };
        // Whether this host actually has delegated cgroups v2 access is
        // environment-dependent; either outcome (Some, if it does; None,
        // if it doesn't) is a pass — the property under test is "doesn't
        // panic and doesn't hang," which both `Ok` and `None` prove.
        let _ = PluginCgroup::create(&limits);
    }
}
