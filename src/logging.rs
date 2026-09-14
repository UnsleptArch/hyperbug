//! A small, hand-rolled structured/leveled logging facility — replaces
//! the `eprintln!`s that used to be scattered across the codebase with
//! zero severity information and no way to filter or ingest them.
//!
//! Deliberately not the `log`/`tracing` crates: this project's own
//! convention (the binary IPC framing in `pydevice_proc.rs`, the hex
//! control-socket protocol) is to hand-roll a small, exact-fit mechanism
//! rather than pull in a general-purpose one, and a leveled `eprintln!`
//! wrapper is genuinely all this needs — no plugin ecosystem of logging
//! backends to support.
//!
//! Every line is single-line and machine-parseable:
//! `[hyperbug] <seconds.millis> <LEVEL> <module::path>: <message>` — a
//! real observability layer (journald, a log-shipper regex, `grep`) can
//! filter on the level token or module path without special support.
//!
//! Filtered by the `HYPERBUG_LOG` environment variable
//! (`error`/`warn`/`info`/`debug`/`trace`, case-insensitive; default
//! `info`) — read once into a `LazyLock`, not on every call, the same
//! discipline `serial.rs`'s `HYPERBUG_SERIAL_TRACE` already established
//! for a hot path. `trace` level subsumes what `HYPERBUG_SERIAL_TRACE`
//! used to gate on its own (`serial.rs`'s per-register-access trace) —
//! one knob instead of two.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    fn parse(s: &str) -> Option<Level> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            "trace" => Some(Level::Trace),
            _ => None,
        }
    }
}

static MAX_LEVEL: LazyLock<Level> =
    LazyLock::new(|| std::env::var("HYPERBUG_LOG").ok().and_then(|s| Level::parse(&s)).unwrap_or(Level::Info));

static START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Whether `HYPERBUG_LOG` enables at least `level` — exposed so a caller
/// can skip building an expensive argument (e.g. a formatted buffer dump)
/// when the line would be filtered out anyway, without duplicating the
/// env-var read.
pub fn enabled(level: Level) -> bool {
    level <= *MAX_LEVEL
}

#[doc(hidden)]
pub fn log_line(level: Level, target: &str, args: std::fmt::Arguments) {
    if !enabled(level) {
        return;
    }
    let elapsed = START.elapsed();
    eprintln!("[hyperbug] {:>6}.{:03} {:<5} {target}: {args}", elapsed.as_secs(), elapsed.subsec_millis(), level.as_str());
}

/// True the first time this exact call site fires, false ever after —
/// used by `log_error_once!`/`log_warn_once!` for a condition that's
/// worth flagging exactly once (e.g. an optional host capability being
/// unavailable), not on every occurrence.
#[doc(hidden)]
pub struct OnceFlag(AtomicBool);

impl OnceFlag {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    pub fn take(&self) -> bool {
        !self.0.swap(true, Ordering::Relaxed)
    }
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logging::log_line($crate::logging::Level::Error, module_path!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logging::log_line($crate::logging::Level::Warn, module_path!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logging::log_line($crate::logging::Level::Info, module_path!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::logging::log_line($crate::logging::Level::Debug, module_path!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        $crate::logging::log_line($crate::logging::Level::Trace, module_path!(), format_args!($($arg)*))
    };
}

/// Logs at `warn` level, but only the first time this call site is ever
/// reached — for a condition worth flagging once per process, not once
/// per occurrence (e.g. "cgroups v2 isn't available").
#[macro_export]
macro_rules! log_warn_once {
    ($($arg:tt)*) => {{
        static FLAG: $crate::logging::OnceFlag = $crate::logging::OnceFlag::new();
        if FLAG.take() {
            $crate::log_warn!($($arg)*);
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parsing_is_case_insensitive_and_rejects_garbage() {
        assert_eq!(Level::parse("Debug"), Some(Level::Debug));
        assert_eq!(Level::parse("WARN"), Some(Level::Warn));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse("nonsense"), None);
    }

    #[test]
    fn enabled_respects_ordering() {
        // Error is the most severe (0) and always enabled when the max
        // level is anything at or above it; Trace (4) is only enabled
        // when the max level is Trace itself.
        assert!(Level::Error <= Level::Info);
        assert!(Level::Trace > Level::Info);
    }

    #[test]
    fn once_flag_fires_exactly_once() {
        let flag = OnceFlag::new();
        assert!(flag.take());
        assert!(!flag.take());
        assert!(!flag.take());
    }
}
