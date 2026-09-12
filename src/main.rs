//! Thin CLI entry point: parses `argv` into a `hyperbug::Args`, hands it
//! to `hyperbug::run`, and translates the returned `Result` into a process
//! exit code. That's all it does — the parsing itself lives in
//! `config.rs`, as a plain function over an argument iterator, so it is
//! testable and so no code below `run()` ever calls `std::process::exit`
//! or panics on an expected failure path (see `lib.rs`/`error.rs`).
//!
//! A CLI-syntax error still exits(2) from here, which is a genuine "this
//! is a command-line tool" concern rather than something a library caller
//! embedding `hyperbug::run` directly ever goes through — they build an
//! `Args` themselves.

use hyperbug::{Args, HyperbugError};

/// Bad arguments. Matches `python/hyperbug/vm.py`'s `_LAUNCH_ERROR_CODES`
/// and `HyperbugError::Config`'s own code, which mean the same thing:
/// hyperbug refused to start, no guest ever ran.
const EXIT_USAGE: i32 = 2;

fn main() {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("hyperbug: {message}");
            std::process::exit(EXIT_USAGE);
        }
    };

    let code = match hyperbug::run(args) {
        Ok(exit) => exit.code(),
        Err(e) => {
            eprintln!("hyperbug: {e}");
            HyperbugError::exit_code(&e)
        }
    };
    std::process::exit(code);
}
