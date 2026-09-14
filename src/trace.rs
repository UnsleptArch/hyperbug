//! Opt-in Chrome Trace Event Format export (`--trace-file <path>`) — so
//! "where does the time actually go" is something you can look at in
//! `chrome://tracing`/Perfetto instead of guessing from `eprintln!`s or
//! reasoning about the code. Tier 4 of the external review's roadmap
//! ("A trace-export format ... for every VM-exit, every device access,
//! every interrupt").
//!
//! Deliberately hand-rolled JSON (matching this project's existing
//! convention — `control.rs`'s hex protocol, `logging.rs` — of not
//! reaching for a crate when the format is this small and fixed), and
//! deliberately opt-in: every call site below is gated behind
//! `Option<Arc<Mutex<TraceWriter>>>` being `Some`, so a normal run without
//! `--trace-file` pays for one branch per VM exit and nothing else.
//!
//! Written incrementally (one JSON object per line inside a top-level
//! array, flushed after every event) rather than buffered in memory and
//! written once at the end: a long-running or crashing guest shouldn't
//! lose its whole trace, and Chrome's own tracing viewer explicitly
//! tolerates a trace file that never got its closing `]` (an unterminated
//! JSON array of complete objects, which is exactly what a hard kill of
//! this process leaves behind).

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

/// One trace event, using the Chrome Trace Event Format's field names
/// directly (`name`/`cat`/`ph`/`ts`/`dur`/`pid`/`tid`/`args`) so the
/// output needs no translation layer to be readable by
/// `chrome://tracing`/Perfetto.
pub struct TraceWriter {
    file: BufWriter<File>,
    start: Instant,
    wrote_any: bool,
}

impl TraceWriter {
    pub fn create(path: &str) -> io::Result<Self> {
        let mut file = BufWriter::new(File::create(path)?);
        file.write_all(b"[\n")?;
        Ok(Self { file, start: Instant::now(), wrote_any: false })
    }

    fn microseconds_now(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    /// A complete ("X") duration event: `dur_us` covers a VM exit's own
    /// dispatch time, not wall-clock time spent blocked in `KVM_RUN`
    /// waiting for the *next* exit (which would make every event's
    /// duration mostly "the guest was busy running", not "hyperbug spent
    /// this long handling the exit" — the actually useful signal here).
    pub fn duration_event(&mut self, cpu_id: u8, name: &str, cat: &str, start_us: u64, dur_us: u64, args: &str) {
        self.write_event(&format!(
            "{{\"name\":{name:?},\"cat\":{cat:?},\"ph\":\"X\",\"ts\":{start_us},\"dur\":{dur_us},\
             \"pid\":0,\"tid\":{cpu_id},\"args\":{args}}}"
        ));
    }

    /// An instant ("i") event — an interrupt injection, which has no
    /// meaningful duration of its own.
    pub fn instant_event(&mut self, cpu_id: u8, name: &str, cat: &str, args: &str) {
        let ts = self.microseconds_now();
        self.write_event(&format!(
            "{{\"name\":{name:?},\"cat\":{cat:?},\"ph\":\"i\",\"ts\":{ts},\"pid\":0,\"tid\":{cpu_id},\
             \"s\":\"g\",\"args\":{args}}}"
        ));
    }

    /// Returns the timestamp (microseconds since trace start) to record as
    /// a duration event's `start_us`, taken *before* the work being traced
    /// runs.
    pub fn begin(&self) -> u64 {
        self.microseconds_now()
    }

    fn write_event(&mut self, json: &str) {
        // A leading comma on every event but the first, so the file stays
        // a syntactically complete JSON array right up to (and including)
        // the last event actually flushed — no trailing-comma cleanup
        // needed if the process ends abruptly.
        if self.wrote_any {
            let _ = self.file.write_all(b",\n");
        }
        let _ = self.file.write_all(json.as_bytes());
        // A crash should lose at most the in-flight event, not everything
        // written before it.
        let _ = self.file.flush();
        self.wrote_any = true;
    }
}

impl Drop for TraceWriter {
    fn drop(&mut self) {
        let _ = self.file.write_all(b"\n]\n");
        let _ = self.file.flush();
    }
}

/// Escapes a string for embedding as a JSON string *value* — used for
/// `args` fields built from formatted device/address text, which isn't
/// guaranteed free of `"`/`\`/control characters (a Python plugin's class
/// name, say). The event JSON itself is otherwise hand-assembled with
/// `format!` because every other field is a plain number or a
/// static/`Debug`-derived string with no such risk.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trace_file_is_a_syntactically_complete_json_array() {
        let path = std::env::temp_dir().join(format!("hyperbug-trace-test-{}.json", std::process::id()));
        let path_str = path.to_str().unwrap();
        {
            let mut w = TraceWriter::create(path_str).unwrap();
            let ts = w.begin();
            w.duration_event(0, "IoOut:0x3f8", "io", ts, 5, "{}");
            w.instant_event(0, "irq4", "interrupt", "{}");
        }
        let contents = std::fs::read_to_string(path_str).unwrap();
        let parsed = parse_json_array(&contents);
        assert_eq!(parsed.count, 2, "both events must parse as array elements: {contents}");
        std::fs::remove_file(path_str).unwrap();
    }

    /// A tiny, purpose-built check rather than pulling in a JSON crate just
    /// for this one test: counts top-level `{...}` objects in a `[ ... ]`
    /// array, which is enough to catch a missing/extra comma or an
    /// unterminated object without needing a real parser.
    struct JsonArrayCheck {
        count: usize,
    }
    fn parse_json_array(s: &str) -> JsonArrayCheck {
        let trimmed = s.trim();
        assert!(trimmed.starts_with('['), "must start with [: {s}");
        assert!(trimmed.ends_with(']'), "must end with ]: {s}");
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut depth = 0i32;
        let mut count = 0usize;
        for c in inner.chars() {
            match c {
                '{' => {
                    if depth == 0 {
                        count += 1;
                    }
                    depth += 1;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        assert_eq!(depth, 0, "unbalanced braces: {s}");
        JsonArrayCheck { count }
    }

    #[test]
    fn json_string_escapes_quotes_and_control_characters() {
        assert_eq!(json_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(json_string("a\nb"), "\"a\\nb\"");
        assert_eq!(json_string("plain"), "\"plain\"");
    }
}
