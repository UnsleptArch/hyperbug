//! Record-and-replay: `Recorder` (Milestone 2) captures real console
//! keystrokes, real TAP network packets, and real virtio-rng output, each
//! tagged with the host branch-count position (`pmu.rs`) they were
//! delivered/produced at. `Replayer` (Milestone 3) reads a recording back
//! and re-delivers it. See `docs/record-replay.md` for the full design
//! and honest current scope — in particular, **replay is
//! poll-granularity, not cycle-exact**: a deliberate choice, not an
//! oversight, made because this host's AMD branch counter isn't
//! confirmed precise (see `pmu.rs`) and there's no Intel hardware to
//! verify that path either — building the harder PMI-precise stopping
//! mechanism on an unconfirmed precision foundation would mean shipping
//! something impossible to verify actually does what it claims.
//!
//! ## What's recorded, and what still isn't
//!
//! - **Keyboard input** (`reactor.rs`'s `push_rx`) and **TAP network
//!   packets** (`reactor.rs`'s `handle_tap`) — both genuinely
//!   asynchronous relative to guest execution, and both are exactly the
//!   "when did this interrupt arrive" nondeterminism a replay needs to
//!   reproduce. Both go through `reactor.rs`, a single, already-
//!   centralized point for exactly the async inputs this needs.
//! - **virtio-rng bytes** (`virtio_rng.rs`) — unlike keyboard/network
//!   input, an RNG request is synchronous from the guest's own point of
//!   view (the guest posts a buffer during a VM exit and the device fills
//!   it immediately, within that same exit), so there's no delivery
//!   *timing* to capture here the way there is for the two above. But the
//!   *data* matters just as much for a future replay: a real Linux guest
//!   derives real internal state (stack-protector canaries, ASLR slide
//!   values) from its first RNG reads, so a replay that handed the guest
//!   *different* random bytes than the recording did would diverge almost
//!   immediately, regardless of how exactly interrupt timing is replayed.
//!   Contained entirely to `VirtioRng`'s own struct (an `Option<Arc<
//!   Recorder>>` field set at construction) rather than touching the
//!   generic `VirtioDeviceOps` trait every other virtio device also
//!   implements.
//! - **KVM's own in-kernel PIT/LAPIC timer interrupts**: **not
//!   addressable by this design at all** without a much larger
//!   architecture change. hyperbug uses KVM's in-kernel irqchip
//!   (`KVM_CREATE_IRQCHIP`) specifically so hyperbug's own userspace code
//!   never has to model PIT/LAPIC/RTC timing — which also means hyperbug
//!   has no code path that "delivers" one of those interrupts to record
//!   in the first place; they happen entirely inside the kernel, invisible
//!   to this process. Replaying a guest exactly would need those
//!   interrupts to land at the same guest-visible moments too, and this
//!   design cannot currently capture that. Recorded honestly as a
//!   structural limitation, not an oversight to quietly work around.
//! - **RDTSC**: as `docs/record-replay.md` already states, unaddressed
//!   and not yet confirmed reachable via the public KVM ioctls surface.
//!
//! ## What replays, and what still doesn't
//!
//! - **Keyboard input**: replayed by `Replayer::poll_keyboard`, called
//!   once per vCPU-loop iteration (`vcpu.rs`, the same cadence as the
//!   existing control-socket/plugin poll) — once the live branch counter
//!   reaches or passes a recorded event's position, its bytes are pushed
//!   into the serial RX queue exactly like a real keystroke would be.
//! - **virtio-rng**: replayed by `Replayer::next_rng_bytes`, called from
//!   `VirtioRng::process_chain` instead of `getrandom(2)` — consumed in
//!   recorded order (position-independent, matching how it was recorded;
//!   see above). If the guest requests more RNG data than was ever
//!   recorded, falls back to real `getrandom` with a one-time warning
//!   rather than hang the guest — a replay that outlives its own
//!   recording's RNG usage isn't reproducing the original run's random
//!   data at that point regardless, so refusing outright would only lose
//!   the guest without buying back any real determinism.
//! - **TAP network packets are recorded but not replayed** in this
//!   milestone — stated directly, not silently dropped. Replaying them
//!   needs the same net-device handles `reactor.rs` already holds, which
//!   `vcpu.rs`'s poll point doesn't have; and real end-to-end testing of
//!   either the recording or a replay path needs `CAP_NET_ADMIN`/root,
//!   unavailable in this project's own dev sandbox for the same reason
//!   `--net` itself has never been fully exercised here. A `--replay` run
//!   logs how many recorded network events it's skipping so this isn't a
//!   silent gap at runtime either.

// `Recorder::precise` has no caller outside this module's own tests —
// kept for parity with `Replayer`'s own precision check and because a
// future caller (surfacing precision in a CLI summary, say) is a real,
// plausible use, not speculative scope.
#![allow(dead_code)]

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::sync::Mutex;

use crate::pmu::BranchCounter;

const MAGIC: &[u8; 4] = b"HBRR";
// Bumped to 2 when `elapsed_ms` was added to every event (see
// `RecordedEvent`'s doc comment) — a real, measured reliability fix, not
// a speculative addition: see item 52's writeup for why the previous
// branch-count-only design failed 4 of 8 real end-to-end replay runs.
const FORMAT_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    KeyboardRx,
    NetRx,
    /// Real random bytes `virtio_rng.rs` returned to the guest. Recorded
    /// even though the request itself is synchronous (no delivery timing
    /// to capture) — see `VirtioRng`'s own doc comment for why the data
    /// still matters for a future replay: a guest's own internal state
    /// (stack-protector canaries, ASLR) derives from its first RNG reads.
    RngBytes,
}

impl EventKind {
    fn to_byte(self) -> u8 {
        match self {
            Self::KeyboardRx => 1,
            Self::NetRx => 2,
            Self::RngBytes => 3,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::KeyboardRx),
            2 => Some(Self::NetRx),
            3 => Some(Self::RngBytes),
            _ => None,
        }
    }
}

/// One recorded async event. `branch_count` is the host branch counter's
/// value (see `pmu.rs`) at the moment `data` was delivered to the guest;
/// `elapsed_ms` is the wall-clock time since the `Recorder` started, in
/// milliseconds — a **fallback** timing signal, not the primary one.
///
/// **Why both exist, found by real testing, not designed in up front**:
/// the first version of `Replayer` used `branch_count` alone. A real
/// end-to-end boot test (record a session, replay it on a completely
/// separate boot) failed 4 of 8 runs — the replayed guest reached its own
/// idle shell prompt and the recorded keystroke simply never arrived. Root
/// cause: on this host's AMD CPU, without the SpecLockMap fix (see
/// `pmu.rs`), the branch counter's overcounting is *speculation-dependent
/// noise*, not a fixed scale factor — once a guest goes idle (mostly
/// `HLT`, almost no counted execution), two separate boots' counters can
/// drift far enough apart that a position reached in the recording is
/// never reached in the replay within any reasonable time. `elapsed_ms`
/// fixes this the same way `rr` itself would tell you to think about
/// it: on an imprecise host, a wall-clock bound is the strictly weaker
/// but *bounded* fallback — `Replayer::poll_keyboard` delivers an event
/// once *either* threshold is reached, so a stalled counter can no longer
/// cause an unbounded (in practice, indefinite) delay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedEvent {
    pub branch_count: u64,
    pub elapsed_ms: u64,
    pub kind: EventKind,
    pub data: Vec<u8>,
}

/// Records async events to `path`, each tagged with the host branch
/// counter's current value and the wall-clock time since recording
/// started (see `RecordedEvent`'s doc comment for why both). One
/// `Recorder` covers the whole guest lifetime — the counter is enabled
/// once, at `start`, and never reset or disabled again, so every recorded
/// position is directly comparable to every other.
pub struct Recorder {
    counter: BranchCounter,
    precise: bool,
    start: std::time::Instant,
    writer: Mutex<BufWriter<File>>,
}

impl Recorder {
    /// `vcpu_tid` is the BSP vCPU thread's Linux TID — for a single-vCPU
    /// guest (the only configuration this supports; see `lib.rs`'s
    /// `validate_record`), that's the process's own main-thread TID,
    /// obtainable as `std::process::id()` even before any vCPU thread is
    /// spawned, since `lib::run()` itself always executes on the process's
    /// main thread and the BSP always runs on "the caller's own thread."
    pub fn start(path: &str, vcpu_tid: libc::pid_t, mem_size: u64) -> Result<Self, String> {
        let (counter, precise) = BranchCounter::open_for_thread(vcpu_tid)?;
        if !precise {
            crate::log_warn!(
                "recording started, but this host's branch counter isn't confirmed precise \
                 (see docs/record-replay.md) — positions in this recording may not be exact"
            );
        }
        counter.reset();
        counter.enable();

        let mut file = File::create(path).map_err(|e| format!("creating record file {path}: {e}"))?;
        file.write_all(MAGIC).map_err(|e| e.to_string())?;
        file.write_all(&FORMAT_VERSION.to_le_bytes()).map_err(|e| e.to_string())?;
        file.write_all(&mem_size.to_le_bytes()).map_err(|e| e.to_string())?;
        file.write_all(&[u8::from(precise)]).map_err(|e| e.to_string())?;

        Ok(Self { counter, precise, start: std::time::Instant::now(), writer: Mutex::new(BufWriter::new(file)) })
    }

    pub fn precise(&self) -> bool {
        self.precise
    }

    /// Records one event. Best-effort: an I/O failure here is logged, not
    /// propagated — a recording glitch shouldn't take down an otherwise
    /// fine guest run.
    pub fn record(&self, kind: EventKind, data: &[u8]) {
        let branch_count = self.counter.read_count();
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        let mut w = self.writer.lock().unwrap();
        if let Err(e) = write_event(&mut *w, branch_count, elapsed_ms, kind, data) {
            crate::log_warn!("record/replay: failed to write event: {e}");
            return;
        }
        // Flushed per event, same durability tradeoff as `trace.rs`: a
        // crash loses at most the in-flight event, not the whole
        // recording.
        let _ = w.flush();
    }
}

fn write_event(w: &mut impl Write, branch_count: u64, elapsed_ms: u64, kind: EventKind, data: &[u8]) -> std::io::Result<()> {
    w.write_all(&[kind.to_byte()])?;
    w.write_all(&branch_count.to_le_bytes())?;
    w.write_all(&elapsed_ms.to_le_bytes())?;
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)
}

pub struct RecordingHeader {
    pub mem_size: u64,
    pub precise: bool,
}

/// Reads a whole recording back — used today only by this module's own
/// round-trip test, and by whoever implements Milestone 3 (replay).
/// Not performance-sensitive (a recording is read once, at replay
/// startup), so this loads the whole thing into memory rather than
/// streaming.
pub fn read_all(path: &str) -> Result<(RecordingHeader, Vec<RecordedEvent>), String> {
    let mut file = File::open(path).map_err(|e| format!("opening record file {path}: {e}"))?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if &magic != MAGIC {
        return Err(format!("{path} doesn't look like a hyperbug recording (bad magic)"));
    }
    let mut version_bytes = [0u8; 4];
    file.read_exact(&mut version_bytes).map_err(|e| e.to_string())?;
    let version = u32::from_le_bytes(version_bytes);
    if version != FORMAT_VERSION {
        return Err(format!("{path} is recording format version {version}, this build only reads {FORMAT_VERSION}"));
    }
    let mut mem_size_bytes = [0u8; 8];
    file.read_exact(&mut mem_size_bytes).map_err(|e| e.to_string())?;
    let mem_size = u64::from_le_bytes(mem_size_bytes);
    let mut precise_byte = [0u8; 1];
    file.read_exact(&mut precise_byte).map_err(|e| e.to_string())?;
    let precise = precise_byte[0] != 0;

    let mut events = Vec::new();
    loop {
        let mut kind_byte = [0u8; 1];
        match file.read_exact(&mut kind_byte) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
        let Some(kind) = EventKind::from_byte(kind_byte[0]) else {
            return Err(format!("{path}: unknown event kind byte {:#x}", kind_byte[0]));
        };
        let mut branch_count_bytes = [0u8; 8];
        file.read_exact(&mut branch_count_bytes).map_err(|e| e.to_string())?;
        let branch_count = u64::from_le_bytes(branch_count_bytes);
        let mut elapsed_ms_bytes = [0u8; 8];
        file.read_exact(&mut elapsed_ms_bytes).map_err(|e| e.to_string())?;
        let elapsed_ms = u64::from_le_bytes(elapsed_ms_bytes);
        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes).map_err(|e| e.to_string())?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let mut data = vec![0u8; len];
        file.read_exact(&mut data).map_err(|e| e.to_string())?;
        events.push(RecordedEvent { branch_count, elapsed_ms, kind, data });
    }

    Ok((RecordingHeader { mem_size, precise }, events))
}

use std::collections::VecDeque;

/// Reads a recording back and re-delivers it — see this module's own doc
/// comment for exactly what replays (keyboard, virtio-rng) and what
/// doesn't yet (TAP packets; cycle-exact timing). One `Replayer` covers
/// the whole replayed guest's lifetime.
pub struct Replayer {
    counter: BranchCounter,
    start: std::time::Instant,
    /// Only `KeyboardRx` events, in their original (already
    /// branch-count-sorted) order.
    keyboard_events: Vec<RecordedEvent>,
    next_keyboard: usize,
    /// Only `RngBytes` payloads, consumed strictly in recorded order —
    /// position-independent, matching how they were recorded (see this
    /// module's doc comment for why an RNG request has no meaningful
    /// delivery *timing* to replay in the first place).
    rng_data: VecDeque<Vec<u8>>,
    /// How many recorded `NetRx` events this replayer is deliberately
    /// not replaying — logged once at startup so this is a visible,
    /// stated gap rather than a silent one.
    skipped_net_events: usize,
    /// Set once `next_rng_bytes` has fallen back to real `getrandom`
    /// because the recording ran out of RNG data — logged only the first
    /// time, not once per request.
    rng_exhausted_warned: bool,
}

impl Replayer {
    /// `vcpu_tid`/`mem_size`: same meaning as `Recorder::start`. Returns
    /// an error if `path` doesn't parse as a recording, or if its
    /// `mem_size` doesn't match this launch's `--mem` — replaying against
    /// a differently-sized guest can't reproduce the original run and
    /// isn't a case worth guessing about.
    pub fn start(path: &str, vcpu_tid: libc::pid_t, mem_size: u64) -> Result<Self, String> {
        let (header, events) = read_all(path)?;
        if header.mem_size != mem_size {
            return Err(format!(
                "{path} was recorded with {} MiB of guest memory, this launch has {} MiB \
                 (--mem must match exactly to replay)",
                header.mem_size / (1024 * 1024),
                mem_size / (1024 * 1024)
            ));
        }
        if !header.precise {
            crate::log_warn!(
                "replaying a recording whose branch counter wasn't confirmed precise when it \
                 was made (see docs/record-replay.md) — timing may not match the original run"
            );
        }

        let (counter, precise) = BranchCounter::open_for_thread(vcpu_tid)?;
        if !precise {
            crate::log_warn!(
                "this host's branch counter isn't confirmed precise either (see \
                 docs/record-replay.md) — replay timing is best-effort, not exact"
            );
        }
        counter.reset();
        counter.enable();

        let mut keyboard_events = Vec::new();
        let mut rng_data = VecDeque::new();
        let mut skipped_net_events = 0;
        for event in events {
            match event.kind {
                EventKind::KeyboardRx => keyboard_events.push(event),
                EventKind::RngBytes => rng_data.push_back(event.data),
                EventKind::NetRx => skipped_net_events += 1,
            }
        }
        if skipped_net_events > 0 {
            crate::log_warn!(
                "replay: {skipped_net_events} recorded network packet(s) will not be replayed \
                 (see docs/record-replay.md — TAP replay isn't implemented yet)"
            );
        }

        Ok(Self {
            counter,
            start: std::time::Instant::now(),
            keyboard_events,
            next_keyboard: 0,
            rng_data,
            skipped_net_events,
            rng_exhausted_warned: false,
        })
    }

    pub fn skipped_net_events(&self) -> usize {
        self.skipped_net_events
    }

    /// Called once per vCPU-loop iteration. Returns the next recorded
    /// keyboard event's bytes once *either* the live branch counter has
    /// reached its recorded position, *or* real wall-clock time since this
    /// replay started has reached the event's own recorded `elapsed_ms` —
    /// whichever comes first. `None` otherwise, or once every recorded
    /// keyboard event has already been delivered.
    ///
    /// **Both signals exist because relying on the branch counter alone
    /// was measured to fail, not assumed to be fine**: see
    /// `RecordedEvent`'s own doc comment for the real end-to-end test
    /// that failed 4 of 8 runs before this fallback existed. The
    /// wall-clock bound trades precision for a hard guarantee: a replay
    /// can now only ever be delayed by at most the same wall-clock gap
    /// the original recording had between events, never indefinitely.
    pub fn poll_keyboard(&mut self) -> Option<Vec<u8>> {
        let next = self.keyboard_events.get(self.next_keyboard)?;
        let reached_by_branch_count = self.counter.read_count() >= next.branch_count;
        let reached_by_wall_clock = self.start.elapsed().as_millis() as u64 >= next.elapsed_ms;
        if reached_by_branch_count || reached_by_wall_clock {
            self.next_keyboard += 1;
            Some(next.data.clone())
        } else {
            None
        }
    }

    /// Called from `VirtioRng::process_chain` instead of `getrandom(2)`.
    /// Returns exactly `want` bytes drawn from the front of the recorded
    /// RNG data, or `None` once the recording has no more — the caller
    /// falls back to real `getrandom` in that case (see this module's own
    /// doc comment for why refusing outright wouldn't buy back any real
    /// determinism at that point anyway).
    pub fn next_rng_bytes(&mut self, want: usize) -> Option<Vec<u8>> {
        let total_available: usize = self.rng_data.iter().map(Vec::len).sum();
        if total_available < want {
            if !self.rng_exhausted_warned {
                crate::log_warn!(
                    "replay: recording ran out of virtio-rng data; falling back to real \
                     getrandom(2) — this guest's random output no longer matches the recording"
                );
                self.rng_exhausted_warned = true;
            }
            return None;
        }
        let mut out = Vec::with_capacity(want);
        while out.len() < want {
            let front = self.rng_data.front_mut().expect("total_available >= want was already checked");
            let need = want - out.len();
            if front.len() <= need {
                out.extend(self.rng_data.pop_front().unwrap());
            } else {
                out.extend(front.drain(..need));
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn write_event_then_read_all_round_trips_exactly() {
        let path = std::env::temp_dir().join(format!("hyperbug-record-test-{}.bin", std::process::id()));
        let path_str = path.to_str().unwrap();

        {
            let mut file = File::create(path_str).unwrap();
            file.write_all(MAGIC).unwrap();
            file.write_all(&FORMAT_VERSION.to_le_bytes()).unwrap();
            file.write_all(&(256u64 * 1024 * 1024).to_le_bytes()).unwrap();
            file.write_all(&[1u8]).unwrap(); // precise = true
            let mut w = BufWriter::new(file);
            write_event(&mut w, 100, 10, EventKind::KeyboardRx, b"hi").unwrap();
            write_event(&mut w, 250, 20, EventKind::NetRx, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
            write_event(&mut w, 250, 20, EventKind::KeyboardRx, b"").unwrap(); // empty data must round-trip too
            w.flush().unwrap();
        }

        let (header, events) = read_all(path_str).unwrap();
        assert_eq!(header.mem_size, 256 * 1024 * 1024);
        assert!(header.precise);
        assert_eq!(
            events,
            vec![
                RecordedEvent { branch_count: 100, elapsed_ms: 10, kind: EventKind::KeyboardRx, data: b"hi".to_vec() },
                RecordedEvent {
                    branch_count: 250,
                    elapsed_ms: 20,
                    kind: EventKind::NetRx,
                    data: vec![0xde, 0xad, 0xbe, 0xef]
                },
                RecordedEvent { branch_count: 250, elapsed_ms: 20, kind: EventKind::KeyboardRx, data: Vec::new() },
            ]
        );

        std::fs::remove_file(path_str).unwrap();
    }

    #[test]
    fn read_all_rejects_a_bad_magic_and_a_truncated_file() {
        let path = std::env::temp_dir().join(format!("hyperbug-record-badmagic-{}.bin", std::process::id()));
        let path_str = path.to_str().unwrap();
        std::fs::write(path_str, b"NOPE").unwrap();
        assert!(read_all(path_str).is_err());

        // A header that claims an event follows but is cut off mid-event
        // must be a clean error, not a panic.
        let path2 = std::env::temp_dir().join(format!("hyperbug-record-truncated-{}.bin", std::process::id()));
        let path2_str = path2.to_str().unwrap();
        let mut file = File::create(path2_str).unwrap();
        file.write_all(MAGIC).unwrap();
        file.write_all(&FORMAT_VERSION.to_le_bytes()).unwrap();
        file.write_all(&0u64.to_le_bytes()).unwrap();
        file.write_all(&[0u8]).unwrap();
        file.write_all(&[EventKind::KeyboardRx.to_byte()]).unwrap();
        file.write_all(&0u64.to_le_bytes()).unwrap(); // branch_count
        file.write_all(&0u64.to_le_bytes()).unwrap(); // elapsed_ms
        file.write_all(&100u32.to_le_bytes()).unwrap(); // claims 100 bytes of data
        file.write_all(b"only a few").unwrap(); // far fewer than claimed
        drop(file);
        assert!(read_all(path2_str).is_err());

        std::fs::remove_file(path_str).unwrap();
        std::fs::remove_file(path2_str).unwrap();
    }

    /// `elapsed_ms` is fixed at `u64::MAX` for every event (never reached
    /// by `Replayer::start`'s own freshly-started clock) so these tests
    /// exercise the branch-count path in isolation, without the wall-clock
    /// fallback ever firing first — that fallback gets its own dedicated
    /// test below.
    fn write_recording(path: &str, mem_size: u64, events: &[(EventKind, u64, &[u8])]) {
        let mut file = File::create(path).unwrap();
        file.write_all(MAGIC).unwrap();
        file.write_all(&FORMAT_VERSION.to_le_bytes()).unwrap();
        file.write_all(&mem_size.to_le_bytes()).unwrap();
        file.write_all(&[1u8]).unwrap();
        let mut w = BufWriter::new(file);
        for &(kind, branch_count, data) in events {
            write_event(&mut w, branch_count, u64::MAX, kind, data).unwrap();
        }
        w.flush().unwrap();
    }

    #[test]
    fn replayer_rejects_a_mem_size_mismatch_without_needing_a_real_counter() {
        let path = std::env::temp_dir().join(format!("hyperbug-replay-memsize-{}.bin", std::process::id()));
        let path_str = path.to_str().unwrap();
        write_recording(path_str, 128 * 1024 * 1024, &[]);

        let err = match Replayer::start(path_str, std::process::id() as libc::pid_t, 256 * 1024 * 1024) {
            Ok(_) => panic!("a mem_size mismatch must be refused"),
            Err(e) => e,
        };
        assert!(err.contains("128"), "got: {err}");
        assert!(err.contains("256"), "got: {err}");

        std::fs::remove_file(path_str).unwrap();
    }

    /// A host-only thread (this test) never enters KVM guest mode, so its
    /// branch counter — real, but never advanced by anything this test
    /// does — stays at exactly 0 for the test's whole lifetime. That's
    /// enough to exercise the real boundary condition: an event recorded
    /// at position 0 delivers immediately; one recorded at any later
    /// position never does, on this thread, without a real guest actually
    /// advancing it. Skips (doesn't fail) if `perf_event_open` isn't
    /// available in this environment, same convention as `pmu.rs`'s own
    /// tests.
    #[test]
    fn replayer_delivers_a_keyboard_event_at_position_zero_and_withholds_a_later_one() {
        let path = std::env::temp_dir().join(format!("hyperbug-replay-kbd-{}.bin", std::process::id()));
        let path_str = path.to_str().unwrap();
        write_recording(
            path_str,
            4096,
            &[
                (EventKind::KeyboardRx, 0, b"a"),
                (EventKind::KeyboardRx, 1_000_000_000, b"b"),
            ],
        );

        let mut replayer = match Replayer::start(path_str, std::process::id() as libc::pid_t, 4096) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipping: {e}");
                let _ = std::fs::remove_file(path_str);
                return;
            }
        };

        assert_eq!(replayer.poll_keyboard(), Some(b"a".to_vec()), "position 0 should deliver immediately");
        assert_eq!(
            replayer.poll_keyboard(),
            None,
            "a later position should not deliver on a thread that never entered guest mode"
        );

        std::fs::remove_file(path_str).unwrap();
    }

    /// The fix for the real reliability problem found by end-to-end
    /// testing (see `RecordedEvent`'s doc comment): a keyboard event whose
    /// `branch_count` a host-only thread's counter will *never* reach
    /// (matching exactly the observed failure — a replay's counter never
    /// catching up to a recorded position) must still deliver once real
    /// wall-clock time reaches the event's `elapsed_ms`.
    #[test]
    fn replayer_falls_back_to_wall_clock_when_the_branch_counter_would_never_reach_position() {
        let path = std::env::temp_dir().join(format!("hyperbug-replay-fallback-{}.bin", std::process::id()));
        let path_str = path.to_str().unwrap();

        let mut file = File::create(path_str).unwrap();
        file.write_all(MAGIC).unwrap();
        file.write_all(&FORMAT_VERSION.to_le_bytes()).unwrap();
        file.write_all(&4096u64.to_le_bytes()).unwrap();
        file.write_all(&[1u8]).unwrap();
        let mut w = BufWriter::new(file);
        // A branch_count this host-only thread's counter will never
        // reach, but an elapsed_ms of 0 — the wall-clock fallback should
        // fire on essentially the first poll.
        write_event(&mut w, u64::MAX, 0, EventKind::KeyboardRx, b"z").unwrap();
        w.flush().unwrap();

        let mut replayer = match Replayer::start(path_str, std::process::id() as libc::pid_t, 4096) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipping: {e}");
                let _ = std::fs::remove_file(path_str);
                return;
            }
        };

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut delivered = None;
        while std::time::Instant::now() < deadline {
            if let Some(bytes) = replayer.poll_keyboard() {
                delivered = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            delivered,
            Some(b"z".to_vec()),
            "an unreachable branch_count must not block delivery forever — the wall-clock \
             fallback should have fired"
        );

        std::fs::remove_file(path_str).unwrap();
    }

    #[test]
    fn replayer_serves_rng_bytes_in_order_split_across_recorded_chunks() {
        let path = std::env::temp_dir().join(format!("hyperbug-replay-rng-{}.bin", std::process::id()));
        let path_str = path.to_str().unwrap();
        write_recording(
            path_str,
            4096,
            &[(EventKind::RngBytes, 0, &[1, 2, 3, 4]), (EventKind::RngBytes, 0, &[5, 6])],
        );

        let mut replayer = match Replayer::start(path_str, std::process::id() as libc::pid_t, 4096) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipping: {e}");
                let _ = std::fs::remove_file(path_str);
                return;
            }
        };

        // A request smaller than the first recorded chunk: served from
        // within it.
        assert_eq!(replayer.next_rng_bytes(2), Some(vec![1, 2]));
        // A request spanning the rest of the first chunk plus into the
        // second: must be seamlessly joined.
        assert_eq!(replayer.next_rng_bytes(3), Some(vec![3, 4, 5]));
        assert_eq!(replayer.next_rng_bytes(1), Some(vec![6]));
        // Exhausted: falls back to `None` rather than blocking or padding.
        assert_eq!(replayer.next_rng_bytes(1), None);

        std::fs::remove_file(path_str).unwrap();
    }

    #[test]
    fn replayer_counts_skipped_net_events_without_disturbing_other_streams() {
        let path = std::env::temp_dir().join(format!("hyperbug-replay-net-{}.bin", std::process::id()));
        let path_str = path.to_str().unwrap();
        write_recording(
            path_str,
            4096,
            &[
                (EventKind::NetRx, 0, &[0xaa]),
                (EventKind::KeyboardRx, 0, b"x"),
                (EventKind::NetRx, 0, &[0xbb]),
            ],
        );

        let mut replayer = match Replayer::start(path_str, std::process::id() as libc::pid_t, 4096) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipping: {e}");
                let _ = std::fs::remove_file(path_str);
                return;
            }
        };
        assert_eq!(replayer.skipped_net_events(), 2);
        assert_eq!(replayer.poll_keyboard(), Some(b"x".to_vec()), "the net events must not have displaced the keyboard one");

        std::fs::remove_file(path_str).unwrap();
    }
}
