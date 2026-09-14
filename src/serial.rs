//! Minimal 16550-compatible UART: enough register behavior for the Linux
//! 8250 console driver to both use kernel-level polled printk output and
//! complete userspace tty startup (which requires a working THR-empty
//! interrupt; without one, `uart_startup()` leaves the port in an error
//! state and every userspace write() fails with -EIO). Also models RX
//! (host stdin -> guest), so this is a real two-way console, not just a
//! guest-to-host log — see `push_rx_byte`.
//!
//! **Multi-UART**: `Serial` is parameterized by its own `base` I/O port
//! (not hardcoded to COM1's) and an output `Sink`, so the identical,
//! already-verified register logic backs COM1 (the interactive console,
//! `Sink::Stdout`) and up to three additional real ISA-convention ports —
//! COM2/COM3/COM4 (`--uart2-log`/`--uart3-log`/`--uart4-log`), each
//! capturing its guest-transmitted bytes to a host file (`Sink::File`).
//! Real BMCs commonly multiplex several serial channels this way (host
//! console pass-through, a debug UART, SOL) — see `machine.rs`'s
//! `SharedState::extra_uarts`. **Output-only, deliberately**: no RX/
//! interactivity for the extra ports (a debug-UART/SOL-capture log has
//! no reason to accept keyboard input the way the interactive COM1
//! console does), and their protocol state isn't part of a snapshot
//! (same category as a Python device plugin's own state — simple and
//! always safely reconstructible fresh, not worth the `SnapshotDeps`
//! plumbing a truly stateful device would need).

use std::collections::VecDeque;
use std::io::Write;
use std::sync::LazyLock;

use crate::tty;

pub const COM1_BASE: u16 = 0x3f8;
pub const COM1_PORTS: std::ops::Range<u16> = COM1_BASE..COM1_BASE + 8;
/// ISA IRQ for COM1, routed 1:1 to GSI 4 by KVM's default in-kernel PIC/IOAPIC.
pub const COM1_IRQ: u32 = 4;

/// Real ISA convention: COM2 and COM4 share IRQ 3, COM1 and COM3 share
/// IRQ 4 — genuine period-correct BIOS behavior (Linux's 8250 driver
/// requests each with `IRQF_SHARED` for exactly this reason), not a
/// hyperbug-specific shortcut. `IrqRegistry::register` already dedupes a
/// repeated GSI (used for virtio-blk's 8 disks/virtio-gpio's 4 banks
/// sharing one GSI each), so registering COM3 on the same GSI COM1
/// already owns needs no special handling here.
pub const COM2_BASE: u16 = 0x2f8;
pub const COM2_PORTS: std::ops::Range<u16> = COM2_BASE..COM2_BASE + 8;
pub const COM2_IRQ: u32 = 3;
pub const COM3_BASE: u16 = 0x3e8;
pub const COM3_PORTS: std::ops::Range<u16> = COM3_BASE..COM3_BASE + 8;
pub const COM3_IRQ: u32 = 4;
pub const COM4_BASE: u16 = 0x2e8;
pub const COM4_PORTS: std::ops::Range<u16> = COM4_BASE..COM4_BASE + 8;
pub const COM4_IRQ: u32 = 3;

/// Where a `Serial` instance's transmitted bytes actually go.
pub enum Sink {
    /// COM1's own real interactive-console path (raw stdout, no
    /// buffering — see `tty::write_stdout`'s own doc comment for why).
    Stdout,
    /// An extra UART's captured output — plain `File::write_all` +
    /// `flush` per write, so a tailing `--uart2-log` reader sees bytes
    /// promptly rather than waiting on internal buffering.
    File(std::fs::File),
}

impl Sink {
    fn write(&mut self, data: &[u8]) {
        match self {
            Sink::Stdout => tty::write_stdout(data),
            Sink::File(f) => {
                // Best-effort: a full disk or a removed log file shouldn't
                // crash the guest's own console I/O.
                let _ = f.write_all(data);
                let _ = f.flush();
            }
        }
    }
}

const REG_RBR: u16 = 0; // receive buffer (read) / THR (write)
const REG_IER: u16 = 1;
const REG_IIR: u16 = 2;
const REG_LSR: u16 = 5;
const REG_MSR: u16 = 6;
const REG_SCR: u16 = 7;

const IER_RDI: u8 = 0x01; // "received data available" interrupt enable
const IER_THRI: u8 = 0x02; // "THR empty" interrupt enable
const IER_MASK: u8 = 0x0f; // only the low four enable bits are implemented
const IIR_NO_INTERRUPT: u8 = 0x01;
const IIR_THRI: u8 = 0x02;
const IIR_RDI: u8 = 0x04;
const LSR_DR: u8 = 0x01; // data ready (RBR has a byte)
const LSR_THRE_TEMT: u8 = 0x60; // transmit holding reg + shift reg both empty
const MSR_CTS_DSR_DCD: u8 = 0xb0; // CTS|DSR|DCD asserted: line looks "connected"

/// `HYPERBUG_SERIAL_TRACE=1` dumps every COM1 register access to stderr —
/// the diagnostic that localized a past console-under-ACPI bug. Read
/// **once**, not per access: this sits on the
/// hottest path in the VMM (one VM exit per console byte in each
/// direction), and `env::var_os` allocates and takes the process-wide
/// environment lock on every call.
static TRACE: LazyLock<bool> = LazyLock::new(|| std::env::var_os("HYPERBUG_SERIAL_TRACE").is_some());

pub struct Serial {
    base: u16,
    sink: Sink,
    ier: u8,
    // Scratch register: driver UART-type autodetection round-trips a value
    // through it, so it must actually store what's written.
    scratch: u8,
    // Real 16550s have a 16-byte RX FIFO; a plain queue is simpler and the
    // guest only ever sees one byte at a time through RBR anyway.
    rx: VecDeque<u8>,
}

impl Default for Serial {
    /// COM1's own configuration — every existing caller (`SharedState::
    /// serial`, every test in this module) expects `Serial::new()` to
    /// mean exactly this, unchanged from before `base`/`Sink` existed.
    fn default() -> Self {
        Self { base: COM1_BASE, sink: Sink::Stdout, ier: 0, scratch: 0, rx: VecDeque::new() }
    }
}

impl Serial {
    pub fn new() -> Self {
        Self::default()
    }

    /// An extra UART (COM2/COM3/COM4) capturing its transmitted bytes to
    /// a host file, opened here (truncated fresh each launch — a log,
    /// not something meant to accumulate silently across runs).
    pub fn new_capture(base: u16, log_path: &str) -> std::io::Result<Self> {
        let file = std::fs::File::create(log_path)?;
        Ok(Self { base, sink: Sink::File(file), ier: 0, scratch: 0, rx: VecDeque::new() })
    }

    /// Host stdin produced a byte for the guest. Returns true if IRQ4
    /// should be pulsed (RDI is enabled) — real 16550s are level-triggered
    /// on "data ready", so this must fire the instant a byte lands, the
    /// same reasoning as the existing THRI-on-enable pulse below.
    pub fn push_rx_byte(&mut self, byte: u8) -> bool {
        self.rx.push_back(byte);
        self.ier & IER_RDI != 0
    }

    /// Returns true if the guest just needs an IRQ4 pulse in response to
    /// this write (i.e. it wrote transmit data with THR-empty IRQs enabled).
    #[inline]
    pub fn handle_out(&mut self, port: u16, data: &[u8]) -> bool {
        // KVM always hands over at least one byte for a port write, but a
        // zero-length slice would otherwise be an out-of-bounds index on
        // the single hottest guest-facing path in the VMM.
        let Some(&byte) = data.first() else { return false };
        let reg = port.wrapping_sub(self.base);
        if *TRACE {
            eprintln!("[serial-trace] OUT reg={reg} data={byte:#x}");
        }
        match reg {
            REG_RBR => {
                self.sink.write(data);
                self.ier & IER_THRI != 0
            }
            REG_IER => {
                self.ier = byte & IER_MASK;
                // THR is permanently "empty" in this model, so enabling
                // THRI must immediately assert the interrupt (real 16550s
                // are level-triggered on the already-true condition) —
                // otherwise nothing ever kicks off the first transmit,
                // since the driver only pushes bytes to THR from its ISR.
                // Likewise, enabling RDI while a byte is already queued
                // must assert immediately for the same reason.
                self.ier & IER_THRI != 0 || (self.ier & IER_RDI != 0 && !self.rx.is_empty())
            }
            REG_SCR => {
                self.scratch = byte;
                false
            }
            // other registers (LCR/MCR/FCR): no-op, we don't model them
            _ => false,
        }
    }

    #[inline]
    pub fn handle_in(&mut self, port: u16, data: &mut [u8]) {
        data.fill(0);
        let reg = port.wrapping_sub(self.base);
        let value = match reg {
            REG_RBR => self.rx.pop_front().unwrap_or(0),
            // Real 16550 priority: RX data-ready outranks THR-empty.
            REG_IIR => {
                if self.ier & IER_RDI != 0 && !self.rx.is_empty() {
                    IIR_RDI
                } else if self.ier & IER_THRI != 0 {
                    IIR_THRI
                } else {
                    IIR_NO_INTERRUPT
                }
            }
            REG_IER => self.ier,
            REG_LSR => {
                let ready = if self.rx.is_empty() { 0 } else { LSR_DR };
                LSR_THRE_TEMT | ready // always ready to transmit
            }
            REG_MSR => MSR_CTS_DSR_DCD,
            REG_SCR => self.scratch,
            _ => 0,
        };
        if let Some(first) = data.first_mut() {
            *first = value;
        }
        if *TRACE {
            eprintln!("[serial-trace] IN  reg={reg} data={value:#x}");
        }
    }
}

impl crate::snapshot::Snapshot for Serial {
    fn save_state(&self) -> Vec<u8> {
        let mut buf = vec![self.ier, self.scratch];
        buf.extend_from_slice(&(self.rx.len() as u32).to_le_bytes());
        buf.extend(self.rx.iter().copied());
        buf
    }

    fn restore_state(&mut self, data: &[u8]) -> Result<(), String> {
        use crate::snapshot::{take_u8, take_u32};
        let mut buf = data;
        self.ier = take_u8(&mut buf)?;
        self.scratch = take_u8(&mut buf)?;
        let n = take_u32(&mut buf)? as usize;
        self.rx = crate::snapshot::take(&mut buf, n)?.iter().copied().collect();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabling_thri_asserts_immediately_because_thr_is_always_empty() {
        // Load-bearing (see this project's Phase 2 notes): the driver only
        // ever pushes bytes to THR from inside its own ISR, so if enabling
        // THRI doesn't assert on an already-empty THR, transmission never
        // starts and every userspace write() fails with -EIO.
        let mut serial = Serial::new();
        assert!(serial.handle_out(COM1_BASE + REG_IER, &[IER_THRI]));
    }

    #[test]
    fn enabling_rdi_asserts_only_when_a_byte_is_already_queued() {
        let mut serial = Serial::new();
        assert!(!serial.handle_out(COM1_BASE + REG_IER, &[IER_RDI]));

        // Nothing to deliver yet, so pushing while RDI is enabled asserts.
        assert!(serial.push_rx_byte(b'x'));
        assert!(serial.handle_out(COM1_BASE + REG_IER, &[IER_RDI]));
    }

    #[test]
    fn rx_shows_up_in_lsr_and_iir_and_drains_through_rbr() {
        let mut serial = Serial::new();
        serial.handle_out(COM1_BASE + REG_IER, &[IER_RDI | IER_THRI]);
        serial.push_rx_byte(b'A');

        let mut data = [0u8; 1];
        serial.handle_in(COM1_BASE + REG_LSR, &mut data);
        assert_eq!(data[0] & LSR_DR, LSR_DR, "data-ready must be set with a byte queued");

        serial.handle_in(COM1_BASE + REG_IIR, &mut data);
        assert_eq!(data[0], IIR_RDI, "RX data-ready outranks THR-empty");

        serial.handle_in(COM1_BASE + REG_RBR, &mut data);
        assert_eq!(data[0], b'A');

        serial.handle_in(COM1_BASE + REG_LSR, &mut data);
        assert_eq!(data[0] & LSR_DR, 0, "data-ready must clear once drained");
    }

    #[test]
    fn the_scratch_register_round_trips_which_is_what_autoconfig_probes() {
        let mut serial = Serial::new();
        serial.handle_out(COM1_BASE + REG_SCR, &[0x5a]);
        let mut data = [0u8; 1];
        serial.handle_in(COM1_BASE + REG_SCR, &mut data);
        assert_eq!(data[0], 0x5a);
    }

    #[test]
    fn a_zero_length_access_is_a_no_op_rather_than_a_panic() {
        let mut serial = Serial::new();
        assert!(!serial.handle_out(COM1_BASE + REG_IER, &[]));
        serial.handle_in(COM1_BASE + REG_LSR, &mut []);
    }

    /// A second `Serial` instance at a different `base` runs the
    /// identical register logic independently of COM1's — the actual
    /// point of parameterizing `base` at all.
    #[test]
    fn a_second_serial_instance_at_a_different_base_works_independently() {
        let dir = std::env::temp_dir().join(format!("hyperbug-uart-unit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("com2.log");

        let mut com1 = Serial::new();
        let mut com2 = Serial::new_capture(COM2_BASE, log_path.to_str().unwrap()).unwrap();

        assert!(com2.handle_out(COM2_BASE + REG_IER, &[IER_THRI]), "THRI-on-enable must fire for COM2 too");
        com2.handle_out(COM2_BASE + REG_RBR, b"hi");

        // COM1 must be completely unaffected by COM2's traffic.
        let mut data = [0u8; 1];
        com1.handle_in(COM1_BASE + REG_LSR, &mut data);
        assert_eq!(data[0] & LSR_DR, 0, "COM1 has no queued RX of its own");

        let captured = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(captured, "hi", "COM2's transmitted bytes must land in its own capture file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_round_trip_preserves_ier_scratch_and_queued_rx_bytes() {
        use crate::snapshot::Snapshot;
        let mut serial = Serial::new();
        serial.handle_out(COM1_BASE + REG_IER, &[IER_RDI | IER_THRI]);
        serial.handle_out(COM1_BASE + REG_SCR, &[0x5a]);
        serial.push_rx_byte(b'A');
        serial.push_rx_byte(b'B');

        let blob = serial.save_state();
        let mut restored = Serial::new();
        restored.restore_state(&blob).unwrap();

        let mut data = [0u8; 1];
        restored.handle_in(COM1_BASE + REG_IER, &mut data);
        assert_eq!(data[0], IER_RDI | IER_THRI);
        restored.handle_in(COM1_BASE + REG_SCR, &mut data);
        assert_eq!(data[0], 0x5a);
        restored.handle_in(COM1_BASE + REG_RBR, &mut data);
        assert_eq!(data[0], b'A', "queued RX bytes must survive in order");
        restored.handle_in(COM1_BASE + REG_RBR, &mut data);
        assert_eq!(data[0], b'B');
    }
}
