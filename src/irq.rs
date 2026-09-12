//! Real KVM irqfd-backed interrupt lines, replacing the old "call
//! `vm.set_irq_line(irq, true); vm.set_irq_line(irq, false)` pulse from
//! whichever thread noticed the event" pattern — replacing the 20ms-poll
//! loop's lack of real irqfd/ioeventfd/epoll integration with the real
//! thing.
//!
//! Once registered, injecting the interrupt is a plain eventfd write from
//! *any* thread — no `VmFd`/ioctl call, and no need to route the event
//! through the shared machine lock or a vCPU thread's own poll loop at
//! delivery time at all. For a PIC-routed (edge-triggered) legacy IRQ —
//! every interrupt line this codebase uses — a single eventfd write is
//! exactly equivalent to the old assert-then-deassert pulse: KVM handles
//! the edge automatically for an irqfd-registered GSI.

use std::collections::HashMap;
use std::sync::Arc;

use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::EventFd;

use crate::error::HyperbugError;

#[derive(Clone)]
pub struct IrqLine {
    eventfd: Arc<EventFd>,
}

impl IrqLine {
    /// Injects one edge-triggered interrupt. Infallible in practice: the
    /// only way an eventfd write fails is a counter overflow after 2^64-1
    /// undelivered pulses.
    #[inline]
    pub fn pulse(&self) {
        let _ = self.eventfd.write(1);
    }
}

/// Every irqfd-backed line this VM has, built once during setup and then
/// read-only — so it can be shared across every vCPU thread and the
/// reactor as a plain `Arc` with no lock at all.
#[derive(Default)]
pub struct IrqRegistry {
    lines: HashMap<u32, IrqLine>,
}

impl IrqRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an irqfd-backed line for `gsi` unless one already exists
    /// (several devices legitimately share a legacy PCI line). Must happen
    /// before any vCPU starts running, same as every other one-time
    /// IRQ-chip setup in `lib.rs::run`.
    pub fn register(&mut self, vm: &VmFd, gsi: u32) -> Result<(), HyperbugError> {
        if self.lines.contains_key(&gsi) {
            return Ok(());
        }
        let eventfd = EventFd::new(0)?;
        vm.register_irqfd(&eventfd, gsi)?;
        self.lines.insert(gsi, IrqLine { eventfd: Arc::new(eventfd) });
        Ok(())
    }

    /// Pulses `gsi`. A miss means some code path is raising an IRQ number
    /// nothing ever registered an irqfd for — a real bug in this codebase,
    /// not a guest-triggerable condition, so it's logged rather than
    /// silently dropped or made fatal (an interrupt that never arrives is
    /// exactly the kind of thing worth seeing loudly during development,
    /// but not worth tearing down an otherwise-fine run over).
    #[inline]
    pub fn pulse(&self, gsi: u32) {
        match self.lines.get(&gsi) {
            Some(line) => line.pulse(),
            None => eprintln!("[hyperbug] BUG: no irqfd registered for IRQ {gsi}"),
        }
    }
}
