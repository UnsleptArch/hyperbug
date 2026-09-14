//! The Python-pluggable contract behind one virtual GPIO bank
//! (`virtio_gpio.rs`'s `VirtioGpio`). Unlike `i2c.rs`'s `I2cBus` (many
//! targets sharing one bus, addressed dynamically), a GPIO bank is a
//! single chip with a fixed line count decided at attach time — real BMC
//! hardware typically has several independent GPIO controllers rather
//! than one shared bus, so each `--gpio-device` gets its own adapter/PCI
//! slot instead of multiplexing through a shared bus object.
//!
//! **No per-iteration `tick()` hook, unlike `Device`/`I2cTargetDevice`'s
//! host-facing cousins.** A GPIO bank's spontaneous events (a simulated
//! button press, a presence-detect line changing) are delivered purely
//! through `self.hyperbug.raise_irq(line)`, a real eventfd write that's
//! thread-safe to call from anywhere — including a plugin's own
//! background Python thread (e.g. `threading.Timer`) — without needing
//! hyperbug to poll it every loop iteration first. Simpler than adding a
//! second polling path when this one already covers the same need.

use std::os::fd::RawFd;

/// `VIRTIO_GPIO_DIRECTION_*` values, per `<linux/virtio_gpio.h>`.
pub const DIRECTION_NONE: u8 = 0x00;
pub const DIRECTION_OUT: u8 = 0x01;
pub const DIRECTION_IN: u8 = 0x02;

/// One virtual GPIO chip. `Send`: called from whichever thread is
/// draining the adapter's virtqueues (a vCPU thread synchronously, or the
/// reactor thread via ioeventfd/completion-eventfd).
pub trait GpioBank: Send {
    /// Number of lines this bank exposes — fixed for the life of the
    /// bank, read once at adapter construction to size the virtio config
    /// space and the event queue.
    fn ngpio(&self) -> u16;

    /// Optional per-line names for `GPIO_V2_GET_LINEINFO_IOCTL`-style
    /// introspection on the guest side. An empty vec (the default a
    /// plugin gets by not declaring `names`) means "don't offer names at
    /// all" — matches the real driver's own behavior of never even
    /// issuing `GET_NAMES` when `gpio_names_size` is 0.
    fn names(&self) -> Vec<String> {
        Vec::new()
    }

    /// One of `DIRECTION_NONE`/`DIRECTION_OUT`/`DIRECTION_IN`.
    fn get_direction(&mut self, line: u16) -> u8;
    /// `direction` is one of the three `DIRECTION_*` constants above —
    /// already validated by `virtio_gpio.rs` before this is called.
    fn set_direction(&mut self, line: u16, direction: u8);
    /// 0 or 1.
    fn get_value(&mut self, line: u16) -> u8;
    /// `value` is 0 or 1 — already masked by `virtio_gpio.rs`.
    fn set_value(&mut self, line: u16, value: u8);

    /// Drains whatever lines have "fired" (spontaneously changed state
    /// via the plugin's own `self.hyperbug.raise_irq(line)`) since the
    /// last call. `virtio_gpio.rs` delivers each one to the guest only
    /// if that line's interrupt is currently armed and enabled — an
    /// event for a line nothing is listening on is simply dropped,
    /// matching real hardware's own behavior for a masked/disabled line.
    fn take_fired_irqs(&mut self) -> Vec<u16> {
        Vec::new()
    }

    /// A raw fd that becomes readable when `take_fired_irqs` has
    /// something new — so the reactor can block in `epoll` instead of
    /// polling. `None` (the default) for a bank that never fires one.
    fn completion_eventfd(&self) -> Option<RawFd> {
        None
    }
}
