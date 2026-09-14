"""A reference GPIO bank: a small, self-invented 4-line BMC-shaped
controller — not a clone of any real chip's line assignment — exercising
the actual Tier-6 use case (power/reset control, presence detection) and
the spontaneous-interrupt path via `self.hyperbug.raise_irq(line)`.

Line map:
  0  power button (input) — a real BMC reads this to detect a physical
     power-button press; `press_power_button()` below simulates one and
     raises a real interrupt on it, same as a guest driver polling for
     `IRQF_TRIGGER_FALLING` would expect.
  1  power-good / presence-detect (input) — starts high (1), can be
     toggled to simulate a device being removed/inserted.
  2  power-control (output) — what a real BMC would drive to actually
     power the host on/off; just a plain read/write bit here.
  3  reset-control (output) — same idea, for a hardware reset line.

Attach with e.g.::

    hyperbug --kernel vmlinuz --gpio-device devices/gpio_button_bank.py:ButtonBank ...
"""

import os
import threading

from hyperbug.device import GpioBank
from hyperbug.gpio import DIRECTION_IN, DIRECTION_NONE, DIRECTION_OUT

LINE_POWER_BUTTON = 0
LINE_PRESENCE = 1
LINE_POWER_CONTROL = 2
LINE_RESET_CONTROL = 3


class ButtonBank(GpioBank):
    ngpio = 4
    names = ["power_button", "presence", "power_control", "reset_control"]

    def __init__(self):
        self._directions = [DIRECTION_IN, DIRECTION_IN, DIRECTION_OUT, DIRECTION_OUT]
        self._values = [1, 1, 0, 0]  # buttons/presence idle high, outputs start low

        # Demonstrates the pattern `hyperbug.device.GpioBank`'s own
        # docstring recommends for a spontaneous event: a plain background
        # thread calling `self.hyperbug.raise_irq()` on its own schedule,
        # with no per-iteration polling hook needed. Off by default;
        # `tests/boot.rs`'s real GPIO interrupt test turns it on to get a
        # real, deterministic button press without needing any other way
        # to reach into a running plugin from outside the guest.
        delay_ms = os.environ.get("HYPERBUG_GPIO_DEMO_AUTOPRESS_MS")
        if delay_ms:
            timer = threading.Timer(int(delay_ms) / 1000.0, self.press_power_button)
            timer.daemon = True
            timer.start()

    def get_direction(self, line: int) -> int:
        return self._directions[line]

    def set_direction(self, line: int, direction: int) -> None:
        self._directions[line] = direction
        if direction == DIRECTION_NONE:
            self._values[line] = 0

    def get_value(self, line: int) -> int:
        return self._values[line]

    def set_value(self, line: int, value: int) -> None:
        self._values[line] = value & 1

    def press_power_button(self) -> None:
        """Not part of the `GpioBank` contract — a convenience for
        testing/demoing: simulates a real, momentary button press (goes
        low, raises the line's interrupt, goes back high) the way a real
        BMC's power-button GPIO behaves."""
        self._values[LINE_POWER_BUTTON] = 0
        self.hyperbug.raise_irq(LINE_POWER_BUTTON)

    def release_power_button(self) -> None:
        self._values[LINE_POWER_BUTTON] = 1
        self.hyperbug.raise_irq(LINE_POWER_BUTTON)

    def set_presence(self, present: bool) -> None:
        """Simulates a presence-detect line changing — e.g. a PSU or
        drive being removed/inserted — and raises its interrupt."""
        self._values[LINE_PRESENCE] = 1 if present else 0
        self.hyperbug.raise_irq(LINE_PRESENCE)
