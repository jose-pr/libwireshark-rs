"""What `libwireshark.Engine` raises when Wireshark refuses or fails."""

from __future__ import annotations

__all__ = ["WiresharkError", "EngineError", "DisplayFilterError"]


class WiresharkError(Exception):
    """The base of every error this package raises at run time."""


class EngineError(WiresharkError):
    """Wireshark's engine did not start, refused a plugin or preference, or
    could not read a capture. The message is Wireshark's."""


class DisplayFilterError(EngineError, ValueError):
    """A display filter did not compile."""
