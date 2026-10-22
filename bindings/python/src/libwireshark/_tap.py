"""A tap listener written as a class: statistics over the packets a
Wireshark tap hands it, offered as `tshark -z <NAME>[,<filter>]`.

```python
class FrameCount(TapListener):
    def __init__(self) -> None:
        self.frames = 0

    def packet(self, packet: TapPacket) -> None:
        self.frames += 1

    def draw(self) -> str:
        return f"pytap: {self.frames} frames\\n"


class PyTap(provide.Provider, Tap):
    NAME = "pytap"
    TAP = "frame"
    LISTENER = FrameCount
```
"""

from __future__ import annotations

__all__ = ["Tap", "TapListener", "TapPacket"]

from dataclasses import dataclass
from typing import Any, ClassVar, Dict, Mapping, Type

from . import kinds


@dataclass(frozen=True)
class TapPacket:
    """One packet that reached the tap."""

    frame: int
    "The frame number, counted from 1."
    len: int
    "The frame's length on the wire."
    time_ns: int
    "When it was captured, in nanoseconds since the Unix epoch."
    source: str
    "The source address, as Wireshark writes it."
    destination: str
    "The destination address."
    src_port: int
    "The source port of its transport, 0 when it has none."
    dst_port: int
    "The destination port."

    @classmethod
    def from_map(cls, packet: Mapping[str, Any]) -> "TapPacket":
        return cls(
            frame=int(packet["frame"]),
            len=int(packet["len"]),
            time_ns=int(packet["time_ns"]),
            source=str(packet["source"]),
            destination=str(packet["destination"]),
            src_port=int(packet["src_port"]),
            dst_port=int(packet["dst_port"]),
        )


class TapListener:
    """One `-z` invocation's state: made with no arguments for each one."""

    def packet(self, packet: TapPacket) -> None:
        """One packet that reached the tap."""

    def draw(self) -> str:
        """The report printed when the capture ends."""
        return ""

    def reset(self) -> None:
        """Wireshark starts over (a new capture): by default, a fresh state."""
        self.__init__()  # type: ignore[misc]


class _Listening:
    """A `TapListener` as the `wireshark_tap_listener` object the host owns."""

    def __init__(self, listener: TapListener) -> None:
        self.listener = listener

    def packet(self, packet: Any) -> None:
        self.listener.packet(TapPacket.from_map(packet.to_python()))

    def draw(self) -> str:
        return self.listener.draw()

    def reset(self) -> None:
        self.listener.reset()


class Tap(kinds.Tap):
    """A tap listener: subclass it beside guatiao's `provide.Provider`.

    `NAME` is the `-z` name (`[a-z][a-z0-9_.-]*`), `TAP` Wireshark's tap it
    listens to (a protocol's filter name: `frame`, `ip`, `udp`), and
    `LISTENER` the `TapListener` class each invocation gets an instance of.
    """

    NAME: ClassVar[str]
    TAP: ClassVar[str]
    LISTENER: ClassVar[Type[TapListener]] = TapListener

    def describe(self) -> Dict[str, Any]:
        return {"name": type(self).NAME, "tap": type(self).TAP}

    def open(self) -> _Listening:  # type: ignore[override]
        return _Listening(type(self).LISTENER())
