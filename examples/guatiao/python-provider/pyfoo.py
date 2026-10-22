"""Plugins as guatiao providers, written in Python: PYFOO over UDP 115 (a
preference), a twin of FOO; the `pytap` tap listener; the `py_double`
display-filter function; the PYGCAP capture format; and the PYL8 codec.
libwireshark-guatiao serves them through the guatiao-py bridge; they need
the `libwireshark` package (bindings/python) importable, which brings
guatiao's Python binding.

The header and the preferences are classes, as with `libwireshark`'s
`Dissector`: the host decodes the header and adds its fields, and asks
`dissect_on` where to bind with the current preferences.
"""

from __future__ import annotations

import struct
from typing import Annotated, List, Optional, Union

from guatiao import Map, provide
from libwireshark import (
    U8,
    U16,
    Base,
    Binding,
    CaptureFile,
    CaptureReader,
    Codec,
    Decoder,
    Expert,
    ExpertGroup,
    FileType,
    FilterFunction,
    FilterReturn,
    Header,
    Meta,
    Preferences,
    ProtocolDissector,
    Record,
    Severity,
    Table,
    Tap,
    TapListener,
    TapPacket,
    TypedPacket,
)

__version__ = "0.1.0"
__all__ = ["Pyfoo", "PyTap", "PyDouble", "PygCap", "Pyl8"]

#: The only version PYFOO knows.
VERSION = 7


class PyfooHeader(Header):
    """PYFOO's header: a version byte, a flags byte and a big-endian length."""

    version: Annotated[U8, Meta(name="Version", values={VERSION: "seven"})]
    "The protocol version"

    flags: Annotated[U8, Meta(name="Flags", base=Base.HEX)]
    "Feature flags"

    length: Annotated[U16, Meta(name="Length")]
    "The message's length"


class UnknownVersion(Expert):
    """Unknown version"""

    GROUP = ExpertGroup.MALFORMED
    SEVERITY = Severity.WARN


class PyfooPreferences(Preferences):
    """PYFOO's settings, under Edit > Preferences > Protocols > PYFOO."""

    port: Annotated[int, Meta(title="UDP port")] = 115
    "UDP port PYFOO is decoded on"


class Pyfoo(provide.Provider, ProtocolDissector, display_name="FOO, in Python"):
    """PYFOO, dissected in Python."""

    NAME = "Python FOO Protocol"
    SHORT_NAME = "PYFOO"
    FILTER_NAME = "pyfoo"
    HEADER = PyfooHeader
    PREFERENCES = PyfooPreferences
    EXPERTS = [UnknownVersion]

    def dissect_on(self, preferences: PyfooPreferences) -> List[Binding]:
        return [Table.udp_port(preferences.port)]

    def dissect(
        self,
        data: bytes,
        header: PyfooHeader,
        preferences: PyfooPreferences,
        packet: TypedPacket,
        conversation: Map,
    ) -> int:
        count = int(conversation.get("count", 0))
        if packet.is_first_pass():
            count += 1
            conversation["count"] = count
        if header.version != VERSION:
            packet.add_expert(UnknownVersion())
        packet.set_info(f"PYFOO version {header.version}, packet {count}")
        return len(data)


class FrameCount(TapListener):
    """One `-z pytap` invocation: the frames seen."""

    def __init__(self) -> None:
        self.frames = 0

    def packet(self, packet: TapPacket) -> None:
        self.frames += 1

    def draw(self) -> str:
        return f"pytap: {self.frames} frames\n"


class PyTap(provide.Provider, Tap):
    """`-z pytap`: frames counted in Python."""

    NAME = "pytap"
    TAP = "frame"
    LISTENER = FrameCount


class PyDouble(provide.Provider, FilterFunction):
    """`py_double(field)`: twice an integer field's value."""

    NAME = "py_double"
    RETURNS = FilterReturn.COUNT

    def apply(self, value: Union[int, str]) -> Optional[int]:
        return value * 2 if isinstance(value, int) else None


#: PYGCAP's first bytes.
MAGIC = b"PYGCAP\0\x01"


class PygCapReader(CaptureReader):
    """Records of a nanosecond time, the captured and original lengths
    (little-endian) and the captured bytes."""

    def read(self, file: CaptureFile) -> Optional[Record]:
        header = file.read_exact(16)
        if header is None:
            return None
        time_ns, captured, original = struct.unpack("<QII", header)
        return Record(file.read_exact(captured) or b"", time_ns=time_ns, original_len=original)


class PygCap(provide.Provider, FileType):
    """PYGCAP, read in Python."""

    NAME = "pygcap"
    DESCRIPTION = "PYGCAP example capture, read by a Python provider"
    EXTENSIONS = ["pygcap"]

    def reader(self, file: CaptureFile) -> Optional[CaptureReader]:
        return PygCapReader() if file.read(len(MAGIC)) == MAGIC else None


class Pyl8Decoder(Decoder):
    """Unsigned 8-bit samples, at the stream's rate (8 kHz unless the SDP says)."""

    def sample_rate(self) -> int:
        return self.format.sample_rate or 8000

    def decode(self, payload: bytes) -> List[int]:
        return [(byte - 128) << 8 for byte in payload]


class Pyl8(provide.Provider, Codec):
    """PYL8, decoded in Python."""

    NAME = "PYL8"
    DECODER = Pyl8Decoder
