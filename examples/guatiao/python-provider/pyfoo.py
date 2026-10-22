"""A dissector as a guatiao provider, written in Python: PYFOO over UDP 115
(a preference), a twin of FOO. libwireshark-guatiao serves it through the
guatiao-py bridge; it needs the `libwireshark` package (bindings/python)
importable, which brings guatiao's Python binding.

The header and the preferences are classes, as with `libwireshark`'s
`Dissector`: the host decodes the header and adds its fields, and asks
`dissect_on` where to bind with the current preferences.
"""

from __future__ import annotations

from typing import Annotated, List

from guatiao import Map, provide
from libwireshark import (
    U8,
    U16,
    Base,
    Binding,
    Expert,
    ExpertGroup,
    Header,
    Meta,
    Preferences,
    ProtocolDissector,
    Severity,
    Table,
    TypedPacket,
)

__version__ = "0.1.0"
__all__ = ["Pyfoo"]

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
