"""The guatiao kinds of a Wireshark dissector, as typed Protocol classes:
`libwireshark_api.h`'s tables, each method in the order its table declares
it, its shapes in the annotations, each `floor_hash` the `#define` beside
the table (the repository's tests compare them).

A dissector usually subclasses `libwireshark.ProtocolDissector`, which
implements `Dissector` from typed classes; the host lends a `Packet` to
`dissect`.
"""

from __future__ import annotations

__all__ = ["Dissector", "Packet"]

from typing import Protocol

from guatiao import Map
from guatiao.kinds import (
    I64,
    U64,
    KindProtocol,
    Lent,
    ListAnswer,
    MapAnswer,
    fallible,
    required,
)


class Packet(
    KindProtocol,
    Protocol,
    kind="wireshark_packet",
    floor_hash=2387250941,
    is_object=True,
):
    """`wireshark_packet_vtable`: one packet, lent by the host for a `dissect` call.

    Field names are the abbreviations the description declared, with or
    without the protocol's filter-name prefix; offsets are in bytes from the
    start of `data`.
    """

    @required
    @fallible
    def add_item(self, field: str, offset: I64, length: I64, little_endian: bool) -> None: ...

    @required
    @fallible
    def add_uint(self, field: str, offset: I64, value: U64) -> None: ...

    @required
    @fallible
    def add_int(self, field: str, offset: I64, value: I64) -> None: ...

    @required
    def set_info(self, text: str) -> None: ...

    @required
    def append_info(self, text: str) -> None: ...

    @required
    @fallible
    def add_expert(self, name: str, text: str) -> None: ...

    @required
    def is_first_pass(self) -> bool: ...

    @required
    def is_postdissector(self) -> bool: ...

    @required
    def frame_number(self) -> I64: ...

    @required
    def src_port(self) -> I64: ...

    @required
    def dst_port(self) -> I64: ...


class Dissector(KindProtocol, Protocol, kind="wireshark_dissector", floor_hash=1003939949):
    """`wireshark_dissector_vtable`: a protocol and its dissection.

    `describe` answers the protocol as a map (the crate's `Description`);
    `dissect_on` the bindings for these preference values, a list of
    `Binding` maps; `dissect` the bytes it took, 0 to decline, given the
    header the host decoded and the preference values; `message_len`, for
    a protocol framed over TCP, a message's whole length from its header, or
    -1 when the header is not this protocol's. `ProtocolDissector` in
    `libwireshark.ProtocolDissector` writes all of it from typed classes.
    """

    @required
    @fallible
    def describe(self) -> MapAnswer: ...

    @required
    @fallible
    def dissect_on(self, preferences: Map) -> ListAnswer: ...

    @required
    @fallible
    def dissect(
        self,
        data: bytes,
        header: Map,
        preferences: Map,
        packet: Lent[Packet],
        conversation: Lent[Map],
    ) -> I64: ...

    def message_len(self, header: bytes) -> I64: ...
