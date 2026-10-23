"""The guatiao kinds of a Wireshark dissector, as typed Protocol classes:
`libwireshark_api.h`'s tables, each method in the order its table declares
it, its shapes in the annotations, each `floor_hash` the `#define` beside
the table (the repository's tests compare them).

A dissector usually subclasses `libwireshark.ProtocolDissector`, which
implements `Dissector` from typed classes; the host lends a `Packet` to
`dissect`. `Tap`, `FilterFunction`, `FileType` and `Codec` are the other
plugin kinds; `libwireshark.Tap` and its siblings implement them from typed
classes. `Host` and `Session` go the other way: the libwireshark-guatiao
library provides them, and `libwireshark.Host` drives them.
"""

from __future__ import annotations

__all__ = [
    "Dissector",
    "Packet",
    "Tap",
    "TapListener",
    "FilterFunction",
    "FileType",
    "CaptureReader",
    "CaptureSource",
    "Codec",
    "Decoder",
    "Host",
    "Session",
]

from typing import Protocol

from guatiao import Map, Value
from guatiao.kinds import (
    I64,
    U64,
    KindProtocol,
    Lent,
    ListAnswer,
    MapAnswer,
    ValueAnswer,
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


class TapListener(
    KindProtocol,
    Protocol,
    kind="wireshark_tap_listener",
    floor_hash=1080358107,
    is_object=True,
):
    """`wireshark_tap_listener_vtable`: one `-z` invocation's state, owned by the host.

    `packet` gets each packet that reached the tap (the crate's `TapPacket`
    map), `draw` answers the report printed at the end, `reset` starts over.
    """

    @required
    @fallible
    def packet(self, packet: Map) -> None: ...

    @required
    @fallible
    def draw(self) -> str: ...

    @required
    @fallible
    def reset(self) -> None: ...


class Tap(KindProtocol, Protocol, kind="wireshark_tap", floor_hash=2408697858):
    """`wireshark_tap_vtable`: a tap listener, offered as `tshark -z <name>`.

    `describe` answers `{name, tap}`; `open` a `TapListener` per invocation.
    """

    @required
    @fallible
    def describe(self) -> MapAnswer: ...

    @required
    @fallible
    def open(self) -> TapListener: ...


class FilterFunction(KindProtocol, Protocol, kind="wireshark_filter_function", floor_hash=3420581637):
    """`wireshark_filter_function_vtable`: `name(field)` in a display filter.

    `describe` answers `{name, returns: "count" | "text"}`; `call` gets each
    value of the field (a number for an integer field, else its display
    text) and answers a number, text, or `None` for no answer.
    """

    @required
    @fallible
    def describe(self) -> MapAnswer: ...

    @required
    @fallible
    def call(self, value: Value) -> ValueAnswer: ...


class CaptureSource(
    KindProtocol,
    Protocol,
    kind="wireshark_capture_source",
    floor_hash=4254949812,
    is_object=True,
):
    """`wireshark_capture_source_vtable`: the file being read, lent for a call.

    `read` fills the buffer and answers the bytes read (0 at the end, -1 on
    an error); `position` is the offset in the file.
    """

    @required
    def read(self, buffer: bytearray) -> I64: ...

    @required
    def position(self) -> I64: ...


class CaptureReader(
    KindProtocol,
    Protocol,
    kind="wireshark_capture_reader",
    floor_hash=2879541183,
    is_object=True,
):
    """`wireshark_capture_reader_vtable`: an open file's reader, owned by the host.

    `encapsulation` is the records' link-layer type (`WTAP_ENCAP_*`); `read`
    answers the record at the file's position (`{data, time_ns?,
    original_len?}`), an empty map at the end.
    """

    @required
    def encapsulation(self) -> I64: ...

    @required
    @fallible
    def read(self, file: Lent[CaptureSource]) -> MapAnswer: ...


class FileType(KindProtocol, Protocol, kind="wireshark_file_type", floor_hash=633579420):
    """`wireshark_file_type_vtable`: a capture file format (Wireshark 4.6 on).

    `describe` answers `{name, description, extensions}`; `open` a
    `CaptureReader` for a file in the format, or raises `guatiao.NotFound`
    for another.
    """

    @required
    @fallible
    def describe(self) -> MapAnswer: ...

    @required
    @fallible
    def open(self, file: Lent[CaptureSource]) -> CaptureReader: ...


class Decoder(
    KindProtocol,
    Protocol,
    kind="wireshark_decoder",
    floor_hash=223420870,
    is_object=True,
):
    """`wireshark_decoder_vtable`: one stream's decoder, owned by the host.

    `decode` writes 16-bit signed little-endian samples into the buffer and
    answers how many it wrote.
    """

    @required
    def sample_rate(self) -> I64: ...

    @required
    def channels(self) -> I64: ...

    @required
    def decoded_len(self, payload: bytes) -> I64: ...

    @required
    def decode(self, payload: bytes, samples: bytearray) -> I64: ...


class Codec(KindProtocol, Protocol, kind="wireshark_codec", floor_hash=3823197131):
    """`wireshark_codec_vtable`: an RTP audio codec.

    `describe` answers `{name}` (the SDP encoding name); `open` a `Decoder`
    for a stream of format `{sample_rate?, channels?}`.
    """

    @required
    @fallible
    def describe(self) -> MapAnswer: ...

    @required
    @fallible
    def open(self, format: Map) -> Decoder: ...


class Session(
    KindProtocol,
    Protocol,
    kind="wireshark_session",
    floor_hash=1680421174,
    is_object=True,
):
    """`wireshark_session_vtable`: an open session, owned by whoever opened it.

    `dissect` answers one frame (the crate's `Dissected` map) of a
    `WTAP_ENCAP_*` link type captured `time_ns` after the Unix epoch;
    `open_file` opens a capture for `next`, keeping the frames that match
    the display filter (all when empty); `next` answers the next one, an
    empty map at the end.
    """

    @required
    @fallible
    def dissect(self, data: bytes, encapsulation: I64, time_ns: I64) -> MapAnswer: ...

    @required
    @fallible
    def open_file(self, path: str, display_filter: str) -> None: ...

    @required
    @fallible
    def next(self) -> MapAnswer: ...


class Host(KindProtocol, Protocol, kind="wireshark_host", floor_hash=2496675255):
    """`wireshark_host_vtable`: starts Wireshark in the calling process.

    `open` takes the crate's `HostConfig` map (`plugins`,
    `skip_installed_plugins`, `config_dir`, `preferences`) and answers the
    session; one may be open at a time.
    """

    @required
    @fallible
    def open(self, config: Map) -> Session: ...
