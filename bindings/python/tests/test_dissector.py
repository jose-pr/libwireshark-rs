"""The typed helpers: what they describe, and how they read what the host passes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Dict, List

import pytest

from libwireshark import (
    U8,
    U16,
    Base,
    Binding,
    Bool,
    Expert,
    ExpertGroup,
    FieldType,
    Header,
    Meta,
    Preferences,
    ProtocolDissector,
    Severity,
    Table,
    TypedPacket,
)
from libwireshark.kinds import (
    CaptureReader,
    CaptureSource,
    Codec,
    Decoder,
    Dissector,
    Engine,
    FileType,
    FilterFunction,
    Packet,
    Session,
    Tap,
    TapListener,
)

HEADER_FILE = (
    Path(__file__).resolve().parents[3] / "crates" / "libwireshark-api" / "include" / "libwireshark_api.h"
)


class FooHeader(Header):
    version: Annotated[U8, Meta(name="Version", values={7: "seven"})]
    "The protocol version"

    flags: Annotated[U8, Meta(base=Base.HEX)]

    up: Annotated[Bool, Meta(offset=1, bitmask=0x01)]
    "Whether the link is up"

    length: Annotated[U16, Meta(little_endian=True)]


class FooPreferences(Preferences):
    port: Annotated[int, Meta(title="UDP port")] = 113
    "UDP port FOO is decoded on"

    verbose: bool = False

    label: str = "FOO"


class UnknownVersion(Expert):
    """Unknown version

    Any version but 7."""

    GROUP = ExpertGroup.MALFORMED
    SEVERITY = Severity.WARN


class Foo(ProtocolDissector):
    NAME = "Foo Protocol"
    SHORT_NAME = "FOO"
    FILTER_NAME = "foo"
    HEADER = FooHeader
    PREFERENCES = FooPreferences
    EXPERTS = [UnknownVersion]

    def dissect_on(self, preferences: FooPreferences) -> List[Binding]:  # type: ignore[override]
        return [Table.udp_port(preferences.port)]

    def dissect(  # type: ignore[override]
        self,
        data: bytes,
        header: FooHeader,
        preferences: FooPreferences,
        packet: TypedPacket,
        conversation: Any,
    ) -> int:
        if header.version != 7:
            packet.add_expert(UnknownVersion("version %d" % header.version))
        packet.set_info(f"{preferences.label} version {header.version}")
        return len(data)


class Recorder:
    """A stand-in for the lent packet: records what is called."""

    def __init__(self) -> None:
        self.calls: List[tuple] = []

    def add_expert(self, name: str, text: str) -> None:
        self.calls.append(("add_expert", name, text))

    def set_info(self, text: str) -> None:
        self.calls.append(("set_info", text))


def test_a_header_class_lays_out_its_annotated_fields() -> None:
    fields = [field.to_map() for field in FooHeader.fields()]
    assert [f["abbrev"] for f in fields] == ["version", "flags", "up", "length"]
    assert fields[0] == {
        "abbrev": "version",
        "name": "Version",
        "type": "u8",
        "blurb": "The protocol version",
        "values": [{"value": 7, "name": "seven"}],
    }
    assert fields[1]["base"] == "hex" and fields[1]["name"] == "flags"
    assert fields[2]["offset"] == 1 and fields[2]["bitmask"] == 1 and fields[2]["type"] == "bool"
    assert fields[3]["little_endian"] is True


def test_a_header_reads_what_the_host_decoded_or_nothing_when_short() -> None:
    header = FooHeader.from_map({"version": 7, "flags": 1, "up": True, "length": 4})
    assert header is not None and header.version == 7 and header.up is True
    assert FooHeader.from_map({"version": 7}) is None


def test_a_header_field_needs_a_width() -> None:
    with pytest.raises(TypeError, match="width"):

        class Bad(Header):
            count: int


def test_preferences_declare_their_kinds_defaults_and_docs() -> None:
    assert FooPreferences.declarations() == [
        {
            "name": "port",
            "type": "uint",
            "default": 113,
            "title": "UDP port",
            "description": "UDP port FOO is decoded on",
        },
        {"name": "verbose", "type": "bool", "default": False},
        {"name": "label", "type": "string", "default": "FOO"},
    ]
    prefs = FooPreferences.from_map({"port": 200})
    assert (prefs.port, prefs.verbose, prefs.label) == (200, False, "FOO")


def test_an_expert_class_is_named_from_its_class_and_docstring() -> None:
    assert UnknownVersion.to_map() == {
        "abbrev": "unknown_version",
        "group": "malformed",
        "severity": "warn",
        "summary": "Unknown version",
    }
    assert UnknownVersion("v9").text == "v9" and UnknownVersion().text == ""


def test_an_expert_class_needs_group_and_severity() -> None:
    with pytest.raises(TypeError, match="GROUP"):

        class Bad(Expert):
            """Bad"""

            SEVERITY = Severity.NOTE


def test_describe_answers_the_description_map() -> None:
    described: Dict[str, Any] = Foo().describe()
    assert described["name"] == "Foo Protocol" and described["filter_name"] == "foo"
    assert [f["abbrev"] for f in described["header"]] == [
        "version",
        "flags",
        "up",
        "length",
    ]
    assert described["experts"][0]["abbrev"] == "unknown_version"
    assert [p["name"] for p in described["preferences"]] == ["port", "verbose", "label"]
    assert "tcp_header_len" not in described


def test_dissect_on_and_dissect_receive_typed_instances() -> None:
    foo = Foo()
    assert foo.dissect_on({"port": 999}) == [{"on": "table", "table": "udp.port", "value": 999}]
    packet = Recorder()
    header = {"version": 9, "flags": 1, "up": True, "length": 4}
    assert foo.dissect(b"\x09\x01\x04\x00", header, {"label": "BAR"}, packet, {}) == 4
    assert packet.calls == [
        ("add_expert", "unknown_version", "version 9"),
        ("set_info", "BAR version 9"),
    ]


def test_a_packet_too_short_for_the_header_is_declined() -> None:
    packet = Recorder()
    assert Foo().dissect(b"\x07", {"version": 7}, {}, packet, {}) == 0
    assert packet.calls == []


def test_the_spellings_are_the_rust_encodings() -> None:
    assert FieldType.U24.value == "u24" and Base.DEC_HEX.value == "dec_hex"
    assert ExpertGroup.RESPONSE_CODE.value == "response_code" and Severity.WARN.value == "warn"


@pytest.mark.skipif(not HEADER_FILE.is_file(), reason="outside a checkout of the repository")
def test_the_kind_classes_carry_the_c_headers_hashes() -> None:
    header = HEADER_FILE.read_text(encoding="utf-8")
    for kind, table in (
        (Dissector, "wireshark_dissector_vtable"),
        (Packet, "wireshark_packet_vtable"),
        (Tap, "wireshark_tap_vtable"),
        (TapListener, "wireshark_tap_listener_vtable"),
        (FilterFunction, "wireshark_filter_function_vtable"),
        (FileType, "wireshark_file_type_vtable"),
        (CaptureReader, "wireshark_capture_reader_vtable"),
        (CaptureSource, "wireshark_capture_source_vtable"),
        (Codec, "wireshark_codec_vtable"),
        (Decoder, "wireshark_decoder_vtable"),
        (Engine, "wireshark_engine_vtable"),
        (Session, "wireshark_session_vtable"),
    ):
        hash_ = int(re.search(rf"#define {table}_FLOOR_HASH (\d+)", header).group(1))  # type: ignore[union-attr]
        assert kind.kind.floor_hash == hash_, table
