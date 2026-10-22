"""The tap, filter function, file type and codec helpers: what they describe,
and how they answer what the host passes."""

from __future__ import annotations

import struct
from typing import Any, List, Optional, Union

import pytest
from guatiao import NotFound

from libwireshark import (
    CaptureFile,
    CaptureReader,
    Codec,
    Decoder,
    FileType,
    FilterFunction,
    FilterReturn,
    Record,
    Tap,
    TapListener,
    TapPacket,
)


class Tree:
    """A stand-in for a value the host lends: `to_python()` answers it."""

    def __init__(self, value: Any) -> None:
        self.value = value

    def to_python(self) -> Any:
        return self.value


class Frames(TapListener):
    def __init__(self) -> None:
        self.frames: List[int] = []

    def packet(self, packet: TapPacket) -> None:
        self.frames.append(packet.frame)

    def draw(self) -> str:
        return f"{len(self.frames)} frames"


class Counting(Tap):
    NAME = "counting"
    TAP = "frame"
    LISTENER = Frames


PACKET = {
    "frame": 3,
    "len": 60,
    "time_ns": 5,
    "source": "192.0.2.1",
    "destination": "192.0.2.2",
    "src_port": 61000,
    "dst_port": 113,
}


def test_a_tap_opens_a_fresh_listener_per_invocation() -> None:
    tap = Counting()
    assert tap.describe() == {"name": "counting", "tap": "frame"}
    first, second = tap.open(), tap.open()
    first.packet(Tree(PACKET))
    assert first.draw() == "1 frames" and second.draw() == "0 frames"
    first.reset()
    assert first.draw() == "0 frames", "reset starts the listener over"


class Double(FilterFunction):
    NAME = "double"

    def apply(self, value: Union[int, str]) -> Optional[int]:
        return value * 2 if isinstance(value, int) else None


def test_a_filter_function_answers_each_value() -> None:
    function = Double()
    assert function.describe() == {"name": "double", "returns": "count"}
    assert function.call(Tree(7)) == 14
    assert function.call(Tree("text")) is None
    assert function.call(Tree(None)) is None
    assert FilterReturn.TEXT.value == "text"


class Source:
    """A stand-in for the lent capture source, over `data`."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def read(self, buffer: bytearray) -> int:
        chunk = self.data[self.at : self.at + len(buffer)]
        buffer[: len(chunk)] = chunk
        self.at += len(chunk)
        return len(chunk)

    def position(self) -> int:
        return self.at


class Lengths(CaptureReader):
    """Records of a length byte and that many bytes."""

    def read(self, file: CaptureFile) -> Optional[Record]:
        length = file.read_exact(1)
        if length is None:
            return None
        return Record(file.read_exact(length[0]) or b"", time_ns=file.position)


class Format(FileType):
    NAME = "lengths"
    DESCRIPTION = "Length-prefixed records"
    EXTENSIONS = ["len"]

    def reader(self, file: CaptureFile) -> Optional[CaptureReader]:
        return Lengths() if file.read(3) == b"LEN" else None


def test_a_file_type_recognises_its_files_and_reads_records() -> None:
    format = Format()
    assert format.describe() == {
        "name": "lengths",
        "description": "Length-prefixed records",
        "extensions": ["len"],
    }
    with pytest.raises(NotFound):
        format.open(Source(b"PCAP"))
    with pytest.raises(NotFound):
        format.open(Source(b"LE"))
    source = Source(b"LEN\x02ab\x01c")
    reader = format.open(source)
    assert reader.encapsulation() == 1
    assert reader.read(source) == {"data": b"ab", "time_ns": 6}
    assert reader.read(source) == {"data": b"c", "time_ns": 8}
    assert reader.read(source) == {}, "the end"


class Unsigned8(Decoder):
    def sample_rate(self) -> int:
        return self.format.sample_rate or 8000

    def decode(self, payload: bytes) -> List[int]:
        return [(byte - 128) << 8 for byte in payload]


class L8(Codec):
    NAME = "L8"
    DECODER = Unsigned8


def test_a_codec_decodes_into_the_hosts_buffer() -> None:
    codec = L8()
    assert codec.describe() == {"name": "L8"}
    decoder = codec.open(Tree({"sample_rate": 16000}))
    assert decoder.sample_rate() == 16000 and decoder.channels() == 1
    assert decoder.decoded_len(b"\x80\xff") == 2
    samples = bytearray(6)
    assert decoder.decode(b"\x80\xff\x00\x40", samples) == 3, "as many as fit"
    assert list(struct.unpack("<3h", samples)) == [0, 127 << 8, -128 << 8]
    assert codec.open(Tree({})).sample_rate() == 8000


class Floating(FilterFunction):
    NAME = "floating"

    def apply(self, value: Union[int, str]) -> Optional[int]:
        return value / 2  # type: ignore[operator,return-value]


def test_a_filter_answer_of_the_wrong_type_is_refused() -> None:
    from guatiao import BadValue

    with pytest.raises(BadValue):
        Floating().call(Tree(7))


class Loud(Decoder):
    def decode(self, payload: bytes) -> List[int]:
        return [100_000, -100_000]


def test_a_decoder_clamps_samples_and_answers_nothing_when_it_fails() -> None:
    decoding = type("LoudCodec", (Codec,), {"NAME": "LOUD", "DECODER": Loud})().open(Tree({}))
    samples = bytearray(4)
    assert decoding.decode(b"ab", samples) == 2
    assert list(struct.unpack("<2h", samples)) == [32767, -32768]
    assert decoding.sample_rate() == 0, "the default raises: logged, answers 0"
