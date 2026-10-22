"""`Engine` dissecting with the example plugins: a Rust dissector plugin, and
the guatiao host serving the Rust provider.

Runs when `LIBWIRESHARK_ENGINE` names the engine library built with its
`provider` feature, the example plugins built beside it, and guatiao's
native library is found (`GUATIAO_LIBRARY`). Wireshark starts once per
process, so every test shares one start.
"""

from __future__ import annotations

import os
import shutil
import struct
import sys
from pathlib import Path
from typing import Iterator, List

import pytest

from libwireshark import DisplayFilterError, Encapsulation, Engine, EngineError

LIBRARY = os.environ.get("LIBWIRESHARK_ENGINE", "")

pytestmark = pytest.mark.skipif(
    not Path(LIBRARY).is_file(), reason="LIBWIRESHARK_ENGINE names no built engine library"
)


def built(name: str) -> str:
    """A library built beside the engine's, by its crate name."""
    if sys.platform == "win32":
        file = f"{name}.dll"
    elif sys.platform == "darwin":
        file = f"lib{name}.dylib"
    else:
        file = f"lib{name}.so"
    path = Path(LIBRARY).parent / file
    if not path.is_file():
        pytest.skip(f"{file} is not built beside the engine")
    return str(path)


def udp(port: int, payload: bytes) -> bytes:
    """`payload` to UDP `port` from 192.0.2.1:61000, in IPv4 in Ethernet."""
    datagram = struct.pack(">HHHH", 61000, port, 8 + len(payload), 0) + payload
    ip = bytearray(
        struct.pack(
            ">BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(datagram),
            1,
            0,
            64,
            17,
            0,
            bytes([192, 0, 2, 1]),
            bytes([192, 0, 2, 2]),
        )
    )
    total = sum(struct.unpack(">10H", bytes(ip)))
    total = (total & 0xFFFF) + (total >> 16)
    ip[10:12] = struct.pack(">H", ~total & 0xFFFF)
    return bytes(12) + b"\x08\x00" + bytes(ip) + datagram


def pcap(frames: List[bytes]) -> bytes:
    file = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        file += struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)) + frame
    return file


# The RSFOO port moved off its default of 113 by a preference.
RSFOO_PORT = 116

FRAMES = [
    udp(111, bytes([7, 1, 2, 3])),
    udp(RSFOO_PORT, bytes([7, 1, 2, 3])),
    udp(111, bytes([9, 1, 0, 4])),
]


@pytest.fixture(scope="module")
def settings(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict]:
    root = tmp_path_factory.mktemp("engine")
    providers = root / "providers"
    providers.mkdir()
    shutil.copy(built("guatiao_rust_provider"), providers)
    os.environ["LIBWIRESHARK_GUATIAO_PATH"] = str(providers)
    (root / "capture.pcap").write_bytes(pcap(FRAMES))
    settings = {
        "plugins": [built("basic_dissector"), built("libwireshark_guatiao")],
        "preferences": {"rsfoo.port": RSFOO_PORT},
        "config_dir": root,
        "skip_installed_plugins": True,
    }
    try:
        Engine(**settings).close()
    except EngineError as error:
        if "4.6 or later" in str(error):
            pytest.skip("the engine is built for a release line before 4.6")
        raise
    yield settings


@pytest.fixture
def engine(settings: dict) -> Iterator[Engine]:
    with Engine(**settings) as engine:
        yield engine


def test_a_frame_dissects_into_fields_and_columns(engine: Engine) -> None:
    foo = engine.dissect(FRAMES[0], Encapsulation.ETHERNET, time=1_700_000_000)
    assert foo.frame == 1
    assert foo["foo.version"] == "7" and foo["foo.length"] == "515"
    assert foo["ip.dst"] == "192.0.2.2"
    assert foo.columns["Protocol"] == "FOO"
    assert foo.columns["Info"] == "FOO version 7, length 515"
    assert "foo" in foo and "rsfoo" not in foo
    protocol = foo.get("foo")
    assert protocol is not None and protocol.value is None
    assert [child.abbrev for child in protocol.children][:2] == ["foo.version", "foo.flags"]
    with pytest.raises(KeyError):
        foo["bar.version"]


def test_a_guatiao_provider_dissects_on_its_preference(engine: Engine) -> None:
    rsfoo = engine.dissect(FRAMES[1])
    assert rsfoo.columns["Protocol"] == "RSFOO"
    assert rsfoo["rsfoo.version"] == "7"


def test_a_capture_reads_through_a_display_filter(engine: Engine, settings: dict) -> None:
    capture = Path(settings["config_dir"]) / "capture.pcap"
    frames = list(engine.read(capture, display_filter="foo"))
    assert [(frame.frame, frame["foo.version"]) for frame in frames] == [(1, "7"), (3, "9")]
    assert len(list(engine.read(capture))) == len(FRAMES)


def test_refusals_raise(engine: Engine, settings: dict) -> None:
    with pytest.raises(DisplayFilterError):
        engine.read(Path(settings["config_dir"]) / "capture.pcap", display_filter="foo ==")
    with pytest.raises(EngineError):
        engine.read(Path(settings["config_dir"]) / "missing.pcap")
    with pytest.raises(EngineError, match="already open"):
        Engine(**settings)


def test_wireshark_starts_once_per_process(settings: dict) -> None:
    with pytest.raises(EngineError):
        Engine()
    with Engine(**settings) as engine:
        assert engine.dissect(FRAMES[0]).frame == 1
    with pytest.raises(ValueError, match="closed"):
        engine.dissect(FRAMES[0])
