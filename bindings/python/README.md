# libwireshark

[![Version](https://img.shields.io/pypi/v/libwireshark.svg)](https://pypi.org/project/libwireshark/)
[![Python versions](https://img.shields.io/pypi/pyversions/libwireshark.svg)](https://pypi.org/project/libwireshark/)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://github.com/jose-pr/libwireshark-rs/)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/libwireshark-rs/test.yaml)](https://github.com/jose-pr/libwireshark-rs/actions/workflows/test.yaml)

Wireshark dissectors written in Python, and Wireshark run from Python.
**A protocol's header, preferences
and expert findings are typed classes, and `dissect_on` and `dissect` are
the methods to write**, as with the Rust `libwireshark::Dissector`. The
[libwireshark-guatiao](https://github.com/jose-pr/libwireshark-rs/tree/master/crates/libwireshark-guatiao)
Wireshark plugin loads it through guatiao's Python bridge.

## Features

- `ProtocolDissector`: names as class attributes, `HEADER`, `PREFERENCES`,
  `EXPERTS`; `dissect_on(preferences)` answers bindings and
  `dissect(data, header, preferences, packet, conversation)` dissects.
- `Header`: annotated attributes laid out in order (`U8` .. `I64`, `Bool`,
  `IPv4`, `IPv6`, `Ether`, sized `bytes` and `str`); the plugin decodes it
  and adds its fields to the tree.
- `Preferences`: annotated attributes with defaults (`bool`, `int`, `str`),
  shown in Wireshark's preferences; the string under an attribute is its
  description.
- `Expert`: one subclass per finding, its docstring the summary;
  `packet.add_expert(UnknownVersion())`.
- `Tap` (with a `TapListener` class per invocation), `FilterFunction`,
  `FileType` (with a `CaptureReader`) and `Codec` (with a `Decoder`): the
  other kinds of plugin, as classes the same way.
- `libwireshark.kinds`: the guatiao kinds themselves, for a plugin written
  without the helpers.

## Installation

```console
pip install "libwireshark @ git+https://github.com/jose-pr/libwireshark-rs#subdirectory=bindings/python"
```

It brings guatiao's Python binding. A provider module also needs a
`*.guatiao-py.toml` manifest beside it, and the guatiao-py bridge library
in the directory the plugin scans.

## Quick start

```python
from typing import Annotated, List

from guatiao import Map, provide
from libwireshark import (
    U8, U16, Base, Binding, Expert, ExpertGroup, Header, Meta, Preferences,
    ProtocolDissector, Severity, Table, TypedPacket,
)


class FooHeader(Header):
    version: Annotated[U8, Meta(name="Version", values={7: "seven"})]
    "The protocol version"

    flags: Annotated[U8, Meta(base=Base.HEX)]
    length: U16


class FooPreferences(Preferences):
    port: Annotated[int, Meta(title="UDP port")] = 113
    "UDP port FOO is decoded on"


class UnknownVersion(Expert):
    "Unknown version"

    GROUP = ExpertGroup.MALFORMED
    SEVERITY = Severity.WARN


class Foo(provide.Provider, ProtocolDissector):
    NAME = "Foo Protocol"
    SHORT_NAME = "FOO"
    FILTER_NAME = "foo"
    HEADER = FooHeader
    PREFERENCES = FooPreferences
    EXPERTS = [UnknownVersion]

    def dissect_on(self, preferences: FooPreferences) -> List[Binding]:
        return [Table.udp_port(preferences.port)]

    def dissect(self, data: bytes, header: FooHeader, preferences: FooPreferences,
                packet: TypedPacket, conversation: Map) -> int:
        if header.version != 7:
            packet.add_expert(UnknownVersion())
        packet.set_info(f"FOO version {header.version}")
        return len(data)
```

## Running Wireshark from Python

`Host` runs Wireshark's dissection engine in your process, with the
plugins you give it: Wireshark plugins built for its release line (4.6 on),
the `libwireshark-guatiao` host and its providers among them.

```python
from libwireshark import Host

with Host(plugins=["basic_dissector.dll"], preferences={"foo.port": 111}) as wireshark:
    frame = wireshark.dissect(data)            # an Ethernet frame
    print(frame["foo.version"], frame.columns["Info"])
    for frame in wireshark.read("capture.pcapng", display_filter="foo"):
        print(frame.frame, [node.abbrev for node in frame.tree])
```

It needs the `libwireshark-guatiao` library (the same one Wireshark loads
as a plugin), built against the Wireshark it runs with and named by
`LIBWIRESHARK_HOST` (or `library=`), and
guatiao's native library (`GUATIAO_LIBRARY`). On Windows, Wireshark's
directory must be on `PATH`. Wireshark starts once per process.

## API overview

| Module | Purpose |
| --- | --- |
| `libwireshark` | `ProtocolDissector`, `Header`, `Preferences`, `Expert`, `Meta`, the field type aliases, bindings |
| `libwireshark` | `Tap`, `TapListener`, `TapPacket`, `FilterFunction`, `FilterReturn`, `FileType`, `CaptureFile`, `CaptureReader`, `Record`, `Codec`, `Decoder`, `StreamFormat`: the other plugin kinds |
| `libwireshark` | `Host`, `Encapsulation`, `Dissected`, `Node`: Wireshark hosted in Python |
| `libwireshark.exceptions` | `WiresharkError`, `HostError`, `DisplayFilterError` |
| `libwireshark.kinds` | the guatiao kinds, `Dissector` to `Decoder`, and `Host` and `Session` |

## Environment variables

| Variable | Effect |
| --- | --- |
| `LIBWIRESHARK_HOST` | the `libwireshark-guatiao` library's path, when `Host` gets no `library` |
| `GUATIAO_LIBRARY` | guatiao's native library, read by guatiao |

## Development

```console
dotagents pyvenv
.pyvenv/<tag>/Scripts/python -m pip install -e "bindings/python[dev]"
.pyvenv/<tag>/Scripts/python -m pytest bindings/python -q
```

### Releasing

Not published yet: it depends on a guatiao revision that is not released.

## License

GPL-2.0-or-later: see [LICENSE](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE).
