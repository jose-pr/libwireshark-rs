# Python

The `libwireshark` package does two things:

- **Dissectors and other plugins written in Python**, served to Wireshark
  by the `libwireshark-bridge` plugin through guatiao's Python bridge.
- **Wireshark hosted in a Python process** (`Host`): dissect frames and
  read captures with Wireshark and the plugins you load.

```console
pip install libwireshark
```

## A dissector

A protocol's names are class attributes, its header and preferences are
annotated classes (the string under an attribute is its description), and
an expert finding is a class whose docstring is its summary:

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

The module is listed in a `*.guatiao-py.toml` manifest naming the kinds it
serves, beside the guatiao-py bridge library, in a directory the guatiao
plugin scans; see [Plugins in other languages](other-languages.md).

## Taps, filter functions, formats and codecs

The other kinds are classes the same way: `Tap` with a `TapListener` per
invocation, `FilterFunction` with an `apply` method, `FileType` with a
`CaptureReader`, and `Codec` with a `Decoder` per stream.

```python
class FrameCount(TapListener):
    def __init__(self) -> None:
        self.frames = 0

    def packet(self, packet: TapPacket) -> None:
        self.frames += 1

    def draw(self) -> str:
        return f"pytap: {self.frames} frames\n"


class PyTap(provide.Provider, Tap):
    NAME = "pytap"
    TAP = "frame"
    LISTENER = FrameCount


class PyDouble(provide.Provider, FilterFunction):
    NAME = "py_double"

    def apply(self, value):
        return value * 2 if isinstance(value, int) else None
```

## Hosting Wireshark

```python
from libwireshark import Host

with Host(plugins=["basic_dissector.dll"], preferences={"foo.port": 111}) as wireshark:
    frame = wireshark.dissect(data)
    print(frame["foo.version"], frame.columns["Info"])
    for frame in wireshark.read("capture.pcapng", display_filter="foo"):
        print(frame.frame, [node.abbrev for node in frame.tree])
```

It needs the `libwireshark-bridge` library (the same one Wireshark loads
as a plugin), built for the Wireshark it runs with and named by
`LIBWIRESHARK_HOST`, and guatiao's native library (`GUATIAO_LIBRARY`). See
[Hosting Wireshark](hosting.md).

| Variable | Effect |
| --- | --- |
| `LIBWIRESHARK_HOST` | the `libwireshark-bridge` library's path, when `Host` gets no `library` |
| `GUATIAO_LIBRARY` | guatiao's native library |

The complete reference is [the Python API](api/python.md).
