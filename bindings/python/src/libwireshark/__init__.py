"""Wireshark dissectors written in Python: a protocol's header, preferences
and expert findings as typed classes, served to Wireshark by the
libwireshark-guatiao host plugin through guatiao's Python bridge.

```python
from typing import Annotated, List

from guatiao import Map, provide
from libwireshark import Binding, Header, Meta, Preferences, ProtocolDissector, Table, TypedPacket, U8


class FooHeader(Header):
    version: Annotated[U8, Meta(name="Version")]
    "The protocol version"


class FooPreferences(Preferences):
    port: int = 113
    "UDP port FOO is decoded on"


class Foo(provide.Provider, ProtocolDissector):
    NAME = "Foo Protocol"
    SHORT_NAME = "FOO"
    FILTER_NAME = "foo"
    HEADER = FooHeader
    PREFERENCES = FooPreferences

    def dissect_on(self, preferences: FooPreferences) -> List[Binding]:
        return [Table.udp_port(preferences.port)]

    def dissect(self, data: bytes, header: FooHeader, preferences: FooPreferences,
                packet: TypedPacket, conversation: Map) -> int:
        packet.set_info(f"FOO version {header.version}")
        return len(data)
```
"""

from __future__ import annotations

from ._dissector import (
    I8,
    I16,
    I24,
    I32,
    I64,
    U8,
    U16,
    U24,
    U32,
    U64,
    Base,
    Binding,
    Bool,
    Ether,
    Expert,
    ExpertGroup,
    Field,
    FieldType,
    Header,
    Heuristic,
    IPv4,
    IPv6,
    Meta,
    NoHeader,
    NoPreferences,
    Postdissector,
    Preferences,
    ProtocolDissector,
    Severity,
    Table,
    TypedPacket,
)
from ._engine import Dissected, Encapsulation, Engine, Node
from .exceptions import DisplayFilterError, EngineError, WiresharkError
from .kinds import Dissector, Packet

__version__ = "0.0.0a0"

__all__ = [
    "Dissector",
    "Packet",
    "ProtocolDissector",
    "TypedPacket",
    "Header",
    "NoHeader",
    "Preferences",
    "NoPreferences",
    "Expert",
    "Field",
    "Meta",
    "FieldType",
    "Base",
    "ExpertGroup",
    "Severity",
    "Table",
    "Heuristic",
    "Postdissector",
    "Binding",
    "U8",
    "U16",
    "U24",
    "U32",
    "U64",
    "I8",
    "I16",
    "I24",
    "I32",
    "I64",
    "Bool",
    "IPv4",
    "IPv6",
    "Ether",
    "Engine",
    "Encapsulation",
    "Dissected",
    "Node",
    "WiresharkError",
    "EngineError",
    "DisplayFilterError",
]
