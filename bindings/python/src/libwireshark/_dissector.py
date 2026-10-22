"""Writing a dissector in Python as one writes a Rust `libwireshark::Dissector`:
the header and the preferences are typed classes, the protocol's names are
class attributes, and `dissect_on` and `dissect` are the methods to write.

```python
class FooHeader(Header):
    version: Annotated[U8, Meta(name="Version", values={7: "seven"})]
    "The protocol version"

    flags: Annotated[U8, Meta(base=Base.HEX)]
    length: U16


class FooPreferences(Preferences):
    port: Annotated[int, Meta(title="UDP port")] = 113
    "UDP port FOO is decoded on"


class Foo(provide.Provider, ProtocolDissector):
    NAME = "Foo Protocol"
    SHORT_NAME = "FOO"
    FILTER_NAME = "foo"
    HEADER = FooHeader
    PREFERENCES = FooPreferences

    def dissect_on(self, preferences: FooPreferences) -> Sequence[Binding]:
        return [Table.udp_port(preferences.port)]

    def dissect(self, data: bytes, header: FooHeader, preferences: FooPreferences,
                packet: Packet, conversation: Map) -> int:
        packet.set_info(f"FOO version {header.version}")
        return len(data)
```

A field's name is its abbreviation and, unless `Meta(name=...)` says
otherwise, its label; the string under it (an attribute docstring) is its
blurb, or a preference's description. The host decodes the header and adds
its fields to the tree; a packet too short for it is declined before
`dissect` sees it.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
import typing
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    ClassVar,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)

from .kinds import Dissector

__all__ = [
    "FieldType",
    "Base",
    "ExpertGroup",
    "Severity",
    "Meta",
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
    "Field",
    "Header",
    "NoHeader",
    "Preferences",
    "NoPreferences",
    "Expert",
    "TypedPacket",
    "Table",
    "Heuristic",
    "Postdissector",
    "Binding",
    "ProtocolDissector",
]


class FieldType(str, Enum):
    """What a field holds."""

    U8 = "u8"
    U16 = "u16"
    U24 = "u24"
    U32 = "u32"
    U64 = "u64"
    I8 = "i8"
    I16 = "i16"
    I24 = "i24"
    I32 = "i32"
    I64 = "i64"
    BOOL = "bool"
    BYTES = "bytes"
    STRING = "string"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    ETHER = "ether"
    NONE = "none"


class Base(str, Enum):
    """How an integer field is shown."""

    DEC = "dec"
    HEX = "hex"
    OCT = "oct"
    DEC_HEX = "dec_hex"
    HEX_DEC = "hex_dec"


class ExpertGroup(str, Enum):
    """What an expert finding is about."""

    CHECKSUM = "checksum"
    SEQUENCE = "sequence"
    RESPONSE_CODE = "response_code"
    REQUEST_CODE = "request_code"
    UNDECODED = "undecoded"
    REASSEMBLE = "reassemble"
    MALFORMED = "malformed"
    DEBUG = "debug"
    PROTOCOL = "protocol"
    SECURITY = "security"
    COMMENTS = "comments"
    DECRYPTION = "decryption"
    ASSUMPTION = "assumption"
    DEPRECATED = "deprecated"


class Severity(str, Enum):
    """How bad an expert finding is."""

    COMMENT = "comment"
    CHAT = "chat"
    NOTE = "note"
    WARN = "warn"
    ERROR = "error"


@dataclass(frozen=True)
class Meta:
    """What a field's type does not say. Header fields take `name`,
    `type`, `base`, `bitmask`, `values`, `offset`, `length` and
    `little_endian`; preferences take `title`."""

    name: Optional[str] = None
    type: Optional[FieldType] = None
    base: Optional[Base] = None
    bitmask: Optional[int] = None
    values: Optional[Mapping[int, str]] = None
    offset: Optional[int] = None
    length: Optional[int] = None
    little_endian: bool = False
    title: Optional[str] = None


U8 = typing.Annotated[int, FieldType.U8]
U16 = typing.Annotated[int, FieldType.U16]
U24 = typing.Annotated[int, FieldType.U24]
U32 = typing.Annotated[int, FieldType.U32]
U64 = typing.Annotated[int, FieldType.U64]
I8 = typing.Annotated[int, FieldType.I8]
I16 = typing.Annotated[int, FieldType.I16]
I24 = typing.Annotated[int, FieldType.I24]
I32 = typing.Annotated[int, FieldType.I32]
I64 = typing.Annotated[int, FieldType.I64]
#: One byte, or the bits of it a `Meta(bitmask=...)` names.
Bool = typing.Annotated[bool, FieldType.BOOL]
#: Four bytes, read as dotted text.
IPv4 = typing.Annotated[str, FieldType.IPV4]
#: Sixteen bytes, read as text.
IPv6 = typing.Annotated[str, FieldType.IPV6]
#: Six bytes.
Ether = typing.Annotated[bytes, FieldType.ETHER]


@dataclass(frozen=True)
class Field:
    """A registered field; `abbrev` is below the protocol's filter name."""

    abbrev: str
    name: str
    type: FieldType
    base: Optional[Base] = None
    bitmask: Optional[int] = None
    blurb: Optional[str] = None
    #: Names for an integer field's values (up to 32 bits).
    values: Mapping[int, str] = field(default_factory=dict)
    offset: Optional[int] = None
    length: Optional[int] = None
    little_endian: bool = False

    def to_map(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "abbrev": self.abbrev,
            "name": self.name,
            "type": self.type.value,
        }
        for key in ("bitmask", "blurb", "offset", "length"):
            if getattr(self, key) is not None:
                out[key] = getattr(self, key)
        if self.base is not None:
            out["base"] = self.base.value
        if self.values:
            out["values"] = [
                {"value": value, "name": name} for value, name in self.values.items()
            ]
        if self.little_endian:
            out["little_endian"] = True
        return out


def _attribute_docs(cls: type) -> Dict[str, str]:
    """The string under each annotated attribute of `cls`'s own body."""
    try:
        source = textwrap.dedent(inspect.getsource(cls))
    except (OSError, TypeError):
        return {}
    docs: Dict[str, str] = {}
    body = ast.parse(source).body[0]
    if not isinstance(body, ast.ClassDef):
        return docs
    statements = body.body
    for statement, following in zip(statements, statements[1:]):
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and isinstance(following, ast.Expr)
            and isinstance(following.value, ast.Constant)
            and isinstance(following.value.value, str)
        ):
            docs[statement.target.id] = inspect.cleandoc(following.value.value)
    return docs


def _declared(
    cls: type,
) -> List[Tuple[str, type, Optional[FieldType], Meta, Optional[str]]]:
    """`cls`'s own annotated attributes: name, base type, field type, meta, doc."""
    hints = typing.get_type_hints(cls, include_extras=True)
    docs: Dict[str, str] = {}
    for klass in reversed(cls.__mro__):
        if "__annotations__" in vars(klass):
            docs.update(_attribute_docs(klass))
    declared = []
    for name, hint in hints.items():
        if name.startswith("_") or typing.get_origin(hint) is ClassVar:
            continue
        base, extras = hint, ()
        if typing.get_origin(hint) is typing.Annotated:
            base, *extras = typing.get_args(hint)
        kind = next((e for e in extras if isinstance(e, FieldType)), None)
        meta = next((e for e in extras if isinstance(e, Meta)), Meta())
        declared.append((name, base, meta.type or kind, meta, docs.get(name)))
    return declared


class Header:
    """A fixed header: annotated attributes, laid out in order.

    `U8` .. `I64`, `Bool`, `IPv4`, `IPv6` and `Ether` carry their width;
    `bytes` and `str` need `Meta(length=...)`. Instances hold the decoded
    values as attributes.
    """

    __wireshark_fields__: ClassVar[List[Field]] = []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        fields = []
        for name, base, kind, meta, doc in _declared(cls):
            if kind is None:
                kind = {bytes: FieldType.BYTES, str: FieldType.STRING}.get(base)
            if kind is None:
                raise TypeError(
                    f"{cls.__name__}.{name}: say its width, as U8 .. I64, or Meta(type=...)"
                )
            if kind in (FieldType.BYTES, FieldType.STRING) and meta.length is None:
                raise TypeError(
                    f"{cls.__name__}.{name}: a {kind.value} field needs Meta(length=...)"
                )
            fields.append(
                Field(
                    abbrev=name,
                    name=meta.name or name,
                    type=kind,
                    base=meta.base,
                    bitmask=meta.bitmask,
                    blurb=doc,
                    values=dict(meta.values or {}),
                    offset=meta.offset,
                    length=meta.length,
                    little_endian=meta.little_endian,
                )
            )
        cls.__wireshark_fields__ = fields

    @classmethod
    def fields(cls) -> List[Field]:
        """The header's fields, in order."""
        return list(cls.__wireshark_fields__)

    @classmethod
    def from_map(cls, values: Mapping[str, Any]) -> Optional["Header"]:
        """The header the host decoded, or `None` when a field is missing:
        a packet too short for it."""
        header = cls.__new__(cls)
        for f in cls.__wireshark_fields__:
            if f.abbrev not in values:
                return None
            setattr(header, f.abbrev, values[f.abbrev])
        return header


class NoHeader(Header):
    """A protocol with no fixed header."""


class Preferences:
    """Protocol preferences: annotated attributes with defaults.

    `bool`, `int` (0 to 2**32-1) and `str` are preferences; the default is
    the attribute's value, the description the string under it, and the
    label `Meta(title=...)` or the name.
    """

    __wireshark_preferences__: ClassVar[List[Dict[str, Any]]] = []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        declared = []
        for name, base, _kind, meta, doc in _declared(cls):
            kind = {bool: "bool", int: "uint", str: "string"}.get(base)
            if kind is None:
                raise TypeError(
                    f"{cls.__name__}.{name}: a preference is a bool, an int or a str"
                )
            if not hasattr(cls, name):
                raise TypeError(f"{cls.__name__}.{name}: a preference needs a default")
            entry: Dict[str, Any] = {
                "name": name,
                "type": kind,
                "default": getattr(cls, name),
            }
            if meta.title is not None:
                entry["title"] = meta.title
            if doc is not None:
                entry["description"] = doc
            declared.append(entry)
        cls.__wireshark_preferences__ = declared

    @classmethod
    def declarations(cls) -> List[Dict[str, Any]]:
        """The preferences, as the description lists them."""
        return [dict(entry) for entry in cls.__wireshark_preferences__]

    @classmethod
    def from_map(cls, values: Mapping[str, Any]) -> "Preferences":
        """The preferences with Wireshark's current values; a missing one
        keeps its default."""
        preferences = cls.__new__(cls)
        for entry in cls.__wireshark_preferences__:
            name = entry["name"]
            setattr(
                preferences, name, values[name] if name in values else entry["default"]
            )
        return preferences


class NoPreferences(Preferences):
    """A protocol with no preferences."""


def _snake_case(name: str) -> str:
    out = []
    for i, c in enumerate(name):
        if (
            c.isupper()
            and i
            and (
                not name[i - 1].isupper()
                or (i + 1 < len(name) and name[i + 1].islower())
            )
        ):
            out.append("_")
        out.append(c.lower())
    return "".join(out)


class Expert:
    """An expert finding, one subclass per finding the protocol may report:

    ```python
    class UnknownVersion(Expert):
        "Unknown version"

        GROUP = ExpertGroup.MALFORMED
        SEVERITY = Severity.WARN

    packet.add_expert(UnknownVersion())          # its summary
    packet.add_expert(UnknownVersion("v9"))      # this text instead
    ```

    The docstring is the summary; `ABBREV` defaults to the class name in
    snake case (`unknown_version`). List the classes in the dissector's
    `EXPERTS`.
    """

    ABBREV: ClassVar[str]
    GROUP: ClassVar[ExpertGroup]
    SEVERITY: ClassVar[Severity]
    SUMMARY: ClassVar[str]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        own = vars(cls)
        if "ABBREV" not in own:
            cls.ABBREV = _snake_case(cls.__name__)
        if "SUMMARY" not in own:
            cls.SUMMARY = inspect.cleandoc(cls.__doc__ or cls.__name__).splitlines()[0]
        for attribute in ("GROUP", "SEVERITY"):
            if not hasattr(cls, attribute):
                raise TypeError(f"{cls.__name__}: an expert finding needs {attribute}")

    def __init__(self, text: str = "") -> None:
        #: What is reported instead of the summary, unless empty.
        self.text = text

    @classmethod
    def to_map(cls) -> Dict[str, Any]:
        return {
            "abbrev": cls.ABBREV,
            "group": ExpertGroup(cls.GROUP).value,
            "severity": Severity(cls.SEVERITY).value,
            "summary": cls.SUMMARY,
        }


@dataclass(frozen=True)
class Table:
    """Packets where the integer table `table` (such as "udp.port") has `value`."""

    table: str
    value: int

    @classmethod
    def udp_port(cls, port: int) -> "Table":
        return cls("udp.port", port)

    @classmethod
    def tcp_port(cls, port: int) -> "Table":
        return cls("tcp.port", port)

    def to_map(self) -> Dict[str, Any]:
        return {"on": "table", "table": self.table, "value": self.value}


@dataclass(frozen=True)
class Heuristic:
    """Packets of the heuristic list `list` (such as "udp") no table claimed."""

    list: str

    def to_map(self) -> Dict[str, Any]:
        return {"on": "heuristic", "list": self.list}


@dataclass(frozen=True)
class Postdissector:
    """Every frame, after all other dissection."""

    def to_map(self) -> Dict[str, Any]:
        return {"on": "postdissector"}


Binding = Union[Table, Heuristic, Postdissector]


class TypedPacket:
    """The lent `Packet`, taking an `Expert` where the kind takes a name:
    `packet.add_expert(UnknownVersion())`. Everything else is the
    packet's own."""

    def __init__(self, packet: Any) -> None:
        self._packet = packet

    def add_expert(
        self, expert: Union[Expert, Type[Expert], str], text: str = ""
    ) -> None:
        if isinstance(expert, Expert):
            self._packet.add_expert(expert.ABBREV, expert.text)
        elif isinstance(expert, type) and issubclass(expert, Expert):
            self._packet.add_expert(expert.ABBREV, text)
        else:
            self._packet.add_expert(expert, text)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._packet, name)


def _mapping(values: Any) -> Mapping[str, Any]:
    """A guatiao map as a plain mapping."""
    to_python = getattr(values, "to_python", None)
    return to_python() if callable(to_python) else values


class ProtocolDissector(Dissector):
    """A `Dissector` written as typed classes.

    Set `NAME` (the tree label), `SHORT_NAME` (the Protocol column) and
    `FILTER_NAME` (the display filter, prefix of fields, findings and
    preferences), and any of `HEADER`, `PREFERENCES`, `FIELDS` (fields
    `dissect` adds itself), `EXPERTS` and `TCP_HEADER_LEN`. Write
    `dissect_on(self, preferences)`, answering bindings, and
    `dissect(self, data, header, preferences, packet, conversation)`, which
    receive instances of `PREFERENCES` and `HEADER`; and `message_len` when
    `TCP_HEADER_LEN` is set.
    """

    NAME: ClassVar[str]
    SHORT_NAME: ClassVar[str]
    FILTER_NAME: ClassVar[str]
    HEADER: ClassVar[Type[Header]] = NoHeader
    PREFERENCES: ClassVar[Type[Preferences]] = NoPreferences
    FIELDS: ClassVar[Sequence[Field]] = ()
    EXPERTS: ClassVar[Sequence[Type[Expert]]] = ()
    TCP_HEADER_LEN: ClassVar[Optional[int]] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        own = vars(cls)
        if "dissect_on" in own and not hasattr(
            own["dissect_on"], "__wireshark_typed__"
        ):
            typed_dissect_on = own["dissect_on"]

            def dissect_on(
                self: ProtocolDissector, preferences: Any
            ) -> List[Dict[str, Any]]:
                typed = type(self).PREFERENCES.from_map(_mapping(preferences))
                return [binding.to_map() for binding in typed_dissect_on(self, typed)]

            dissect_on.__wireshark_typed__ = typed_dissect_on  # type: ignore[attr-defined]
            cls.dissect_on = dissect_on  # type: ignore[method-assign]
        if "dissect" in own and not hasattr(own["dissect"], "__wireshark_typed__"):
            typed_dissect = own["dissect"]

            def dissect(
                self: ProtocolDissector,
                data: bytes,
                header: Any,
                preferences: Any,
                packet: Any,
                conversation: Any,
            ) -> int:
                typed_header = type(self).HEADER.from_map(_mapping(header))
                if typed_header is None:
                    return 0
                typed_preferences = type(self).PREFERENCES.from_map(
                    _mapping(preferences)
                )
                return int(
                    typed_dissect(
                        self,
                        data,
                        typed_header,
                        typed_preferences,
                        TypedPacket(packet),
                        conversation,
                    )
                )

            dissect.__wireshark_typed__ = typed_dissect  # type: ignore[attr-defined]
            cls.dissect = dissect  # type: ignore[method-assign]

    def describe(self) -> Dict[str, Any]:
        cls = type(self)
        out: Dict[str, Any] = {
            "name": cls.NAME,
            "short_name": cls.SHORT_NAME,
            "filter_name": cls.FILTER_NAME,
            "header": [f.to_map() for f in cls.HEADER.fields()],
            "fields": [f.to_map() for f in cls.FIELDS],
            "experts": [e.to_map() for e in cls.EXPERTS],
            "preferences": cls.PREFERENCES.declarations(),
        }
        if cls.TCP_HEADER_LEN is not None:
            out["tcp_header_len"] = cls.TCP_HEADER_LEN
        return out

    def message_len(self, header: bytes) -> int:
        return -1
