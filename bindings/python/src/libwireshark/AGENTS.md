# `libwireshark` — public API header

Header-file-style reference for the `libwireshark` package: every public
export with its signature, arguments, contract and gotchas, so the package
can be used without reading its source. It ships inside the package and is
self-contained. Development documentation lives with the source at
<https://github.com/jose-pr/libwireshark-rs>.

Import from `libwireshark`; `libwireshark.kinds` holds the guatiao kind
classes. Modules starting with `_` are private.

Install from the repository (`bindings/python`); it requires guatiao's
Python binding at the revision the plugin is built with. No extras.

A dissector written here is served to Wireshark by the
`libwireshark-guatiao` plugin through guatiao's Python bridge
(`guatiao_py`), which imports the module its `*.guatiao-py.toml` manifest
names. On Windows the directory holding `python3.dll` must be on Wireshark's
`PATH`.

## `ProtocolDissector`

```python
class ProtocolDissector(kinds.Dissector):   # subclass beside guatiao's provide.Provider
    NAME: str                  # tree label
    SHORT_NAME: str            # Protocol column
    FILTER_NAME: str           # display filter: [a-z][a-z0-9_.-]*
    HEADER: type[Header] = NoHeader
    PREFERENCES: type[Preferences] = NoPreferences
    FIELDS: Sequence[Field] = ()          # fields dissect adds itself
    EXPERTS: Sequence[type[Expert]] = ()
    TCP_HEADER_LEN: int | None = None     # framed over TCP: header length message_len reads

    def dissect_on(self, preferences) -> Sequence[Binding]        # yours
    def dissect(self, data: bytes, header, preferences,
                packet: TypedPacket, conversation: Map) -> int     # yours: bytes taken, 0 declines
    def message_len(self, header: bytes) -> int                    # -1 by default
    def describe(self) -> dict                                     # built from the attributes
```

- The class wraps the `dissect_on` and `dissect` a subclass defines: they
  receive a `PREFERENCES` instance with Wireshark's current values and a
  `HEADER` instance with what the plugin decoded. A packet too short for
  the header is declined before `dissect` runs.
- `dissect_on` runs when the protocol is handed off and whenever
  preferences are applied; bindings it no longer lists are removed.
- `conversation` is a guatiao map kept per conversation; change it only
  when `packet.is_first_pass()`.
- An exception declines the packet.

## `Header`

```python
class FooHeader(Header):
    version: Annotated[U8, Meta(name="Version", values={7: "seven"})]
    "The protocol version"                  # the blurb
    flags: Annotated[U8, Meta(base=Base.HEX)]
    up: Annotated[Bool, Meta(offset=1, bitmask=0x01)]
    payload: Annotated[bytes, Meta(length=4)]
```

- Fields in declaration order, each at `Meta(offset=)` or right after the
  previous one; the attribute name is the abbreviation, `Meta(name=)` (else
  the name) the label.
- Widths: `U8 U16 U24 U32 U64 I8 I16 I24 I32 I64`, `Bool` (1, masked by
  `bitmask`), `IPv4` (4, as text), `IPv6` (16, as text), `Ether` (6, bytes);
  `bytes` and `str` need `Meta(length=)`. Anything else is a `TypeError`
  when the class is defined.
- `Meta(little_endian=True)` for a little-endian integer; signed integers
  are shown in decimal only.
- `fields() -> list[Field]`; `from_map(map) -> Header | None`.

## `Preferences`

```python
class FooPreferences(Preferences):
    port: Annotated[int, Meta(title="UDP port")] = 113
    "UDP port FOO is decoded on"            # the description
```

- `bool`, `int` (0 to 2**32-1) and `str`, each with a default; the name is
  the key (`-o <filter_name>.<name>:<value>`), lower-case letters, digits and
  `_`. `declarations() -> list[dict]`; `from_map(map) -> Preferences`.

## `Expert`

```python
class UnknownVersion(Expert):
    "Unknown version"                       # the summary: the docstring's first line
    GROUP = ExpertGroup.MALFORMED
    SEVERITY = Severity.WARN
    # ABBREV = "unknown_version"            # default: the class name in snake case

packet.add_expert(UnknownVersion())         # the summary
packet.add_expert(UnknownVersion("v9"))     # this text
```

`GROUP` and `SEVERITY` are required (`TypeError` when the class is defined).

## Other exports

- `TypedPacket`: what `dissect` gets: the lent `kinds.Packet`, its
  `add_expert` taking an `Expert` instance or class as well as a name.
- `Meta(name, type, base, bitmask, values, offset, length, little_endian, title)`.
- `Field(abbrev, name, type, base=None, bitmask=None, blurb=None, values={}, offset=None, length=None, little_endian=False)`.
- `Table(table, value)`, `Table.udp_port(port)`, `Table.tcp_port(port)`,
  `Heuristic(list)`, `Postdissector()`; `Binding` is their union.
- `FieldType`, `Base`, `ExpertGroup`, `Severity`: `str` enums spelled as
  the description map spells them.
- `kinds.Dissector`, `kinds.Packet`: the kinds (`wireshark_dissector`,
  FLOOR_HASH 1003939949; `wireshark_packet`, 2387250941).
