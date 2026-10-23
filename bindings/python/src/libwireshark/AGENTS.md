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
`libwireshark-bridge` plugin through guatiao's Python bridge
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

## Taps, filter functions, file types and codecs

Each is subclassed beside guatiao's `provide.Provider`, as
`ProtocolDissector` is, and listed in the module's manifest `kinds`.

```python
class Tap(kinds.Tap):                         # -z NAME[,filter]
    NAME: str; TAP: str                        # TAP: a protocol's filter name ("frame", "ip")
    LISTENER: type[TapListener]                # made with no arguments per invocation
class TapListener:
    def packet(self, packet: TapPacket) -> None
    def draw(self) -> str
    def reset(self) -> None                    # default: __init__ again
@dataclass(frozen=True)
class TapPacket: frame: int; len: int; time_ns: int; source: str; destination: str; src_port: int; dst_port: int

class FilterFunction(kinds.FilterFunction):   # NAME(field) in a display filter, 4.4 on
    NAME: str; RETURNS: FilterReturn = FilterReturn.COUNT    # or TEXT
    def apply(self, value: int | str) -> int | str | None    # int for integer fields, else display text

class FileType(kinds.FileType):               # 4.6 on
    NAME: str; DESCRIPTION: str; EXTENSIONS: Sequence[str] = ()
    def reader(self, file: CaptureFile) -> CaptureReader | None   # None: another format
class CaptureReader:
    ENCAPSULATION: int = Encapsulation.ETHERNET
    def read(self, file: CaptureFile) -> Record | None     # None at the end
class CaptureFile:                             # lent for the call
    def read(self, size: int) -> bytes                     # OSError when Wireshark cannot read
    def read_exact(self, size: int) -> bytes | None        # None at a clean end; EOFError inside
    position: int
@dataclass(frozen=True)
class Record: data: bytes; time_ns: int | None = None; original_len: int | None = None

class Codec(kinds.Codec):
    NAME: str                                  # the SDP encoding name
    DECODER: type[Decoder]                     # made with the stream's StreamFormat
class Decoder:
    format: StreamFormat                       # sample_rate, channels: int | None
    def sample_rate(self) -> int
    def channels(self) -> int                  # 1
    def decoded_len(self, payload: bytes) -> int           # len(payload)
    def decode(self, payload: bytes) -> Sequence[int]      # 16-bit signed samples
```

- An `EOFError` while `reader` reads counts as another format; any other
  exception is reported by the bridge and counts as another format too.
- `apply` answering the wrong type (a float, a negative or 33-bit int for
  `COUNT`) raises `guatiao.BadValue`: no answer for that value.
- Decoded samples past the host's buffer are dropped and the rest clamped
  to 16 bits; an exception in a `Decoder` method is logged
  (`logging`, the module's logger) and answers nothing.

## `Host`: Wireshark hosted in Python

```python
class Host:                        # a context manager; close() ends the session
    def __init__(self, plugins: Iterable[PathLike] = (), *,
                 preferences: Mapping[str, object] | None = None,   # as tshark -o; bool -> TRUE/FALSE
                 config_dir: PathLike | None = None,                # profile; default the user's
                 skip_installed_plugins: bool = False,
                 library: PathLike | None = None)                   # else LIBWIRESHARK_HOST
    def dissect(self, data: bytes, encapsulation: int = Encapsulation.ETHERNET,
                time: None | float | datetime = None) -> Dissected  # seconds since the epoch
    def read(self, path: PathLike, display_filter: str | None = None) -> Iterator[Dissected]
    def close(self) -> None

class Encapsulation(IntEnum): ETHERNET = 1; RAW_IP = 7       # WTAP_ENCAP_*; any int works

@dataclass(frozen=True)
class Dissected:
    frame: int                        # from 1 in the session, or in the file
    columns: dict[str, str]           # text by column title
    tree: tuple[Node, ...]
    def get(self, abbrev) -> Node | None;  def all(self, abbrev) -> Iterator[Node]
    def __getitem__(self, abbrev) -> str | None   # first node's value; KeyError if none
    def __contains__(self, abbrev) -> bool

@dataclass(frozen=True)
class Node:
    abbrev: str; name: str; label: str  # abbrev and name empty for a text item
    value: str | None                   # display text; None for protocols and text
    offset: int; length: int; hidden: bool; generated: bool; children: tuple[Node, ...]
```

- It loads the `libwireshark-bridge` library (the plugin itself, built
  for the running Wireshark's release line) through
  guatiao's registry, so guatiao's native library must be found
  (`GUATIAO_LIBRARY`, see guatiao's documentation) and, on Windows,
  Wireshark's directory must be on `PATH`.
- Wireshark starts once per process, at the first `Host`, as tshark
  starts: the listed plugins are registered before it (dissectors and file
  types, the `libwireshark-bridge` host among them), installed ones after
  unless skipped. A later `Host` must give the same settings; one may be
  open at a time (`HostError` names the open one). The library, once
  loaded, stays loaded.
- `read` opens the file when called (errors raise then) and dissects as
  it is iterated; it starts a fresh capture (numbers and conversations
  restart) and ends a read in progress. Calls are serialised per host.
- A plugin both listed and installed registers its protocols twice, which
  aborts the process: pass `skip_installed_plugins=True`.

## Exceptions (`libwireshark.exceptions`)

- `WiresharkError(Exception)`: the base.
- `HostError(WiresharkError)`: the library is missing or already
  loaded from elsewhere, Wireshark did not start, refused a plugin or a
  preference, a capture could not be read; the message is Wireshark's.
- `DisplayFilterError(HostError, ValueError)`: a display filter did not
  compile.
- `ValueError`: a call on a closed host, a time before the epoch.

## Environment variables

| Variable | Effect |
| --- | --- |
| `LIBWIRESHARK_HOST` | the `libwireshark-bridge` library's path, when `Host` gets no `library` |
| `GUATIAO_LIBRARY` | guatiao's native library (guatiao's own variable) |

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
  FLOOR_HASH 1003939949; `wireshark_packet`, 2387250941); `kinds.Host`,
  `kinds.Session` (`wireshark_host`, 2496675255; `wireshark_session`,
  1680421174), which `Host` drives.
