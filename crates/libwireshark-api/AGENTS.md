# `libwireshark-api` — API header

The guatiao kinds a Wireshark plugin written in any language implements,
and `libwireshark-guatiao` loads. Self-contained: a provider author reads
this, `include/libwireshark_api.h` (C) or the `libwireshark` Python
package (the repository's `bindings/python`), not the source. Source:
<https://github.com/jose-pr/libwireshark-rs>.

No default features; `c-header` regenerates the committed C header. MSRV
1.89. Depends on `guatiao` (feature `provider`), re-exported as
`libwireshark_api::guatiao`: name guatiao through that path
(`crate = ::libwireshark_api::guatiao` on the derives) so host and
provider share one copy. Not on crates.io yet: guatiao comes from a git
revision of its repository.

## Kinds

```rust
#[guatiao::kind(name = "wireshark_dissector")]
pub trait Dissector: Send + Sync {
    fn describe(&self) -> Result<Map, ProviderError>;                    // a Description
    fn dissect_on(&self, preferences: &Map) -> Result<List, ProviderError>; // Binding maps
    fn dissect(&self, data: &[u8], header: &Map, preferences: &Map,
               packet: &mut dyn Packet, conversation: &mut Map) -> Result<i64, ProviderError>;
    fn message_len(&self, header: &[u8]) -> i64 { -1 }                   // appended slot
}

#[guatiao::kind(object, name = "wireshark_packet")]                       // lent by the host
pub trait Packet: Send {
    fn add_item(&mut self, field: &str, offset: i64, length: i64, little_endian: bool) -> Result<(), ProviderError>;
    fn add_uint(&mut self, field: &str, offset: i64, value: u64) -> Result<(), ProviderError>;
    fn add_int(&mut self, field: &str, offset: i64, value: i64) -> Result<(), ProviderError>;
    fn set_info(&mut self, text: &str);
    fn append_info(&mut self, text: &str);
    fn add_expert(&mut self, name: &str, text: &str) -> Result<(), ProviderError>; // "" = summary
    fn is_first_pass(&self) -> bool;
    fn is_postdissector(&self) -> bool;
    fn frame_number(&self) -> i64;
    fn src_port(&self) -> i64;
    fn dst_port(&self) -> i64;
}
```

| Kind | FLOOR_HASH |
| --- | --- |
| `wireshark_dissector` | 1003939949 |
| `wireshark_packet` | 2387250941 |
| `wireshark_engine` | 2496675255 |
| `wireshark_session` | 1680421174 |

- `describe` is asked once, when the host loads the provider.
- `dissect_on` is asked when the protocol is handed off and whenever
  Wireshark applies preferences, with every preference's current value by
  name; bindings it no longer lists are removed.
- `dissect` runs on Wireshark's dissection thread for every packet (or
  framed message) that reaches the protocol. `header` holds the header
  fields `data` holds whole, decoded (integers as numbers, masked and
  shifted by their bitmask; `bool`; addresses as text; `bytes`/`ether` as
  bytes; `string` as text). `conversation` is this protocol's state for
  the packet's conversation, kept as the call leaves it; change it only
  when `packet.is_first_pass()`. Answer the bytes taken (more than `data`
  counts as all of it); 0, a negative answer, an error or a panic declines,
  and a declining dissector adds nothing first. On accepting, the host adds
  the header fields to the tree.
- `Packet`: names are a description's abbreviations, with or without
  `<filter_name>.`. With no tree (Wireshark did not ask for one) adding is
  a success that adds nothing; a field that does not fit (past the data, a
  value wider than the field, a length its type does not take) is an
  error. Calls from another thread than `dissect`'s are refused.
- `message_len` matters only with `tcp_header_len`: TCP is reassembled and
  `dissect` sees whole messages. Answer the length including the header;
  with -1, or less than the header, the rest of the segment is handed to
  `dissect` as one message.

### The other direction: Wireshark as a provider (`engine`)

```rust
#[guatiao::kind(name = "wireshark_engine")]
pub trait Engine: Send + Sync {
    fn open(&self, config: &Map) -> Result<Object<dyn Session>, ProviderError>; // EngineConfig
}
#[guatiao::kind(object, name = "wireshark_session")]                    // owned by the opener
pub trait Session: Send {
    fn dissect(&mut self, data: &[u8], encapsulation: i64, time_ns: i64) -> Result<Map, ProviderError>; // Dissected
    fn open_file(&mut self, path: &str, display_filter: &str) -> Result<(), ProviderError>;          // "" = all
    fn next(&mut self) -> Result<Map, ProviderError>;                    // Dissected; {} at the end
}
```

`libwireshark-engine` provides these; a host opens a session to dissect
with Wireshark itself. Models in `libwireshark_api::engine`:
`EngineConfig { plugins, skip_installed_plugins, config_dir, preferences }`,
`Dissected { frame, columns: [Column { title, text }], tree: [Node] }`,
`Node { abbrev, name, label, value?, offset, length, hidden, generated,
children }`, with `Dissected::{to_map, from_map, get, all}`.

## The description (`Description`)

```rust
pub struct Description {          // Clone, Debug, Default, PartialEq, ToValue, FromValue, Schema
    pub name: String, pub short_name: String, pub filter_name: String,
    pub header: Vec<Field>,       // default []: laid out in order, decoded and added by the host
    pub fields: Vec<Field>,       // default []: added by the dissector itself
    pub experts: Vec<Expert>,     // default []
    pub preferences: Vec<Preference>, // default []
    pub tcp_header_len: Option<u32>,
}
pub struct Field { pub abbrev: String, pub name: String, pub kind: FieldType /* key "type" */,
    pub base: Option<Base>, pub bitmask: Option<u64>, pub blurb: Option<String>,
    pub values: Vec<NamedValue> /* default [] */,
    pub offset: Option<u32>,      // header: default right after the previous field
    pub length: Option<u32>,      // header: bytes/string length
    pub little_endian: bool }     // header: default false
impl Field { fn new(abbrev, name, kind) -> Self; fn with_values(self, [(u32, &str)]) -> Self;
             fn with_base(self, Base) -> Self; fn width(&self) -> Option<u32>; }
pub struct NamedValue { pub value: u32, pub name: String }
pub struct Expert { pub abbrev: String, pub group: ExpertGroup, pub severity: Severity, pub summary: String }
pub struct Preference { pub name: String, pub title: Option<String>, pub description: Option<String>,
    pub kind: PreferenceType /* key "type" */, pub default: Value }
pub enum FieldType { U8, U16, U24, U32, U64, I8, I16, I24, I32, I64, Bool, Bytes, String, Ipv4, Ipv6, Ether, None }
pub enum Base { Dec, Hex, Oct, DecHex, HexDec }
pub enum ExpertGroup { Checksum, Sequence, ResponseCode, RequestCode, Undecoded, Reassemble,
    Malformed, Debug, Protocol, Security, Comments, Decryption, Assumption, Deprecated }
pub enum Severity { Comment, Chat, Note, Warn, Error }
pub enum PreferenceType { Bool, Uint, String }
pub enum Binding { Table { table: String, value: u32 }, Heuristic { list: String }, Postdissector }
impl Binding { fn udp_port(u16) -> Self; fn tcp_port(u16) -> Self;
               fn to_list(&[Self]) -> Result<List, ProviderError>; fn from_list(&List) -> Result<Vec<Self>, ProviderError>; }
impl Description { fn to_map(&self) -> Result<Map, ProviderError>; fn from_map(&Map) -> Result<Self, ProviderError>; }
```

The map, for a provider in another language: keys as the field names
(`kind` is `"type"`); enum values snake_case text (`"u8"`, `"dec_hex"`,
`"response_code"`, `"warn"`, `"uint"`); a binding is a map tagged by
`"on"`: `{"on": "table", "table": "udp.port", "value": 113}`,
`{"on": "heuristic", "list": "udp"}`, `{"on": "postdissector"}`. An absent
optional key and `null` are the same.

The host refuses (and reports) a description Wireshark would abort on: a
filter name not of a lower-case letter then `[a-z0-9_.-]`, a field or
finding abbreviation not of `[A-Za-z0-9_.-]` (no leading or trailing
`.`), a bitmask or base on a non-integer, a signed integer not shown in
decimal, a preference name not of `[a-z0-9_]`, a `tcp_header_len` of 0, a
header field with no width.

## Rust: `ProtocolDissector`

```rust
pub trait ProtocolDissector: Send + Sync + 'static {
    const NAME: &'static str; const SHORT_NAME: &'static str; const FILTER_NAME: &'static str;
    const TCP_HEADER_LEN: Option<u32> = None;
    type Header: Schema + FromValue;                              // NoHeader for none
    type Preferences: Schema + FromValue + ToValue + Default;     // NoPreferences for none
    fn header() -> Result<Vec<Field>, ProviderError> { header_fields::<Self::Header>() }
    fn fields() -> Vec<Field> { vec![] }
    fn experts() -> Vec<Expert> { vec![] }
    fn preferences() -> Result<Vec<Preference>, ProviderError> { preference_list::<Self::Preferences>() }
    fn description() -> Result<Description, ProviderError>;     // from the above
    fn dissect_on(&self, preferences: &Self::Preferences) -> Vec<Binding>;
    fn dissect(&self, data: &[u8], header: &Self::Header, preferences: &Self::Preferences,
               packet: &mut dyn Packet, conversation: &mut Map) -> Result<i64, ProviderError>;
    fn message_len(&self, header: &[u8]) -> i64 { -1 }
}
libwireshark_api::dissector!(Type);   // impl Dissector for Type from the above
pub trait ExpertInfo {                // a finding as a type
    const ABBREV: &'static str; const GROUP: ExpertGroup; const SEVERITY: Severity;
    const SUMMARY: &'static str;
    fn text(&self) -> &str { "" }     // reported instead of the summary unless empty
    fn expert() -> Expert;            // for ProtocolDissector::experts
}
pub trait PacketExt { fn report<E: ExpertInfo>(&mut self, finding: &E) -> Result<(), ProviderError>; }
// implemented for dyn Packet: packet.report(&UnknownVersion)?
pub fn header_fields<T: Schema>() -> Result<Vec<Field>, ProviderError>;
pub fn preference_list<T: Schema + ToValue + Default>() -> Result<Vec<Preference>, ProviderError>;
```

- `header_fields`: the struct's fields in order; the name is the
  abbreviation, `#[schema(title = "..")]` (else the name) the label, the
  doc comment the blurb. `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`,
  `i64` and `bool` are laid out by width; anything else is an error naming
  the field. Override `header()` to add names for values, a base, a
  bitmask, offsets or other types.
- `preference_list`: `bool`, unsigned integers up to 32 bits and `String`;
  defaults from `Default`, labels from titles, descriptions from doc
  comments.
- A header that does not read from the decoded map (a packet too short)
  declines the packet before `dissect` runs.

## Python (the `libwireshark` package, `bindings/python`)

```python
class Header:                        # annotated attributes, laid out in order
    @classmethod fields() -> list[Field]; @classmethod from_map(m) -> Header | None
class Preferences:                   # annotated attributes with defaults: bool, int, str
    @classmethod declarations() -> list[dict]; @classmethod from_map(m) -> Preferences
class ProtocolDissector(Dissector):  # subclass with provide.Provider
    NAME; SHORT_NAME; FILTER_NAME
    HEADER = NoHeader; PREFERENCES = NoPreferences
    FIELDS = (); EXPERTS = (); TCP_HEADER_LEN = None   # EXPERTS: Expert subclasses
    def dissect_on(self, preferences) -> Sequence[Binding]        # yours
    def dissect(self, data, header, preferences, packet, conversation) -> int  # yours
    def message_len(self, header: bytes) -> int                    # -1; override when framed
Meta(name=, type=, base=, bitmask=, values={int: str}, offset=, length=, little_endian=, title=)
U8 U16 U24 U32 U64 I8 I16 I24 I32 I64 Bool IPv4 IPv6 Ether   # Annotated aliases with a width
class Expert:                        # one subclass per finding
    GROUP: ExpertGroup; SEVERITY: Severity
    ABBREV = snake_case(class name); SUMMARY = docstring's first line   # defaults
    def __init__(self, text: str = "")  # reported instead of the summary unless empty
TypedPacket                          # what dissect gets: the packet, add_expert(UnknownVersion())
Field(...)
Table(table, value), Table.udp_port(p), Table.tcp_port(p), Heuristic(list), Postdissector()
FieldType, Base, ExpertGroup, Severity                         # str enums, spelled as the map
```

- The string under an attribute (an attribute docstring) is a header
  field's blurb or a preference's description; `Meta(name=...)` labels a
  header field, `Meta(title=...)` a preference. `bytes` and `str` header
  fields need `Meta(length=...)`.
- `ProtocolDissector` wraps the `dissect_on` and `dissect` a subclass
  writes, so they receive `PREFERENCES` and `HEADER` instances; a header
  that does not read (a short packet) declines before `dissect` runs.

## Gotchas

- A changed FLOOR_HASH breaks every provider built against the old one;
  new methods are appended with a default body.
- A provider is a `cdylib` whose only job is `guatiao::providers!(..)`;
  a provider type in a library crate needs a separate plugin crate.
