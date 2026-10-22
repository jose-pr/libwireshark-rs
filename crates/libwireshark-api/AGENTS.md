# `libwireshark-api` — API header

The guatiao kinds a Wireshark plugin written in any language implements,
and `libwireshark-guatiao` loads. Self-contained: a provider author reads
this, `include/libwireshark_api.h` (C) or `python/wireshark_kinds.py`
(Python), not the source. Source: <https://github.com/jose-pr/libwireshark-rs>.

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
    fn describe(&self) -> Result<Map, ProviderError>;              // a Description, as a map
    fn dissect(&self, data: &[u8], packet: &mut dyn Packet, conversation: &mut Map)
        -> Result<i64, ProviderError>;                              // bytes taken; 0 declines
    fn message_len(&self, header: &[u8]) -> i64 { -1 }             // appended slot
}

#[guatiao::kind(object, name = "wireshark_packet")]                 // lent by the host
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
| `wireshark_dissector` | 3883230505 |
| `wireshark_packet` | 2387250941 |

- `describe` is asked once, when the host loads the provider; its answer
  is registered with Wireshark for the process.
- `dissect` runs on Wireshark's dissection thread, once per packet (or per
  framed message) that reaches the protocol. `data` is the captured bytes.
  `conversation` is this protocol's state for the packet's conversation:
  empty the first time, kept as the call leaves it. Packets are dissected
  more than once: change state only when `packet.is_first_pass()`.
- Answer 0 to decline, adding nothing to `packet` first. An error, a panic
  or a negative answer declines too.
- Field and expert names are the abbreviations the description declared,
  with or without `<filter_name>.`. A field that does not fit (no tree,
  past the captured bytes, a value wider than the field) is an error the
  provider may ignore.
- `message_len` matters only with `tcp_header_len`: TCP is reassembled and
  `dissect` sees whole messages. Answer the length including the header;
  -1, or less than the header, marks the rest of the segment as not this
  protocol's.

## The description (`Description`)

```rust
pub struct Description {          // Clone, Debug, Default, PartialEq, ToValue, FromValue, Schema
    pub name: String, pub short_name: String, pub filter_name: String,
    pub fields: Vec<Field>,       // default []
    pub experts: Vec<Expert>,     // default []
    pub bindings: Vec<Binding>,   // default []
    pub tcp_header_len: Option<u32>,
}
pub struct Field { pub abbrev: String, pub name: String, pub kind: FieldType /* key "type" */,
    pub base: Option<Base>, pub bitmask: Option<u64>, pub blurb: Option<String>,
    pub values: Vec<NamedValue> /* default [] */ }
impl Field { pub fn new(abbrev, name, kind: FieldType) -> Self; }
pub struct NamedValue { pub value: u32, pub name: String }
pub struct Expert { pub abbrev: String, pub group: ExpertGroup, pub severity: Severity, pub summary: String }
pub enum FieldType { U8, U16, U24, U32, U64, I8, I16, I24, I32, I64, Bool, Bytes, String, Ipv4, Ipv6, Ether, None }
pub enum Base { Dec, Hex, Oct, DecHex, HexDec }
pub enum ExpertGroup { Checksum, Sequence, ResponseCode, RequestCode, Undecoded, Reassemble,
    Malformed, Debug, Protocol, Security, Comments, Decryption, Assumption, Deprecated }
pub enum Severity { Comment, Chat, Note, Warn, Error }
pub enum Binding { Table { table: String, value: u32 }, Heuristic { list: String }, Postdissector }
impl Description {
    pub fn to_map(&self) -> Result<Map, ProviderError>;
    pub fn from_map(map: &Map) -> Result<Self, ProviderError>; // GUATIAO_ERR_BAD_VALUE naming the key
}
```

The map, for a provider in another language: keys as the field names
(`kind` is `"type"`); enum values snake_case text (`"u8"`, `"dec_hex"`,
`"response_code"`, `"warn"`); a binding is a map tagged by `"on"`:
`{"on": "table", "table": "udp.port", "value": 113}`,
`{"on": "heuristic", "list": "udp"}`, `{"on": "postdissector"}`. An absent
optional key and `null` are the same.

## Gotchas

- A changed FLOOR_HASH breaks every provider built against the old one;
  new methods are appended with a default body.
- A provider is a `cdylib` whose only job is `guatiao::providers!(..)`;
  a provider type in a library crate needs a separate plugin crate.
