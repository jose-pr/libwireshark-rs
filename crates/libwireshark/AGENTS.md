# `libwireshark` — API header

Header-file-style reference for the `libwireshark` crate: every public item with
its signature, contract and gotchas, so the crate can be used without
reading its source. It ships inside the package and is self-contained.
Development documentation lives with the source at
<https://github.com/jose-pr/libwireshark-rs>.

| Feature | Adds | Default |
| --- | --- | --- |
| `derive` | `#[derive(Header)]`, `#[derive(Preferences)]` (from `libwireshark-derive`) | off |

MSRV 1.89, edition 2024. A default build depends on `libwireshark-sys` and
`libloading`.

The root re-exports everything below except the `prefs` module's contents
(the root has `prefs::Preferences` and `prefs::NoPreferences`). `sys` is
`libwireshark-sys`. `__private` is for `plugin!` and the derives only.

`unsafe` is confined to `src/packet.rs` and `src/plugin/`; a plugin written
with this crate needs none.

## A plugin

```rust
libwireshark::plugin!(DissectorA, DissectorB);
libwireshark::plugin!(dissectors = [DissectorA], taps = [TapA, TapB]);
libwireshark::plugin!(version = "1.2.0", dissectors = [DissectorA, DissectorB], taps = [TapA]);
```

Write it once, at the root of a `cdylib` crate. It defines `#[no_mangle]`
`plugin_version` (the crate's `CARGO_PKG_VERSION` unless given),
`plugin_want_major`, `plugin_want_minor`, `plugin_describe` (dissector, plus
tap listener when there are taps) and
`plugin_register`, and a static holding the plugin's registration state. A
plugin crate can be `#![forbid(unsafe_code)]`.

Install the built library under `<plugin dir>/<major>.<minor>/epan/`; the
personal plugin directory is `%APPDATA%\Wireshark\plugins` on Windows and
`~/.local/lib/wireshark/plugins` elsewhere. Wireshark loads only `*.dll` on
Windows and `*.so` elsewhere: on macOS rename Cargo's `.dylib` to `.so`, and
the version directory is `<major>-<minor>` there.

## Protocols (`Dissector`)

```rust
pub trait Dissector: 'static {
    type Preferences: Preferences;
    type Header: Header;
    const NAME: &'static str;        // tree label
    const SHORT_NAME: &'static str;  // Protocol column
    const FILTER_NAME: &'static str; // display filter; prefix of fields and preferences
    const EXPERTS: &'static [Expert] = &[];
    fn dissect_on(preferences: &Self::Preferences) -> Vec<Binding> { Vec::new() }
    fn tcp_framing() -> Option<TcpFraming> { None }
    fn dissect(preferences: &Self::Preferences, packet: &mut PacketView<'_>)
        -> Option<DissectResult<Self::Header>>;
}
```

- `dissect_on` runs at load and every time Wireshark applies preferences;
  bindings no longer returned are removed, new ones added. Read the
  preferences for a configurable port, or ignore them for a fixed one. The
  default attaches to nothing.
- A protocol whose `NAME`, `SHORT_NAME` or `FILTER_NAME` Wireshark already
  has (a protocol, or a preference module such as `stream`) is left out:
  Wireshark would abort the process on the duplicate.
- With `tcp_framing` returning `Some`, packets arriving over TCP are
  reassembled and split into whole messages (`tcp_dissect_pdus`); `dissect`
  then sees one message at a time, possibly several per frame.
- `dissect` returns `None` to decline the packet. On `Some(result)` the
  runtime sets the Protocol column to `SHORT_NAME`, adds the protocol's tree
  item over `result.size` bytes, adds `result.header` (see `Header::add_to`)
  and replaces the Info column with `result.info` if any. Items added to the
  `PacketView` during `dissect` go under the same item. Header insertion
  errors are ignored.
- A panic in `dissect` is caught; the packet is declined.
- When stored preferences fail to convert (`PreferenceError`), the last good
  snapshot is kept; at load, the defaults.

```rust
#[non_exhaustive]
pub struct DissectResult<H> { pub header: H, pub size: usize, pub info: Option<String> }
impl<H> DissectResult<H> {
    pub fn new(header: H, size: usize) -> Self;
    pub fn with_info(self, info: impl Into<String>) -> Self;
}

pub struct Binding; // Copy, Eq, Hash
impl Binding {
    pub const fn uint(table: &'static str, value: u32) -> Self; // "udp.port", "ethertype", ...
    pub const fn tcp_port(port: u16) -> Self;
    pub const fn udp_port(port: u16) -> Self;
    pub const fn heuristic(list: &'static str) -> Self;         // "udp", "tcp", ...
    pub const fn postdissector() -> Self;
}

pub struct TcpFraming; // Copy
impl TcpFraming {
    pub const fn new(header_len: usize, message_len: fn(&[u8]) -> Option<usize>) -> Self;
    pub const fn header_len(&self) -> usize;
    pub fn message_len(&self, header: &[u8]) -> Option<usize>;
}
```

- `heuristic(list)`: packets of that heuristic list no table claimed are
  offered to `dissect`; `None` passes them on. Registered as
  `<filter>_<list>`, enabled; users can turn it off in Enabled Protocols.
- `postdissector()`: every frame, after all other dissection, with the whole
  frame. The runtime leaves the Protocol column alone and appends the Info
  text. Wireshark gives plugins no way to remove a post-dissector, so
  dropping it from `dissect_on` turns it off rather than removing it.
- `TcpFraming::new(header_len, message_len)`: `message_len` gets the first
  `header_len` bytes of a message and returns its total length, header
  included; `None` stops dissection of the rest of the segment.

## Packets (`PacketView<'packet>`)

Exists only inside `dissect`; not `Send`/`Sync`; exposes no pointers.

```rust
fn captured_len(&self) -> usize;
fn reported_len(&self) -> usize;
fn bytes(&self) -> &'packet [u8];                 // all captured bytes
fn get_u8(&self, offset: usize) -> Option<u8>;    // None past the capture
fn get_{u16,u24,u32,u64,i16,i32,i64}_{be,le}(&self, offset: usize) -> Option<_>; // u24 -> u32
fn get_i8(&self, offset: usize) -> Option<i8>;
fn src_port(&self) -> u32; fn dst_port(&self) -> u32; fn frame_number(&self) -> u32; // 0 if unknown
fn set_info(&mut self, text: &str);               // replace the Info column
fn append_info(&mut self, text: &str);
fn has_tree(&self) -> bool;
fn is_first_pass(&self) -> bool;                  // false when Wireshark dissects the packet again
fn is_postdissector(&self) -> bool;
fn with_conversation<T: Default + Send + 'static, R>(&mut self, f: impl FnOnce(&mut T) -> R)
    -> Option<R>;                                 // per conversation, protocol and type
fn tap<T: Any + Send>(&mut self, value: T);     // to the tap named FILTER_NAME
fn add_expert(&mut self, name: &str) -> Result<(), PacketFieldError>;
fn add_expert_text(&mut self, name: &str, text: &str) -> Result<(), PacketFieldError>;
fn add_item(&mut self, field: &str, offset: usize, length: usize, encoding: Encoding)
    -> Result<(), PacketFieldError>;              // Wireshark decodes by the field's type
fn add_uint(&mut self, field: &str, offset: usize, value: u32) -> Result<(), PacketFieldError>;   // U8..U32
fn add_int(&mut self, field: &str, offset: usize, value: i32) -> Result<(), PacketFieldError>;    // I8..I32
fn add_uint64(&mut self, field: &str, offset: usize, value: u64) -> Result<(), PacketFieldError>; // U64
fn add_int64(&mut self, field: &str, offset: usize, value: i64) -> Result<(), PacketFieldError>;  // I64
fn add_header<H: Header>(&mut self, header: &H) -> Result<(), PacketFieldError>;
```

- `field` is a registered field's abbreviation, with or without the
  `<FILTER_NAME>.` prefix.
- Integer insertion takes the width from the field's registered type and
  covers that many bytes at `offset`; the range must be captured.
- Text after an interior NUL is dropped from column text.
- `Encoding`: `BIG_ENDIAN`, `LITTLE_ENDIAN`, `NA`, `ASCII`, `UTF_8`,
  `from_bits(u32)`, `bits()`, and `|`.
- `with_conversation`: the conversation is Wireshark's (addresses and
  ports). `T::default()` the first time; values are dropped when another
  capture is opened. The value is taken out while `f` runs. Update state on
  `is_first_pass()` only: Wireshark re-dissects packets.
- `add_expert(name)` reports a finding declared in `Dissector::EXPERTS`
  (`name` with or without the `<FILTER_NAME>.` prefix) on the protocol's
  item; `add_expert_text` replaces its summary.

## Taps

```rust
pub trait Tap: Default + Send + 'static {
    const NAME: &'static str;   // tshark -z NAME   or   -z NAME,FILTER
    const TAP: &'static str;    // "frame", "udp", "ip", ... or a FILTER_NAME of this plugin
    fn packet(&mut self, packet: &TapPacket<'_>);
    fn draw(&self) -> String;   // printed when the capture ends
    fn reset(&mut self) { *self = Self::default(); }
}

impl TapPacket<'_> {
    fn frame_number(&self) -> u32;
    fn len(&self) -> u32;                    // frame length on the wire
    fn is_empty(&self) -> bool;
    fn time(&self) -> core::time::Duration;  // since the Unix epoch
    fn src_port(&self) -> u32; fn dst_port(&self) -> u32;
    fn source(&self) -> String; fn destination(&self) -> String; // addresses as shown
    fn data<T: 'static>(&self) -> Option<&T>; // what PacketView::tap published
}
```

- Each `-z` invocation starts a listener with `T::default()`; an invalid
  filter or tap name is reported on stderr and the listener is not started.
- `data` is `Some` only on a tap named like a protocol of the same plugin,
  for values of type `T` that protocol published with `PacketView::tap` in
  the same frame.
- `draw` output goes to stdout after C's buffered stdout is flushed.

## Expert info

```rust
pub struct Expert; // Copy
impl Expert {
    pub const fn new(abbrev: &'static str, group: ExpertGroup, severity: Severity,
                     summary: &'static str) -> Self;
    // getters: abbrev, group, severity, summary
}
#[non_exhaustive] pub enum Severity { Comment, Chat, Note, Warning, Error }
#[non_exhaustive] pub enum ExpertGroup { Checksum, Sequence, ResponseCode, RequestCode,
    Undecoded, Reassemble, Malformed, Debug, Protocol, Security, Comments, Decryption,
    Assumption, Deprecated }
```

An expert's abbreviation is placed under the filter name like a field's, and
is a display filter (`foo.bad_length`).

## Fields (`Header`)

```rust
pub trait Header {
    fn fields() -> &'static [FieldInfo];
    fn add_to(&self, packet: &mut PacketView<'_>) -> Result<(), PacketFieldError>;
}
pub struct NoHeader; // no fields

pub struct FieldInfo; // Copy
impl FieldInfo {
    pub const fn new(name: &'static str, abbrev: &'static str, kind: FieldType) -> Self;
    pub const fn with_base(self, base: Base) -> Self;      // default Base::Dec
    pub const fn with_bitmask(self, bitmask: u64) -> Self;
    pub const fn with_blurb(self, blurb: &'static str) -> Self;
    pub const fn with_values(self, values: &'static [(u32, &'static str)]) -> Self; // integers <= 32 bits
    // getters: name, abbrev, kind, base, bitmask, blurb, values
}
#[non_exhaustive] pub enum FieldType { U8, U16, U24, U32, U64, I8, I16, I24, I32, I64,
    Bool, Bytes, String, Ipv4, Ipv6, Ether, None }  // FieldType::width() -> Option<usize>
#[non_exhaustive] pub enum Base { None, Dec, Hex, Oct, DecHex, HexDec }
```

An abbreviation not starting with `<FILTER_NAME>.` is registered under it:
`version` in protocol `foo` is `foo.version`.

`#[derive(Header)]` (feature `derive`) on a struct with named fields of
`u8 u16 u32 u64 i8 i16 i32 i64` (inserted with the struct's value), or
`bool` (one byte), `[u8; N]` (bytes; a MAC address with `kind = "ether"` on
`[u8; 6]`), `Ipv4Addr`, `Ipv6Addr` (inserted by Wireshark from the packet
bytes at the field's offset):

```rust
#[derive(Header)]
#[header(endian = "little")]        // optional; default "big"
struct H {
    #[header(abbrev = "foo.ver", name = "Version", blurb = "...", display = "hex",
             bitmask = 0xf0, offset = 0, endian = "big",
             values = KINDS)]  // every key optional; values: &[(u32, &str)]
    version: u8,
}
// generated besides the trait impl:
impl H { pub const SIZE: usize; pub fn decode(bytes: &[u8]) -> Option<Self>; }
```

`abbrev` defaults to the field name, `name` to the field name. `display` is
`dec` (default), `hex`, `oct`, `dec_hex` or `hex_dec`. `offset` is in bytes
and defaults to the end of the previous field; `SIZE` is the furthest end.
`decode` returns `None` when `bytes` is shorter than `SIZE`. `SIZE` and
`decode` have the struct's visibility.

## Preferences (`libwireshark::prefs`)

```rust
pub trait Preferences: Default + Send + Sync + 'static {
    fn declarations() -> Vec<Declaration>;
    fn from_values(values: &PreferenceMap) -> Result<Self, PreferenceError>; // missing key = default
}
pub struct NoPreferences;
pub type PreferenceMap = HashMap<&'static str, Value>;
#[non_exhaustive] pub enum Value { Bool(bool), Uint(u32), String(String) }
pub trait PreferenceValue: Sized {   // bool, u8, u16, u32, String
    fn to_value(&self) -> Value;
    fn from_value(value: &Value) -> Result<Self, PreferenceError>;
}
pub struct Declaration;
impl Declaration {
    pub fn new(name: &'static str, title: &'static str, description: &'static str, default: Value) -> Self;
    pub fn with_base(self, base: u32) -> Self; // 8, 10 (default) or 16
    // getters: name, title, description, default_value, base
}
```

A preference named `port` in protocol `foo` is `foo.port` (`tshark -o
foo.port:4242`). `#[derive(Preferences)]` (feature `derive`) reads each
field with `PreferenceValue`; the struct's `Default` gives the defaults.
`#[preference(name = "...", title = "...", description = "...", base = 16)]`,
every key optional: `name` defaults to the field name, `title` to `name`.

## Errors

```rust
#[non_exhaustive] pub enum PacketFieldError {
    NoTree,               // Wireshark did not ask for a tree for this packet
    UnknownField,
    UnsupportedFieldType, // the operation does not fit the field's type
    OutOfBounds,          // range outside the captured bytes
    ValueOutOfRange,      // value wider than the field
}
#[non_exhaustive] pub enum PreferenceError { WrongKind, OutOfRange }
```

Both implement `Display` and `core::error::Error`.

## Gotchas

- A plugin loads only in the Wireshark release line (major.minor)
  `libwireshark-sys` was built against; build once per line.
- Two protocols on the same table entry: the one attached last wins, and
  Wireshark's own plugins (`gryphon` on TCP 7000, for instance) attach after
  yours. `tshark -G decodes` shows who holds an entry.
- TCP and UDP offer a packet to the lower of its two ports first: a client
  port another protocol claims (SAP NI's 40000) wins over your server port.
- String preferences are allocated with GLib's `g_strdup` (Wireshark frees
  them); GLib is loaded at run time (`glib-2.0-0.dll`,
  `libglib-2.0.0.dylib`, `libglib-2.0.so.0`). If it cannot be loaded, string
  preferences are not registered.
- Registration state lives for the process; Wireshark never unloads plugins.
