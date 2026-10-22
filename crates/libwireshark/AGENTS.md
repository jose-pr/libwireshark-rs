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

`unsafe` is confined to `src/packet.rs` and `src/plugin.rs`; a plugin written
with this crate needs none.

## A plugin

```rust
libwireshark::plugin!(DissectorA, DissectorB);
libwireshark::plugin!(version = "1.2.0", dissectors = [DissectorA, DissectorB]);
```

Write it once, at the root of a `cdylib` crate. It defines `#[no_mangle]`
`plugin_version` (the crate's `CARGO_PKG_VERSION` unless given),
`plugin_want_major`, `plugin_want_minor`, `plugin_describe` (dissector) and
`plugin_register`, and a static holding the plugin's registration state. A
plugin crate can be `#![forbid(unsafe_code)]`.

Install the built library under `<plugin dir>/<major>.<minor>/epan/`; the
personal plugin directory is `%APPDATA%\Wireshark\plugins` on Windows and
`~/.local/lib/wireshark/plugins` elsewhere.

## Protocols (`Dissector`)

```rust
pub trait Dissector: 'static {
    type Preferences: Preferences;
    type Header: Header;
    const NAME: &'static str;        // tree label
    const SHORT_NAME: &'static str;  // Protocol column
    const FILTER_NAME: &'static str; // display filter; prefix of fields and preferences
    fn dissect_on(preferences: &Self::Preferences) -> Vec<Binding> { Vec::new() }
    fn dissect(preferences: &Self::Preferences, packet: &mut PacketView<'_>)
        -> Option<DissectResult<Self::Header>>;
}
```

- `dissect_on` runs at load and every time Wireshark applies preferences;
  entries no longer returned are removed, new ones added. Read the
  preferences for a configurable port, or ignore them for a fixed one. The
  default attaches to nothing.
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
    pub const fn table(&self) -> &'static str;
    pub const fn value(&self) -> u32;
}
```

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
    // getters: name, abbrev, kind, base, bitmask, blurb
}
#[non_exhaustive] pub enum FieldType { U8, U16, U24, U32, U64, I8, I16, I24, I32, I64,
    Bool, Bytes, String, Ipv4, Ipv6, Ether, None }  // FieldType::width() -> Option<usize>
#[non_exhaustive] pub enum Base { None, Dec, Hex, Oct, DecHex, HexDec }
```

An abbreviation not starting with `<FILTER_NAME>.` is registered under it:
`version` in protocol `foo` is `foo.version`.

`#[derive(Header)]` (feature `derive`) on a struct with named fields of
`u8 u16 u32 u64 i8 i16 i32 i64`:

```rust
#[derive(Header)]
#[header(endian = "little")]        // optional; default "big"
struct H {
    #[header(abbrev = "foo.ver", name = "Version", blurb = "...", display = "hex",
             bitmask = 0xf0, offset = 0, endian = "big")]  // every key optional
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
- Two protocols on the same table entry: the one attached last wins.
- String preferences are allocated with GLib's `g_strdup` (Wireshark frees
  them); GLib is loaded at run time (`glib-2.0-0.dll`,
  `libglib-2.0.0.dylib`, `libglib-2.0.so.0`). If it cannot be loaded, string
  preferences are not registered.
- Registration state lives for the process; Wireshark never unloads plugins.
