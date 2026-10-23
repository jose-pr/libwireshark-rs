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

`unsafe` is confined to `src/packet.rs`, `src/tap.rs`, `src/filter.rs`,
`src/file_type.rs` and `src/plugin/`; a plugin written with this crate needs
none.

## A plugin

```rust
libwireshark::plugin!(DissectorA, DissectorB);
libwireshark::plugin!(dissectors = [DissectorA], taps = [TapA, TapB]);
libwireshark::plugin!(version = "1.2.0", dissectors = [DissectorA, DissectorB], taps = [TapA]);
libwireshark::plugin!(dissectors = [DissectorA], taps = [TapA], filters = [FunctionA]);
libwireshark::plugin!(file_types = [FormatA], dissectors = [DissectorA]);
libwireshark::plugin!(codecs = [CodecA]);
libwireshark::plugin!(dynamic = protocols, dissectors = [DissectorA]); // fn protocols() -> Vec<Protocol>
libwireshark::plugin!(dynamic = registrations);                // fn registrations() -> Registrations
```

Keys: `version` (a `&str` expression), `dissectors`, `taps`, `filters`,
`file_types`, `codecs`, `dynamic` (a function name in scope, or a
parenthesised path); any order, each optional. `plugin!(A, B)` is
`plugin!(dissectors = [A, B])`. An unknown key is a compile error, and so is
`codecs` beside any other list or `dynamic`.

Write it once, at the root of a `cdylib` crate. It defines `#[no_mangle]`
`plugin_version` (the crate's `CARGO_PKG_VERSION` unless given),
`plugin_want_major`, `plugin_want_minor`, `plugin_describe` and
`plugin_register`, and a static holding the plugin's registration state.
`plugin_describe` reports each kind the plugin has: dissector, file type,
codec, tap listener, display-filter function. A plugin crate can be
`#![forbid(unsafe_code)]`.

Install the built library under `<plugin dir>/<major>.<minor>/<kind>/`; the
personal plugin directory is `%APPDATA%\Wireshark\plugins` on Windows and
`~/.local/lib/wireshark/plugins` elsewhere. Wireshark loads only `*.dll` on
Windows and `*.so` elsewhere: on macOS rename Cargo's `.dylib` to `.so`, and
the version directory is `<major>-<minor>` there. `<kind>`:

| The library has | `<kind>` | Why |
| --- | --- | --- |
| dissectors, taps, filter functions | `epan` | |
| file types (and anything but codecs) | `wiretap` | loaded before protocols register, so the rest still registers |
| codecs, alone | `codecs` | loaded after protocols register |

A library is loaded once per directory it is in: never install the same one
in two.

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
    pub const fn encapsulation(encapsulation: Encapsulation) -> Self; // "wtap_encap" table
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
- `encapsulation(e)`: every frame of a capture whose link-layer type is `e`
  (such as `Encapsulation::user(0)` for a file type's private link layer),
  from its first byte.
- `postdissector()`: every frame, after all other dissection, with the whole
  frame. The runtime leaves the Protocol column alone and appends the Info
  text. Wireshark gives plugins no way to remove a post-dissector, so
  dropping it from `dissect_on` turns it off rather than removing it.
- `TcpFraming::new(header_len, message_len)`: `message_len` gets the first
  `header_len` bytes of a message and returns its total length, header
  included; with `None`, or less than the header, the rest of the segment
  is handed to `dissect` as one message, which may decline it.
- A `uint` binding to a table that does not exist, or is not keyed by
  integers, binds nothing (reported on stderr); Wireshark would abort on
  the second. A protocol whose names Wireshark already has is left out,
  also reported on stderr.

## Registered at run time (`libwireshark::dynamic`)

```rust
#[non_exhaustive] pub struct ProtocolSpec {
    pub name: &'static str, pub short_name: &'static str, pub filter_name: &'static str,
    pub fields: Vec<FieldInfo>, pub experts: Vec<Expert>, pub preferences: Vec<Declaration>,
}
impl ProtocolSpec {
    pub fn new(name: &'static str, short_name: &'static str, filter_name: &'static str) -> Self;
    pub fn with_fields(self, Vec<FieldInfo>) -> Self;
    pub fn with_experts(self, Vec<Expert>) -> Self;
    pub fn with_preferences(self, Vec<Declaration>) -> Self;
}
pub trait DynamicDissector: Send + Sync + 'static {
    type Preferences: Send + Sync + 'static;
    fn preferences(&self, values: &PreferenceMap) -> Option<Self::Preferences>; // None keeps the last
    fn dissect_on(&self, preferences: &Self::Preferences) -> Vec<Binding>;
    fn tcp_header_len(&self) -> Option<usize> { None }       // Some: framed over TCP
    fn message_len(&self, header: &[u8]) -> Option<usize> { None } // whole length, header included
    fn dissect(&self, preferences: &Self::Preferences, packet: &mut PacketView<'_>) -> Option<usize>;
}
impl Protocol { pub fn dynamic(spec: ProtocolSpec, dissector: impl DynamicDissector) -> Self; }

#[derive(Default)] #[non_exhaustive] pub struct Registrations {   // From<Vec<Protocol>>
    pub protocols: Vec<Protocol>, pub taps: Vec<Tap>, pub filters: Vec<FilterFunction>,
    pub file_types: Vec<FileType>, pub codecs: Vec<Codec>,
}
pub trait DynamicTap: Send + 'static {
    fn packet(&mut self, packet: &TapPacket<'_>); fn draw(&self) -> String; fn reset(&mut self);
}
impl Tap { pub fn new(name: &'static str, tap: &'static str,
                      new: impl Fn() -> Box<dyn DynamicTap> + Send + Sync + 'static) -> Self; }
pub enum FilterReturn { Count, Text }
pub enum FilterValue { Count(u32), Text(String) }      // of another kind than declared: no answer
pub trait DynamicFilterFunction: Send + Sync + 'static {
    fn call(&self, value: &FieldValue<'_>) -> Option<FilterValue>;
}
impl FilterFunction { pub fn new(name: &'static str, returns: FilterReturn,
                                 function: impl DynamicFilterFunction) -> Self; }
pub trait DynamicFileType: Send + Sync + 'static {
    fn open(&self, file: &mut CaptureFile<'_>) -> io::Result<Option<Box<dyn DynamicReader>>>;
}
pub trait DynamicReader: 'static {
    fn encapsulation(&self) -> Encapsulation;
    fn read(&mut self, file: &mut CaptureFile<'_>, record: &mut Record<'_>) -> io::Result<bool>;
}
impl FileType { pub fn new(name: &'static str, description: &'static str,
                           extensions: &'static [&'static str], format: impl DynamicFileType) -> Self; }
pub trait DynamicCodec: Send + 'static {
    fn sample_rate(&self) -> u32; fn channels(&self) -> u32 { 1 }
    fn decoded_len(&self, payload: &[u8]) -> usize;
    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize;
}
impl Codec { pub fn new(name: &'static str,
                        new: impl Fn(&StreamFormat) -> Box<dyn DynamicCodec> + Send + Sync + 'static) -> Self; }
```

- Each behaves as its static counterpart (`Tap`, `FilterFunction` 4.4 on,
  `FileType` 4.6 on, `Codec`), with the same name checks.
- Display-filter functions, file formats and codecs reach Wireshark through
  callbacks with no data pointer, so each plugin holds 32 of each kind
  registered at run time; more are skipped and reported on stderr.
- From any plugin directory of a program that dissects: file formats
  wiretap did not register when it started are registered with the plugin's
  protocols, and codecs register when the program starts its codecs
  (sharkd and Wireshark do, after `epan_init`; tshark only for `-G`). The
  tools that only read files (editcap, mergecap, capinfos) load
  `wiretap/` alone: a format they should read belongs there.

- For a plugin that learns its protocols when it loads. `plugin!(dynamic =
  f)` calls `f` once, in `plugin_register`; its protocols are registered
  beside the static ones, with the same name checks.
- `dissect` adds its own fields and Info text through `packet`; on
  accepting, the runtime sizes the tree item and sets the Protocol column,
  except for a post-dissector, which appends to the Info column itself
  (`is_postdissector`). A declining dissector (`None`) adds nothing first.
- Framing is `tcp_header_len` and `message_len` together, as `TcpFraming`.
- Preferences are as a `Dissector`'s: declared in the spec, read from
  Wireshark's values by `preferences` each time they are applied, then
  `dissect_on` runs again.
- Wireshark keeps what is registered for the process: owned text becomes
  `&'static str` with `String::leak`. No preferences yet.

## Hosting Wireshark (`libwireshark::host`, feature `host`)

For a program, never a plugin: Wireshark's dissection engine (EPAN with
wiretap) in the calling process, on every release line (3.0 to 4.6; the
build script's `wireshark_M_m` flags select each line's calls).

```rust
pub struct HostConfig {                    // Clone, Default, PartialEq
    pub plugins: Vec<PathBuf>,             // plugin libraries for this release line
    pub skip_installed_plugins: bool,
    pub config_dir: Option<PathBuf>,       // a profile; default the user's
    pub preferences: BTreeMap<String, String>, // as tshark -o name:value
}
pub struct Host;                           // Send, !Sync; drop ends the session
impl Host {
    pub fn open(config: &HostConfig) -> Result<Host, HostError>;
    pub fn dissect(&mut self, data: &[u8], encapsulation: Encapsulation, time: Duration)
        -> Result<Dissected, HostError>;     // time: since the Unix epoch
    pub fn read(&mut self, path: &Path, display_filter: Option<&str>) -> Result<Capture<'_>, HostError>;
    pub fn open_file(&mut self, path: &Path, display_filter: Option<&str>) -> Result<(), HostError>;
    pub fn next_frame(&mut self) -> Result<Option<Dissected>, HostError>; // read without the borrow
}
pub struct Capture<'a>;                    // Iterator<Item = Result<Dissected, HostError>>; an error ends it
pub struct Dissected { pub frame: u32, pub columns: Vec<Column>, pub tree: Vec<Node> }
impl Dissected { fn get(&self, abbrev) -> Option<&Node>; fn all(..) -> impl Iterator; fn column(&self, title) -> Option<&str> }
pub struct Column { pub title: String, pub text: String }
pub struct Node { abbrev, name, label, value: Option<String>, offset: i64, length: i64,
                  hidden: bool, generated: bool, children: Vec<Node> } // text items: empty abbrev/name
#[non_exhaustive] pub enum HostError {
    AlreadyOpen, Configured, Symbols(String), Init(String),
    Plugin { path, reason }, Preference { preference, reason }, Filter(String), File(String),
}
```

- Wireshark starts once per process, at the first `open`, as tshark does:
  logging, configuration, the listed plugins' `plugin_register` (their
  `plugin_want_major/minor` must match), wiretap, EPAN (installed plugins
  unless skipped), the profile's preferences, then `preferences`. A failed
  start is final for the process.
- A later `open` must give an equal `HostConfig` (`Configured`); one session
  at a time (`AlreadyOpen`, also inside Wireshark itself, where EPAN runs).
- `dissect` frames share conversations and count from 1; `read` starts a
  fresh capture, keeps what the display filter passes, numbered as in the
  file.
- libwiretap, libwsutil and GLib functions are resolved from the libraries
  libwireshark loaded. On Windows, Wireshark's data and plugin directories
  are set (`WIRESHARK_DATA_DIR`, `WIRESHARK_PLUGIN_DIR`, when unset) to
  libwireshark's directory, which must be on `PATH`. Wireshark's reports go
  to stderr as `libwireshark-host: ...`.
- A plugin both listed and installed registers twice and aborts the
  process: `skip_installed_plugins`.
- The module keeps process statics (the start, the open session): the
  recorded exception to this crate's no-statics rule.

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

## Display-filter functions

```rust
pub trait FilterFunction: 'static {
    const NAME: &'static str;   // used in filters as NAME(field)
    type Output: FilterOutput;  // u32 or String (sealed)
    fn call(value: &FieldValue<'_>) -> Option<Self::Output>;
}

impl<'a> FieldValue<'a> {
    fn as_u64(&self) -> Option<u64>;  // unsigned integer fields
    fn as_i64(&self) -> Option<i64>;  // signed integer fields
    fn as_str(&self) -> Option<&'a str>; // text fields, UTF-8 only
    fn to_text(&self) -> String;      // any field, as Wireshark displays it
}
```

- Wireshark 4.4 on. A plugin built for an older line still loads; its
  functions are not registered, and a filter naming one is rejected.
- A function takes exactly one argument, which must be a field (Wireshark's
  own check, from `count` for `u32` and `string` for `String`; a literal is
  rejected with "Only fields can be used as parameter").
- `call` runs once per occurrence of the field in the packet; `None` adds no
  result. The filter matches when any result compares as written:
  `port_class(udp.dstport) == "well-known"`.
- A panic in `call` is caught, and the call then reports no results.

## File types

```rust
pub trait FileType: Sized + 'static {
    const NAME: &'static str;         // short name: tshark -X read_format:NAME
    const DESCRIPTION: &'static str;  // in Wireshark's file type lists
    const EXTENSIONS: &'static [&'static str] = &[]; // without the dot; first is the default
    fn open(file: &mut CaptureFile<'_>) -> io::Result<Option<Self>>;
    fn encapsulation(&self) -> Encapsulation;
    fn read(&self, file: &mut CaptureFile<'_>, record: &mut Record<'_>) -> io::Result<bool>;
}

impl io::Read for CaptureFile<'_> {}
impl CaptureFile<'_> { fn position(&self) -> u64; } // of the decompressed contents

impl Record<'_> {
    fn set_time(&mut self, since_epoch: Duration);  // nanosecond precision
    fn set_original_len(&mut self, len: u32);       // on the wire; default the data's length
    fn read_data(&mut self, file: &mut CaptureFile<'_>, len: usize) -> io::Result<()>;
    fn extend_data(&mut self, bytes: &[u8]);
}

pub struct Encapsulation; // Copy, Eq, Hash: WTAP_ENCAP_*
impl Encapsulation {
    pub const ETHERNET: Self;
    pub const RAW_IP: Self;
    pub const fn user(index: u8) -> Option<Self>; // USER0..USER15 (pcap DLT_USER)
    pub const fn from_raw(value: i32) -> Self;
    pub const fn to_raw(self) -> i32;
}
```

- Wireshark 4.6 on, where a reader's structures are public; before, the
  plugin loads and registers no format.
- Wireshark tries every format's `open` on every file it opens, from the
  start of the file. `Ok(None)`, or an `UnexpectedEof` error, means "not
  this format"; any other error fails the open.
- `read` is called for each record in order, then again for a single record
  from the offset `position()` gave before it (`tshark -2`, Wireshark's
  packet list): a record must be readable from its own offset with only
  what `open` returned. `Ok(false)` ends the file; a record cut short
  (`UnexpectedEof`) is reported as a truncated file, `InvalidData` as a
  damaged one with the error's message.
- Every record is a packet of the format's `encapsulation`, captured from
  interface 0. Packets then go to the dissectors as from any capture.
- A format whose `NAME` Wireshark already has is left out.

## Codecs

```rust
pub trait Codec: 'static {
    const NAME: &'static str;   // payload format: SDP rtpmap name or static payload type name
    fn new(format: &StreamFormat) -> Self;
    fn sample_rate(&self) -> u32;
    fn channels(&self) -> u32 { 1 }
    fn decoded_len(&self, payload: &[u8]) -> usize;  // samples, at most
    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize; // samples written
}

#[non_exhaustive] pub struct StreamFormat {
    pub sample_rate: Option<u32>, // a=rtpmap clock rate; None before 4.2
    pub channels: Option<u32>,
}
```

- Used by Wireshark's RTP player and `sharkd`'s RTP download, not by tshark.
- `NAME` is compared ignoring case; Wireshark refuses a name already
  registered (its own codecs: G.711, G.722, G.726, G.729, iLBC, L16, Opus,
  SBC, AMR).
- One decoder per stream and payload type; `decode` gets one RTP payload.
- A panic is caught; the callback reports nothing (0 samples, 0 Hz).

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
    WrongLength,          // add_item: a length the field's type does not take
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
- `libwireshark-sys` reports its release line to build scripts as
  `DEP_WIRESHARK_VERSION` (`major.minor`); this crate enables file types
  from it.
