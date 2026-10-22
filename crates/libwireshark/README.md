# libwireshark

Safe Rust runtime helpers for native Wireshark protocol plugins. The crate
depends on `libwireshark-sys`; building a plugin still requires a matching
Wireshark development SDK and native libraries.

## Packet access

Wireshark passes a callback-scoped `PacketView` to a protocol's dissector
function. Packet reads return `None` when the requested bytes are not captured
or the offset cannot be represented by Wireshark's API.

`captured_len` and `reported_len` expose the tvbuff lengths. `PacketView` is
callback-scoped, exposes no raw Wireshark pointers, and is neither `Send` nor
`Sync`.

`PacketView` provides `get_u8`, plus `get_u16_be/le`, `get_u24_be/le`,
`get_u32_be/le`, and `get_u64_be/le`. Signed reads are available as `get_i8`,
`get_i16_be/le`, `get_i24_be/le`, `get_i32_be/le`, and `get_i64_be/le`.
The `_be` methods use network byte order; `_le` methods use little-endian byte
order. Twenty-four-bit signed reads sign-extend into `i32`.

Typed dissectors return `Option<DissectResult<Header>>`. `None` declines the
packet; a result carries the decoded header, consumed byte count, and optional
Info-column text. The runtime adds the header fields and Info text to Wireshark
after the dissector returns. The mutable `PacketView` remains available for
protocol-specific tree items that are not represented by the header.

## Protocol tree fields

`add_uint(field, offset, width, value)` adds an `FT_UINT8`, `FT_UINT16`,
`FT_UINT24`, or `FT_UINT32` field. `add_int` supports the matching signed
field types. `add_uint64` and `add_int64` add 64-bit fields. Each method checks
the registered field type, field width, representable value, and captured
packet range before calling Wireshark.

`add_item(field, offset, length, encoding)` uses Wireshark's generic field
decoder for any registered field type. Pass `ENC_*` flags from
`libwireshark::bindings` for byte order or text encoding. It checks the field,
tree, and complete captured byte range before calling EPAN.

Field insertion returns `PacketFieldError`, which distinguishes a missing
tree, unknown field, unsupported type, width mismatch, out-of-range packet
bytes, and a value that does not fit the field width.

With the `macros` feature, `#[derive(Header)]` on a named integer struct
declares its registered fields and implements `Header::add_to`. Decode the
values into that struct, then call `packet.add_header(&header)` to add them to
the packet tree. `#[derive(Preferences)]` maps a named struct to Wireshark
preferences.

Implement `Dissector` with associated `Preferences` and `Header` types. Fixed
table mappings are declared as the static `DISSECT_ON` slice. Protocols whose
table mapping depends on a preference set `PREFERENCE_DRIVEN_DISSECT_ON` and
override `dissect_on`; Wireshark invokes the runtime apply callback to update
the mapping when preferences change.

`add_info(text)` appends to the Info column when the callback has column data.
It returns `NulError` for text containing an interior NUL byte.

## Plugin entry point

With the `macros` feature, apply `#[libwireshark::wireshark_plugin]` to a type
implementing `WiresharkPlugin`. Its `protocols()` method returns a static slice
of `ProtocolRegistration` values, so fixed registrations need no `Vec`. Use
`ProtocolRegistration::dissector::<FooDissector>()` for a type implementing
`Dissector`, or `ProtocolRegistration::custom(build_protocol)` for a custom
protocol builder. Each protocol can bind its dissector to one or more Wireshark
tables. `PluginOptions` can override the exported plugin version string, which
defaults to the Cargo package version. Preferences remain scoped to protocols.
A synchronous zero-argument function returning `Protocol` is also supported
for a simple single-protocol plugin. The macro resolves renamed runtime
dependencies and exports Wireshark's metadata and `plugin_register` entry point.
