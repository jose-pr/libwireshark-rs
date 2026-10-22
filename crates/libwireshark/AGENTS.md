# libwireshark API

`libwireshark` provides safe callback-scoped packet access and protocol-tree
helpers over `libwireshark-sys`. Building a plugin requires a Wireshark SDK
matching the bindings and target used by the build.

## Root exports

- `PacketView<'packet>`: callback-scoped packet and dissection context.
- `PacketFieldError`: non-exhaustive error returned by checked field insertion.
- `DissectorAdd`: dissector-table attachment description.
- `DissectResult<H>`: decoded header values, consumed byte count, and optional
  Info-column text returned by a typed dissector.
- `Dissector`: protocol implementation trait; `protocol()` converts it to the runtime descriptor.
- `Preferences` and `PreferenceValue`: typed preference declarations and conversion.
- `PreferenceMap`, `PreferenceError`, and `NoPreferences`: current preference values, conversion error, and empty preference configuration.
- `header::Header` and `HeaderFieldInfo`: static display-filter field
  declarations and decoded-header application.
- `bindings`: raw `libwireshark-sys` declarations.
- `Protocol`, `ProtocolRegistration`, `ProtocolPlugin`, `WiresharkPlugin`,
  `PluginOptions`, and `plugin_register`: plugin and protocol registration API.
- `wireshark_plugin`: attribute macro when the `macros` feature is enabled.

## PacketView

Wireshark constructs a `PacketView` only for the duration of a dissector
callback. It exposes no raw Wireshark pointers.

- `captured_len(&self) -> usize` and `reported_len(&self) -> usize` return the
  captured and reported packet lengths.
- `get_u8(&self, offset: usize) -> Option<u8>` reads a byte.
- `get_u16_be/le`, `get_u24_be/le`, `get_u32_be/le`, and `get_u64_be/le` read
  unsigned integers and return `Option<u16/u32/u64>` according to width.
- `get_i8`, `get_i16_be/le`, `get_i24_be/le`, `get_i32_be/le`, and
  `get_i64_be/le` read signed integers and return `Option<i8/i16/i32/i64>`.
- `_be` means network byte order; `_le` means little-endian byte order.
  Twenty-four-bit signed reads sign-extend into `i32`.
- `add_info(&mut self, text: &str) -> Result<(), NulError>` appends to the
  Info column when available.
- `has_tree(&self) -> bool` reports whether Wireshark supplied a protocol tree.
- `add_uint(field, offset, width, value)` inserts FT_UINT8/16/24/32 values;
  `add_int` inserts FT_INT8/16/24/32 values.
- `add_uint64(field, offset, value)` and `add_int64(field, offset, value)`
  insert FT_UINT64 and FT_INT64 values.
- `add_item(field, offset, length, encoding)` inserts any registered field
  using Wireshark's generic decoder; `encoding` uses `ENC_*` flags from
  `bindings`.
- `add_header(&decoded_header)` applies the decoded values in a type
  implementing `header::Header` to the protocol tree.

Numeric reads return `None` if their full byte range is not captured or their
offset cannot be represented by the native API. Field insertion checks the
registered field type, byte width, value range, and captured packet range
before calling EPAN. Errors are `NoTree`, `UnknownField`,
`UnsupportedFieldType`, `WidthMismatch`, `OutOfBounds`, and `ValueOutOfRange`.

## Typed protocol declarations

`Dissector` requires associated `Preferences` and `Header` types, protocol
name constants, and a `dissect(&Preferences, &mut PacketView)` callback that
returns `Option<DissectResult<Header>>`. Return `None` when the packet does not
match; on `Some`, the runtime adds the result header, optional Info text, and
returns its consumed byte count.
Set `DISSECT_ON` to a static slice of table attachments for fixed bindings; it
defaults to empty. For preference-dependent bindings, set
`PREFERENCE_DRIVEN_DISSECT_ON` and override `dissect_on(&Preferences)`. Wireshark
recomputes those bindings when preferences are applied. `Dissector::protocol()`
builds the descriptor accepted by the runtime registration layer. A preference
conversion error makes the callback consume zero bytes. Use `NoHeader` for a
protocol without registered fields.

With the `macros` feature, `#[derive(Preferences)]` supports named structs
whose fields are `bool`, `u32`, or `String`. `#[preference(name = "...", title
= "...", description = "...")]` overrides preference metadata.
`#[derive(Header)]` supports named structs with `u8`, `u16`, `u32`, `u64`,
`i8`, `i16`, `i32`, or `i64` fields. Each field requires
`#[header(abbrev = "filter.name")]`; `name`, `blurb`, `display = "dec" |`
`"hex" | "oct"`, `bitmask`, and byte `offset` are optional. Without an
explicit offset, integer fields are laid out consecutively from zero. The
derive provides both field registration metadata and `Header::add_to`, so a
dissector can decode a header value and pass it to `packet.add_header(...)`.

## Plugin entry point

With the `macros` feature, apply `#[libwireshark::wireshark_plugin]` to a type
implementing `WiresharkPlugin`; return a static slice of
`ProtocolRegistration` values from `protocols()`. Use
`ProtocolRegistration::dissector::<Type>()` for a `Dissector` or
`ProtocolRegistration::custom(builder)` for a custom protocol builder.
`PluginOptions::version` overrides the exported plugin version; the Cargo
package version is the default. Preferences belong to individual protocols. A
synchronous zero-argument function returning `Protocol` is also accepted for a
single-protocol plugin. The macro exports Wireshark's metadata and
`plugin_register` entry point. Without it, export an equivalent entry point and
initialize protocol descriptors through the runtime registration API.
