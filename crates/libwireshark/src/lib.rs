#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
// Lets the derives' `::libwireshark` paths resolve in this crate's own tests.
extern crate self as libwireshark;

#[allow(unsafe_code)]
#[doc(hidden)]
#[path = "plugin/mod.rs"]
pub mod __private;
mod dissector;
mod expert;
#[allow(unsafe_code)]
mod filter;
mod header;
mod macros;
#[allow(unsafe_code)]
mod packet;
pub mod prefs;
#[allow(unsafe_code)]
mod tap;

/// The raw `libwireshark-sys` bindings, for what this crate does not wrap.
pub use libwireshark_sys as sys;

pub use dissector::{Binding, DissectResult, Dissector, TcpFraming};
pub use expert::{Expert, ExpertGroup, Severity};
pub use filter::{FieldValue, FilterFunction, FilterOutput};
pub use header::{Base, FieldInfo, FieldType, Header, NoHeader};
pub use packet::{Encoding, PacketFieldError, PacketView};
pub use prefs::{NoPreferences, Preferences};
pub use tap::{Tap, TapPacket};

/// `#[derive(Header)]`: registered fields from a struct, and `Self::decode`
/// reading them from packet bytes.
///
/// Fields are `u8`..`u64` and `i8`..`i64` (added with the struct's value),
/// or `bool`, `[u8; N]`, `Ipv4Addr` and `Ipv6Addr` (added by Wireshark from
/// the packet bytes). Each is registered as `<filter>.<field name>` unless
/// `#[header(abbrev = "...")]` names it. Other keys: `name` (the label,
/// default the field name), `blurb`, `display` (`"dec"`, `"hex"`, `"oct"`,
/// `"dec_hex"`, `"hex_dec"`), `bitmask`, `offset` (bytes; default right after
/// the previous field), `endian` (`"big"`, the default, or `"little"`, also
/// accepted on the struct), `values = PATH` (a `&[(u32, &str)]` naming an
/// integer field's values) and `kind = "ether"` (a `[u8; 6]` MAC address).
///
/// ```compile_fail
/// #[derive(libwireshark::Header)]
/// struct Tuple(u8);
/// ```
#[cfg(feature = "derive")]
#[cfg_attr(docsrs, doc(cfg(feature = "derive")))]
pub use libwireshark_derive::Header;

/// `#[derive(Preferences)]`: registered preferences from a struct whose
/// fields are `bool`, `u8`, `u16`, `u32` or `String`; its `Default` gives the
/// defaults.
///
/// `#[preference(name = "...", title = "...", description = "...", base = 16)]`
/// sets a field's key (default the field name), label (default the key),
/// description, and integer base.
#[cfg(feature = "derive")]
#[cfg_attr(docsrs, doc(cfg(feature = "derive")))]
pub use libwireshark_derive::Preferences;

// The repository README's example, compiled with this crate's doctests.
#[cfg(all(doctest, feature = "derive"))]
#[doc = include_str!("../../../README.md")]
struct RepositoryReadme;
