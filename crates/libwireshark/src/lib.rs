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
#[path = "plugin.rs"]
pub mod __private;
mod dissector;
mod header;
mod macros;
#[allow(unsafe_code)]
mod packet;
pub mod prefs;

/// The raw `libwireshark-sys` bindings, for what this crate does not wrap.
pub use libwireshark_sys as sys;

pub use dissector::{Binding, DissectResult, Dissector};
pub use header::{Base, FieldInfo, FieldType, Header, NoHeader};
pub use packet::{Encoding, PacketFieldError, PacketView};
pub use prefs::{NoPreferences, Preferences};

/// `#[derive(Header)]`: registered fields from a struct of integers, and
/// `Self::decode` reading them from packet bytes.
///
/// Each field is registered as `<filter>.<field name>` unless
/// `#[header(abbrev = "...")]` names it. Other keys: `name` (the label,
/// default the field name), `blurb`, `display` (`"dec"`, `"hex"`, `"oct"`,
/// `"dec_hex"`, `"hex_dec"`), `bitmask`, `offset` (bytes; default right after
/// the previous field) and `endian` (`"big"`, the default, or `"little"`,
/// also accepted on the struct).
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
