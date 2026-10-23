#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

extern crate alloc;

/// The guatiao this crate's kinds are built with; providers name it
/// through this path so both sides use one copy.
pub use guatiao;

pub mod codec;
pub mod file_type;
pub mod filter;
pub mod host;
mod model;
pub mod tap;
mod typed;

pub use codec::{Codec, CodecDescription, Decoder, StreamFormat};
pub use file_type::{CaptureReader, CaptureRecord, CaptureSource, FileType, FileTypeDescription};
pub use filter::{FilterDescription, FilterFunction, FilterReturn};
pub use model::{
    Base, Binding, Description, Expert, ExpertGroup, Field, FieldType, NamedValue, Preference,
    PreferenceType, Severity,
};
pub use tap::{Tap, TapDescription, TapListener, TapPacket};
pub use typed::{
    ExpertInfo, NoHeader, NoPreferences, PacketExt, ProtocolDissector, header_fields,
    preference_list,
};

#[doc(hidden)]
pub mod __private {
    pub use crate::typed::read;
}

use guatiao::library::ProviderError;
use guatiao::{List, Map};

/// A protocol a provider dissects: `wireshark_dissector`.
///
/// The host asks for [`describe`](Self::describe) once and registers the
/// protocol, its header fields and its preferences. Each time Wireshark
/// applies preferences it asks [`dissect_on`](Self::dissect_on) where the
/// protocol gets packets, and for every packet that reaches it calls
/// [`dissect`](Self::dissect), on Wireshark's dissection thread.
///
/// A Rust provider usually implements [`ProtocolDissector`] instead, whose
/// header and preferences are typed structs, and writes
/// [`dissector!`](crate::dissector) to implement this kind from it.
#[guatiao::kind(name = "wireshark_dissector")]
pub trait Dissector: Send + Sync {
    /// The protocol, as a map in the shape of [`Description`].
    fn describe(&self) -> Result<Map, ProviderError>;

    /// Where the protocol gets packets for these preference values (a map
    /// keyed by preference name): a list of [`Binding`] maps.
    fn dissect_on(&self, preferences: &Map) -> Result<List, ProviderError>;

    /// Dissects one packet (or one framed message).
    ///
    /// `data` is its captured bytes; `header` the description's header
    /// fields decoded from them (those `data` holds whole), by abbreviation;
    /// `preferences` the current values; `packet` where fields and columns
    /// go; `conversation` the state this protocol keeps for the packet's
    /// conversation, empty the first time and kept as left. Answers the
    /// bytes taken: 0 declines, and a declining dissector adds nothing to
    /// `packet` first. On accepting, the host adds the header fields.
    fn dissect(
        &self,
        data: &[u8],
        header: &Map,
        preferences: &Map,
        packet: &mut dyn Packet,
        conversation: &mut Map,
    ) -> Result<i64, ProviderError>;

    /// For a protocol framed over TCP (`tcp_header_len` in its
    /// description): a message's whole length, header included, from its
    /// first `tcp_header_len` bytes; -1 when the header is not this
    /// protocol's.
    fn message_len(&self, header: &[u8]) -> i64 {
        let _ = header;
        -1
    }
}

/// One packet being dissected: `wireshark_packet`, lent by the host for a
/// [`Dissector::dissect`] call.
///
/// Field names are the abbreviations a [`Description`] declared, with or
/// without the protocol's `<filter_name>.` prefix. Offsets and lengths are
/// in bytes from the start of `data`.
#[guatiao::kind(object, name = "wireshark_packet")]
pub trait Packet: Send {
    /// Adds the field over `length` bytes at `offset`, decoded by Wireshark
    /// from the field's type (multi-byte integers big-endian unless
    /// `little_endian`).
    fn add_item(
        &mut self,
        field: &str,
        offset: i64,
        length: i64,
        little_endian: bool,
    ) -> Result<(), ProviderError>;

    /// Adds an unsigned integer field with `value`, over its width at `offset`.
    fn add_uint(&mut self, field: &str, offset: i64, value: u64) -> Result<(), ProviderError>;

    /// Adds a signed integer field with `value`, over its width at `offset`.
    fn add_int(&mut self, field: &str, offset: i64, value: i64) -> Result<(), ProviderError>;

    /// Replaces the Info column's text.
    fn set_info(&mut self, text: &str);

    /// Appends to the Info column's text.
    fn append_info(&mut self, text: &str);

    /// Reports the expert finding `name`, with `text` instead of its
    /// summary unless `text` is empty.
    fn add_expert(&mut self, name: &str, text: &str) -> Result<(), ProviderError>;

    /// Whether Wireshark dissects this packet for the first time: update
    /// conversation state only then, since packets are dissected again.
    fn is_first_pass(&self) -> bool;

    /// Whether the protocol runs as a post-dissector for this packet:
    /// append to the Info column rather than replace it.
    fn is_postdissector(&self) -> bool;

    /// The packet's frame number, counted from 1.
    fn frame_number(&self) -> i64;

    /// The source port of the packet's transport, 0 when it has none.
    fn src_port(&self) -> i64;

    /// The destination port of the packet's transport, 0 when it has none.
    fn dst_port(&self) -> i64;
}
