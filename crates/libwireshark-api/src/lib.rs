#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

extern crate alloc;

/// The guatiao this crate's kinds are built with; providers name it
/// through this path so both sides use one copy.
pub use guatiao;

use alloc::string::String;
use alloc::vec::Vec;
use guatiao::library::ProviderError;
use guatiao::{FromValue, Map, Schema, ToValue};

/// A protocol a provider dissects: `wireshark_dissector`.
///
/// The host asks for [`describe`](Self::describe) once, registers the
/// protocol it answers, and calls [`dissect`](Self::dissect) for every
/// packet that reaches it, on Wireshark's dissection thread.
#[guatiao::kind(name = "wireshark_dissector")]
pub trait Dissector: Send + Sync {
    /// The protocol, as a map in the shape of [`Description`].
    fn describe(&self) -> Result<Map, ProviderError>;

    /// Dissects one packet (or one framed message): `data` is its captured
    /// bytes, `packet` where fields and columns go, and `conversation` the
    /// state this protocol keeps for the packet's conversation, empty the
    /// first time and kept as left. Answers the bytes taken; 0 declines,
    /// and a declining dissector adds nothing to `packet` first.
    fn dissect(
        &self,
        data: &[u8],
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

/// What [`Dissector::describe`] answers: a protocol, its fields, expert
/// findings and where it gets packets.
#[derive(Clone, Debug, Default, PartialEq, ToValue, FromValue, Schema)]
pub struct Description {
    /// The tree label, such as "Foo Protocol".
    pub name: String,
    /// The Protocol column, such as "FOO".
    pub short_name: String,
    /// The display filter name, such as "foo": the prefix of every field
    /// and finding.
    pub filter_name: String,
    /// Registered fields.
    #[map(default)]
    pub fields: Vec<Field>,
    /// Expert findings.
    #[map(default)]
    pub experts: Vec<Expert>,
    /// Where the protocol gets packets.
    #[map(default)]
    pub bindings: Vec<Binding>,
    /// For messages framed over TCP: the fixed header length
    /// [`Dissector::message_len`] reads a message's length from.
    pub tcp_header_len: Option<u32>,
}

/// One registered field.
#[derive(Clone, Debug, PartialEq, ToValue, FromValue, Schema)]
pub struct Field {
    /// The abbreviation below the protocol's filter name, such as "version".
    pub abbrev: String,
    /// The label in the tree.
    pub name: String,
    /// What the field holds.
    #[map(rename = "type")]
    pub kind: FieldType,
    /// How an integer is shown.
    pub base: Option<Base>,
    /// The bits of the integer this field covers.
    pub bitmask: Option<u64>,
    /// A sentence describing the field.
    pub blurb: Option<String>,
    /// Names for an integer field's values (up to 32 bits).
    #[map(default)]
    pub values: Vec<NamedValue>,
}

/// What a field holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ToValue, FromValue, Schema)]
#[map(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum FieldType {
    U8,
    U16,
    U24,
    U32,
    U64,
    I8,
    I16,
    I24,
    I32,
    I64,
    Bool,
    Bytes,
    String,
    Ipv4,
    Ipv6,
    Ether,
    /// A label with no value.
    None,
}

/// How an integer field is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ToValue, FromValue, Schema)]
#[map(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Base {
    Dec,
    Hex,
    Oct,
    DecHex,
    HexDec,
}

/// A name for one value of an integer field.
#[derive(Clone, Debug, PartialEq, ToValue, FromValue, Schema)]
pub struct NamedValue {
    /// The value.
    pub value: u32,
    /// Its name.
    pub name: String,
}

/// An expert finding the protocol may report.
#[derive(Clone, Debug, PartialEq, ToValue, FromValue, Schema)]
pub struct Expert {
    /// The abbreviation below the protocol's filter name.
    pub abbrev: String,
    /// What it is about.
    pub group: ExpertGroup,
    /// How bad it is.
    pub severity: Severity,
    /// The text reported unless the dissector gives its own.
    pub summary: String,
}

/// What an expert finding is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ToValue, FromValue, Schema)]
#[map(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ExpertGroup {
    Checksum,
    Sequence,
    ResponseCode,
    RequestCode,
    Undecoded,
    Reassemble,
    Malformed,
    Debug,
    Protocol,
    Security,
    Comments,
    Decryption,
    Assumption,
    Deprecated,
}

/// How bad an expert finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ToValue, FromValue, Schema)]
#[map(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Severity {
    Comment,
    Chat,
    Note,
    Warn,
    Error,
}

/// One way the protocol gets packets.
#[derive(Clone, Debug, PartialEq, ToValue, FromValue, Schema)]
#[map(tag = "on")]
#[map(rename_all = "snake_case")]
pub enum Binding {
    /// Packets where the integer table `table` (such as "udp.port") has `value`.
    Table {
        /// The table's name.
        table: String,
        /// The value.
        value: u32,
    },
    /// Every packet of the heuristic list `list` (such as "udp") no table claimed.
    Heuristic {
        /// The list's name.
        list: String,
    },
    /// Every frame, after all other dissection.
    Postdissector,
}

impl Field {
    /// A field with no base, bitmask, blurb or named values.
    pub fn new(abbrev: impl Into<String>, name: impl Into<String>, kind: FieldType) -> Self {
        Self {
            abbrev: abbrev.into(),
            name: name.into(),
            kind,
            base: None,
            bitmask: None,
            blurb: None,
            values: Vec::new(),
        }
    }
}

impl Description {
    /// The description as the map [`Dissector::describe`] answers.
    ///
    /// # Errors
    ///
    /// When the value cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(refused)
    }

    /// The description a [`Dissector::describe`] map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape; the error names the key.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(refused)
    }
}

fn refused(error: guatiao::MapError) -> ProviderError {
    ProviderError::new(
        guatiao::Status::GUATIAO_ERR_BAD_VALUE,
        &alloc::format!("{error}"),
    )
}
