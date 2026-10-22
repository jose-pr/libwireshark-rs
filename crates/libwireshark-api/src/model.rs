//! What [`Dissector::describe`](crate::Dissector::describe) answers, and
//! what [`dissect_on`](crate::Dissector::dissect_on) lists: the encodings
//! every language writes.

use alloc::string::String;
use alloc::vec::Vec;
use guatiao::library::ProviderError;
use guatiao::{FromValue, List, Map, Schema, ToValue, Value};

/// A protocol: its names, the header the host decodes and adds, the
/// fields and findings the dissector adds itself, and its preferences.
#[derive(Clone, Debug, Default, PartialEq, ToValue, FromValue, Schema)]
pub struct Description {
    /// The tree label, such as "Foo Protocol".
    pub name: String,
    /// The Protocol column, such as "FOO".
    pub short_name: String,
    /// The display filter name, such as "foo": the prefix of every field,
    /// finding and preference.
    pub filter_name: String,
    /// The fixed header at the start of every packet, in order: the host
    /// decodes it for `dissect` and adds it to the tree when the packet is
    /// accepted.
    #[map(default)]
    pub header: Vec<Field>,
    /// More fields, which the dissector adds itself.
    #[map(default)]
    pub fields: Vec<Field>,
    /// Expert findings.
    #[map(default)]
    pub experts: Vec<Expert>,
    /// Preferences, in the order Wireshark shows them.
    #[map(default)]
    pub preferences: Vec<Preference>,
    /// For messages framed over TCP: the fixed header length
    /// [`Dissector::message_len`](crate::Dissector::message_len) reads a
    /// message's length from.
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
    /// The bits of the integer this field covers; in a header, the field
    /// shares its bytes with the others at its offset.
    pub bitmask: Option<u64>,
    /// A sentence describing the field.
    pub blurb: Option<String>,
    /// Names for an integer field's values (up to 32 bits).
    #[map(default)]
    pub values: Vec<NamedValue>,
    /// In a header: the byte offset; by default right after the previous
    /// field.
    pub offset: Option<u32>,
    /// In a header: the length of a `bytes` or `string` field.
    pub length: Option<u32>,
    /// In a header: a multi-byte integer is little-endian.
    #[map(default)]
    pub little_endian: bool,
}

impl Field {
    /// A field with nothing but its abbreviation, label and type.
    pub fn new(abbrev: impl Into<String>, name: impl Into<String>, kind: FieldType) -> Self {
        Self {
            abbrev: abbrev.into(),
            name: name.into(),
            kind,
            base: None,
            bitmask: None,
            blurb: None,
            values: Vec::new(),
            offset: None,
            length: None,
            little_endian: false,
        }
    }

    /// The same field with names for its values.
    #[must_use]
    pub fn with_values<'a>(mut self, values: impl IntoIterator<Item = (u32, &'a str)>) -> Self {
        self.values = values
            .into_iter()
            .map(|(value, name)| NamedValue {
                value,
                name: name.into(),
            })
            .collect();
        self
    }

    /// The same field shown in `base`.
    #[must_use]
    pub fn with_base(mut self, base: Base) -> Self {
        self.base = Some(base);
        self
    }

    /// The bytes the field spans in a header: its type's width, or its
    /// `length` for `bytes` and `string`.
    pub fn width(&self) -> Option<u32> {
        self.kind.width().or(self.length)
    }
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

impl FieldType {
    /// The bytes a value of this type spans; `None` for `bytes`, `string`
    /// and `none`, whose length a header field gives.
    pub const fn width(self) -> Option<u32> {
        Some(match self {
            Self::U8 | Self::I8 | Self::Bool => 1,
            Self::U16 | Self::I16 => 2,
            Self::U24 | Self::I24 => 3,
            Self::U32 | Self::I32 | Self::Ipv4 => 4,
            Self::U64 | Self::I64 => 8,
            Self::Ipv6 => 16,
            Self::Ether => 6,
            Self::Bytes | Self::String | Self::None => return None,
        })
    }

    /// Whether values are signed integers.
    pub const fn is_signed(self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I24 | Self::I32 | Self::I64
        )
    }
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

/// A protocol preference, under Edit › Preferences › Protocols and as
/// `-o <filter_name>.<name>:<value>`.
#[derive(Clone, Debug, PartialEq, ToValue, FromValue, Schema)]
pub struct Preference {
    /// The key.
    pub name: String,
    /// The label; by default the key.
    pub title: Option<String>,
    /// A sentence describing it.
    pub description: Option<String>,
    /// What it holds.
    #[map(rename = "type")]
    pub kind: PreferenceType,
    /// Its value until the user changes it: a boolean, a number from 0 to
    /// 2^32-1, or text, by `kind`.
    pub default: Value,
}

/// What a preference holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ToValue, FromValue, Schema)]
#[map(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum PreferenceType {
    Bool,
    Uint,
    String,
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

impl Binding {
    /// Packets to or from UDP port `port`.
    pub fn udp_port(port: u16) -> Self {
        Self::Table {
            table: "udp.port".into(),
            value: port.into(),
        }
    }

    /// Packets to or from TCP port `port`.
    pub fn tcp_port(port: u16) -> Self {
        Self::Table {
            table: "tcp.port".into(),
            value: port.into(),
        }
    }

    /// `bindings` as the list [`Dissector::dissect_on`](crate::Dissector::dissect_on) answers.
    ///
    /// # Errors
    ///
    /// When the list cannot be built (an allocation failed).
    pub fn to_list(bindings: &[Self]) -> Result<List, ProviderError> {
        List::from_value(&bindings.to_value()?).map_err(refused)
    }

    /// The bindings a `dissect_on` list holds.
    ///
    /// # Errors
    ///
    /// When the list is not of bindings; the error says where.
    pub fn from_list(list: &List) -> Result<Vec<Self>, ProviderError> {
        Vec::<Self>::from_value(&list.to_value()?).map_err(refused)
    }
}

impl Description {
    /// The description as the map [`Dissector::describe`](crate::Dissector::describe) answers.
    ///
    /// # Errors
    ///
    /// When the value cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(refused)
    }

    /// The description a [`Dissector::describe`](crate::Dissector::describe) map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape; the error names the key.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(refused)
    }
}

pub(crate) fn refused(error: impl core::fmt::Display) -> ProviderError {
    ProviderError::new(
        guatiao::Status::GUATIAO_ERR_BAD_VALUE,
        &alloc::format!("{error}"),
    )
}
