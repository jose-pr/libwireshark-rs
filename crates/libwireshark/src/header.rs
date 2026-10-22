//! The display-filter fields a protocol registers, and the decoded header
//! value that fills them for one packet.

use crate::packet::{PacketFieldError, PacketView};

/// A protocol's registered fields, and how a decoded value of this type is
/// added to the protocol tree.
///
/// `#[derive(Header)]` (feature `derive`) writes both methods from a struct
/// of integer fields.
pub trait Header {
    /// The fields to register, in registration order.
    fn fields() -> &'static [FieldInfo];

    /// Adds this decoded value's fields to `packet`'s protocol tree.
    ///
    /// # Errors
    ///
    /// The first [`PacketFieldError`] an insertion returns.
    fn add_to(&self, packet: &mut PacketView<'_>) -> Result<(), PacketFieldError>;
}

/// The header of a protocol that registers no fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoHeader;

impl Header for NoHeader {
    fn fields() -> &'static [FieldInfo] {
        &[]
    }

    fn add_to(&self, _: &mut PacketView<'_>) -> Result<(), PacketFieldError> {
        Ok(())
    }
}

/// One display-filter field: its label, filter name, type and display base.
///
/// An abbreviation that does not start with the protocol's filter name is
/// registered below it: `version` in protocol `foo` is `foo.version`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldInfo {
    name: &'static str,
    abbrev: &'static str,
    kind: FieldType,
    base: Base,
    bitmask: u64,
    blurb: &'static str,
    values: Option<&'static [(u32, &'static str)]>,
}

impl FieldInfo {
    /// A field shown as `name`, filtered as `abbrev`, in decimal, with no
    /// bitmask or description.
    pub const fn new(name: &'static str, abbrev: &'static str, kind: FieldType) -> Self {
        Self {
            name,
            abbrev,
            kind,
            base: Base::Dec,
            bitmask: 0,
            blurb: "",
            values: None,
        }
    }

    /// The same field shown in `base`.
    #[must_use]
    pub const fn with_base(mut self, base: Base) -> Self {
        self.base = base;
        self
    }

    /// The same field limited to the bits of `bitmask`.
    #[must_use]
    pub const fn with_bitmask(mut self, bitmask: u64) -> Self {
        self.bitmask = bitmask;
        self
    }

    /// The same field with a description, shown as the field's tooltip.
    #[must_use]
    pub const fn with_blurb(mut self, blurb: &'static str) -> Self {
        self.blurb = blurb;
        self
    }

    /// The same field shown by name: a value found in `values` is displayed
    /// as its text, with the number after it. For integer fields up to 32
    /// bits; a signed value is matched by its two's-complement bits
    /// (`-1i32 as u32`).
    #[must_use]
    pub const fn with_values(mut self, values: &'static [(u32, &'static str)]) -> Self {
        self.values = Some(values);
        self
    }

    /// The label shown in the protocol tree.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The display-filter abbreviation as declared, relative or full.
    pub const fn abbrev(&self) -> &'static str {
        self.abbrev
    }

    /// The field's value type.
    pub const fn kind(&self) -> FieldType {
        self.kind
    }

    /// The base integers are shown in.
    pub const fn base(&self) -> Base {
        self.base
    }

    /// The bits of the value this field shows; `0` for all of them.
    pub const fn bitmask(&self) -> u64 {
        self.bitmask
    }

    /// The field's description.
    pub const fn blurb(&self) -> &'static str {
        self.blurb
    }

    /// The names its values are shown by, if any.
    pub const fn values(&self) -> Option<&'static [(u32, &'static str)]> {
        self.values
    }
}

/// The value type of a field, Wireshark's `FT_*`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FieldType {
    /// `FT_UINT8`.
    U8,
    /// `FT_UINT16`.
    U16,
    /// `FT_UINT24`.
    U24,
    /// `FT_UINT32`.
    U32,
    /// `FT_UINT64`.
    U64,
    /// `FT_INT8`.
    I8,
    /// `FT_INT16`.
    I16,
    /// `FT_INT24`.
    I24,
    /// `FT_INT32`.
    I32,
    /// `FT_INT64`.
    I64,
    /// `FT_BOOLEAN`.
    Bool,
    /// `FT_BYTES`.
    Bytes,
    /// `FT_STRING`.
    String,
    /// `FT_IPv4`.
    Ipv4,
    /// `FT_IPv6`.
    Ipv6,
    /// `FT_ETHER`.
    Ether,
    /// `FT_NONE`: a label with no value.
    None,
}

impl FieldType {
    /// Width in bytes of a fixed-width integer type.
    pub const fn width(self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U24 | Self::I24 => Some(3),
            Self::U32 | Self::I32 => Some(4),
            Self::U64 | Self::I64 => Some(8),
            _ => None,
        }
    }

    pub(crate) const fn is_unsigned(self) -> bool {
        matches!(
            self,
            Self::U8 | Self::U16 | Self::U24 | Self::U32 | Self::U64
        )
    }

    pub(crate) const fn is_signed(self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I24 | Self::I32 | Self::I64
        )
    }
}

/// How an integer field is shown, Wireshark's `BASE_*`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Base {
    /// No base: for non-integer fields.
    None,
    /// Decimal.
    #[default]
    Dec,
    /// Hexadecimal.
    Hex,
    /// Octal.
    Oct,
    /// Decimal, then hexadecimal in parentheses.
    DecHex,
    /// Hexadecimal, then decimal in parentheses.
    HexDec,
}
