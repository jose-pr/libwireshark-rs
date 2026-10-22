//! A dissector whose header and preferences are typed structs, as
//! `libwireshark::Dissector`'s are: the Rust way to write a provider.

use crate::model::refused;
use crate::{
    Binding, Description, Expert, ExpertGroup, Field, FieldType, Packet, Preference,
    PreferenceType, Severity,
};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use guatiao::library::ProviderError;
use guatiao::schema::{KindRef as Kind, SchemaRef};
use guatiao::{FromValue, Map, Schema, ToValue};

/// A protocol whose header and preferences are structs: implement this,
/// then write [`dissector!`](crate::dissector) for the type to make it a
/// [`Dissector`](crate::Dissector) a host loads.
///
/// ```
/// use libwireshark_api::guatiao::library::ProviderError;
/// use libwireshark_api::guatiao::{self, FromValue, Map, Provider, Schema, ToValue};
/// use libwireshark_api::{Binding, Packet, ProtocolDissector};
///
/// /// FOO's header: field names are the abbreviations, doc comments the blurbs.
/// #[derive(Schema, FromValue)]
/// #[map(crate = ::libwireshark_api::guatiao)]
/// struct FooHeader {
///     /// The protocol version.
///     version: u8,
///     flags: u8,
///     length: u16,
/// }
///
/// /// FOO's preferences: doc comments are their descriptions.
/// #[derive(Schema, FromValue, ToValue)]
/// #[map(crate = ::libwireshark_api::guatiao)]
/// struct FooPreferences {
///     /// UDP port FOO is decoded on.
///     #[schema(title = "UDP port")]
///     port: u16,
/// }
///
/// impl Default for FooPreferences {
///     fn default() -> Self {
///         Self { port: 113 }
///     }
/// }
///
/// #[derive(Default, Provider)]
/// #[provider(libwireshark_api::Dissector, crate = ::libwireshark_api::guatiao)]
/// struct Foo;
///
/// impl ProtocolDissector for Foo {
///     const NAME: &'static str = "Foo Protocol";
///     const SHORT_NAME: &'static str = "FOO";
///     const FILTER_NAME: &'static str = "foo";
///     type Header = FooHeader;
///     type Preferences = FooPreferences;
///
///     fn dissect_on(&self, preferences: &FooPreferences) -> Vec<Binding> {
///         vec![Binding::udp_port(preferences.port)]
///     }
///
///     fn dissect(
///         &self,
///         data: &[u8],
///         header: &FooHeader,
///         _preferences: &FooPreferences,
///         packet: &mut dyn Packet,
///         _conversation: &mut Map,
///     ) -> Result<i64, ProviderError> {
///         packet.set_info(&format!("FOO version {}", header.version));
///         Ok(data.len() as i64)
///     }
/// }
///
/// libwireshark_api::dissector!(Foo);
/// ```
pub trait ProtocolDissector: Send + Sync + 'static {
    /// The tree label.
    const NAME: &'static str;
    /// The Protocol column.
    const SHORT_NAME: &'static str;
    /// The display filter name: prefix of fields, findings and preferences.
    const FILTER_NAME: &'static str;
    /// For messages framed over TCP: the fixed header length
    /// [`message_len`](Self::message_len) reads.
    const TCP_HEADER_LEN: Option<u32> = None;

    /// The fixed header the host decodes and adds: a struct of integers and
    /// `bool`s laid out in field order (see [`header_fields`]), or
    /// [`NoHeader`]. A packet too short for it is declined.
    type Header: Schema + FromValue;

    /// The preferences: a struct of `bool`s, unsigned integers up to 32
    /// bits and `String`s whose `Default` gives the defaults (see
    /// [`preference_list`]), or [`NoPreferences`].
    type Preferences: Schema + FromValue + ToValue + Default;

    /// The header's fields; override to add names for values, a base or a
    /// bitmask to what the struct says.
    ///
    /// # Errors
    ///
    /// As [`header_fields`].
    fn header() -> Result<Vec<Field>, ProviderError> {
        header_fields::<Self::Header>()
    }

    /// Fields the dissector adds itself.
    fn fields() -> Vec<Field> {
        Vec::new()
    }

    /// Expert findings the dissector may report.
    fn experts() -> Vec<Expert> {
        Vec::new()
    }

    /// The preferences' declarations.
    ///
    /// # Errors
    ///
    /// As [`preference_list`].
    fn preferences() -> Result<Vec<Preference>, ProviderError> {
        preference_list::<Self::Preferences>()
    }

    /// The whole description, from the items above.
    ///
    /// # Errors
    ///
    /// When the header or the preferences cannot be described.
    fn description() -> Result<Description, ProviderError> {
        Ok(Description {
            name: Self::NAME.to_string(),
            short_name: Self::SHORT_NAME.to_string(),
            filter_name: Self::FILTER_NAME.to_string(),
            header: Self::header()?,
            fields: Self::fields(),
            experts: Self::experts(),
            preferences: Self::preferences()?,
            tcp_header_len: Self::TCP_HEADER_LEN,
        })
    }

    /// Where the protocol gets packets with these preferences.
    fn dissect_on(&self, preferences: &Self::Preferences) -> Vec<Binding>;

    /// Dissects one packet, its header already decoded: the bytes taken, 0
    /// to decline (adding nothing first).
    ///
    /// # Errors
    ///
    /// A refusal declines the packet, as 0 does.
    fn dissect(
        &self,
        data: &[u8],
        header: &Self::Header,
        preferences: &Self::Preferences,
        packet: &mut dyn Packet,
        conversation: &mut Map,
    ) -> Result<i64, ProviderError>;

    /// A framed message's whole length, header included, from its first
    /// [`TCP_HEADER_LEN`](Self::TCP_HEADER_LEN) bytes; -1 when the header
    /// is not this protocol's.
    fn message_len(&self, header: &[u8]) -> i64 {
        let _ = header;
        -1
    }
}

/// An expert finding as a type, the way a dissector names and reports it:
///
/// ```
/// use libwireshark_api::{ExpertGroup, ExpertInfo, Severity};
///
/// /// Unknown version.
/// struct UnknownVersion;
///
/// impl ExpertInfo for UnknownVersion {
///     const ABBREV: &'static str = "unknown_version";
///     const GROUP: ExpertGroup = ExpertGroup::Malformed;
///     const SEVERITY: Severity = Severity::Warn;
///     const SUMMARY: &'static str = "Unknown version";
/// }
/// ```
///
/// List it in [`ProtocolDissector::experts`] as `UnknownVersion::expert()`
/// and report it with [`PacketExt::report`]: `packet.report(&UnknownVersion)`.
pub trait ExpertInfo {
    /// The abbreviation below the protocol's filter name.
    const ABBREV: &'static str;
    /// What it is about.
    const GROUP: ExpertGroup;
    /// How bad it is.
    const SEVERITY: Severity;
    /// What is reported unless [`text`](Self::text) says otherwise.
    const SUMMARY: &'static str;

    /// The text reported for this occurrence; empty for the summary.
    fn text(&self) -> &str {
        ""
    }

    /// The finding as the description lists it.
    fn expert() -> Expert
    where
        Self: Sized,
    {
        Expert {
            abbrev: Self::ABBREV.to_string(),
            group: Self::GROUP,
            severity: Self::SEVERITY,
            summary: Self::SUMMARY.to_string(),
        }
    }
}

/// Reporting an [`ExpertInfo`] on a lent [`Packet`].
pub trait PacketExt {
    /// Reports `finding` on the packet: its summary, or its text.
    ///
    /// # Errors
    ///
    /// As [`Packet::add_expert`].
    fn report<E: ExpertInfo>(&mut self, finding: &E) -> Result<(), ProviderError>;
}

impl PacketExt for dyn Packet + '_ {
    fn report<E: ExpertInfo>(&mut self, finding: &E) -> Result<(), ProviderError> {
        self.add_expert(E::ABBREV, finding.text())
    }
}

/// A protocol with no fixed header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Schema, FromValue, ToValue)]
#[map(crate = ::guatiao)]
pub struct NoHeader {}

/// A protocol with no preferences.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Schema, FromValue, ToValue)]
#[map(crate = ::guatiao)]
pub struct NoPreferences {}

fn schema_of<T: Schema>() -> Result<guatiao::Value, ProviderError> {
    Ok(T::schema()?)
}

fn text(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_string())
}

/// The header fields of `T`'s schema, in its field order: each field's
/// name is the abbreviation, its title (by default the name) the label,
/// its doc comment the blurb. `u8`..`u64` (but no 24-bit width), `i8`..`i64`
/// and `bool` are laid out by their width, one after the other.
///
/// # Errors
///
/// `GUATIAO_ERR_BAD_VALUE` naming a field of another type: describe such a
/// header with [`ProtocolDissector::header`] instead.
pub fn header_fields<T: Schema>() -> Result<Vec<Field>, ProviderError> {
    let schema = schema_of::<T>()?;
    let schema = SchemaRef::new(&schema).ok_or_else(|| refused("the header is not a struct"))?;
    schema
        .fields()
        .map(|field| {
            let kind = match field.kind() {
                Kind::Bool => FieldType::Bool,
                Kind::Int { min, max, .. } => match (min, max) {
                    (Some(0), Some(0xff)) => FieldType::U8,
                    (Some(0), Some(0xffff)) => FieldType::U16,
                    (Some(0), Some(0xffff_ffff)) => FieldType::U32,
                    (Some(0), None) => FieldType::U64,
                    (Some(-0x80), Some(0x7f)) => FieldType::I8,
                    (Some(-0x8000), Some(0x7fff)) => FieldType::I16,
                    (Some(-0x8000_0000), Some(0x7fff_ffff)) => FieldType::I32,
                    (Some(i64::MIN), Some(i64::MAX)) => FieldType::I64,
                    _ => return Err(unlaid(field.key())),
                },
                _ => return Err(unlaid(field.key())),
            };
            let mut laid = Field::new(
                field.key(),
                text(field.title()).unwrap_or_else(|| field.key().to_string()),
                kind,
            );
            laid.blurb = text(field.description());
            Ok(laid)
        })
        .collect()
}

fn unlaid(key: &str) -> ProviderError {
    refused(alloc::format!(
        "header field `{key}`: only integers and bool are laid out from their type"
    ))
}

/// The preferences of `T`'s schema, in its field order: each field's name
/// is the key, its title (by default the name) the label, its doc comment
/// the description, and `T::default()` the default. `bool`, unsigned
/// integers up to 32 bits and `String` are preferences.
///
/// # Errors
///
/// `GUATIAO_ERR_BAD_VALUE` naming a field of another type.
pub fn preference_list<T: Schema + ToValue + Default>() -> Result<Vec<Preference>, ProviderError> {
    let schema = schema_of::<T>()?;
    let schema =
        SchemaRef::new(&schema).ok_or_else(|| refused("the preferences are not a struct"))?;
    let defaults = Map::from_value(&T::default().to_value()?).map_err(refused)?;
    schema
        .fields()
        .map(|field| {
            let kind = match field.kind() {
                Kind::Bool => PreferenceType::Bool,
                Kind::Int {
                    min: Some(0),
                    max: Some(max),
                    ..
                } if max <= 0xffff_ffff => PreferenceType::Uint,
                Kind::Str { .. } => PreferenceType::String,
                _ => {
                    return Err(refused(alloc::format!(
                        "preference `{}`: only bool, unsigned integers up to 32 bits and String",
                        field.key()
                    )));
                }
            };
            let default = defaults.get(field.key()).cloned().ok_or_else(|| {
                refused(alloc::format!(
                    "preference `{}` has no default",
                    field.key()
                ))
            })?;
            Ok(Preference {
                name: field.key().to_string(),
                title: text(field.title()),
                description: text(field.description()),
                kind,
                default,
            })
        })
        .collect()
}

/// For [`dissector!`](crate::dissector): `T` from a map the host passed.
#[doc(hidden)]
pub fn read<T: FromValue>(map: &Map) -> Result<T, ProviderError> {
    T::from_value(&map.to_value()?).map_err(refused)
}

/// Implements [`Dissector`](crate::Dissector) for a type implementing
/// [`ProtocolDissector`]: the description from its items, the header and
/// preferences read into its structs.
#[macro_export]
macro_rules! dissector {
    ($type:ty) => {
        impl $crate::Dissector for $type {
            fn describe(
                &self,
            ) -> ::core::result::Result<$crate::guatiao::Map, $crate::guatiao::library::ProviderError>
            {
                <$type as $crate::ProtocolDissector>::description()?.to_map()
            }

            fn dissect_on(
                &self,
                preferences: &$crate::guatiao::Map,
            ) -> ::core::result::Result<$crate::guatiao::List, $crate::guatiao::library::ProviderError>
            {
                let preferences = $crate::__private::read::<
                    <$type as $crate::ProtocolDissector>::Preferences,
                >(preferences)?;
                $crate::Binding::to_list(&<$type as $crate::ProtocolDissector>::dissect_on(
                    self,
                    &preferences,
                ))
            }

            fn dissect(
                &self,
                data: &[u8],
                header: &$crate::guatiao::Map,
                preferences: &$crate::guatiao::Map,
                packet: &mut dyn $crate::Packet,
                conversation: &mut $crate::guatiao::Map,
            ) -> ::core::result::Result<i64, $crate::guatiao::library::ProviderError> {
                let ::core::result::Result::Ok(header) = $crate::__private::read::<
                    <$type as $crate::ProtocolDissector>::Header,
                >(header) else {
                    return ::core::result::Result::Ok(0);
                };
                let preferences = $crate::__private::read::<
                    <$type as $crate::ProtocolDissector>::Preferences,
                >(preferences)?;
                <$type as $crate::ProtocolDissector>::dissect(
                    self,
                    data,
                    &header,
                    &preferences,
                    packet,
                    conversation,
                )
            }

            fn message_len(&self, header: &[u8]) -> i64 {
                <$type as $crate::ProtocolDissector>::message_len(self, header)
            }
        }
    };
}
