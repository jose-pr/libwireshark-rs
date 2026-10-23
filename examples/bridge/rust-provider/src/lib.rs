//! Plugins as guatiao providers, written in Rust: RSFOO over UDP 113 (a
//! preference), a twin of FOO, and in `extras` a tap listener, a
//! display-filter function, a capture format and a codec.
//! `libwireshark-bridge` loads this library and registers what it
//! describes; the library links no Wireshark.
//!
//! The header and the preferences are structs, as with `libwireshark`'s
//! `Dissector`: the host decodes the header and adds its fields, and asks
//! `dissect_on` where to bind with the current preferences.

#![forbid(unsafe_code)]

use libwireshark_api::guatiao::library::ProviderError;
use libwireshark_api::guatiao::{self, FromValue, Map, Provider, Schema, ToValue};
use libwireshark_api::{
    Base, Binding, Expert, ExpertGroup, ExpertInfo, Field, Packet, PacketExt, ProtocolDissector,
    Severity, header_fields,
};

/// The only version RSFOO knows.
const VERSION: u8 = 7;

/// RSFOO's header: field names are the abbreviations, doc comments the blurbs.
#[derive(Schema, FromValue)]
#[map(crate = ::libwireshark_api::guatiao)]
pub struct RsfooHeader {
    /// The protocol version.
    #[schema(title = "Version")]
    pub version: u8,
    /// Feature flags.
    #[schema(title = "Flags")]
    pub flags: u8,
    /// The message's length.
    #[schema(title = "Length")]
    pub length: u16,
}

/// A version RSFOO does not know.
pub struct UnknownVersion;

impl ExpertInfo for UnknownVersion {
    const ABBREV: &'static str = "unknown_version";
    const GROUP: ExpertGroup = ExpertGroup::Malformed;
    const SEVERITY: Severity = Severity::Warn;
    const SUMMARY: &'static str = "Unknown version";
}

/// RSFOO's preferences: doc comments are their descriptions.
#[derive(Schema, FromValue, ToValue)]
#[map(crate = ::libwireshark_api::guatiao)]
pub struct RsfooPreferences {
    /// UDP port RSFOO is decoded on.
    #[schema(title = "UDP port")]
    pub port: u16,
}

impl Default for RsfooPreferences {
    fn default() -> Self {
        Self { port: 113 }
    }
}

/// RSFOO: a version byte, a flags byte and a big-endian length.
#[derive(Default, Provider)]
#[provider(libwireshark_api::Dissector, crate = ::libwireshark_api::guatiao)]
pub struct Rsfoo;

impl ProtocolDissector for Rsfoo {
    const NAME: &'static str = "Rust FOO Protocol";
    const SHORT_NAME: &'static str = "RSFOO";
    const FILTER_NAME: &'static str = "rsfoo";
    type Header = RsfooHeader;
    type Preferences = RsfooPreferences;

    /// The struct's fields, with a name for version 7 and the flags in hex.
    fn header() -> Result<Vec<Field>, ProviderError> {
        let mut fields = header_fields::<RsfooHeader>()?;
        for field in &mut fields {
            match field.abbrev.as_str() {
                "version" => *field = field.clone().with_values([(u32::from(VERSION), "seven")]),
                "flags" => *field = field.clone().with_base(Base::Hex),
                _ => {}
            }
        }
        Ok(fields)
    }

    fn experts() -> Vec<Expert> {
        vec![UnknownVersion::expert()]
    }

    fn dissect_on(&self, preferences: &RsfooPreferences) -> Vec<Binding> {
        vec![Binding::udp_port(preferences.port)]
    }

    fn dissect(
        &self,
        data: &[u8],
        header: &RsfooHeader,
        _preferences: &RsfooPreferences,
        packet: &mut dyn Packet,
        conversation: &mut Map,
    ) -> Result<i64, ProviderError> {
        let mut count = conversation
            .get("count")
            .and_then(|count| i64::from_value(count).ok())
            .unwrap_or(0);
        if packet.is_first_pass() {
            count += 1;
            conversation.set("count", count);
        }
        if header.version != VERSION {
            packet.report(&UnknownVersion)?;
        }
        packet.set_info(&format!("RSFOO version {}, packet {count}", header.version));
        Ok(i64::try_from(data.len()).unwrap_or(i64::MAX))
    }
}

mod extras;

pub use extras::{RsDouble, RsTap, RsgCap, Rsl8};

libwireshark_api::dissector!(Rsfoo);
guatiao::providers!(Rsfoo, RsTap, RsDouble, RsgCap, Rsl8);
