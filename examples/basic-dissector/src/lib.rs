//! One protocol, FOO over UDP: preferences, header fields decoded from the
//! packet, and a port the user can change.

#![forbid(unsafe_code)]

use libwireshark::{Binding, DissectResult, Dissector, Header, PacketView, Preferences};

/// FOO's settings, under Edit › Preferences › Protocols › FOO.
#[derive(Preferences)]
struct FooPreferences {
    #[preference(title = "UDP port", description = "UDP port FOO is decoded on")]
    port: u16,
    #[preference(
        title = "Show payload summary",
        description = "Add the payload size to the Info column"
    )]
    show_summary: bool,
    #[preference(title = "Label", description = "Text the Info column starts with")]
    label: String,
}

impl Default for FooPreferences {
    fn default() -> Self {
        Self {
            port: 111,
            show_summary: true,
            label: "FOO".to_owned(),
        }
    }
}

/// FOO's four-byte header; filter on `foo.version`, `foo.flags`, `foo.length`.
#[derive(Header)]
struct FooHeader {
    #[header(name = "Version", blurb = "Protocol version")]
    version: u8,
    #[header(name = "Flags", display = "hex")]
    flags: u8,
    #[header(name = "Length")]
    length: u16,
}

struct Foo;

impl Dissector for Foo {
    type Preferences = FooPreferences;
    type Header = FooHeader;

    const NAME: &'static str = "FOO Protocol";
    const SHORT_NAME: &'static str = "FOO";
    const FILTER_NAME: &'static str = "foo";

    fn dissect_on(preferences: &FooPreferences) -> Vec<Binding> {
        vec![Binding::udp_port(preferences.port)]
    }

    fn dissect(
        preferences: &FooPreferences,
        packet: &mut PacketView<'_>,
    ) -> Option<DissectResult<FooHeader>> {
        let header = FooHeader::decode(packet.bytes())?;
        let mut info = format!("{} version {}", preferences.label, header.version);
        if preferences.show_summary {
            info.push_str(&format!(", length {}", header.length));
        }
        Some(DissectResult::new(header, packet.captured_len()).with_info(info))
    }
}

libwireshark::plugin!(Foo);
