//! Two protocols in one plugin, on fixed ports: BAR over TCP and BAZ over UDP.

#![forbid(unsafe_code)]

use libwireshark::{Binding, DissectResult, Dissector, Header, NoPreferences, PacketView};

/// A one-byte version, shared by both protocols' headers.
#[derive(Header)]
struct Version {
    #[header(name = "Version")]
    version: u8,
}

struct Bar;

impl Dissector for Bar {
    type Preferences = NoPreferences;
    type Header = Version;

    const NAME: &'static str = "BAR over TCP";
    const SHORT_NAME: &'static str = "BAR";
    const FILTER_NAME: &'static str = "bar";

    fn dissect_on(_: &NoPreferences) -> Vec<Binding> {
        vec![Binding::tcp_port(4242)]
    }

    fn dissect(_: &NoPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<Version>> {
        let header = Version::decode(packet.bytes())?;
        let info = format!(
            "BAR version {}, {} bytes",
            header.version,
            packet.captured_len()
        );
        Some(DissectResult::new(header, packet.captured_len()).with_info(info))
    }
}

struct Baz;

impl Dissector for Baz {
    type Preferences = NoPreferences;
    type Header = Version;

    const NAME: &'static str = "BAZ over UDP";
    const SHORT_NAME: &'static str = "BAZ";
    const FILTER_NAME: &'static str = "baz";

    fn dissect_on(_: &NoPreferences) -> Vec<Binding> {
        vec![Binding::udp_port(4242)]
    }

    fn dissect(_: &NoPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<Version>> {
        let header = Version::decode(packet.bytes())?;
        let info = format!(
            "BAZ version {}, {} bytes",
            header.version,
            packet.captured_len()
        );
        Some(DissectResult::new(header, packet.captured_len()).with_info(info))
    }
}

libwireshark::plugin!(Bar, Baz);
