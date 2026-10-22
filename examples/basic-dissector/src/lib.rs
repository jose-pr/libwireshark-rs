use ws_runtime::{
    DissectResult, Dissector, Header, PacketView, Preferences, ProtocolRegistration,
    WiresharkPlugin, wireshark_plugin,
};

#[derive(Preferences)]
struct FooPreferences {
    #[preference(
        title = "Show payload summary",
        description = "Append a summary to the Info column"
    )]
    show_summary: bool,
    #[preference(
        name = "max_bytes",
        title = "Maximum bytes",
        description = "Maximum payload bytes to report"
    )]
    max_bytes: u32,
    label: String,
    #[preference(
        title = "UDP port",
        description = "UDP destination port used to select this dissector"
    )]
    port: u32,
}

impl Default for FooPreferences {
    fn default() -> Self {
        Self {
            show_summary: true,
            max_bytes: 256,
            label: "FOO".to_owned(),
            port: 111,
        }
    }
}

struct FooDissector;

#[wireshark_plugin]
struct FooPlugin;

const FOO_PROTOCOLS: &[ProtocolRegistration] = &[ProtocolRegistration::dissector::<FooDissector>()];

impl WiresharkPlugin for FooPlugin {
    fn protocols() -> &'static [ProtocolRegistration] {
        FOO_PROTOCOLS
    }
}

#[derive(Header)]
#[allow(dead_code)]
struct FooHeader {
    #[header(abbrev = "foton.version", name = "Version", blurb = "Protocol version")]
    version: u8,
}

impl Dissector for FooDissector {
    type Preferences = FooPreferences;
    type Header = FooHeader;

    const NAME: &'static str = "FOO2";
    const SHORT_NAME: &'static str = "foos";
    const FILTER_NAME: &'static str = "foton";
    const PREFERENCE_DRIVEN_DISSECT_ON: bool = true;

    fn dissect_on(preferences: &Self::Preferences) -> Vec<ws_runtime::DissectorAdd> {
        vec![ws_runtime::DissectorAdd::Uint(
            "udp.port",
            preferences.port,
            false,
        )]
    }

    fn dissect(
        preferences: &Self::Preferences,
        packet: &mut PacketView<'_>,
    ) -> Option<DissectResult<Self::Header>> {
        let captured = packet.captured_len();
        if captured == 0 {
            return None;
        }
        let Some(version) = packet.get_u8(0) else {
            return None;
        };
        let mut result = DissectResult::new(FooHeader { version }, captured);
        if preferences.show_summary {
            let length = captured.min(preferences.max_bytes as usize);
            result = result.with_info(format!(
                "{} version {version} ({length} bytes)",
                preferences.label
            ));
        }
        Some(result)
    }
}
