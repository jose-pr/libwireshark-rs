use libwireshark::{
    DissectResult, Dissector, NoHeader, NoPreferences, PacketView, ProtocolRegistration,
    WiresharkPlugin, wireshark_plugin,
};
#[wireshark_plugin]
struct TcpPlugin;

const TCP_PROTOCOLS: &[ProtocolRegistration] = &[ProtocolRegistration::dissector::<TcpDissector>()];

impl WiresharkPlugin for TcpPlugin {
    fn protocols() -> &'static [ProtocolRegistration] {
        TCP_PROTOCOLS
    }
}

struct TcpDissector;

impl Dissector for TcpDissector {
    type Preferences = NoPreferences;
    type Header = NoHeader;

    const NAME: &'static str = "FOO over TCP";
    const SHORT_NAME: &'static str = "FOO-TCP";
    const FILTER_NAME: &'static str = "foo_tcp";
    const DISSECT_ON: &'static [libwireshark::DissectorAdd] =
        &[libwireshark::DissectorAdd::Uint("tcp.port", 4242, false)];

    fn dissect(
        _: &Self::Preferences,
        packet: &mut PacketView<'_>,
    ) -> Option<DissectResult<Self::Header>> {
        let length = packet.captured_len();
        if length == 0 {
            return None;
        }
        let Some(version) = packet.get_u8(0) else {
            return None;
        };
        Some(
            DissectResult::new(NoHeader, length)
                .with_info(format!("FOO over TCP, version {version}, {length} bytes")),
        )
    }
}
