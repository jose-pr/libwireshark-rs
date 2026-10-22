use libwireshark::{
    DissectResult, Dissector, NoHeader, NoPreferences, PacketView, ProtocolRegistration,
    WiresharkPlugin, wireshark_plugin,
};
#[wireshark_plugin]
struct UdpPlugin;

const UDP_PROTOCOLS: &[ProtocolRegistration] = &[ProtocolRegistration::dissector::<UdpDissector>()];

impl WiresharkPlugin for UdpPlugin {
    fn protocols() -> &'static [ProtocolRegistration] {
        UDP_PROTOCOLS
    }
}

struct UdpDissector;

impl Dissector for UdpDissector {
    type Preferences = NoPreferences;
    type Header = NoHeader;

    const NAME: &'static str = "FOO over UDP";
    const SHORT_NAME: &'static str = "FOO-UDP";
    const FILTER_NAME: &'static str = "foo_udp";
    const DISSECT_ON: &'static [libwireshark::DissectorAdd] =
        &[libwireshark::DissectorAdd::Uint("udp.port", 4242, false)];

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
                .with_info(format!("FOO over UDP, version {version}, {length} bytes")),
        )
    }
}
