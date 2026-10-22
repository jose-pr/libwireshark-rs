use libwireshark::{
    DissectResult, Dissector, NoHeader, NoPreferences, PacketView, ProtocolRegistration,
    WiresharkPlugin, wireshark_plugin,
};
#[wireshark_plugin]
struct FooPlugin;

const FOO_PROTOCOLS: &[ProtocolRegistration] = &[
    ProtocolRegistration::dissector::<TcpDissector>(),
    ProtocolRegistration::dissector::<UdpDissector>(),
];

impl WiresharkPlugin for FooPlugin {
    fn protocols() -> &'static [ProtocolRegistration] {
        FOO_PROTOCOLS
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
        let version = packet.get_u8(0)?;
        Some(
            DissectResult::new(NoHeader, length)
                .with_info(format!("FOO over TCP, version {version}, {length} bytes")),
        )
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
        let version = packet.get_u8(0)?;
        Some(
            DissectResult::new(NoHeader, length)
                .with_info(format!("FOO over UDP, version {version}, {length} bytes")),
        )
    }
}
