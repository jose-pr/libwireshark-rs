//! A protocol described at run time: RFOO over UDP 112, FOO's twin, whose
//! names and fields are built when Wireshark loads the plugin rather than
//! declared as types. A plugin that learns its protocols from elsewhere (a
//! file, other plugins) is built this way.

#![forbid(unsafe_code)]

use libwireshark::dynamic::{DynamicDissector, Protocol, ProtocolSpec};
use libwireshark::{Binding, Encoding, FieldInfo, FieldType, PacketView};

const PORT: u16 = 112;

struct Rfoo;

impl DynamicDissector for Rfoo {
    fn bindings(&self) -> Vec<Binding> {
        vec![Binding::udp_port(PORT)]
    }

    fn dissect(&self, packet: &mut PacketView<'_>) -> Option<usize> {
        let version = packet.get_u8(0)?;
        let length = packet.get_u16_be(2)?;
        // A short capture or no tree leaves the rest of the dissection standing.
        let _ = packet.add_uint("version", 0, u32::from(version));
        let _ = packet.add_item("length", 2, 2, Encoding::BIG_ENDIAN);
        packet.set_info(&format!("RFOO version {version}, length {length}"));
        Some(packet.captured_len())
    }
}

/// The protocols this plugin registers, built when Wireshark loads it.
fn protocols() -> Vec<Protocol> {
    let fields = ["version", "length"]
        .into_iter()
        .zip([FieldType::U8, FieldType::U16])
        .map(|(abbrev, kind)| {
            let name: &'static str = capitalised(abbrev).leak();
            FieldInfo::new(name, abbrev, kind)
        })
        .collect();
    let spec = ProtocolSpec::new("Run-time FOO Protocol", "RFOO", "rfoo").with_fields(fields);
    vec![Protocol::dynamic(spec, Rfoo)]
}

fn capitalised(word: &str) -> String {
    let mut letters = word.chars();
    letters
        .next()
        .map(|first| first.to_uppercase().chain(letters).collect())
        .unwrap_or_default()
}

libwireshark::plugin!(dynamic = protocols);
