//! What a plugin registers at run time: RFOO over UDP 112 (a preference),
//! FOO's twin, whose names, fields and preferences are built when Wireshark
//! loads the plugin rather than declared as types; the `rtap` tap listener,
//! counting frames; and the `rdouble` display-filter function. A plugin that
//! learns what it provides from elsewhere (a file, other plugins) is built
//! this way.

#![forbid(unsafe_code)]

use libwireshark::dynamic::{
    DynamicDissector, DynamicFilterFunction, DynamicTap, FilterFunction, FilterReturn, FilterValue,
    Protocol, ProtocolSpec, Registrations, Tap,
};
use libwireshark::prefs::{Declaration, PreferenceMap, Value};
use libwireshark::{Binding, Encoding, FieldInfo, FieldType, FieldValue, PacketView, TapPacket};

const PORT: u32 = 112;

struct Rfoo;

impl DynamicDissector for Rfoo {
    /// The UDP port.
    type Preferences = u16;

    fn preferences(&self, values: &PreferenceMap) -> Option<u16> {
        match values.get("port")? {
            Value::Uint(port) => u16::try_from(*port).ok(),
            _ => None,
        }
    }

    fn dissect_on(&self, port: &u16) -> Vec<Binding> {
        vec![Binding::udp_port(*port)]
    }

    fn dissect(&self, _port: &u16, packet: &mut PacketView<'_>) -> Option<usize> {
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
    let port = Declaration::new(
        "port",
        "UDP port",
        "UDP port RFOO is decoded on",
        Value::Uint(PORT),
    );
    let spec = ProtocolSpec::new("Run-time FOO Protocol", "RFOO", "rfoo")
        .with_fields(fields)
        .with_preferences(vec![port]);
    vec![Protocol::dynamic(spec, Rfoo)]
}

/// `-z rtap`: counts the frames.
#[derive(Default)]
struct FrameCount(u64);

impl DynamicTap for FrameCount {
    fn packet(&mut self, _packet: &TapPacket<'_>) {
        self.0 += 1;
    }

    fn draw(&self) -> String {
        format!(
            "rtap: {} frames
",
            self.0
        )
    }

    fn reset(&mut self) {
        self.0 = 0;
    }
}

/// `rdouble(field)`: twice an unsigned field's value.
struct Double;

impl DynamicFilterFunction for Double {
    fn call(&self, value: &FieldValue<'_>) -> Option<FilterValue> {
        let doubled = value.as_u64()?.checked_mul(2)?;
        Some(FilterValue::Count(u32::try_from(doubled).ok()?))
    }
}

/// Everything this plugin registers, built when Wireshark loads it.
fn registrations() -> Registrations {
    let mut registrations = Registrations::from(protocols());
    registrations.taps.push(Tap::new(
        "rtap",
        "frame",
        || Box::new(FrameCount::default()),
    ));
    registrations
        .filters
        .push(FilterFunction::new("rdouble", FilterReturn::Count, Double));
    registrations
}

fn capitalised(word: &str) -> String {
    let mut letters = word.chars();
    letters
        .next()
        .map(|first| first.to_uppercase().chain(letters).collect())
        .unwrap_or_default()
}

libwireshark::plugin!(dynamic = registrations);
