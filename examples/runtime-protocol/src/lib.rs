//! What a plugin registers at run time: RFOO over UDP 112 (a preference),
//! FOO's twin, whose names, fields and preferences are built when Wireshark
//! loads the plugin rather than declared as types; the `rtap` tap listener,
//! counting frames; the `rdouble` display-filter function; the RRCAP
//! capture format (Wireshark 4.6 on); and the RL8 codec. A plugin that
//! learns what it provides from elsewhere (a file, other plugins) is built
//! this way. Installed in `epan/`, it still provides the format and codec.

#![forbid(unsafe_code)]

use libwireshark::dynamic::{
    Codec, DynamicCodec, DynamicDissector, DynamicFileType, DynamicFilterFunction, DynamicReader,
    DynamicTap, FileType, FilterFunction, FilterReturn, FilterValue, Protocol, ProtocolSpec,
    Registrations, Tap,
};
use libwireshark::prefs::{Declaration, PreferenceMap, Value};
use libwireshark::{
    Binding, CaptureFile, Encapsulation, Encoding, FieldInfo, FieldType, FieldValue, PacketView,
    Record, StreamFormat, TapPacket,
};
use std::io::{self, Read};
use std::time::Duration;

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

/// RRCAP: an 8-byte magic, then records of a nanosecond time, the captured
/// and original lengths (little-endian) and the captured bytes.
struct Rrcap;

const MAGIC: &[u8; 8] = b"RRCAP\0\0\x01";

/// The most bytes of one record.
const MAX_CAPTURED: u32 = 262_144;

impl DynamicFileType for Rrcap {
    fn open(&self, file: &mut CaptureFile<'_>) -> io::Result<Option<Box<dyn DynamicReader>>> {
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        Ok((&magic == MAGIC).then(|| Box::new(RrcapReader) as Box<dyn DynamicReader>))
    }
}

struct RrcapReader;

impl DynamicReader for RrcapReader {
    fn encapsulation(&self) -> Encapsulation {
        Encapsulation::ETHERNET
    }

    fn read(&mut self, file: &mut CaptureFile<'_>, record: &mut Record<'_>) -> io::Result<bool> {
        let mut header = [0; 16];
        let start = file.read(&mut header)?;
        if start == 0 {
            return Ok(false);
        }
        file.read_exact(&mut header[start..])?;
        let [time, lengths] = [&header[..8], &header[8..]];
        let time = u64::from_le_bytes(time.try_into().expect("eight bytes"));
        let captured = u32::from_le_bytes(lengths[..4].try_into().expect("four bytes"));
        let original = u32::from_le_bytes(lengths[4..].try_into().expect("four bytes"));
        if captured > MAX_CAPTURED || original < captured {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("rrcap: record of {captured} bytes, {original} on the wire"),
            ));
        }
        record.set_time(Duration::from_nanos(time));
        record.set_original_len(original);
        record.read_data(file, captured as usize)?;
        Ok(true)
    }
}

/// RL8: unsigned 8-bit samples, as L8, at the stream's rate (8 kHz unless
/// the SDP says).
struct Rl8 {
    rate: u32,
}

impl DynamicCodec for Rl8 {
    fn sample_rate(&self) -> u32 {
        self.rate
    }

    fn decoded_len(&self, payload: &[u8]) -> usize {
        payload.len()
    }

    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize {
        for (sample, byte) in samples.iter_mut().zip(payload) {
            *sample = (i16::from(*byte) - 128) << 8;
        }
        payload.len().min(samples.len())
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
    registrations.file_types.push(FileType::new(
        "rrcap",
        "RRCAP example capture, registered at run time",
        &["rrcap"],
        Rrcap,
    ));
    registrations
        .codecs
        .push(Codec::new("RL8", |format: &StreamFormat| {
            Box::new(Rl8 {
                rate: format.sample_rate.unwrap_or(8000),
            }) as Box<dyn DynamicCodec>
        }));
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
