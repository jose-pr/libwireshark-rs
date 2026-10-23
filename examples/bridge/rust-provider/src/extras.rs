//! The other kinds of plugin, as providers: the `rstap` tap listener, the
//! `rs_double` display-filter function, the RSGCAP capture format and the
//! RSL8 codec.

use libwireshark_api::guatiao::library::{Object, ProviderError};
use libwireshark_api::guatiao::{FromValue, Map, Provider, Status, Value};
use libwireshark_api::{
    CaptureReader, CaptureRecord, CaptureSource, Codec, CodecDescription, Decoder, FileType,
    FileTypeDescription, FilterDescription, FilterFunction, FilterReturn, StreamFormat, Tap,
    TapDescription, TapListener, TapPacket,
};

/// `-z rstap`: frames and bytes seen.
#[derive(Default, Provider)]
#[provider(libwireshark_api::Tap, crate = ::libwireshark_api::guatiao)]
pub struct RsTap;

impl Tap for RsTap {
    fn describe(&self) -> Result<Map, ProviderError> {
        TapDescription {
            name: "rstap".into(),
            tap: "frame".into(),
        }
        .to_map()
    }

    fn open(&self) -> Result<Object<dyn TapListener>, ProviderError> {
        Ok(Totals::default().into_object())
    }
}

/// One invocation's totals.
#[derive(Default)]
struct Totals {
    frames: u64,
    bytes: u64,
}

impl TapListener for Totals {
    fn packet(&mut self, packet: &Map) -> Result<(), ProviderError> {
        let packet = TapPacket::from_map(packet)?;
        self.frames += 1;
        self.bytes += u64::from(packet.len);
        Ok(())
    }

    fn draw(&mut self) -> Result<String, ProviderError> {
        Ok(format!(
            "rstap: {} frames, {} bytes\n",
            self.frames, self.bytes
        ))
    }

    fn reset(&mut self) -> Result<(), ProviderError> {
        *self = Self::default();
        Ok(())
    }
}

/// `rs_double(field)`: twice an integer field's value.
#[derive(Default, Provider)]
#[provider(libwireshark_api::FilterFunction, crate = ::libwireshark_api::guatiao)]
pub struct RsDouble;

impl FilterFunction for RsDouble {
    fn describe(&self) -> Result<Map, ProviderError> {
        FilterDescription {
            name: "rs_double".into(),
            returns: FilterReturn::Count,
        }
        .to_map()
    }

    fn call(&self, value: &Value) -> Result<Value, ProviderError> {
        Ok(u32::from_value(value)
            .ok()
            .and_then(|number| number.checked_mul(2))
            .map_or_else(Value::null, Value::from))
    }
}

/// RSGCAP: an 8-byte magic, then records of a nanosecond time, the
/// captured and original lengths (little-endian) and the captured bytes.
#[derive(Default, Provider)]
#[provider(libwireshark_api::FileType, crate = ::libwireshark_api::guatiao)]
pub struct RsgCap;

const MAGIC: &[u8; 8] = b"RSGCAP\0\x01";

/// Reads exactly `buffer.len()` bytes: `false` at a clean end of file.
fn read_exact(file: &mut dyn CaptureSource, buffer: &mut [u8]) -> Result<bool, ProviderError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            0 if filled == 0 => return Ok(false),
            read if read <= 0 => {
                return Err(ProviderError::new(
                    Status::GUATIAO_ERR_BAD_VALUE,
                    "a short record",
                ));
            }
            read => filled += usize::try_from(read).unwrap_or(0),
        }
    }
    Ok(true)
}

impl FileType for RsgCap {
    fn describe(&self) -> Result<Map, ProviderError> {
        FileTypeDescription {
            name: "rsgcap".into(),
            description: "RSGCAP example capture, read by a guatiao provider".into(),
            extensions: vec!["rsgcap".into()],
        }
        .to_map()
    }

    fn open(
        &self,
        file: &mut dyn CaptureSource,
    ) -> Result<Object<dyn CaptureReader>, ProviderError> {
        let mut magic = [0; 8];
        if !read_exact(file, &mut magic).unwrap_or(false) || &magic != MAGIC {
            return Err(ProviderError::new(
                Status::GUATIAO_ERR_NOT_FOUND,
                "not RSGCAP",
            ));
        }
        Ok(RsgCapReader.into_object())
    }
}

struct RsgCapReader;

impl CaptureReader for RsgCapReader {
    fn encapsulation(&self) -> i64 {
        1
    }

    fn read(&mut self, file: &mut dyn CaptureSource) -> Result<Map, ProviderError> {
        let mut header = [0; 16];
        if !read_exact(file, &mut header)? {
            return Ok(Map::new());
        }
        let [time, lengths] = [&header[..8], &header[8..]];
        let time = u64::from_le_bytes(time.try_into().expect("eight bytes"));
        let captured = u32::from_le_bytes(lengths[..4].try_into().expect("four bytes"));
        let original = u32::from_le_bytes(lengths[4..].try_into().expect("four bytes"));
        if captured > 262_144 {
            return Err(ProviderError::new(
                Status::GUATIAO_ERR_BAD_VALUE,
                "a record too long",
            ));
        }
        let mut data = vec![0; captured as usize];
        if !read_exact(file, &mut data)? && captured > 0 {
            return Err(ProviderError::new(
                Status::GUATIAO_ERR_BAD_VALUE,
                "a short record",
            ));
        }
        CaptureRecord {
            data: data.into(),
            time_ns: i64::try_from(time).ok(),
            original_len: Some(original),
        }
        .to_map()
    }
}

/// RSL8: unsigned 8-bit samples, at the stream's rate (8 kHz unless the
/// SDP says).
#[derive(Default, Provider)]
#[provider(libwireshark_api::Codec, crate = ::libwireshark_api::guatiao)]
pub struct Rsl8;

impl Codec for Rsl8 {
    fn describe(&self) -> Result<Map, ProviderError> {
        CodecDescription {
            name: "RSL8".into(),
        }
        .to_map()
    }

    fn open(&self, format: &Map) -> Result<Object<dyn Decoder>, ProviderError> {
        let format = StreamFormat::from_map(format)?;
        Ok(Rsl8Decoder {
            rate: format.sample_rate.unwrap_or(8000),
        }
        .into_object())
    }
}

struct Rsl8Decoder {
    rate: u32,
}

impl Decoder for Rsl8Decoder {
    fn sample_rate(&self) -> i64 {
        i64::from(self.rate)
    }

    fn channels(&self) -> i64 {
        1
    }

    fn decoded_len(&self, payload: &[u8]) -> i64 {
        i64::try_from(payload.len()).unwrap_or(i64::MAX)
    }

    fn decode(&mut self, payload: &[u8], samples: &mut [u8]) -> i64 {
        let (samples, _) = samples.as_chunks_mut::<2>();
        for (sample, byte) in samples.iter_mut().zip(payload) {
            *sample = ((i16::from(*byte) - 128) << 8).to_le_bytes();
        }
        i64::try_from(payload.len().min(samples.len())).unwrap_or(0)
    }
}
