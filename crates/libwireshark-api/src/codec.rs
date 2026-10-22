//! Audio codecs: RTP payloads decoded for Wireshark's RTP player (and
//! sharkd's audio download).

use alloc::string::String;
use guatiao::library::{Object, ProviderError};
use guatiao::{FromValue, Map, Schema, ToValue};

/// An audio codec: `wireshark_codec`.
///
/// The host asks for [`describe`](Self::describe) once and registers the
/// codec; Wireshark [`open`](Self::open)s a [`Decoder`] per stream.
#[guatiao::kind(name = "wireshark_codec")]
pub trait Codec: Send + Sync {
    /// The codec, as a map in the shape of [`CodecDescription`].
    fn describe(&self) -> Result<Map, ProviderError>;

    /// A decoder for one stream, whose format (a map in the shape of
    /// [`StreamFormat`]) its SDP announced.
    fn open(&self, format: &Map) -> Result<Object<dyn Decoder>, ProviderError>;
}

/// One stream's decoder: `wireshark_decoder`, owned by the host.
#[guatiao::kind(object, name = "wireshark_decoder")]
pub trait Decoder: Send {
    /// The decoded samples per second.
    fn sample_rate(&self) -> i64;

    /// Interleaved channels in the decoded samples.
    fn channels(&self) -> i64;

    /// How many samples `payload` decodes to, at most.
    fn decoded_len(&self, payload: &[u8]) -> i64;

    /// Decodes `payload` into `samples`, 16-bit signed little-endian, two
    /// bytes each: the samples written.
    fn decode(&mut self, payload: &[u8], samples: &mut [u8]) -> i64;
}

/// What [`Codec::describe`] answers.
#[derive(Clone, Debug, Default, PartialEq, Eq, ToValue, FromValue, Schema)]
pub struct CodecDescription {
    /// The RTP encoding name it decodes, as an SDP `a=rtpmap` names it
    /// (`"L16"`, `"PCMU"`).
    pub name: String,
}

/// A stream's format, as [`Codec::open`] receives it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ToValue, FromValue, Schema)]
pub struct StreamFormat {
    /// The sample rate the SDP announced.
    pub sample_rate: Option<u32>,
    /// The channels the SDP announced.
    pub channels: Option<u32>,
}

impl CodecDescription {
    /// The map [`Codec::describe`] answers.
    ///
    /// # Errors
    ///
    /// When the map cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(crate::model::refused)
    }

    /// The description a [`Codec::describe`] map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(crate::model::refused)
    }
}

impl StreamFormat {
    /// The map [`Codec::open`] receives.
    ///
    /// # Errors
    ///
    /// When the map cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(crate::model::refused)
    }

    /// The format a [`Codec::open`] map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(crate::model::refused)
    }
}
