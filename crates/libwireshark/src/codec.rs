//! Audio codecs: decoders Wireshark's RTP player and `sharkd` use for RTP
//! payloads.
//!
//! Wireshark looks for codecs only in libraries in the `codecs` plugin
//! directory, and loads them after protocols are registered, so a codec
//! library holds codecs and nothing else.

/// A decoder of one RTP payload format to 16-bit samples.
///
/// Wireshark finds it by its payload format's name: the one an SDP
/// `a=rtpmap` line gives a dynamic payload type, or the name of a static
/// payload type.
///
/// ```no_run
/// use libwireshark::{Codec, StreamFormat};
///
/// /// L8 (RFC 3551): unsigned 8-bit samples, offset by 128.
/// struct L8 {
///     rate: u32,
/// }
///
/// impl Codec for L8 {
///     const NAME: &'static str = "L8";
///
///     fn new(format: &StreamFormat) -> Self {
///         L8 { rate: format.sample_rate.unwrap_or(8000) }
///     }
///
///     fn sample_rate(&self) -> u32 {
///         self.rate
///     }
///
///     fn decoded_len(&self, payload: &[u8]) -> usize {
///         payload.len()
///     }
///
///     fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize {
///         for (sample, byte) in samples.iter_mut().zip(payload) {
///             *sample = (i16::from(*byte) - 128) << 8;
///         }
///         payload.len().min(samples.len())
///     }
/// }
///
/// libwireshark::plugin!(codecs = [L8]);
/// ```
pub trait Codec: 'static {
    /// The payload format's name; Wireshark compares it ignoring case.
    const NAME: &'static str;

    /// A decoder for one stream.
    fn new(format: &StreamFormat) -> Self;

    /// The decoded samples' rate, in Hz.
    fn sample_rate(&self) -> u32;

    /// How many channels the samples interleave; Wireshark's player plays
    /// one.
    fn channels(&self) -> u32 {
        1
    }

    /// How many samples `payload` decodes to, at most.
    fn decoded_len(&self, payload: &[u8]) -> usize;

    /// Decodes `payload` into `samples`, which holds
    /// [`decoded_len`](Self::decoded_len) of them; returns how many it wrote.
    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize;
}

/// What the capture says of a stream's format, from SDP; `None` where it
/// says nothing, and always before Wireshark 4.2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamFormat {
    /// The clock rate of `a=rtpmap`, in Hz.
    pub sample_rate: Option<u32>,
    /// The channel count of `a=rtpmap`.
    pub channels: Option<u32>,
}
