//! An audio codec, L8 (RFC 3551: 8-bit samples offset by 128), which
//! Wireshark's RTP player and `sharkd` use for RTP payloads an SDP
//! `a=rtpmap:<type> L8/<rate>` names. Install the library in the `codecs`
//! plugin directory.

#![forbid(unsafe_code)]

use libwireshark::{Codec, StreamFormat};

/// RFC 3551 gives L8 no fixed rate; SDP's `a=rtpmap` names one.
const DEFAULT_RATE: u32 = 8000;

struct L8 {
    rate: u32,
}

impl Codec for L8 {
    const NAME: &'static str = "L8";

    fn new(format: &StreamFormat) -> Self {
        Self {
            rate: format.sample_rate.unwrap_or(DEFAULT_RATE),
        }
    }

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

libwireshark::plugin!(codecs = [L8]);
