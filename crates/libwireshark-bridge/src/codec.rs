//! Audio codecs from providers: a decoder per stream, which the provider
//! answers.

use crate::describe;
use crate::host::{report, served};
use guatiao::library::Object;
use libwireshark::StreamFormat;
use libwireshark::dynamic::{Codec, DynamicCodec};
use libwireshark_api::{self as api, CodecDescription, Decoder};
use std::collections::HashSet;

/// Every codec offered; a name taken earlier is skipped.
pub(crate) fn codecs(registry: &guatiao::library::Registry) -> Vec<Codec> {
    let mut names = HashSet::new();
    let mut codecs = Vec::new();
    for (key, codec) in served::<dyn api::Codec>(registry) {
        let description = match codec
            .describe()
            .and_then(|map| CodecDescription::from_map(&map))
        {
            Ok(description) => description,
            Err(error) => {
                report(true, &format!("{key}: describe: {}", error.message()));
                continue;
            }
        };
        let name = &description.name;
        if name.is_empty() || name.contains('\0') || !names.insert(name.clone()) {
            report(
                true,
                &format!("{key}: the codec name {name:?} is empty or offered already"),
            );
            continue;
        }
        report(false, &format!("{key} decodes {name}"));
        let key: &'static str = describe::leak(&key);
        codecs.push(Codec::new(
            describe::leak(name),
            move |format: &StreamFormat| {
                Box::new(Decoding::open(key, &*codec, format)) as Box<dyn DynamicCodec>
            },
        ));
    }
    codecs
}

/// One stream's decoder: the provider's, or none when it would not open one.
struct Decoding {
    decoder: Option<Object<dyn Decoder>>,
}

impl Decoding {
    fn open(key: &str, codec: &dyn api::Codec, format: &StreamFormat) -> Self {
        let format = api::StreamFormat {
            sample_rate: format.sample_rate,
            channels: format.channels,
        };
        let decoder = format.to_map().and_then(|format| codec.open(&format));
        match decoder {
            Ok(decoder) => Self {
                decoder: Some(decoder),
            },
            Err(error) => {
                report(true, &format!("{key}: open: {}", error.message()));
                Self { decoder: None }
            }
        }
    }
}

impl DynamicCodec for Decoding {
    fn sample_rate(&self) -> u32 {
        self.decoder.as_ref().map_or(0, |decoder| {
            u32::try_from(decoder.sample_rate()).unwrap_or(0)
        })
    }

    fn channels(&self) -> u32 {
        self.decoder
            .as_ref()
            .map_or(1, |decoder| u32::try_from(decoder.channels()).unwrap_or(1))
    }

    fn decoded_len(&self, payload: &[u8]) -> usize {
        self.decoder.as_ref().map_or(0, |decoder| {
            usize::try_from(decoder.decoded_len(payload)).unwrap_or(0)
        })
    }

    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize {
        let Some(decoder) = &mut self.decoder else {
            return 0;
        };
        let mut bytes = vec![0u8; samples.len() * 2];
        let written = usize::try_from(decoder.decode(payload, &mut bytes))
            .unwrap_or(0)
            .min(samples.len());
        let (pairs, _) = bytes.as_chunks::<2>();
        for (sample, pair) in samples.iter_mut().zip(pairs).take(written) {
            *sample = i16::from_le_bytes(*pair);
        }
        written
    }
}
