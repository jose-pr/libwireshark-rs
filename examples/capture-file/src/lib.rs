//! A capture file format, RSCAP, which Wireshark 4.6 and later open like a
//! pcap: `tshark -r capture.rscap`. Install the library in the `wiretap`
//! plugin directory.
//!
//! An RSCAP file is the magic `RSCAP\0\0\x01`, then per packet a 16-byte
//! little-endian header (capture time in nanoseconds since the Unix epoch,
//! captured length, length on the wire) and the captured Ethernet frame.

#![forbid(unsafe_code)]

use libwireshark::{CaptureFile, Encapsulation, FileType, Record};
use std::io::{self, Read};
use std::time::Duration;

const MAGIC: &[u8; 8] = b"RSCAP\0\0\x01";

/// The largest captured length accepted, so a corrupt header cannot ask
/// for gigabytes.
const MAX_CAPTURED: u32 = 262_144;

struct Rscap;

impl FileType for Rscap {
    const NAME: &'static str = "rscap";
    const DESCRIPTION: &'static str = "RSCAP example capture";
    const EXTENSIONS: &'static [&'static str] = &["rscap"];

    fn open(file: &mut CaptureFile<'_>) -> io::Result<Option<Self>> {
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        Ok((&magic == MAGIC).then_some(Rscap))
    }

    fn encapsulation(&self) -> Encapsulation {
        Encapsulation::ETHERNET
    }

    fn read(&self, file: &mut CaptureFile<'_>, record: &mut Record<'_>) -> io::Result<bool> {
        let mut header = [0; 16];
        let start = file.read(&mut header)?;
        if start == 0 {
            return Ok(false);
        }
        file.read_exact(&mut header[start..])?;
        let time = u64::from_le_bytes(header[..8].try_into().expect("eight bytes"));
        let captured = u32::from_le_bytes(header[8..12].try_into().expect("four bytes"));
        let original = u32::from_le_bytes(header[12..16].try_into().expect("four bytes"));
        if captured > MAX_CAPTURED || original < captured {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("rscap: record of {captured} bytes, {original} on the wire"),
            ));
        }
        record.set_time(Duration::from_nanos(time));
        record.set_original_len(original);
        record.read_data(file, captured as usize)?;
        Ok(true)
    }
}

libwireshark::plugin!(file_types = [Rscap]);
