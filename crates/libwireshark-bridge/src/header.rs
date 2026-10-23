//! A description's header: laid out once, decoded for each packet into the
//! map `dissect` reads, and added to the tree when the packet is accepted.

use core::net::{Ipv4Addr, Ipv6Addr};
use guatiao::{Buffer, Map};
use libwireshark::{Encoding, PacketView};
use libwireshark_api as api;

/// One header field at its place.
#[derive(Debug)]
pub(crate) struct Laid {
    abbrev: String,
    kind: api::FieldType,
    offset: usize,
    width: usize,
    bitmask: Option<u64>,
    little_endian: bool,
}

/// The header's fields at their offsets: each where its `offset` says, else
/// right after the field before it.
///
/// # Errors
///
/// The abbreviation of a field with no width (`bytes` or `string` without
/// a `length`, `none`), or one wider than 8 bytes holding an integer.
pub(crate) fn lay_out(header: &[api::Field]) -> Result<Vec<Laid>, String> {
    let mut next = 0usize;
    header
        .iter()
        .map(|field| {
            let width = field.width().ok_or_else(|| field.abbrev.clone())? as usize;
            let offset = field.offset.map_or(next, |offset| offset as usize);
            next = offset + width;
            Ok(Laid {
                abbrev: field.abbrev.clone(),
                kind: field.kind,
                offset,
                width,
                bitmask: field.bitmask,
                little_endian: field.little_endian,
            })
        })
        .collect()
}

impl Laid {
    fn bytes<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        data.get(self.offset..self.offset.checked_add(self.width)?)
    }

    /// The field's integer, masked and shifted down by its bitmask.
    fn unsigned(&self, bytes: &[u8]) -> u64 {
        let fold = |value: u64, byte: &u8| value << 8 | u64::from(*byte);
        let raw = if self.little_endian {
            bytes.iter().rev().fold(0, fold)
        } else {
            bytes.iter().fold(0, fold)
        };
        match self.bitmask {
            Some(mask) if mask != 0 => (raw & mask) >> mask.trailing_zeros(),
            _ => raw,
        }
    }

    fn put(&self, data: &[u8], map: &mut Map) {
        let Some(bytes) = self.bytes(data) else {
            return;
        };
        let key = self.abbrev.as_str();
        match self.kind {
            api::FieldType::Bool => map.set(key, self.unsigned(bytes) != 0),
            kind if kind.is_signed() && self.bitmask.is_none() => {
                let bits = 64 - 8 * self.width as u32;
                map.set(key, ((self.unsigned(bytes) << bits) as i64) >> bits);
            }
            api::FieldType::U8
            | api::FieldType::U16
            | api::FieldType::U24
            | api::FieldType::U32
            | api::FieldType::U64
            | api::FieldType::I8
            | api::FieldType::I16
            | api::FieldType::I24
            | api::FieldType::I32
            | api::FieldType::I64 => map.set(key, self.unsigned(bytes)),
            api::FieldType::Ipv4 => {
                let octets: [u8; 4] = bytes.try_into().unwrap_or_default();
                map.set(key, Ipv4Addr::from(octets).to_string().as_str());
            }
            api::FieldType::Ipv6 => {
                let octets: [u8; 16] = bytes.try_into().unwrap_or_default();
                map.set(key, Ipv6Addr::from(octets).to_string().as_str());
            }
            api::FieldType::String => map.set(key, String::from_utf8_lossy(bytes).as_ref()),
            api::FieldType::Bytes | api::FieldType::Ether | api::FieldType::None => {
                map.set(key, Buffer::from(bytes));
            }
        }
    }

    fn add(&self, packet: &mut PacketView<'_>) {
        let encoding = if self.little_endian {
            Encoding::LITTLE_ENDIAN
        } else {
            Encoding::BIG_ENDIAN
        };
        // Past the captured bytes or with no tree: the packet stands without it.
        let _ = packet.add_item(&self.abbrev, self.offset, self.width, encoding);
    }
}

/// The header fields `data` holds whole, by abbreviation.
pub(crate) fn decode(header: &[Laid], data: &[u8]) -> Map {
    let mut map = Map::new();
    for field in header {
        field.put(data, &mut map);
    }
    map
}

/// Adds the header fields to the accepted packet's tree.
pub(crate) fn add(header: &[Laid], packet: &mut PacketView<'_>) {
    for field in header {
        field.add(packet);
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, lay_out};
    use guatiao::FromValue;
    use libwireshark_api::{Field, FieldType};

    fn number(map: &guatiao::Map, key: &str) -> i64 {
        i64::from_value(map.get(key).expect("decoded")).expect("a number")
    }

    #[test]
    fn fields_follow_each_other_unless_placed_and_masks_shift_down() {
        let mut flag = Field::new("flag", "Flag", FieldType::Bool);
        flag.offset = Some(1);
        flag.bitmask = Some(0x04);
        let mut high = Field::new("high", "High", FieldType::U8);
        high.offset = Some(1);
        high.bitmask = Some(0xf0);
        let mut little = Field::new("little", "Little", FieldType::U16);
        little.little_endian = true;
        let header = [
            Field::new("version", "Version", FieldType::U8),
            flag,
            high,
            little,
            Field::new("signed", "Signed", FieldType::I8),
        ];
        let laid = lay_out(&header).expect("all have widths");
        let map = decode(&laid, &[7, 0xa4, 0x34, 0x12, 0xff]);
        assert_eq!(number(&map, "version"), 7);
        assert!(bool::from_value(map.get("flag").expect("decoded")).expect("a bool"));
        assert_eq!(number(&map, "high"), 0xa);
        assert_eq!(number(&map, "little"), 0x1234, "after the masked byte");
        assert_eq!(number(&map, "signed"), -1);
    }

    #[test]
    fn a_field_past_the_data_is_left_out() {
        let laid = lay_out(&[
            Field::new("version", "Version", FieldType::U8),
            Field::new("length", "Length", FieldType::U16),
        ])
        .expect("widths");
        let map = decode(&laid, &[7, 1]);
        assert!(map.get("version").is_some());
        assert!(map.get("length").is_none());
    }

    #[test]
    fn a_field_without_a_width_is_named() {
        assert_eq!(
            lay_out(&[Field::new("payload", "Payload", FieldType::Bytes)]).unwrap_err(),
            "payload"
        );
    }
}
