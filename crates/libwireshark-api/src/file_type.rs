//! Capture file formats: files Wireshark opens with `-r` (from 4.6).

use alloc::string::String;
use alloc::vec::Vec;
use guatiao::library::{Object, ProviderError};
use guatiao::{Bytes, FromValue, Map, Schema, ToValue};

/// A capture file format: `wireshark_file_type`.
///
/// The host asks for [`describe`](Self::describe) once and registers the
/// format; Wireshark then offers each file it opens to
/// [`open`](Self::open), which answers a reader or
/// `GUATIAO_ERR_NOT_FOUND` for a file of another format.
#[guatiao::kind(name = "wireshark_file_type")]
pub trait FileType: Send + Sync {
    /// The format, as a map in the shape of [`FileTypeDescription`].
    fn describe(&self) -> Result<Map, ProviderError>;

    /// The reader of `file`, positioned at its start; refused with
    /// `GUATIAO_ERR_NOT_FOUND` when it is not in this format, any other
    /// status for a read error.
    fn open(
        &self,
        file: &mut dyn CaptureSource,
    ) -> Result<Object<dyn CaptureReader>, ProviderError>;
}

/// An open file's reader: `wireshark_capture_reader`, owned by the host.
/// Wireshark reads a file from one thread, one record at a time; for a
/// second pass it repositions `file` at a record's start before reading.
#[guatiao::kind(object, name = "wireshark_capture_reader")]
pub trait CaptureReader: Send {
    /// The link-layer type of every record (`WTAP_ENCAP_*`: 1 is Ethernet).
    fn encapsulation(&self) -> i64;

    /// The record at `file`'s position, as a map in the shape of
    /// [`CaptureRecord`]; an empty map at the end of the file.
    fn read(&mut self, file: &mut dyn CaptureSource) -> Result<Map, ProviderError>;
}

/// The file being read: `wireshark_capture_source`, lent by the host for a
/// call. Reads go through Wireshark, which undoes compression.
#[guatiao::kind(object, name = "wireshark_capture_source")]
pub trait CaptureSource: Send {
    /// Reads into `buffer`: the bytes read, 0 at the end of the file, -1
    /// on an error.
    fn read(&mut self, buffer: &mut [u8]) -> i64;

    /// The position in the file, in bytes from its start.
    fn position(&self) -> i64;
}

/// What [`FileType::describe`] answers.
#[derive(Clone, Debug, Default, PartialEq, Eq, ToValue, FromValue, Schema)]
pub struct FileTypeDescription {
    /// The format's short name, as `tshark -F` lists it.
    pub name: String,
    /// Its name for people.
    pub description: String,
    /// The extensions its files end in, without the dot.
    #[map(default)]
    pub extensions: Vec<String>,
}

/// One record, as [`CaptureReader::read`] answers it.
#[derive(Clone, Debug, Default, PartialEq, Eq, ToValue, FromValue, Schema)]
pub struct CaptureRecord {
    /// The captured bytes.
    pub data: Bytes,
    /// When it was captured, in nanoseconds since the Unix epoch.
    pub time_ns: Option<i64>,
    /// Its length on the wire, when more was sent than captured.
    pub original_len: Option<u32>,
}

impl FileTypeDescription {
    /// The map [`FileType::describe`] answers.
    ///
    /// # Errors
    ///
    /// When the map cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(crate::model::refused)
    }

    /// The description a [`FileType::describe`] map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(crate::model::refused)
    }
}

impl CaptureRecord {
    /// The map [`CaptureReader::read`] answers.
    ///
    /// # Errors
    ///
    /// When the map cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(crate::model::refused)
    }

    /// The record a [`CaptureReader::read`] map holds; `None` for the empty
    /// map that ends the file.
    ///
    /// # Errors
    ///
    /// When the map is neither empty nor in this shape.
    pub fn from_map(map: &Map) -> Result<Option<Self>, ProviderError> {
        if map.is_empty() {
            return Ok(None);
        }
        Self::from_value(&map.to_value()?)
            .map(Some)
            .map_err(crate::model::refused)
    }
}
