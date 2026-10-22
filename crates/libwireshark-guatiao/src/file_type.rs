//! Capture file formats from providers: the provider reads the file through
//! a source lent for each call, which reads through Wireshark.

use crate::describe;
use crate::host::{report, served};
use alloc::sync::Arc;
use core::time::Duration;
use guatiao::Status;
use guatiao::library::{Object, ProviderError};
use libwireshark::dynamic::{DynamicFileType, DynamicReader, FileType};
use libwireshark::{CaptureFile, Encapsulation, Record};
use libwireshark_api::{
    self as api, CaptureReader, CaptureRecord, CaptureSource, FileTypeDescription,
};
use std::collections::HashSet;
use std::io::{self, Read};
use std::thread::ThreadId;

/// Every format offered; a name taken earlier is skipped.
pub(crate) fn formats(registry: &guatiao::library::Registry) -> Vec<FileType> {
    let mut names = HashSet::new();
    let mut formats = Vec::new();
    for (key, format) in served::<dyn api::FileType>(registry) {
        let description = match format
            .describe()
            .and_then(|map| FileTypeDescription::from_map(&map))
        {
            Ok(description) => description,
            Err(error) => {
                report(true, &format!("{key}: describe: {}", error.message()));
                continue;
            }
        };
        let name = match describe::name("file type", &description.name, "_") {
            Ok(name) => name,
            Err(error) => {
                report(true, &format!("{key}: {error}"));
                continue;
            }
        };
        if !names.insert(name) {
            report(
                true,
                &format!("{key}: the format {name} is offered already"),
            );
            continue;
        }
        let extensions: Vec<&'static str> = description
            .extensions
            .iter()
            .map(|extension| describe::leak(extension))
            .collect();
        report(false, &format!("{key} reads the format {name}"));
        formats.push(FileType::new(
            name,
            describe::leak(&description.description),
            extensions.leak(),
            Format {
                key: describe::leak(&key),
                format,
            },
        ));
    }
    formats
}

/// One provider's format, as libwireshark opens files with it.
struct Format {
    key: &'static str,
    format: Arc<dyn api::FileType>,
}

/// A refusal as a read error Wireshark reports.
fn failed(key: &str, call: &str, error: &ProviderError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{key}: {call}: {}", error.message()),
    )
}

impl DynamicFileType for Format {
    fn open(&self, file: &mut CaptureFile<'_>) -> io::Result<Option<Box<dyn DynamicReader>>> {
        match self.format.open(&mut Source::new(file)) {
            Ok(reader) => Ok(Some(Box::new(Reader {
                key: self.key,
                encapsulation: Encapsulation::from_raw(
                    i32::try_from(reader.encapsulation()).unwrap_or(0),
                ),
                reader,
            }))),
            Err(error) if error.status == Status::GUATIAO_ERR_NOT_FOUND => Ok(None),
            Err(error) => Err(failed(self.key, "open", &error)),
        }
    }
}

/// An open file's reader: the provider's.
struct Reader {
    key: &'static str,
    encapsulation: Encapsulation,
    reader: Object<dyn CaptureReader>,
}

impl DynamicReader for Reader {
    fn encapsulation(&self) -> Encapsulation {
        self.encapsulation
    }

    fn read(&mut self, file: &mut CaptureFile<'_>, record: &mut Record<'_>) -> io::Result<bool> {
        let map = self
            .reader
            .read(&mut Source::new(file))
            .map_err(|error| failed(self.key, "read", &error))?;
        let Some(read) =
            CaptureRecord::from_map(&map).map_err(|error| failed(self.key, "read", &error))?
        else {
            return Ok(false);
        };
        if let Some(time) = read.time_ns {
            record.set_time(Duration::from_nanos(u64::try_from(time).unwrap_or(0)));
        }
        if let Some(original) = read.original_len {
            record.set_original_len(original);
        }
        record.extend_data(read.data.as_ref());
        Ok(true)
    }
}

/// The file lent to a provider for one call.
struct Source<'call, 'file> {
    file: &'call mut CaptureFile<'file>,
    /// The reading thread: the only one the file may be used from.
    thread: ThreadId,
}

// SAFETY: the file is reached only on the thread that lent it, the one
// reading; a slot called from any other thread does nothing.
unsafe impl Send for Source<'_, '_> {}

impl<'call, 'file> Source<'call, 'file> {
    fn new(file: &'call mut CaptureFile<'file>) -> Self {
        Self {
            file,
            thread: std::thread::current().id(),
        }
    }

    fn here(&self) -> bool {
        std::thread::current().id() == self.thread
    }
}

impl CaptureSource for Source<'_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> i64 {
        if !self.here() {
            return -1;
        }
        match self.file.read(buffer) {
            Ok(read) => i64::try_from(read).unwrap_or(-1),
            Err(_) => -1,
        }
    }

    fn position(&self) -> i64 {
        if !self.here() {
            return -1;
        }
        i64::try_from(self.file.position()).unwrap_or(-1)
    }
}
