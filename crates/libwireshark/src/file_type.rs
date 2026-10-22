//! Capture file formats: files Wireshark opens and reads packets from.
//!
//! Wireshark reads file formats from plugins from 4.6 on, where a reader's
//! structures are public; on an older release line a plugin's formats are
//! not registered. Wireshark looks for them only in libraries in the
//! `wiretap` plugin directory.

use crate::sys;
use alloc::string::String;
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::fmt;
use core::time::Duration;
use std::io;

/// A capture file format Wireshark can open: `tshark -r file.ext`.
///
/// ```no_run
/// use libwireshark::{CaptureFile, Encapsulation, FileType, Record};
/// use std::io::{self, Read};
/// use std::time::Duration;
///
/// /// `MYCAP001`, then per packet: a u32 length, a u64 time in ns, the frame.
/// struct MyCapture;
///
/// impl FileType for MyCapture {
///     const NAME: &'static str = "mycap";
///     const DESCRIPTION: &'static str = "My capture";
///     const EXTENSIONS: &'static [&'static str] = &["mycap"];
///
///     fn open(file: &mut CaptureFile<'_>) -> io::Result<Option<Self>> {
///         let mut magic = [0; 8];
///         file.read_exact(&mut magic)?;
///         Ok((&magic == b"MYCAP001").then_some(MyCapture))
///     }
///
///     fn encapsulation(&self) -> Encapsulation {
///         Encapsulation::ETHERNET
///     }
///
///     fn read(&self, file: &mut CaptureFile<'_>, record: &mut Record<'_>) -> io::Result<bool> {
///         let mut header = [0; 12];
///         match file.read_exact(&mut header) {
///             Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
///             result => result?,
///         }
///         let len = u32::from_le_bytes(header[..4].try_into().unwrap());
///         let time = u64::from_le_bytes(header[4..].try_into().unwrap());
///         record.set_time(Duration::from_nanos(time));
///         record.read_data(file, len as usize)?;
///         Ok(true)
///     }
/// }
///
/// libwireshark::plugin!(file_types = [MyCapture]);
/// ```
pub trait FileType: Sized + 'static {
    /// The format's short name, as `tshark -X read_format:NAME` takes it.
    const NAME: &'static str;
    /// The format's name in Wireshark's file type lists.
    const DESCRIPTION: &'static str;
    /// File name extensions, without the dot; the first is the default.
    const EXTENSIONS: &'static [&'static str] = &[];

    /// Recognises a file from its start: `Ok(Some(_))`, holding what reading
    /// its records needs, when it is in this format, and `Ok(None)` when it
    /// is not. A file too short to tell (`UnexpectedEof`) is not.
    fn open(file: &mut CaptureFile<'_>) -> io::Result<Option<Self>>;

    /// The link-layer type of the file's packets.
    fn encapsulation(&self) -> Encapsulation;

    /// Reads the record at the file's position into `record`; `Ok(false)`
    /// at the end of the file.
    ///
    /// Wireshark also reads a record again from where it started, so a
    /// record must be readable from its own offset with only what `open`
    /// returned. An `InvalidData` error reports the file as malformed.
    fn read(&self, file: &mut CaptureFile<'_>, record: &mut Record<'_>) -> io::Result<bool>;
}

/// The link-layer type of a capture's packets (`WTAP_ENCAP_*`): which
/// dissector Wireshark starts each packet with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Encapsulation(i32);

impl Encapsulation {
    /// Ethernet frames.
    pub const ETHERNET: Self = Self(sys::WTAP_ENCAP_ETHERNET as i32);
    /// IP packets, v4 or v6 by their version field.
    pub const RAW_IP: Self = Self(sys::WTAP_ENCAP_RAW_IP as i32);

    /// One of the 16 encapsulations reserved for private use (`USER0` to
    /// `USER15`, pcap's `DLT_USER`); `None` past 15. A protocol takes such
    /// packets with [`Binding::encapsulation`](crate::Binding::encapsulation).
    pub const fn user(index: u8) -> Option<Self> {
        if index < 16 {
            Some(Self(sys::WTAP_ENCAP_USER0 as i32 + index as i32))
        } else {
            None
        }
    }

    /// The encapsulation whose `WTAP_ENCAP_*` value is `value`.
    pub const fn from_raw(value: i32) -> Self {
        Self(value)
    }

    /// Its `WTAP_ENCAP_*` value.
    pub const fn to_raw(self) -> i32 {
        self.0
    }
}

/// The wiretap, wsutil and GLib functions a reader is given, resolved from
/// the running Wireshark.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(file_type_plugins), allow(dead_code, reason = "resolved from 4.6"))]
pub(crate) struct FileApi {
    pub(crate) read: unsafe extern "C" fn(*mut c_void, c_uint, *mut c_void) -> c_int,
    pub(crate) tell: unsafe extern "C" fn(*mut c_void) -> i64,
    pub(crate) seek: unsafe extern "C" fn(*mut c_void, i64, c_int, *mut c_int) -> i64,
    pub(crate) error: unsafe extern "C" fn(*mut c_void, *mut *mut c_char) -> c_int,
    pub(crate) assure_space: unsafe extern "C" fn(*mut c_void, usize),
    pub(crate) strdup: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    pub(crate) free: unsafe extern "C" fn(*mut c_void),
}

/// The file being read, positioned where the next read starts.
pub struct CaptureFile<'a> {
    handle: *mut c_void,
    api: &'a FileApi,
}

impl fmt::Debug for CaptureFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureFile")
            .field("position", &self.position())
            .finish()
    }
}

#[cfg_attr(not(file_type_plugins), allow(dead_code, reason = "opened from 4.6"))]
impl<'a> CaptureFile<'a> {
    /// # Safety
    ///
    /// `handle` is the `FILE_T` of an open capture, live for `'a`.
    pub(crate) unsafe fn from_raw(handle: *mut c_void, api: &'a FileApi) -> Self {
        Self { handle, api }
    }

    /// The offset of the next byte to read, from the start of the file
    /// (of its decompressed contents, when it is compressed).
    pub fn position(&self) -> u64 {
        // SAFETY: a live handle (see `from_raw`).
        let position = unsafe { (self.api.tell)(self.handle) };
        u64::try_from(position).unwrap_or(0)
    }

    pub(crate) fn seek(&mut self, offset: i64) -> io::Result<()> {
        let mut code = 0;
        // SAFETY: a live handle; 0 is `SEEK_SET`.
        if unsafe { (self.api.seek)(self.handle, offset, 0, &mut code) } < 0 {
            return Err(WiretapError::new(code, None).into());
        }
        Ok(())
    }
}

impl io::Read for CaptureFile<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = c_uint::try_from(buf.len()).unwrap_or(c_uint::MAX);
        // SAFETY: `buf` holds at least `count` writable bytes.
        let read = unsafe { (self.api.read)(buf.as_mut_ptr().cast(), count, self.handle) };
        if let Ok(read) = usize::try_from(read) {
            return Ok(read);
        }
        let mut info = core::ptr::null_mut();
        // SAFETY: a live handle; the message is a GLib copy, freed here.
        let code = unsafe { (self.api.error)(self.handle, &mut info) };
        let text = (!info.is_null()).then(|| {
            // SAFETY: NUL-terminated, freed exactly once.
            unsafe {
                let text = CStr::from_ptr(info).to_string_lossy().into_owned();
                (self.api.free)(info.cast());
                text
            }
        });
        Err(WiretapError::new(code, text).into())
    }
}

/// A wiretap error code from reading the file, carried through `io::Error`
/// back to Wireshark unchanged.
#[derive(Debug)]
pub(crate) struct WiretapError {
    pub(crate) code: c_int,
    pub(crate) info: Option<String>,
}

impl WiretapError {
    fn new(code: c_int, info: Option<String>) -> Self {
        Self { code, info }
    }
}

impl fmt::Display for WiretapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.info {
            Some(info) => write!(f, "wiretap error {}: {info}", self.code),
            None => write!(f, "wiretap error {}", self.code),
        }
    }
}

impl core::error::Error for WiretapError {}

impl From<WiretapError> for io::Error {
    fn from(error: WiretapError) -> Self {
        io::Error::other(error)
    }
}

/// The packet a [`FileType::read`] fills in.
pub struct Record<'a> {
    inner: RecordInner<'a>,
}

impl fmt::Debug for Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record").finish_non_exhaustive()
    }
}

#[cfg(file_type_plugins)]
struct RecordInner<'a> {
    record: &'a mut sys::wtap_rec,
    api: &'a FileApi,
    time: Option<Duration>,
    original_len: Option<u32>,
}

/// Records exist only where Wireshark reads file formats from plugins.
#[cfg(not(file_type_plugins))]
struct RecordInner<'a>(Never, core::marker::PhantomData<&'a ()>);

#[cfg(not(file_type_plugins))]
enum Never {}

#[cfg(file_type_plugins)]
impl<'a> Record<'a> {
    /// # Safety
    ///
    /// `record` is the record of the running read callback.
    pub(crate) unsafe fn from_raw(record: &'a mut sys::wtap_rec, api: &'a FileApi) -> Self {
        Self {
            inner: RecordInner {
                record,
                api,
                time: None,
                original_len: None,
            },
        }
    }

    fn buffer(&mut self) -> &mut sys::Buffer {
        &mut self.inner.record.data
    }

    fn data_len(&self) -> usize {
        let buffer = &self.inner.record.data;
        buffer.first_free - buffer.start
    }

    /// The time, the length on the wire and the captured length, after
    /// `read` returned a record.
    pub(crate) fn finish(self) -> (Option<Duration>, u32, Option<u32>) {
        let captured = u32::try_from(self.data_len()).unwrap_or(u32::MAX);
        (self.inner.time, captured, self.inner.original_len)
    }
}

impl Record<'_> {
    /// When the packet was captured, since the Unix epoch.
    pub fn set_time(&mut self, since_epoch: Duration) {
        #[cfg(file_type_plugins)]
        {
            self.inner.time = Some(since_epoch);
        }
        #[cfg(not(file_type_plugins))]
        {
            let _ = since_epoch;
            match self.inner.0 {}
        }
    }

    /// The packet's length on the wire, when the record holds only its
    /// start; by default the length of its data.
    pub fn set_original_len(&mut self, len: u32) {
        #[cfg(file_type_plugins)]
        {
            self.inner.original_len = Some(len);
        }
        #[cfg(not(file_type_plugins))]
        {
            let _ = len;
            match self.inner.0 {}
        }
    }

    /// Reads the next `len` bytes of `file` as more of the packet's data.
    pub fn read_data(&mut self, file: &mut CaptureFile<'_>, len: usize) -> io::Result<()> {
        #[cfg(file_type_plugins)]
        {
            let api = self.inner.api;
            let buffer = self.buffer();
            // SAFETY: makes `len` bytes writable past `first_free`.
            unsafe { (api.assure_space)(core::ptr::from_mut(buffer).cast(), len) };
            // SAFETY: `assure_space` allocated them; they are written before
            // `first_free` moves past them.
            let free =
                unsafe { core::slice::from_raw_parts_mut(buffer.data.add(buffer.first_free), len) };
            io::Read::read_exact(file, free)?;
            buffer.first_free += len;
            Ok(())
        }
        #[cfg(not(file_type_plugins))]
        {
            let _ = (file, len);
            match self.inner.0 {}
        }
    }

    /// Appends `bytes` to the packet's data.
    pub fn extend_data(&mut self, bytes: &[u8]) {
        #[cfg(file_type_plugins)]
        {
            let api = self.inner.api;
            let buffer = self.buffer();
            // SAFETY: as in `read_data`, with the bytes copied from `bytes`.
            unsafe {
                (api.assure_space)(core::ptr::from_mut(buffer).cast(), bytes.len());
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    buffer.data.add(buffer.first_free),
                    bytes.len(),
                );
            }
            buffer.first_free += bytes.len();
        }
        #[cfg(not(file_type_plugins))]
        {
            let _ = bytes;
            match self.inner.0 {}
        }
    }
}
