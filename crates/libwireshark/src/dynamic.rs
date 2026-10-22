//! What a plugin registers at run time: for a plugin that learns what it
//! provides when it loads, such as a host of plugins written in other
//! languages. Known at compile time, each is a [`Dissector`](crate::Dissector),
//! a [`Tap`](crate::Tap), a [`FilterFunction`](crate::FilterFunction), a
//! [`FileType`](crate::FileType) or a [`Codec`](crate::Codec).

use crate::codec::StreamFormat;
use crate::dissector::Binding;
use crate::expert::Expert;
use crate::file_type::{CaptureFile, Encapsulation, Record};
use crate::filter::FieldValue;
use crate::header::FieldInfo;
use crate::packet::PacketView;
use crate::prefs::{Declaration, PreferenceMap};
use crate::tap::TapPacket;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

pub use crate::__private::Protocol;

/// A protocol's names, fields, expert findings and preferences, as
/// [`Dissector`](crate::Dissector)'s constants and types say them for a
/// static one.
///
/// Wireshark keeps what is registered for the process: build owned text
/// into `&'static str` with `String::leak`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ProtocolSpec {
    /// The tree label.
    pub name: &'static str,
    /// The Protocol column.
    pub short_name: &'static str,
    /// The display filter name; prefix of the fields and findings.
    pub filter_name: &'static str,
    /// Registered fields, abbreviations relative to `filter_name`.
    pub fields: Vec<FieldInfo>,
    /// Expert findings, abbreviations relative to `filter_name`.
    pub experts: Vec<Expert>,
    /// Preferences, in the order Wireshark shows them.
    pub preferences: Vec<Declaration>,
}

impl ProtocolSpec {
    /// A protocol with these names and nothing else.
    pub fn new(name: &'static str, short_name: &'static str, filter_name: &'static str) -> Self {
        Self {
            name,
            short_name,
            filter_name,
            fields: Vec::new(),
            experts: Vec::new(),
            preferences: Vec::new(),
        }
    }

    /// The same protocol with `fields`.
    #[must_use]
    pub fn with_fields(mut self, fields: Vec<FieldInfo>) -> Self {
        self.fields = fields;
        self
    }

    /// The same protocol with `experts`.
    #[must_use]
    pub fn with_experts(mut self, experts: Vec<Expert>) -> Self {
        self.experts = experts;
        self
    }

    /// The same protocol with `preferences`.
    #[must_use]
    pub fn with_preferences(mut self, preferences: Vec<Declaration>) -> Self {
        self.preferences = preferences;
        self
    }
}

/// What dissects a protocol registered with [`Protocol::dynamic`].
///
/// Unlike [`Dissector::dissect`](crate::Dissector::dissect), `dissect` adds
/// its fields and Info text itself, through `packet`. When it accepts, the
/// runtime sizes the protocol's tree item and, unless the protocol runs as
/// a post-dissector, sets the Protocol column. A post-dissector leaves the
/// columns lower layers wrote: append to the Info column
/// ([`PacketView::append_info`]) when [`PacketView::is_postdissector`].
pub trait DynamicDissector: Send + Sync + 'static {
    /// What `dissect_on` and `dissect` read: built from the protocol's
    /// preference values each time Wireshark applies them.
    type Preferences: Send + Sync + 'static;

    /// The preferences from Wireshark's current values, keyed by
    /// [`Declaration::name`]; `None` keeps the last ones that built.
    fn preferences(&self, values: &PreferenceMap) -> Option<Self::Preferences>;

    /// Where the protocol gets packets; asked when it is handed off and
    /// whenever Wireshark applies preferences. Bindings no longer
    /// returned are removed.
    fn dissect_on(&self, preferences: &Self::Preferences) -> Vec<Binding>;

    /// For messages framed over TCP: the fixed header length
    /// [`message_len`](Self::message_len) reads a message's length from.
    /// With `Some`, packets arriving over TCP are reassembled and `dissect`
    /// sees one whole message at a time.
    fn tcp_header_len(&self) -> Option<usize> {
        None
    }

    /// A framed message's whole length, header included, from its first
    /// [`tcp_header_len`](Self::tcp_header_len) bytes. With `None`, or less
    /// than the header length, the rest of the segment is handed to
    /// `dissect` as one message, which may decline it.
    fn message_len(&self, header: &[u8]) -> Option<usize> {
        let _ = header;
        None
    }

    /// Dissects the packet: the bytes it takes, or `None` to decline. A
    /// declining dissector adds nothing to `packet` first.
    fn dissect(
        &self,
        preferences: &Self::Preferences,
        packet: &mut PacketView<'_>,
    ) -> Option<usize>;
}

/// Everything a plugin registers at run time: what
/// [`plugin!(dynamic = f)`](crate::plugin)'s `f` answers. A `Vec<Protocol>`
/// converts into one holding only protocols.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Registrations {
    /// Protocols, as [`Protocol::dynamic`] builds them.
    pub protocols: Vec<Protocol>,
    /// Tap listeners, offered as `-z <name>`.
    pub taps: Vec<Tap>,
    /// Display-filter functions (Wireshark 4.4 and later).
    pub filters: Vec<FilterFunction>,
    /// Capture file formats (Wireshark 4.6 and later).
    pub file_types: Vec<FileType>,
    /// Audio codecs, for the RTP player.
    pub codecs: Vec<Codec>,
}

impl From<Vec<Protocol>> for Registrations {
    fn from(protocols: Vec<Protocol>) -> Self {
        Self {
            protocols,
            ..Self::default()
        }
    }
}

/// A tap listener's state, as [`Tap`](crate::Tap) is for a static one:
/// one per `-z` invocation, made by [`Tap::new`]'s factory.
pub trait DynamicTap: Send + 'static {
    /// One packet that reached the tap.
    fn packet(&mut self, packet: &TapPacket<'_>);

    /// The report printed when the capture ends.
    fn draw(&self) -> String;

    /// Wireshark starts over (a new capture).
    fn reset(&mut self);
}

/// The factory of a run-time tap's listeners.
pub(crate) type TapFactory = dyn Fn() -> Box<dyn DynamicTap> + Send + Sync;

/// A tap listener registered at run time, offered as `-z <name>[,<filter>]`.
pub struct Tap {
    pub(crate) name: &'static str,
    pub(crate) tap: &'static str,
    pub(crate) new: Box<TapFactory>,
}

impl core::fmt::Debug for Tap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tap")
            .field("name", &self.name)
            .field("tap", &self.tap)
            .finish_non_exhaustive()
    }
}

impl Tap {
    /// The listener `name` on Wireshark's tap `tap` (a protocol's filter
    /// name, such as `"frame"` or `"ip"`); `new` makes each invocation's
    /// state.
    pub fn new(
        name: &'static str,
        tap: &'static str,
        new: impl Fn() -> Box<dyn DynamicTap> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name,
            tap,
            new: Box::new(new),
        }
    }
}

/// What a run-time display-filter function answers for each value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FilterReturn {
    /// An unsigned 32-bit number.
    Count,
    /// Text.
    Text,
}

/// One answer of a run-time display-filter function; one that is not of
/// its declared [`FilterReturn`] counts as no answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterValue {
    /// For [`FilterReturn::Count`].
    Count(u32),
    /// For [`FilterReturn::Text`].
    Text(String),
}

/// A run-time display-filter function's body, as
/// [`FilterFunction`](crate::FilterFunction) is for a static one.
pub trait DynamicFilterFunction: Send + Sync + 'static {
    /// The answer for one value of the field passed, or `None` to give
    /// none for it.
    fn call(&self, value: &FieldValue<'_>) -> Option<FilterValue>;
}

/// A display-filter function registered at run time: `name(field)` in a
/// display filter, from Wireshark 4.4.
pub struct FilterFunction {
    pub(crate) name: &'static str,
    pub(crate) returns: FilterReturn,
    pub(crate) function: Box<dyn DynamicFilterFunction>,
}

impl core::fmt::Debug for FilterFunction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FilterFunction")
            .field("name", &self.name)
            .field("returns", &self.returns)
            .finish_non_exhaustive()
    }
}

impl FilterFunction {
    /// The function `name`, answering `returns` through `function`.
    pub fn new(
        name: &'static str,
        returns: FilterReturn,
        function: impl DynamicFilterFunction,
    ) -> Self {
        Self {
            name,
            returns,
            function: Box::new(function),
        }
    }
}

/// A run-time capture file format: recognises a file and opens a reader,
/// as [`FileType::open`](crate::FileType::open) does for a static one.
pub trait DynamicFileType: Send + Sync + 'static {
    /// The reader of `file` (positioned at its start), `None` when it is
    /// not in this format.
    ///
    /// # Errors
    ///
    /// A read error; running out of bytes counts as "not this format".
    fn open(&self, file: &mut CaptureFile<'_>) -> std::io::Result<Option<Box<dyn DynamicReader>>>;
}

/// An open file's reader. Wireshark reads a file from one thread, one
/// record at a time.
pub trait DynamicReader: 'static {
    /// The link-layer type of every record.
    fn encapsulation(&self) -> Encapsulation;

    /// The record at the file's position into `record`: `false` at the end
    /// of the file.
    ///
    /// # Errors
    ///
    /// A read error, or [`std::io::ErrorKind::InvalidData`] for a damaged
    /// record.
    fn read(
        &mut self,
        file: &mut CaptureFile<'_>,
        record: &mut Record<'_>,
    ) -> std::io::Result<bool>;
}

/// A capture file format registered at run time (Wireshark 4.6 and later),
/// from any plugin directory.
pub struct FileType {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) extensions: &'static [&'static str],
    #[cfg_attr(
        not(file_type_plugins),
        expect(dead_code, reason = "file types register from 4.6")
    )]
    pub(crate) format: Box<dyn DynamicFileType>,
}

impl core::fmt::Debug for FileType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileType")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("extensions", &self.extensions)
            .finish_non_exhaustive()
    }
}

impl FileType {
    /// The format `name` (short, as `tshark -F` lists it), described for
    /// people by `description`, whose files end in `extensions`.
    pub fn new(
        name: &'static str,
        description: &'static str,
        extensions: &'static [&'static str],
        format: impl DynamicFileType,
    ) -> Self {
        Self {
            name,
            description,
            extensions,
            format: Box::new(format),
        }
    }
}

/// A run-time codec's decoder for one stream, as [`Codec`](crate::Codec)
/// is for a static one.
pub trait DynamicCodec: Send + 'static {
    /// The decoded samples per second.
    fn sample_rate(&self) -> u32;

    /// Interleaved channels in the decoded samples.
    fn channels(&self) -> u32 {
        1
    }

    /// How many samples `payload` decodes to, at most.
    fn decoded_len(&self, payload: &[u8]) -> usize;

    /// Decodes `payload` into `samples`; the samples written.
    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize;
}

/// The factory of a run-time codec's decoders.
pub(crate) type CodecFactory = dyn Fn(&StreamFormat) -> Box<dyn DynamicCodec> + Send + Sync;

/// An audio codec registered at run time, for RTP payloads named `name`
/// (the `a=rtpmap` encoding, such as `"L16"`).
pub struct Codec {
    pub(crate) name: &'static str,
    pub(crate) new: Box<CodecFactory>,
}

impl core::fmt::Debug for Codec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Codec")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Codec {
    /// The codec `name`; `new` makes each stream's decoder.
    pub fn new(
        name: &'static str,
        new: impl Fn(&StreamFormat) -> Box<dyn DynamicCodec> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name,
            new: Box::new(new),
        }
    }
}
