//! Protocols described at run time: for a plugin that learns what it
//! dissects when it loads, such as a host of plugins written in other
//! languages. A protocol known at compile time is a [`Dissector`](crate::Dissector).

use crate::dissector::Binding;
use crate::expert::Expert;
use crate::header::FieldInfo;
use crate::packet::PacketView;
use crate::prefs::{Declaration, PreferenceMap};
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
