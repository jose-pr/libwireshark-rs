//! The trait a protocol implements, what its dissector returns, and where
//! Wireshark hands it packets.

use crate::expert::Expert;
use crate::header::Header;
use crate::packet::PacketView;
use crate::prefs::Preferences;
use alloc::string::String;
use alloc::vec::Vec;

/// A protocol: its names, preferences, fields, the tables it is attached to,
/// and the function that decodes one packet.
///
/// A plugin lists its protocols with [`plugin!`](crate::plugin).
///
/// ```no_run
/// use libwireshark::{Binding, DissectResult, Dissector, NoHeader, NoPreferences, PacketView};
///
/// struct Echo;
///
/// impl Dissector for Echo {
///     type Preferences = NoPreferences;
///     type Header = NoHeader;
///     const NAME: &'static str = "Echo Protocol";
///     const SHORT_NAME: &'static str = "ECHO";
///     const FILTER_NAME: &'static str = "echo";
///
///     fn dissect_on(_: &NoPreferences) -> Vec<Binding> {
///         vec![Binding::udp_port(7)]
///     }
///
///     fn dissect(_: &NoPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<NoHeader>> {
///         Some(DissectResult::new(NoHeader, packet.captured_len()).with_info("echo"))
///     }
/// }
///
/// libwireshark::plugin!(Echo);
/// ```
pub trait Dissector: 'static {
    /// The preferences this protocol registers; [`NoPreferences`](crate::NoPreferences) for none.
    type Preferences: Preferences;
    /// The fields this protocol registers; [`NoHeader`](crate::NoHeader) for none.
    type Header: Header;

    /// The protocol's full name, shown in the protocol tree.
    const NAME: &'static str;
    /// The short name shown in the Protocol column.
    const SHORT_NAME: &'static str;
    /// The display-filter name, and the prefix of every field and preference.
    const FILTER_NAME: &'static str;
    /// The expert-info findings the dissector can report with
    /// [`PacketView::add_expert`].
    const EXPERTS: &'static [Expert] = &[];

    /// Where Wireshark hands this protocol packets: dissector-table entries,
    /// heuristic lists, or every packet as a post-dissector.
    ///
    /// Called when the plugin is loaded and again whenever Wireshark applies
    /// preferences; entries no longer listed are removed. An implementation
    /// may read `preferences` (a configurable port) or ignore them (a fixed
    /// one). The default attaches to nothing, for a protocol another
    /// dissector calls by name.
    fn dissect_on(preferences: &Self::Preferences) -> Vec<Binding> {
        let _ = preferences;
        Vec::new()
    }

    /// How the protocol's messages are delimited in a TCP stream.
    ///
    /// With `Some`, packets arriving over TCP are reassembled and split
    /// into whole messages (Wireshark's `tcp_dissect_pdus`), and
    /// [`dissect`](Self::dissect) sees one message at a time. The default,
    /// `None`, hands over each segment as it is.
    fn tcp_framing() -> Option<TcpFraming> {
        None
    }

    /// Decodes one packet, or returns `None` when it is not this protocol's.
    ///
    /// On `Some`, the runtime sets the Protocol column, adds the protocol's
    /// tree item over the consumed bytes, then the header's fields and the
    /// Info text. Items added to `packet` directly go under the same item.
    /// From a heuristic list, `None` tells Wireshark to try the next
    /// protocol.
    fn dissect(
        preferences: &Self::Preferences,
        packet: &mut PacketView<'_>,
    ) -> Option<DissectResult<Self::Header>>;
}

/// A packet a dissector accepted: the decoded header, how many bytes it
/// used, and the Info column text.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DissectResult<H> {
    /// The decoded header added to the protocol tree.
    pub header: H,
    /// The number of bytes this protocol consumed.
    pub size: usize,
    /// Text for the Info column, replacing what lower layers wrote.
    pub info: Option<String>,
}

impl<H> DissectResult<H> {
    /// An accepted packet with no Info text.
    pub fn new(header: H, size: usize) -> Self {
        Self {
            header,
            size,
            info: None,
        }
    }

    /// The same result with `info` for the Info column.
    #[must_use]
    pub fn with_info(mut self, info: impl Into<String>) -> Self {
        self.info = Some(info.into());
        self
    }
}

/// One way Wireshark hands a protocol packets. A configurable entry is a
/// preference read in [`Dissector::dissect_on`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Binding(pub(crate) Target);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Target {
    Uint { table: &'static str, value: u32 },
    Heuristic { list: &'static str },
    Postdissector,
}

impl Binding {
    /// Packets where the integer table `table` (such as `"udp.port"` or
    /// `"ethertype"`) has `value`.
    pub const fn uint(table: &'static str, value: u32) -> Self {
        Self(Target::Uint { table, value })
    }

    /// Packets to or from TCP port `port`.
    pub const fn tcp_port(port: u16) -> Self {
        Self::uint("tcp.port", port as u32)
    }

    /// Packets to or from UDP port `port`.
    pub const fn udp_port(port: u16) -> Self {
        Self::uint("udp.port", port as u32)
    }

    /// Every packet of a capture whose link-layer type is `encapsulation`:
    /// the protocol reads the frame from its first byte.
    pub const fn encapsulation(encapsulation: crate::Encapsulation) -> Self {
        Self::uint("wtap_encap", encapsulation.to_raw() as u32)
    }

    /// Every packet of the heuristic list `list` (such as `"udp"` or `"tcp"`)
    /// that no table claimed: [`Dissector::dissect`] decides by returning
    /// `Some` or `None`. Users can turn it off under Analyze › Enabled
    /// Protocols.
    pub const fn heuristic(list: &'static str) -> Self {
        Self(Target::Heuristic { list })
    }

    /// Every packet, after all other dissection, with the whole frame.
    pub const fn postdissector() -> Self {
        Self(Target::Postdissector)
    }
}

/// How messages are delimited in a TCP stream: a fixed-length header from
/// which a message's total length can be read.
#[derive(Clone, Copy, Debug)]
pub struct TcpFraming {
    header_len: usize,
    message_len: fn(&[u8]) -> Option<usize>,
}

impl TcpFraming {
    /// Messages that start with `header_len` bytes, from which
    /// `message_len` reads the whole message's length, header included.
    /// `message_len` returning `None`, or less than `header_len`, marks the
    /// rest of the segment as not this protocol's.
    pub const fn new(header_len: usize, message_len: fn(&[u8]) -> Option<usize>) -> Self {
        Self {
            header_len,
            message_len,
        }
    }

    /// The fixed header length.
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// The whole message's length, from its first [`header_len`](Self::header_len) bytes.
    pub fn message_len(&self, header: &[u8]) -> Option<usize> {
        (self.message_len)(header)
    }
}

#[cfg(test)]
mod tests {
    use super::{Binding, Target, TcpFraming};

    #[test]
    fn port_bindings_name_their_transport_table() {
        assert_eq!(Binding::udp_port(111), Binding::uint("udp.port", 111));
        assert_eq!(
            Binding::tcp_port(4242).0,
            Target::Uint {
                table: "tcp.port",
                value: 4242
            }
        );
        assert_ne!(Binding::heuristic("udp"), Binding::heuristic("tcp"));
    }

    #[test]
    fn framing_reads_a_length_prefix() {
        let framing = TcpFraming::new(2, |header| {
            Some(usize::from(u16::from_be_bytes([header[0], header[1]])))
        });
        assert_eq!(framing.header_len(), 2);
        assert_eq!(framing.message_len(&[0, 9]), Some(9));
    }
}
