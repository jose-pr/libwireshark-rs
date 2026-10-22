//! The trait a protocol implements, what its dissector returns, and where
//! Wireshark hands it packets.

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

    /// The dissector-table entries that route packets to this protocol.
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

    /// Decodes one packet, or returns `None` when it is not this protocol's.
    ///
    /// On `Some`, the runtime sets the Protocol column, adds the protocol's
    /// tree item over the consumed bytes, then the header's fields and the
    /// Info text. Items added to `packet` directly go under the same item.
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

/// An entry in one of Wireshark's dissector tables: "packets where
/// `table` is `value` go to this protocol". A configurable entry is a
/// preference read in [`Dissector::dissect_on`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Binding {
    table: &'static str,
    value: u32,
}

impl Binding {
    /// An entry in the integer table `table` (such as `"udp.port"` or
    /// `"ethertype"`) for `value`.
    pub const fn uint(table: &'static str, value: u32) -> Self {
        Self { table, value }
    }

    /// An entry for TCP port `port`.
    pub const fn tcp_port(port: u16) -> Self {
        Self::uint("tcp.port", port as u32)
    }

    /// An entry for UDP port `port`.
    pub const fn udp_port(port: u16) -> Self {
        Self::uint("udp.port", port as u32)
    }

    /// The dissector table's name.
    pub const fn table(&self) -> &'static str {
        self.table
    }

    /// The value the entry matches.
    pub const fn value(&self) -> u32 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::Binding;

    #[test]
    fn port_bindings_name_their_transport_table() {
        assert_eq!(Binding::udp_port(111), Binding::uint("udp.port", 111));
        assert_eq!(Binding::tcp_port(4242).table(), "tcp.port");
    }
}
