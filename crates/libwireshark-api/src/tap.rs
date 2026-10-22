//! Tap listeners: statistics a provider keeps over the packets Wireshark
//! hands a tap, offered as `tshark -z <name>[,<filter>]`.

use alloc::string::String;
use guatiao::library::{Object, ProviderError};
use guatiao::{FromValue, Map, Schema, ToValue};

/// A tap listener: `wireshark_tap`.
///
/// The host asks for [`describe`](Self::describe) once, offers the
/// listener as `-z <name>`, and [`open`](Self::open)s one
/// [`TapListener`] per invocation.
#[guatiao::kind(name = "wireshark_tap")]
pub trait Tap: Send + Sync {
    /// The listener, as a map in the shape of [`TapDescription`].
    fn describe(&self) -> Result<Map, ProviderError>;

    /// One invocation's state.
    fn open(&self) -> Result<Object<dyn TapListener>, ProviderError>;
}

/// One `-z` invocation's state: `wireshark_tap_listener`, owned by the
/// host. Calls come from Wireshark's dissection thread, one at a time.
#[guatiao::kind(object, name = "wireshark_tap_listener")]
pub trait TapListener: Send {
    /// One packet that reached the tap, as a map in the shape of
    /// [`TapPacket`].
    fn packet(&mut self, packet: &Map) -> Result<(), ProviderError>;

    /// The report printed when the capture ends.
    fn draw(&mut self) -> Result<String, ProviderError>;

    /// Wireshark starts over (a new capture).
    fn reset(&mut self) -> Result<(), ProviderError>;
}

/// What [`Tap::describe`] answers.
#[derive(Clone, Debug, Default, PartialEq, Eq, ToValue, FromValue, Schema)]
pub struct TapDescription {
    /// The `-z` name: `[a-z][a-z0-9_.-]*`.
    pub name: String,
    /// Wireshark's tap it listens to: a protocol's filter name, such as
    /// `frame`, `ip` or `udp`.
    pub tap: String,
}

/// One packet, as [`TapListener::packet`] receives it.
#[derive(Clone, Debug, Default, PartialEq, Eq, ToValue, FromValue, Schema)]
pub struct TapPacket {
    /// The frame number, counted from 1.
    pub frame: u32,
    /// The frame's length on the wire.
    pub len: u32,
    /// When it was captured, in nanoseconds since the Unix epoch.
    pub time_ns: i64,
    /// The source address, as Wireshark writes it.
    pub source: String,
    /// The destination address.
    pub destination: String,
    /// The source port of its transport, 0 when it has none.
    pub src_port: u32,
    /// The destination port.
    pub dst_port: u32,
}

impl TapDescription {
    /// The map [`Tap::describe`] answers.
    ///
    /// # Errors
    ///
    /// When the map cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(crate::model::refused)
    }

    /// The description a [`Tap::describe`] map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(crate::model::refused)
    }
}

impl TapPacket {
    /// The map [`TapListener::packet`] receives.
    ///
    /// # Errors
    ///
    /// When the map cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(crate::model::refused)
    }

    /// The packet a [`TapListener::packet`] map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(crate::model::refused)
    }
}
