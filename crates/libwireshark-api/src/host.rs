//! Wireshark's dissection engine as a provider: what a host in any
//! language opens to dissect frames and read captures with Wireshark and
//! the plugins it loads.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use guatiao::library::{Object, ProviderError};
use guatiao::{FromValue, Map, Schema, ToValue};

/// Opens Wireshark's dissection engine in the calling process:
/// `wireshark_host`.
#[guatiao::kind(name = "wireshark_host")]
pub trait Host: Send + Sync {
    /// Starts the engine with `config` (an [`HostConfig`] map) and
    /// answers its session. Wireshark's state is per process: a second
    /// session while one is open is refused, and plugins and preferences
    /// are fixed once the first starts.
    fn open(&self, config: &Map) -> Result<Object<dyn Session>, ProviderError>;
}

/// The open host: `wireshark_session`. Calls are one at a time.
#[guatiao::kind(object, name = "wireshark_session")]
pub trait Session: Send {
    /// Dissects one frame of `encapsulation` (a `WTAP_ENCAP_*` value: 1 is
    /// Ethernet) captured at `time_ns` nanoseconds since the Unix epoch:
    /// a [`Dissected`] map. Frames dissected one after the other share
    /// conversations, as in one capture.
    fn dissect(
        &mut self,
        data: &[u8],
        encapsulation: i64,
        time_ns: i64,
    ) -> Result<Map, ProviderError>;

    /// Opens the capture file `path` for [`next`](Self::next), keeping only
    /// frames that match `display_filter` (all, when empty).
    fn open_file(&mut self, path: &str, display_filter: &str) -> Result<(), ProviderError>;

    /// The next matching frame of the open file, as a [`Dissected`] map;
    /// an empty map at its end.
    fn next(&mut self) -> Result<Map, ProviderError>;
}

/// How the host starts Wireshark.
#[derive(Clone, Debug, Default, PartialEq, ToValue, FromValue, Schema)]
pub struct HostConfig {
    /// Plugin libraries to load besides Wireshark's own: dissector plugins
    /// built for this release line, `libwireshark-bridge` among them.
    #[map(default)]
    pub plugins: Vec<String>,
    /// Load only `plugins`, not those installed in Wireshark's plugin
    /// directories. A plugin listed and also installed would register
    /// its protocols twice, which Wireshark does not survive.
    #[map(default)]
    pub skip_installed_plugins: bool,
    /// A configuration directory (profile) to read preferences from; by
    /// default the user's.
    pub config_dir: Option<String>,
    /// Preference values, as `-o name:value` takes them (`"foo.port"` →
    /// `"113"`).
    #[map(default)]
    pub preferences: BTreeMap<String, String>,
}

/// One dissected frame.
#[derive(Clone, Debug, Default, PartialEq, ToValue, FromValue)]
pub struct Dissected {
    /// The frame number, counted from 1 in the session (or the file).
    pub frame: u32,
    /// The packet list's columns, in Wireshark's order.
    #[map(default)]
    pub columns: Vec<Column>,
    /// The protocol tree: one node per protocol, each holding its fields.
    #[map(default)]
    pub tree: Vec<Node>,
}

/// One column of the packet list.
#[derive(Clone, Debug, Default, PartialEq, ToValue, FromValue, Schema)]
pub struct Column {
    /// Its title, such as "Protocol".
    pub title: String,
    /// Its text for this frame.
    pub text: String,
}

/// One item of the protocol tree.
#[derive(Clone, Debug, Default, PartialEq, ToValue, FromValue)]
pub struct Node {
    /// The field's filter name, such as "ip.src"; empty for a text item.
    pub abbrev: String,
    /// The field's name, such as "Source Address".
    pub name: String,
    /// The line the tree shows.
    pub label: String,
    /// The value as Wireshark displays it, for a field that has one.
    pub value: Option<String>,
    /// Where the item starts in the frame, in bytes (-1: nowhere).
    pub offset: i64,
    /// How many bytes it covers.
    pub length: i64,
    /// Present for filtering but not shown in the tree.
    #[map(default)]
    pub hidden: bool,
    /// Computed by a dissector, not read from the frame.
    #[map(default)]
    pub generated: bool,
    /// Items below it.
    #[map(default)]
    pub children: Vec<Node>,
}

impl Dissected {
    /// The frame as the map [`Session::dissect`] answers.
    ///
    /// # Errors
    ///
    /// When the map cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(crate::model::refused)
    }

    /// The frame a [`Session::dissect`] map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(crate::model::refused)
    }

    /// Every node with `abbrev`, depth first in tree order.
    pub fn all<'a>(&'a self, abbrev: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        let mut stack: Vec<&Node> = self.tree.iter().rev().collect();
        core::iter::from_fn(move || {
            while let Some(node) = stack.pop() {
                stack.extend(node.children.iter().rev());
                if node.abbrev == abbrev {
                    return Some(node);
                }
            }
            None
        })
    }

    /// The first node with `abbrev`.
    pub fn get(&self, abbrev: &str) -> Option<&Node> {
        fn find<'a>(nodes: &'a [Node], abbrev: &str) -> Option<&'a Node> {
            nodes.iter().find_map(|node| {
                if node.abbrev == abbrev {
                    Some(node)
                } else {
                    find(&node.children, abbrev)
                }
            })
        }
        find(&self.tree, abbrev)
    }
}
