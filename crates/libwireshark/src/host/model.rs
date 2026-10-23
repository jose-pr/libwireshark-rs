//! What the host takes and answers.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use std::path::PathBuf;

/// How the host starts Wireshark.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostConfig {
    /// Plugin libraries to load besides Wireshark's own: plugins built for
    /// this release line, `libwireshark-guatiao` among them.
    pub plugins: Vec<PathBuf>,
    /// Load only `plugins`, not those installed in Wireshark's plugin
    /// directories. A plugin listed and also installed would register its
    /// protocols twice, which Wireshark does not survive.
    pub skip_installed_plugins: bool,
    /// A configuration directory (profile) to read preferences from; by
    /// default the user's.
    pub config_dir: Option<PathBuf>,
    /// Preference values, as `tshark -o name:value` takes them
    /// (`"foo.port"` → `"113"`).
    pub preferences: BTreeMap<String, String>,
}

/// One dissected frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dissected {
    /// The frame number, counted from 1 in the session (or the file).
    pub frame: u32,
    /// The packet list's columns, in Wireshark's order.
    pub columns: Vec<Column>,
    /// The protocol tree: one node per protocol, each holding its fields.
    pub tree: Vec<Node>,
}

/// One column of the packet list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Column {
    /// Its title, such as "Protocol".
    pub title: String,
    /// Its text for this frame.
    pub text: String,
}

/// One item of the protocol tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Node {
    /// The field's filter name, such as "ip.src"; empty for a text item.
    pub abbrev: String,
    /// The field's name, such as "Source Address"; empty for a text item.
    pub name: String,
    /// The line the tree shows.
    pub label: String,
    /// The value as Wireshark displays it; `None` for protocols and text.
    pub value: Option<String>,
    /// Where the item starts in its data, in bytes.
    pub offset: i64,
    /// How many bytes it covers.
    pub length: i64,
    /// Present for filtering, not shown.
    pub hidden: bool,
    /// Computed by a dissector, not read from the frame.
    pub generated: bool,
    /// Items below it.
    pub children: Vec<Node>,
}

impl Dissected {
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

    /// The text of the column titled `title`.
    pub fn column(&self, title: &str) -> Option<&str> {
        self.columns
            .iter()
            .find(|column| column.title == title)
            .map(|column| column.text.as_str())
    }
}
