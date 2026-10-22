//! Finding providers and turning each into a protocol.

use crate::describe::{self, Names};
use crate::dirs::{PATH_VARIABLE, plugin_dirs};
use crate::header::{self, Laid};
use crate::packet::Lent;
use alloc::sync::Arc;
use guatiao::Map;
use guatiao::library::{Kind, Order, Registry, ScanRules, SearchPath, Skipped, scan_path};
use libwireshark::dynamic::{DynamicDissector, Protocol};
use libwireshark::prefs::PreferenceMap;
use libwireshark::{Binding, PacketView};
use libwireshark_api::{Description, Dissector};
use std::path::Path;

/// Set to anything: report what loaded, not only what failed.
const LOG_VARIABLE: &str = "LIBWIRESHARK_GUATIAO_LOG";

fn report(verbose: bool, line: &str) {
    if verbose || std::env::var_os(LOG_VARIABLE).is_some() {
        eprintln!("libwireshark-guatiao: {line}");
    }
}

/// Every dissector the search path and its sources offer, as protocols.
pub(crate) fn protocols() -> Vec<Protocol> {
    let mut path = SearchPath::parse(&std::env::var(PATH_VARIABLE).unwrap_or_default());
    for dir in plugin_dirs() {
        path = path.with(dir);
    }
    // Handles taken from the registry point into the libraries it mapped,
    // which Wireshark uses for the process: the registry lives as long.
    let registry: &'static mut Registry = Box::leak(Box::new(Registry::new(
        "libwireshark-guatiao",
        env!("CARGO_PKG_VERSION"),
    )));
    let rules = ScanRules::parse(&[format!("kind={}", <dyn Dissector as Kind>::NAME)])
        .expect("a rule written here");
    let scanned = scan_path(registry, &path, Order::Ascending, &rules);
    for (file, key) in &scanned.loaded {
        report(false, &format!("loaded {} as {key}", file.display()));
    }
    for (file, error) in &scanned.failed {
        report(true, &format!("{}: {error}", file.display()));
    }
    for (place, error) in &scanned.unreadable {
        report(false, &format!("{}: {error}", place.display()));
    }
    for (file, skipped) in &scanned.skipped {
        match skipped {
            Skipped::Source { .. } => add_source(registry, file),
            skipped => report(false, &format!("{}: {skipped}", file.display())),
        }
    }
    let refreshed = registry.refresh();
    for served in &refreshed.loaded {
        report(
            false,
            &format!("{} served {} as {}", served.source, served.id, served.key),
        );
    }
    for refused in &refreshed.refused {
        report(true, &format!("{}: {}", refused.source, refused.reason));
    }

    let mut protocols = Vec::new();
    for offer in registry.offers::<dyn Dissector>() {
        let key = offer.key().unwrap_or(offer.id()).to_owned();
        let Some(dissector) = offer.shared() else {
            report(
                true,
                &format!("{key}: built only from a configuration, which this host does not give"),
            );
            continue;
        };
        let description = match dissector
            .describe()
            .and_then(|map| Description::from_map(&map))
        {
            Ok(description) => description,
            Err(error) => {
                report(true, &format!("{key}: describe: {}", error.message()));
                continue;
            }
        };
        let laid = match header::lay_out(&description.header) {
            Ok(laid) => laid,
            Err(field) => {
                report(true, &format!("{key}: header field {field} has no width"));
                continue;
            }
        };
        let spec = match describe::protocol(&description) {
            Ok(spec) => spec,
            Err(error) => {
                report(true, &format!("{key}: {error}"));
                continue;
            }
        };
        report(
            false,
            &format!("{key} dissects {}", description.filter_name),
        );
        protocols.push(Protocol::dynamic(
            spec,
            Provided {
                key,
                dissector,
                header: laid,
                tcp_header_len: description.tcp_header_len.map(|len| len as usize),
                names: Names::default(),
            },
        ));
    }
    for (provider, mismatch) in registry.mismatches::<dyn Dissector>() {
        report(true, &format!("{}: {mismatch}", provider.key()));
    }
    protocols
}

/// Adds the source file `file`, serving the libraries in its directory.
fn add_source(registry: &mut Registry, file: &Path) {
    let dir = file
        .parent()
        .unwrap_or(Path::new("."))
        .display()
        .to_string();
    let mut config = Map::new();
    let mut dirs = guatiao::List::new();
    dirs.push(dir.as_str());
    let mut paths = guatiao::List::new();
    paths.push(dir.as_str());
    config.set("dirs", dirs);
    config.set("paths", paths);
    match registry.add_source_file(file, &config) {
        Ok(name) => report(false, &format!("added the source {name}")),
        Err(error) => report(true, &format!("{}: {error}", file.display())),
    }
}

/// One provider's dissector, as libwireshark calls it.
struct Provided {
    key: String,
    dissector: Arc<dyn Dissector>,
    header: Vec<Laid>,
    tcp_header_len: Option<usize>,
    names: Names,
}

/// The state a protocol keeps per conversation: the provider's map.
#[derive(Default)]
struct Conversation(Option<Map>);

impl DynamicDissector for Provided {
    /// The values as the map the provider reads.
    type Preferences = Map;

    fn preferences(&self, values: &PreferenceMap) -> Option<Map> {
        Some(describe::preference_map(values))
    }

    fn dissect_on(&self, preferences: &Map) -> Vec<Binding> {
        let bindings = self
            .dissector
            .dissect_on(preferences)
            .and_then(|list| libwireshark_api::Binding::from_list(&list));
        match bindings {
            Ok(bindings) => bindings
                .iter()
                .map(|binding| self.names.binding(binding))
                .collect(),
            Err(error) => {
                report(
                    true,
                    &format!("{}: dissect_on: {}", self.key, error.message()),
                );
                Vec::new()
            }
        }
    }

    fn tcp_header_len(&self) -> Option<usize> {
        self.tcp_header_len
    }

    fn message_len(&self, header: &[u8]) -> Option<usize> {
        usize::try_from(self.dissector.message_len(header)).ok()
    }

    fn dissect(&self, preferences: &Map, packet: &mut PacketView<'_>) -> Option<usize> {
        let data = packet.bytes();
        let decoded = header::decode(&self.header, data);
        let mut conversation = packet
            .with_conversation(|state: &mut Conversation| state.0.take())
            .flatten()
            .unwrap_or_default();
        let taken = self.dissector.dissect(
            data,
            &decoded,
            preferences,
            &mut Lent::new(packet),
            &mut conversation,
        );
        packet.with_conversation(|state: &mut Conversation| state.0 = Some(conversation));
        let taken = usize::try_from(taken.ok()?)
            .ok()
            .filter(|&taken| taken > 0)?
            .min(data.len());
        header::add(&self.header, packet);
        Some(taken)
    }
}
