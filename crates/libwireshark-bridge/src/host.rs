//! Finding providers, and turning each dissector into a protocol.

use crate::describe::{self, Names};
use crate::dirs::{PATH_VARIABLE, plugin_dirs};
use crate::header::{self, Laid};
use crate::packet::Lent;
use alloc::sync::Arc;
use guatiao::Map;
use guatiao::library::{Kind, Order, Registry, SearchPath, Skipped, scan_path_with};
use libwireshark::dynamic::{DynamicDissector, Protocol, Registrations};
use libwireshark::prefs::PreferenceMap;
use libwireshark::{Binding, PacketView};
use libwireshark_api::{Codec, Description, Dissector, FileType, FilterFunction, Tap};
use std::path::Path;

/// Set to anything: report what loaded, not only what failed.
const LOG_VARIABLE: &str = "LIBWIRESHARK_BRIDGE_LOG";

/// Writes `line` to stderr when it is a problem (`verbose`) or when
/// `LIBWIRESHARK_BRIDGE_LOG` asks for everything.
pub(crate) fn report(verbose: bool, line: &str) {
    if verbose || std::env::var_os(LOG_VARIABLE).is_some() {
        eprintln!("libwireshark-bridge: {line}");
    }
}

/// The kinds this host serves: a library declaring none is not mapped.
const KINDS: [&str; 5] = [
    <dyn Dissector as Kind>::NAME,
    <dyn Tap as Kind>::NAME,
    <dyn FilterFunction as Kind>::NAME,
    <dyn FileType as Kind>::NAME,
    <dyn Codec as Kind>::NAME,
];

/// Everything the search path and its sources offer, registered with
/// Wireshark when it loads this plugin.
pub(crate) fn registrations() -> Registrations {
    let registry = load();
    let mut registrations = Registrations::from(protocols(registry));
    registrations.taps = crate::tap::taps(registry);
    registrations.filters = crate::filter::functions(registry);
    registrations.file_types = crate::file_type::formats(registry);
    registrations.codecs = crate::codec::codecs(registry);
    registrations
}

/// The registry of every provider on the search path.
fn load() -> &'static Registry {
    let mut path = SearchPath::parse(&std::env::var(PATH_VARIABLE).unwrap_or_default());
    for dir in plugin_dirs() {
        path = path.with(dir);
    }
    // Handles taken from the registry point into the libraries it mapped,
    // which Wireshark uses for the process: the registry lives as long.
    let registry: &'static mut Registry = Box::leak(Box::new(Registry::new(
        "libwireshark-bridge",
        env!("CARGO_PKG_VERSION"),
    )));
    let scanned = scan_path_with(registry, &path, Order::Ascending, |declared| {
        if KINDS.iter().any(|kind| declared.has("kind", kind)) {
            Ok(())
        } else {
            Err(format!("serves none of {}", KINDS.join(", ")))
        }
    });
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
    registry
}

/// Each provider of `K` with its default instance, by key; one built only
/// from a configuration, or whose table does not read, is reported.
pub(crate) fn served<K: ?Sized + Kind>(registry: &Registry) -> Vec<(String, Arc<K>)> {
    let mut served = Vec::new();
    for offer in registry.offers::<K>() {
        let key = offer.key().unwrap_or(offer.id()).to_owned();
        match offer.shared() {
            Some(provider) => served.push((key, provider)),
            None => report(
                true,
                &format!("{key}: built only from a configuration, which this host does not give"),
            ),
        }
    }
    for (provider, mismatch) in registry.mismatches::<K>() {
        report(true, &format!("{}: {mismatch}", provider.key()));
    }
    served
}

/// Every dissector offered, as protocols.
fn protocols(registry: &Registry) -> Vec<Protocol> {
    let mut protocols = Vec::new();
    for (key, dissector) in served::<dyn Dissector>(registry) {
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
