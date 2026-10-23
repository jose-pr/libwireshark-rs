//! Wireshark itself as a guatiao provider of `wireshark_host`: what
//! the `libwireshark` Python package, or a host in any language guatiao
//! reaches, loads (this library) to dissect with Wireshark.

use core::time::Duration;
use guatiao::library::{Object, ProviderError};
use guatiao::{FromValue, Map, Provider, Status, ToValue};
use libwireshark::Encapsulation;
use libwireshark::host::{self, Host, HostError};
use libwireshark_api::host::{self as kinds, Session as _};
use std::path::{Path, PathBuf};

fn refused(error: &HostError) -> ProviderError {
    let status = match error {
        HostError::AlreadyOpen => Status::GUATIAO_ERR_BUSY,
        HostError::Symbols(_) | HostError::Init(_) => Status::GUATIAO_ERR_INTERNAL,
        _ => Status::GUATIAO_ERR_BAD_VALUE,
    };
    ProviderError::new(status, &error.to_string())
}

fn bad_value(what: &str) -> ProviderError {
    ProviderError::new(Status::GUATIAO_ERR_BAD_VALUE, what)
}

/// The configuration map as the engine takes it.
fn config(map: &Map) -> Result<host::HostConfig, ProviderError> {
    let config = kinds::HostConfig::from_value(&map.to_value()?)
        .map_err(|error| bad_value(&format!("engine configuration: {error}")))?;
    Ok(host::HostConfig {
        plugins: config.plugins.into_iter().map(PathBuf::from).collect(),
        skip_installed_plugins: config.skip_installed_plugins,
        config_dir: config.config_dir.map(PathBuf::from),
        preferences: config.preferences,
    })
}

fn node(node: host::Node) -> kinds::Node {
    kinds::Node {
        abbrev: node.abbrev,
        name: node.name,
        label: node.label,
        value: node.value,
        offset: node.offset,
        length: node.length,
        hidden: node.hidden,
        generated: node.generated,
        children: node.children.into_iter().map(self::node).collect(),
    }
}

/// A frame as the map the kind answers.
fn dissected(frame: host::Dissected) -> Result<Map, ProviderError> {
    kinds::Dissected {
        frame: frame.frame,
        columns: frame
            .columns
            .into_iter()
            .map(|column| kinds::Column {
                title: column.title,
                text: column.text,
            })
            .collect(),
        tree: frame.tree.into_iter().map(node).collect(),
    }
    .to_map()
}

/// Starts Wireshark in the calling process.
#[derive(Default, Provider)]
#[provider(libwireshark_api::host::Host, crate = ::libwireshark_api::guatiao)]
pub struct WiresharkHost;

impl kinds::Host for WiresharkHost {
    fn open(&self, config: &Map) -> Result<Object<dyn kinds::Session>, ProviderError> {
        let host = Host::open(&self::config(config)?).map_err(|error| refused(&error))?;
        Ok(Session(host).into_object())
    }
}

/// An open session, owned by the guatiao host that opened it.
struct Session(Host);

impl kinds::Session for Session {
    fn dissect(
        &mut self,
        data: &[u8],
        encapsulation: i64,
        time_ns: i64,
    ) -> Result<Map, ProviderError> {
        let encapsulation = i32::try_from(encapsulation)
            .map_err(|_| bad_value(&format!("encapsulation {encapsulation}")))?;
        let time = Duration::from_nanos(u64::try_from(time_ns).unwrap_or(0));
        let frame = self
            .0
            .dissect(data, Encapsulation::from_raw(encapsulation), time)
            .map_err(|error| refused(&error))?;
        dissected(frame)
    }

    fn open_file(&mut self, path: &str, display_filter: &str) -> Result<(), ProviderError> {
        let filter = Some(display_filter).filter(|filter| !filter.is_empty());
        self.0
            .open_file(Path::new(path), filter)
            .map_err(|error| refused(&error))
    }

    fn next(&mut self) -> Result<Map, ProviderError> {
        match self.0.next_frame().map_err(|error| refused(&error))? {
            Some(frame) => dissected(frame),
            None => Ok(Map::new()),
        }
    }
}
