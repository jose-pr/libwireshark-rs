//! The engine as a guatiao provider of `wireshark_engine`: what the
//! `libwireshark` Python package, or a host in any language guatiao
//! reaches, loads to dissect with Wireshark.

use crate::{Encapsulation, Engine, EngineConfig, EngineError};
use core::time::Duration;
use guatiao::library::{Object, ProviderError};
use guatiao::{FromValue, Map, Provider, Status, ToValue};
use libwireshark_api::engine::{self as kinds, Session as _};
use std::path::Path;

fn refused(error: &EngineError) -> ProviderError {
    let status = match error {
        EngineError::Unsupported => Status::GUATIAO_ERR_UNSUPPORTED,
        EngineError::AlreadyOpen => Status::GUATIAO_ERR_BUSY,
        EngineError::Symbols(_) | EngineError::Init(_) => Status::GUATIAO_ERR_INTERNAL,
        _ => Status::GUATIAO_ERR_BAD_VALUE,
    };
    ProviderError::new(status, &error.to_string())
}

fn bad_value(what: &str) -> ProviderError {
    ProviderError::new(Status::GUATIAO_ERR_BAD_VALUE, what)
}

/// Starts Wireshark in the calling process.
#[derive(Default, Provider)]
#[provider(libwireshark_api::engine::Engine, crate = ::libwireshark_api::guatiao)]
pub struct WiresharkEngine;

impl kinds::Engine for WiresharkEngine {
    fn open(&self, config: &Map) -> Result<Object<dyn kinds::Session>, ProviderError> {
        let config = EngineConfig::from_value(&config.to_value()?)
            .map_err(|error| bad_value(&format!("engine configuration: {error}")))?;
        let engine = Engine::open(&config).map_err(|error| refused(&error))?;
        Ok(Session(engine).into_object())
    }
}

/// An open engine, owned by the host that opened it.
struct Session(Engine);

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
        self.0
            .dissect(data, Encapsulation(encapsulation), time)
            .map_err(|error| refused(&error))?
            .to_map()
    }

    fn open_file(&mut self, path: &str, display_filter: &str) -> Result<(), ProviderError> {
        let filter = Some(display_filter).filter(|filter| !filter.is_empty());
        self.0
            .open_file(Path::new(path), filter)
            .map_err(|error| refused(&error))
    }

    fn next(&mut self) -> Result<Map, ProviderError> {
        match self.0.next_frame().map_err(|error| refused(&error))? {
            Some(frame) => frame.to_map(),
            None => Ok(Map::new()),
        }
    }
}

guatiao::providers!(WiresharkEngine);
