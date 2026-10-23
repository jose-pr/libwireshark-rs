//! Tap listeners from providers: each `-z` invocation opens a listener the
//! provider keeps its statistics in.

use crate::describe;
use crate::host::{report, served};
use alloc::sync::Arc;
use guatiao::Map;
use guatiao::library::Object;
use libwireshark::TapPacket;
use libwireshark::dynamic::{DynamicTap, Tap};
use libwireshark_api::{self as api, TapDescription, TapListener};
use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};

/// Every tap listener offered, by its `-z` name; a name taken earlier is
/// skipped.
pub(crate) fn taps(registry: &guatiao::library::Registry) -> Vec<Tap> {
    let mut names = HashSet::new();
    let mut taps = Vec::new();
    for (key, provider) in served::<dyn api::Tap>(registry) {
        let description = match provider
            .describe()
            .and_then(|map| TapDescription::from_map(&map))
        {
            Ok(description) => description,
            Err(error) => {
                report(true, &format!("{key}: describe: {}", error.message()));
                continue;
            }
        };
        let checked = describe::name("tap", &description.name, "_.-").and_then(|name| {
            let tap = describe::name("tap source", &description.tap, "_.-")?;
            Ok((name, tap))
        });
        let (name, tap) = match checked {
            Ok(names) => names,
            Err(error) => {
                report(true, &format!("{key}: {error}"));
                continue;
            }
        };
        if !names.insert(name) {
            report(true, &format!("{key}: the tap {name} is offered already"));
            continue;
        }
        report(false, &format!("{key} listens to {tap} as -z {name}"));
        let key: &'static str = describe::leak(&key);
        taps.push(Tap::new(name, tap, move || {
            Box::new(Listener::open(key, &provider)) as Box<dyn DynamicTap>
        }));
    }
    taps
}

/// One invocation's listener: the provider's, or none when it would not
/// open one (reported once).
struct Listener {
    key: &'static str,
    listener: Option<Mutex<Object<dyn TapListener>>>,
    /// Whether a refused call was reported: once per invocation.
    reported: bool,
}

impl Listener {
    fn open(key: &'static str, provider: &Arc<dyn api::Tap>) -> Self {
        let listener = match provider.open() {
            Ok(listener) => Some(Mutex::new(listener)),
            Err(error) => {
                report(true, &format!("{key}: open: {}", error.message()));
                None
            }
        };
        Self {
            key,
            listener,
            reported: false,
        }
    }

    fn refused(&mut self, call: &str, message: &str) {
        if !self.reported {
            self.reported = true;
            report(true, &format!("{}: {call}: {message}", self.key));
        }
    }
}

/// The packet as the provider reads it.
fn packet_map(packet: &TapPacket<'_>) -> Option<Map> {
    let time = packet.time();
    api::TapPacket {
        frame: packet.frame_number(),
        len: packet.len(),
        time_ns: i64::try_from(time.as_nanos()).unwrap_or(i64::MAX),
        source: packet.source(),
        destination: packet.destination(),
        src_port: packet.src_port(),
        dst_port: packet.dst_port(),
    }
    .to_map()
    .ok()
}

impl DynamicTap for Listener {
    fn packet(&mut self, packet: &TapPacket<'_>) {
        let Some(listener) = &self.listener else {
            return;
        };
        let Some(map) = packet_map(packet) else {
            return;
        };
        let result = listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .packet(&map);
        if let Err(error) = result {
            self.refused("packet", error.message());
        }
    }

    fn draw(&self) -> String {
        let Some(listener) = &self.listener else {
            return String::new();
        };
        match listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .draw()
        {
            Ok(report) => report,
            Err(error) => {
                report(true, &format!("{}: draw: {}", self.key, error.message()));
                String::new()
            }
        }
    }

    fn reset(&mut self) {
        let Some(listener) = &self.listener else {
            return;
        };
        let result = listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reset();
        if let Err(error) = result {
            self.refused("reset", error.message());
        }
    }
}
