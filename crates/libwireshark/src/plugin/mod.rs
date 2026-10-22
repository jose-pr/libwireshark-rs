//! What [`plugin!`](crate::plugin) expands to call: the plugin's state,
//! registration with EPAN, and the C callbacks that reach the dissectors.
//!
//! Everything here is `#[doc(hidden)]`; a plugin names only the macro.

mod callbacks;
mod codecs;
mod file_types;
mod filters;
mod preferences;
mod protocol;
mod runtime;
mod symbols;
mod taps;

pub use callbacks::{HeuristicFn, HeuristicResult, heuristic_result};
pub use codecs::CodecSpec;
pub use file_types::FileTypeSpec;
pub use filters::{FilterSpec, PluginStatic};
pub use protocol::Protocol;
pub use taps::TapSpec;

use crate::sys;
use core::ffi::c_int;
use core::panic::AssertUnwindSafe;
use runtime::Runtime;
use std::panic::catch_unwind;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// For derive expansions, which cannot assume `extern crate alloc`.
pub use alloc::vec::Vec;

/// The release line the plugin is built for, checked by Wireshark's loader.
pub const WANT_MAJOR: c_int = sys::VERSION_MAJOR as c_int;
/// See [`WANT_MAJOR`].
pub const WANT_MINOR: c_int = sys::VERSION_MINOR as c_int;

/// `version` followed by a NUL, for the `plugin_version` export.
///
/// # Panics
///
/// At compile time, when `N` is not `version.len() + 1`.
pub const fn nul_terminated<const N: usize>(version: &str) -> [u8; N] {
    let source = version.as_bytes();
    assert!(source.len() + 1 == N, "N is the version's length plus one");
    let mut bytes = [0u8; N];
    let mut index = 0;
    while index < source.len() {
        bytes[index] = source[index];
        index += 1;
    }
    bytes
}

/// The plugin's callbacks that start each kind of registration.
#[derive(Clone, Copy, Debug)]
pub struct Entries {
    /// Protocols, fields and preferences.
    pub register_protoinfo: extern "C" fn(),
    /// Dissector handles and table entries.
    pub register_handoff: extern "C" fn(),
    /// Tap listeners.
    pub register_taps: extern "C" fn(),
    /// Display-filter functions.
    pub register_filters: extern "C" fn(),
    /// Their removal.
    pub deregister_filters: extern "C" fn(),
    /// File formats.
    pub register_file_types: extern "C" fn(),
    /// Codecs.
    pub register_codecs: extern "C" fn(),
}

/// The tables `plugin_register` hands to Wireshark, one per interface.
#[derive(Debug)]
pub struct Tables {
    protocols: sys::proto_plugin,
    taps: sys::tap_plugin,
    filters: filters::DfilterPlugin,
    file_types: file_types::WtapPlugin,
    codecs: codecs::CodecsPlugin,
}

impl Tables {
    /// The tables that start registration with `entries`.
    pub const fn new(entries: Entries) -> Self {
        Self {
            protocols: sys::proto_plugin {
                register_protoinfo: Some(entries.register_protoinfo),
                register_handoff: Some(entries.register_handoff),
            },
            taps: sys::tap_plugin {
                register_tap_listener: Some(entries.register_taps),
            },
            filters: filters::dfilter_plugin(entries.register_filters, entries.deregister_filters),
            file_types: file_types::wtap_plugin(entries.register_file_types),
            codecs: codecs::codecs_plugin(entries.register_codecs),
        }
    }
}

/// The plugin's own C callbacks, which reach its [`Plugin`] static: C
/// callbacks without a data pointer cannot be shared by plugins.
#[derive(Clone, Copy, Debug)]
pub struct Callbacks {
    /// Preferences applied.
    pub apply: extern "C" fn(),
    /// A heuristic list offers a packet.
    pub heuristic: HeuristicFn,
    /// Wireshark closes a capture.
    pub cleanup: extern "C" fn(),
}

/// A plugin's protocols and their registration state.
pub struct Plugin {
    protocols: &'static [Protocol],
    dynamic: Option<fn() -> Vec<Protocol>>,
    dynamic_protocols: Mutex<&'static [Protocol]>,
    taps: &'static [TapSpec],
    filters: &'static [FilterSpec],
    file_types: &'static [FileTypeSpec],
    codecs: &'static [CodecSpec],
    state: Mutex<Vec<Runtime>>,
    filter_state: Mutex<Option<filters::Registered>>,
    file_type_state: Mutex<Option<file_types::Registered>>,
}

impl core::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plugin")
            .field("protocols", &self.protocols)
            .field("dynamic_protocols", &self.dynamic_protocols)
            .field("taps", &self.taps)
            .field("filters", &self.filters)
            .field("file_types", &self.file_types)
            .field("codecs", &self.codecs)
            .finish_non_exhaustive()
    }
}

impl Plugin {
    /// A plugin of `protocols`, those `dynamic` builds when Wireshark loads
    /// it, `taps`, `filters`, `file_types` and `codecs`.
    pub const fn new(
        protocols: &'static [Protocol],
        dynamic: Option<fn() -> Vec<Protocol>>,
        taps: &'static [TapSpec],
        filters: &'static [FilterSpec],
        file_types: &'static [FileTypeSpec],
        codecs: &'static [CodecSpec],
    ) -> Self {
        Self {
            protocols,
            dynamic,
            dynamic_protocols: Mutex::new(&[]),
            taps,
            filters,
            file_types,
            codecs,
            state: Mutex::new(Vec::new()),
            filter_state: Mutex::new(None),
            file_type_state: Mutex::new(None),
        }
    }

    /// `plugin_describe`'s answer: what the plugin provides
    /// (`WS_PLUGIN_DESC_*`).
    pub fn describe(&'static self) -> u32 {
        const DISSECTOR: u32 = 1 << 0;
        const FILE_TYPE: u32 = 1 << 1;
        const CODEC: u32 = 1 << 2;
        const TAP_LISTENER: u32 = 1 << 4;
        const DFILTER: u32 = 1 << 5;
        [
            (
                self.protocols.len() + usize::from(self.dynamic.is_some()),
                DISSECTOR,
            ),
            (self.file_types.len(), FILE_TYPE),
            (self.codecs.len(), CODEC),
            (self.taps.len(), TAP_LISTENER),
            (self.filters.len(), DFILTER),
        ]
        .into_iter()
        .filter(|&(count, _)| count > 0)
        .fold(0, |flags, (_, flag)| flags | flag)
    }

    /// `plugin_register`: hands Wireshark the table of each interface the
    /// plugin uses.
    pub fn register(&'static self, tables: &'static Tables) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Some(build) = self.dynamic {
                let mut built = self
                    .dynamic_protocols
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                // A panicking builder means no run-time protocols, not none
                // of the plugin's other tables.
                if built.is_empty()
                    && let Ok(protocols) = catch_unwind(build)
                {
                    *built = protocols.leak();
                }
            }
            // SAFETY: the tables and their callbacks are statics of the
            // plugin library.
            unsafe {
                if self.protocols().next().is_some() {
                    sys::proto_register_plugin(&tables.protocols);
                }
                if !self.taps.is_empty() {
                    sys::tap_register_plugin(&tables.taps);
                }
            }
            if !self.filters.is_empty() {
                filters::register_plugin(&tables.filters);
            }
            if !self.file_types.is_empty() {
                file_types::register_plugin(&tables.file_types);
            }
            if !self.codecs.is_empty() {
                codecs::register_plugin(&tables.codecs);
            }
        }));
    }

    /// The `wtap_plugin` callback: registers the file formats.
    pub fn register_file_types(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let mut state = self.file_type_state();
            if state.is_none() {
                *state = file_types::register(self.file_types);
            }
        }));
    }

    fn file_type_state(&self) -> MutexGuard<'_, Option<file_types::Registered>> {
        self.file_type_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The `codecs_plugin` callback: registers the codecs.
    pub fn register_codecs(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| codecs::register(self.codecs)));
    }

    /// The display-filter plugin `init`: registers the filter functions.
    pub fn register_filters(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let mut state = self
                .filter_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if state.is_none() {
                *state = filters::register(self.filters);
            }
        }));
    }

    /// The display-filter plugin `cleanup`: deregisters them.
    pub fn deregister_filters(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Some(registered) = self
                .filter_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                registered.deregister();
            }
        }));
    }

    fn filter_api(&'static self) -> Option<filters::Api> {
        self.filter_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|registered| registered.api)
    }

    /// Wireshark's tap registration: offers each tap as `-z <name>`.
    pub fn register_taps(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            for spec in self.taps {
                taps::register(spec, self);
            }
        }));
    }

    /// The static protocols, then those built when the plugin registered.
    fn protocols(&'static self) -> impl Iterator<Item = &'static Protocol> {
        let dynamic: &'static [Protocol] = *self
            .dynamic_protocols
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.protocols.iter().chain(dynamic)
    }

    fn state(&self) -> MutexGuard<'_, Vec<Runtime>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wireshark's `register_protoinfo`: protocols, fields, expert entries
    /// and preferences.
    pub fn register_protoinfo(&'static self, callbacks: Callbacks) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let glib = preferences::Glib::load();
            let mut state = self.state();
            if !state.is_empty() {
                return;
            }
            state.extend(
                self.protocols()
                    .filter_map(|spec| Runtime::register(spec, callbacks, glib.as_ref())),
            );
            // SAFETY: `cleanup` is a static function of the plugin library.
            unsafe {
                sys::register_cleanup_routine(Some(callbacks::trampoline(callbacks.cleanup)))
            };
            // Wireshark frees `g_strdup`'d preference defaults through GLib,
            // so the library stays loaded for the process.
            core::mem::forget(glib);
        }));
    }

    /// Wireshark's `register_handoff`: dissector handles and table entries.
    pub fn register_handoff(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            for runtime in self.state().iter_mut() {
                runtime.handoff();
            }
        }));
    }

    /// The preferences callback: reloads every protocol's typed preferences
    /// and re-evaluates its bindings.
    pub fn apply_preferences(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            for runtime in self.state().iter_mut() {
                runtime.reload();
                runtime.attach();
            }
        }));
    }

    /// The cleanup callback: drops conversation values of the closed capture.
    pub fn cleanup(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            for runtime in self.state().iter() {
                runtime.clear_conversations();
            }
        }));
    }

    /// A heuristic list offers a packet to the protocol named by
    /// `pinfo->current_proto`; returns whether it took it.
    ///
    /// # Safety
    ///
    /// The arguments are those of the running heuristic dissector callback.
    pub unsafe fn heuristic(
        &'static self,
        tvb: *mut sys::tvbuff_t,
        pinfo: *mut sys::packet_info,
        tree: *mut sys::proto_tree,
    ) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: the caller's contract.
            let current = unsafe { pinfo.as_ref() }.map(|pinfo| pinfo.current_proto)?;
            let shared = self
                .state()
                .iter()
                .find_map(|runtime| runtime.named(current))?;
            // SAFETY: `shared` is boxed in a runtime that lives for the
            // process; the arguments are the caller's.
            unsafe { callbacks::dissect(shared.as_ref(), tvb, pinfo, tree) }
        }))
        .ok()
        .flatten()
        .is_some()
    }
}
