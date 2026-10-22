//! What [`plugin!`](crate::plugin) expands to call: the plugin's state,
//! registration with EPAN, and the C callbacks that reach the dissectors.
//!
//! Everything here is `#[doc(hidden)]`; a plugin names only the macro.

mod callbacks;
mod filters;
mod preferences;
mod protocol;
mod runtime;
mod taps;

pub use callbacks::{HeuristicFn, HeuristicResult, heuristic_result};
pub use filters::{DfilterPlugin, FilterSpec, PluginStatic, dfilter_plugin};
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

/// `plugin_describe`'s answer for a plugin with `taps` taps and `filters`
/// filter functions: dissectors, plus tap listeners and display-filter
/// functions when it has any (`WS_PLUGIN_DESC_*`).
pub const fn describe(taps: usize, filters: usize) -> u32 {
    const DISSECTOR: u32 = 1 << 0;
    const TAP_LISTENER: u32 = 1 << 4;
    const DFILTER: u32 = 1 << 5;
    let mut flags = DISSECTOR;
    if taps > 0 {
        flags |= TAP_LISTENER;
    }
    if filters > 0 {
        flags |= DFILTER;
    }
    flags
}

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

/// The registration table `plugin_register` hands to Wireshark.
pub const fn proto_plugin(
    register_protoinfo: extern "C" fn(),
    register_handoff: extern "C" fn(),
) -> sys::proto_plugin {
    sys::proto_plugin {
        register_protoinfo: Some(register_protoinfo),
        register_handoff: Some(register_handoff),
    }
}

/// The tap registration table `plugin_register` hands to Wireshark.
pub const fn tap_plugin(register_tap_listener: extern "C" fn()) -> sys::tap_plugin {
    sys::tap_plugin {
        register_tap_listener: Some(register_tap_listener),
    }
}

/// Registers the plugin's tables with Wireshark: the tap and display-filter
/// tables only when the plugin has taps or filter functions.
pub fn register(
    plugin: &'static sys::proto_plugin,
    taps: &'static sys::tap_plugin,
    filters: &'static DfilterPlugin,
    [has_taps, has_filters]: [bool; 2],
) {
    // SAFETY: the tables and their callbacks are statics of the plugin library.
    unsafe {
        sys::proto_register_plugin(plugin);
        if has_taps {
            sys::tap_register_plugin(taps);
        }
    }
    if has_filters {
        filters::register_plugin(filters);
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
    taps: &'static [TapSpec],
    filters: &'static [FilterSpec],
    state: Mutex<Vec<Runtime>>,
    filter_state: Mutex<Option<filters::Registered>>,
}

impl core::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plugin")
            .field("protocols", &self.protocols)
            .field("taps", &self.taps)
            .field("filters", &self.filters)
            .finish_non_exhaustive()
    }
}

impl Plugin {
    /// A plugin of `protocols`, `taps` and `filters`, registered when
    /// Wireshark loads it.
    pub const fn new(
        protocols: &'static [Protocol],
        taps: &'static [TapSpec],
        filters: &'static [FilterSpec],
    ) -> Self {
        Self {
            protocols,
            taps,
            filters,
            state: Mutex::new(Vec::new()),
            filter_state: Mutex::new(None),
        }
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
                self.protocols
                    .iter()
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
