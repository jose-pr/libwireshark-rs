//! What [`plugin!`](crate::plugin) expands to call: the plugin's state,
//! registration with EPAN, and the C callbacks that reach the dissectors.
//!
//! Everything here is `#[doc(hidden)]`; a plugin names only the macro.

mod callbacks;
mod preferences;
mod protocol;
mod runtime;

pub use callbacks::{HeuristicFn, HeuristicResult, heuristic_result};
pub use protocol::Protocol;

use crate::sys;
use core::ffi::c_int;
use core::panic::AssertUnwindSafe;
use runtime::Runtime;
use std::panic::catch_unwind;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// For derive expansions, which cannot assume `extern crate alloc`.
pub use alloc::vec::Vec;

/// `plugin_describe`'s answer: this library holds dissectors.
pub const DESCRIBE_DISSECTOR: u32 = 1;

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

/// Registers the plugin's table with Wireshark.
pub fn register(plugin: &'static sys::proto_plugin) {
    // SAFETY: the table and its callbacks are statics of the plugin library.
    unsafe { sys::proto_register_plugin(plugin) };
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
    state: Mutex<Vec<Runtime>>,
}

impl core::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plugin")
            .field("protocols", &self.protocols)
            .finish_non_exhaustive()
    }
}

impl Plugin {
    /// A plugin of `protocols`, registered when Wireshark loads it.
    pub const fn new(protocols: &'static [Protocol]) -> Self {
        Self {
            protocols,
            state: Mutex::new(Vec::new()),
        }
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
