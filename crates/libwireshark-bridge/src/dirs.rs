//! Where the host looks for providers.

use core::ffi::{CStr, c_char};
use std::path::PathBuf;

/// The variable naming more places to look, separated as `PATH` is.
pub(crate) const PATH_VARIABLE: &str = "LIBWIRESHARK_BRIDGE_PATH";

/// The directory below a plugin directory that holds providers: not below
/// a release line's, since a provider serves every line.
const PROVIDERS: &str = "bridge";

/// The `bridge` directory of Wireshark's personal plugin directory, then
/// of its global one, as the running Wireshark names them.
pub(crate) fn plugin_dirs() -> Vec<PathBuf> {
    let Some(wsutil) = wsutil() else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    for name in [&b"get_plugins_pers_dir\0"[..], b"get_plugins_dir\0"] {
        // SAFETY: both are `char *(void)` in every release line; the text
        // is copied here (the personal directory's, allocated for the
        // caller, is left allocated: once, at load).
        let path = unsafe {
            let Ok(function) = wsutil.get::<unsafe extern "C" fn() -> *const c_char>(name) else {
                continue;
            };
            let path = function();
            if path.is_null() {
                continue;
            }
            CStr::from_ptr(path).to_string_lossy().into_owned()
        };
        dirs.push(PathBuf::from(path).join(PROVIDERS));
    }
    dirs
}

/// libwsutil, already loaded by the Wireshark that loaded this plugin.
fn wsutil() -> Option<libloading::Library> {
    #[cfg(windows)]
    {
        libloading::os::windows::Library::open_already_loaded("libwsutil.dll")
            .ok()
            .map(Into::into)
    }
    #[cfg(not(windows))]
    {
        Some(libloading::os::unix::Library::this().into())
    }
}
