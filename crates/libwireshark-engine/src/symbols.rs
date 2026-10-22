//! The libwiretap, libwsutil and GLib functions the engine calls, and the
//! libwireshark ones its headers bundle lacks, resolved from the libraries
//! the process already holds: the build links libwireshark alone.

use crate::EngineError;
use core::ffi::{c_char, c_int, c_uint, c_void};
use libwireshark_sys as sys;
use std::path::PathBuf;

/// The functions, with the signatures Wireshark 4.6's headers declare.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Api {
    /// `ws_log_init(vcmdarg_err)`, given null: errors in the logging
    /// environment variables go to stderr.
    pub(crate) ws_log_init: unsafe extern "C" fn(*const c_void),
    pub(crate) init_process_policies: unsafe extern "C" fn(),
    pub(crate) configuration_init: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    pub(crate) set_persconffile_dir: unsafe extern "C" fn(*const c_char),
    /// `init_report_message(name, const struct report_message_routines *)`.
    pub(crate) init_report_message: unsafe extern "C" fn(*const c_char, *const c_void),
    pub(crate) timestamp_set_type: unsafe extern "C" fn(c_int),
    pub(crate) timestamp_set_precision: unsafe extern "C" fn(c_int),
    pub(crate) timestamp_set_seconds_type: unsafe extern "C" fn(c_int),
    pub(crate) wtap_init: unsafe extern "C" fn(bool),
    pub(crate) wtap_open_offline: unsafe extern "C" fn(
        *const c_char,
        c_uint,
        *mut c_int,
        *mut *mut c_char,
        bool,
    ) -> *mut sys::wtap,
    pub(crate) wtap_read: unsafe extern "C" fn(
        *mut sys::wtap,
        *mut sys::wtap_rec,
        *mut c_int,
        *mut *mut c_char,
        *mut i64,
    ) -> bool,
    pub(crate) wtap_close: unsafe extern "C" fn(*mut sys::wtap),
    pub(crate) wtap_file_type_subtype: unsafe extern "C" fn(*mut sys::wtap) -> c_int,
    pub(crate) wtap_strerror: unsafe extern "C" fn(c_int) -> *const c_char,
    pub(crate) wtap_rec_init: unsafe extern "C" fn(*mut sys::wtap_rec, usize),
    pub(crate) wtap_rec_reset: unsafe extern "C" fn(*mut sys::wtap_rec),
    pub(crate) wtap_rec_cleanup: unsafe extern "C" fn(*mut sys::wtap_rec),
    pub(crate) wtap_setup_packet_rec: unsafe extern "C" fn(*mut sys::wtap_rec, c_int),
    pub(crate) ws_buffer_append: unsafe extern "C" fn(*mut sys::Buffer, *const u8, usize),
    /// `g_strdup_vprintf(format, va_list)`: a `va_list` crosses as one
    /// pointer-sized argument on every target the engine supports.
    pub(crate) g_strdup_vprintf: unsafe extern "C" fn(*const c_char, *mut c_void) -> *mut c_char,
    pub(crate) g_free: unsafe extern "C" fn(*mut c_void),
}

/// The path libwireshark was loaded from.
#[cfg(unix)]
pub(crate) fn libwireshark_path() -> Result<PathBuf, EngineError> {
    use std::os::unix::ffi::OsStrExt;
    // A string in libwireshark's own read-only data: its address names the
    // library even where the process loaded it with local symbols.
    // SAFETY: no arguments; answers a static string.
    let anchor = unsafe { sys::epan_get_version() }.cast::<c_void>();
    // SAFETY: zeroed is a valid `Dl_info`, which `dladdr` fills.
    let mut info: libc::Dl_info = unsafe { core::mem::zeroed() };
    // SAFETY: `anchor` lies in a loaded library.
    if unsafe { libc::dladdr(anchor, &mut info) } == 0 || info.dli_fname.is_null() {
        return Err(EngineError::Symbols("the path of libwireshark".into()));
    }
    // SAFETY: `dladdr` answered a NUL-terminated path.
    let path = unsafe { core::ffi::CStr::from_ptr(info.dli_fname) };
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes())))
}

/// The path libwireshark was loaded from.
#[cfg(windows)]
pub(crate) fn libwireshark_path() -> Result<PathBuf, EngineError> {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleFileNameW(module: *mut c_void, name: *mut u16, size: u32) -> u32;
    }
    let library = libloading::os::windows::Library::open_already_loaded("libwireshark.dll")
        .map_err(|error| EngineError::Symbols(format!("libwireshark.dll: {error}")))?;
    // Leaked: libwireshark stays loaded for the process.
    let module = library.into_raw() as *mut c_void;
    let mut name = vec![0u16; 32 * 1024];
    let size = u32::try_from(name.len()).unwrap_or(u32::MAX);
    // SAFETY: `module` is loaded; the buffer holds `size` units.
    let written = unsafe { GetModuleFileNameW(module, name.as_mut_ptr(), size) } as usize;
    if written == 0 || written >= name.len() {
        return Err(EngineError::Symbols("the path of libwireshark.dll".into()));
    }
    name.truncate(written);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&name)))
}

/// The already loaded library `windows` names on Windows, or whose file
/// name starts with `unix_prefix` beside libwireshark elsewhere: loading it
/// again opens the copy the process holds.
fn loaded(windows: &str, unix_prefix: &str) -> Result<libloading::Library, EngineError> {
    #[cfg(windows)]
    {
        let _ = unix_prefix;
        libloading::os::windows::Library::open_already_loaded(windows)
            .map(Into::into)
            .map_err(|error| EngineError::Symbols(format!("{windows}: {error}")))
    }
    #[cfg(unix)]
    {
        let _ = windows;
        let path = libwireshark_path()?;
        if unix_prefix.is_empty() {
            // SAFETY: libwireshark itself, already loaded.
            return unsafe { libloading::Library::new(&path) }
                .map_err(|error| EngineError::Symbols(format!("{}: {error}", path.display())));
        }
        let dir = path
            .parent()
            .ok_or_else(|| EngineError::Symbols(format!("the directory of {}", path.display())))?;
        let mut candidates = std::fs::read_dir(dir)
            .map_err(|error| EngineError::Symbols(format!("{}: {error}", dir.display())))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(unix_prefix))
            })
            .collect::<Vec<_>>();
        // The shortest name first: `libwiretap.so` before `libwiretap.so.16.0.9`.
        candidates.sort_by_key(|path| path.as_os_str().len());
        candidates
            .iter()
            // SAFETY: a library of the running Wireshark, already loaded:
            // its initialisers do not run again.
            .find_map(|candidate| unsafe { libloading::Library::new(candidate) }.ok())
            .ok_or_else(|| {
                EngineError::Symbols(format!("{unix_prefix}* beside {}", path.display()))
            })
    }
}

/// GLib, which every Wireshark library links.
fn glib() -> Result<libloading::Library, EngineError> {
    #[cfg(windows)]
    {
        loaded("glib-2.0-0.dll", "")
    }
    #[cfg(unix)]
    {
        let this: libloading::Library = libloading::os::unix::Library::this().into();
        // SAFETY: only looked up.
        if unsafe { this.get::<unsafe extern "C" fn()>(b"g_free\0") }.is_ok() {
            return Ok(this);
        }
        // Loaded with local symbols: reach GLib by its soname.
        ["libglib-2.0.so.0", "libglib-2.0.0.dylib"]
            .iter()
            // SAFETY: GLib, already loaded as libwireshark's dependency.
            .find_map(|name| unsafe { libloading::Library::new(name) }.ok())
            .ok_or_else(|| EngineError::Symbols("GLib".into()))
    }
}

/// The function `name` (NUL-terminated) of `library`.
///
/// # Safety
///
/// `T` is the function's signature.
unsafe fn function<T: Copy>(library: &libloading::Library, name: &[u8]) -> Result<T, EngineError> {
    // SAFETY: the caller's contract.
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|_| {
            EngineError::Symbols(
                String::from_utf8_lossy(name.strip_suffix(b"\0").unwrap_or(name)).into_owned(),
            )
        })
}

impl Api {
    pub(crate) fn load() -> Result<Self, EngineError> {
        // Loads libwireshark, with wiretap and wsutil, where a binary
        // delay-loads it.
        // SAFETY: no arguments; answers a static string.
        let _ = unsafe { sys::epan_get_version() };
        let wireshark = loaded("libwireshark.dll", "")?;
        let wiretap = loaded("libwiretap.dll", "libwiretap.")?;
        let wsutil = loaded("libwsutil.dll", "libwsutil.")?;
        let glib = glib()?;
        // SAFETY: each signature is the one Wireshark 4.6 declares.
        let api = unsafe {
            Self {
                ws_log_init: function(&wsutil, b"ws_log_init\0")?,
                init_process_policies: function(&wsutil, b"init_process_policies\0")?,
                configuration_init: function(&wsutil, b"configuration_init\0")?,
                set_persconffile_dir: function(&wsutil, b"set_persconffile_dir\0")?,
                init_report_message: function(&wsutil, b"init_report_message\0")?,
                timestamp_set_type: function(&wireshark, b"timestamp_set_type\0")?,
                timestamp_set_precision: function(&wireshark, b"timestamp_set_precision\0")?,
                timestamp_set_seconds_type: function(&wireshark, b"timestamp_set_seconds_type\0")?,
                wtap_init: function(&wiretap, b"wtap_init\0")?,
                wtap_open_offline: function(&wiretap, b"wtap_open_offline\0")?,
                wtap_read: function(&wiretap, b"wtap_read\0")?,
                wtap_close: function(&wiretap, b"wtap_close\0")?,
                wtap_file_type_subtype: function(&wiretap, b"wtap_file_type_subtype\0")?,
                wtap_strerror: function(&wiretap, b"wtap_strerror\0")?,
                wtap_rec_init: function(&wiretap, b"wtap_rec_init\0")?,
                wtap_rec_reset: function(&wiretap, b"wtap_rec_reset\0")?,
                wtap_rec_cleanup: function(&wiretap, b"wtap_rec_cleanup\0")?,
                wtap_setup_packet_rec: function(&wiretap, b"wtap_setup_packet_rec\0")?,
                ws_buffer_append: function(&wsutil, b"ws_buffer_append\0")?,
                g_strdup_vprintf: function(&glib, b"g_strdup_vprintf\0")?,
                g_free: function(&glib, b"g_free\0")?,
            }
        };
        // The functions outlive these handles: the libraries stay loaded
        // for the process.
        core::mem::forget((wireshark, wiretap, wsutil, glib));
        Ok(api)
    }
}
