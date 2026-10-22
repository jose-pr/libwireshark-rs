//! The engine on Wireshark 4.6: started as tshark starts, one frame at a
//! time as tshark's single pass dissects it.

use crate::symbols::Api;
use crate::{Column, Dissected, EngineConfig, EngineError, Node};
use alloc::ffi::CString;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::{self, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use libwireshark_sys as sys;
use std::io::Write as _;
use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError};

/// Wireshark's state is per process and starts once: the configuration it
/// started with, or why it did not.
static STARTED: Mutex<Option<Result<Started, EngineError>>> = Mutex::new(None);

/// Whether a session is open: EPAN dissects for one at a time.
static OPEN: AtomicBool = AtomicBool::new(false);

/// The functions, for the report callbacks too.
static API: OnceLock<Result<Api, EngineError>> = OnceLock::new();

#[derive(Clone, Debug)]
struct Started {
    config: EngineConfig,
    /// The packet list's column count, from the loaded preferences.
    columns: c_int,
}

fn api() -> Result<Api, EngineError> {
    API.get_or_init(Api::load).clone()
}

/// A C string Wireshark answered, as text.
///
/// # Safety
///
/// `text` is null or NUL-terminated.
unsafe fn text(text: *const c_char) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned()
}

/// Text Wireshark allocated with GLib, freed once read.
///
/// # Safety
///
/// `owned` is null or a NUL-terminated GLib allocation.
unsafe fn take(api: &Api, owned: *mut c_char) -> Option<String> {
    if owned.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let read = unsafe { text(owned) };
    // SAFETY: a GLib allocation, not used again.
    unsafe { (api.g_free)(owned.cast()) };
    Some(read)
}

/// What wiretap says `err` means, with its detail.
///
/// # Safety
///
/// `detail` is null or a GLib allocation, freed here.
unsafe fn wtap_error(api: &Api, err: c_int, detail: *mut c_char) -> String {
    // SAFETY: answers a static string.
    let mut message = unsafe { text((api.wtap_strerror)(err)) };
    // SAFETY: the caller's contract.
    if let Some(detail) = unsafe { take(api, detail) } {
        message = format!("{message} ({detail})");
    }
    message
}

fn c_string(
    value: &str,
    error: impl FnOnce(String) -> EngineError,
) -> Result<CString, EngineError> {
    CString::new(value).map_err(|_| error(format!("{value:?} holds a NUL byte")))
}

/// Starts Wireshark as tshark does: the plugins in `config` registered
/// before wiretap and EPAN start, then the profile's preferences with
/// `config`'s on top.
fn start(config: &EngineConfig) -> Result<Started, EngineError> {
    let api = api()?;
    // SAFETY: each call is one tshark makes once, in this order, before
    // any dissection.
    unsafe {
        // Wireshark's log levels, from `WIRESHARK_LOG_LEVEL` and the like.
        (api.ws_log_init)(ptr::null());
        (api.init_process_policies)();
        #[cfg(windows)]
        locate_installation()?;
        let program = std::env::current_exe()
            .ok()
            .and_then(|path| path.to_str().and_then(|path| CString::new(path).ok()))
            .unwrap_or_default();
        if let Some(why) = take(&api, (api.configuration_init)(program.as_ptr())) {
            report(&format!("configuration: {why}"));
        }
        if let Some(dir) = &config.config_dir {
            let dir = c_string(dir, EngineError::Init)?;
            (api.set_persconffile_dir)(dir.as_ptr());
        }
        (api.init_report_message)(
            c"libwireshark-engine".as_ptr(),
            ptr::from_ref(&ROUTINES).cast(),
        );
        // tshark's defaults: times relative to the first frame.
        (api.timestamp_set_type)(0);
        (api.timestamp_set_precision)(-1);
        (api.timestamp_set_seconds_type)(0);

        let (mut major, mut minor, mut micro) = (0, 0, 0);
        sys::epan_get_version_number(&mut major, &mut minor, &mut micro);
        for plugin in &config.plugins {
            register(plugin, (major, minor))?;
        }
        let installed = !config.skip_installed_plugins;
        (api.wtap_init)(installed);
        if !sys::epan_init(None, null_mut(), installed) {
            return Err(EngineError::Init("epan_init failed".into()));
        }
        let prefs = sys::epan_load_settings();
        for (name, value) in &config.preferences {
            set_preference(&api, name, value)?;
        }
        sys::prefs_apply_all();
        Ok(Started {
            config: config.clone(),
            columns: if prefs.is_null() {
                0
            } else {
                (*prefs).num_cols
            },
        })
    }
}

/// Points Wireshark at the installation libwireshark came from: on
/// Windows it otherwise looks beside the running program.
#[cfg(windows)]
fn locate_installation() -> Result<(), EngineError> {
    let library = crate::symbols::libwireshark_path()?;
    let Some(dir) = library.parent() else {
        return Ok(());
    };
    for (variable, path) in [
        ("WIRESHARK_DATA_DIR", dir.to_path_buf()),
        ("WIRESHARK_PLUGIN_DIR", dir.join("plugins")),
    ] {
        if std::env::var_os(variable).is_none() {
            // SAFETY: Windows serialises access to the environment, and
            // Wireshark reads these only once it starts, after this.
            unsafe { std::env::set_var(variable, path) };
        }
    }
    Ok(())
}

/// Loads the plugin library at `path` and runs its `plugin_register`, as
/// Wireshark's own loader does, so it registers with EPAN's start.
fn register(path: &str, line: (c_int, c_int)) -> Result<(), EngineError> {
    let fail = |reason: String| EngineError::Plugin {
        path: path.into(),
        reason,
    };
    // SAFETY: a Wireshark plugin's initialisers only set its statics.
    let library =
        unsafe { libloading::Library::new(path) }.map_err(|error| fail(error.to_string()))?;
    let wanted = |name: &[u8]| {
        // SAFETY: the plugin ABI's `const int plugin_want_major` and `_minor`.
        unsafe { library.get::<*const c_int>(name) }
            .ok()
            .map(|symbol| unsafe { **symbol })
    };
    let (Some(major), Some(minor)) = (
        wanted(b"plugin_want_major\0"),
        wanted(b"plugin_want_minor\0"),
    ) else {
        return Err(fail("not a Wireshark plugin".into()));
    };
    if (major, minor) != line {
        return Err(fail(format!(
            "built for Wireshark {major}.{minor}, not {}.{}",
            line.0, line.1
        )));
    }
    // SAFETY: the plugin ABI's `void plugin_register(void)`.
    let plugin_register = unsafe { library.get::<unsafe extern "C" fn()>(b"plugin_register\0") }
        .map_err(|_| fail("no plugin_register".into()))?;
    // SAFETY: called once, before EPAN starts, as Wireshark calls it.
    unsafe { plugin_register() };
    // The plugin's registrations point into it for the process.
    core::mem::forget(library);
    Ok(())
}

/// Sets one preference as `-o name:value` does.
///
/// # Safety
///
/// After `epan_load_settings`.
unsafe fn set_preference(api: &Api, name: &str, value: &str) -> Result<(), EngineError> {
    let preference = format!("{name}:{value}");
    let fail = |reason: String| EngineError::Preference {
        preference: preference.clone(),
        reason,
    };
    let mut argument = CString::new(preference.as_str())
        .map_err(|_| fail("holds a NUL byte".into()))?
        .into_bytes_with_nul();
    let mut detail = null_mut();
    // SAFETY: a writable NUL-terminated copy; `detail` is GLib's to fill.
    let result = unsafe { sys::prefs_set_pref(argument.as_mut_ptr().cast(), &mut detail) };
    // SAFETY: freed once read.
    let detail = unsafe { take(api, detail) };
    match result {
        sys::prefs_set_pref_e_PREFS_SET_OK => Ok(()),
        sys::prefs_set_pref_e_PREFS_SET_NO_SUCH_PREF => Err(fail("no such preference".into())),
        sys::prefs_set_pref_e_PREFS_SET_OBSOLETE => Err(fail("obsolete".into())),
        _ => Err(fail(detail.unwrap_or_else(|| "not a valid value".into()))),
    }
}

fn report(message: &str) {
    let _ = writeln!(std::io::stderr(), "libwireshark-engine: {message}");
}

/// `struct report_message_routines`: where Wireshark reports failures
/// that are not the caller's to handle, as tshark prints them.
#[repr(C)]
struct Routines {
    vreport_failure: unsafe extern "C" fn(*const c_char, *mut c_void),
    vreport_warning: unsafe extern "C" fn(*const c_char, *mut c_void),
    report_open_failure: unsafe extern "C" fn(*const c_char, c_int, bool),
    report_read_failure: unsafe extern "C" fn(*const c_char, c_int),
    report_write_failure: unsafe extern "C" fn(*const c_char, c_int),
    report_rename_failure: unsafe extern "C" fn(*const c_char, *const c_char, c_int),
    report_cfile_open_failure: unsafe extern "C" fn(*const c_char, c_int, *mut c_char),
    report_cfile_dump_open_failure: unsafe extern "C" fn(*const c_char, c_int, *mut c_char, c_int),
    report_cfile_read_failure: unsafe extern "C" fn(*const c_char, c_int, *mut c_char),
    report_cfile_write_failure:
        unsafe extern "C" fn(*const c_char, *const c_char, c_int, *mut c_char, u64, c_int),
    report_cfile_close_failure: unsafe extern "C" fn(*const c_char, c_int, *mut c_char),
}

static ROUTINES: Routines = Routines {
    vreport_failure: formatted,
    vreport_warning: formatted,
    report_open_failure: system_error_open,
    report_read_failure: system_error,
    report_write_failure: system_error,
    report_rename_failure: rename_failure,
    report_cfile_open_failure: capture_error,
    report_cfile_dump_open_failure: dump_error,
    report_cfile_read_failure: capture_error,
    report_cfile_write_failure: write_error,
    report_cfile_close_failure: capture_error,
};

unsafe extern "C" fn formatted(format: *const c_char, arguments: *mut c_void) {
    if let Some(Ok(api)) = API.get() {
        // SAFETY: Wireshark's format and its arguments.
        if let Some(message) = unsafe { take(api, (api.g_strdup_vprintf)(format, arguments)) } {
            report(&message);
        }
    }
}

unsafe extern "C" fn system_error_open(file: *const c_char, err: c_int, _writing: bool) {
    // SAFETY: Wireshark's file name.
    unsafe { system_error(file, err) };
}

unsafe extern "C" fn system_error(file: *const c_char, err: c_int) {
    // SAFETY: Wireshark's file name.
    let file = unsafe { text(file) };
    report(&format!(
        "{file}: {}",
        std::io::Error::from_raw_os_error(err)
    ));
}

unsafe extern "C" fn rename_failure(from: *const c_char, to: *const c_char, err: c_int) {
    // SAFETY: Wireshark's file names.
    let (from, to) = unsafe { (text(from), text(to)) };
    report(&format!(
        "{from} -> {to}: {}",
        std::io::Error::from_raw_os_error(err)
    ));
}

unsafe extern "C" fn capture_error(file: *const c_char, err: c_int, detail: *mut c_char) {
    if let Some(Ok(api)) = API.get() {
        // SAFETY: Wireshark's file name, and its detail to free.
        let (file, message) = unsafe { (text(file), wtap_error(api, err, detail)) };
        report(&format!("{file}: {message}"));
    }
}

unsafe extern "C" fn dump_error(
    file: *const c_char,
    err: c_int,
    detail: *mut c_char,
    _type: c_int,
) {
    // SAFETY: as `capture_error`.
    unsafe { capture_error(file, err, detail) };
}

unsafe extern "C" fn write_error(
    _from: *const c_char,
    file: *const c_char,
    err: c_int,
    detail: *mut c_char,
    _frame: u64,
    _type: c_int,
) {
    // SAFETY: as `capture_error`.
    unsafe { capture_error(file, err, detail) };
}

/// The frames a dissection may look back at, as tshark's capture file
/// keeps them; EPAN reaches them through `packet_provider_data`.
struct Frames {
    count: u32,
    cumulative_bytes: u32,
    elapsed: sys::nstime_t,
    reference: *const sys::frame_data,
    reference_frame: sys::frame_data,
    previous_displayed: *const sys::frame_data,
    previous_displayed_frame: sys::frame_data,
}

impl Frames {
    fn new() -> Box<Self> {
        Box::new(Self {
            count: 0,
            cumulative_bytes: 0,
            elapsed: sys::nstime_t { secs: 0, nsecs: 0 },
            reference: ptr::null(),
            // SAFETY: plain C data, all zero before its first use.
            reference_frame: unsafe { core::mem::zeroed() },
            previous_displayed: ptr::null(),
            // SAFETY: as above.
            previous_displayed_frame: unsafe { core::mem::zeroed() },
        })
    }
}

/// `get_frame_ts`: the time of a frame this session still holds.
unsafe extern "C" fn frame_time(
    provider: *mut sys::packet_provider_data,
    number: u32,
) -> *const sys::nstime_t {
    // SAFETY: `provider` is the session's boxed `Frames`.
    let frames = unsafe { &*provider.cast::<Frames>() };
    for frame in [frames.reference, frames.previous_displayed] {
        // SAFETY: each points at one of `frames`' own copies.
        if !frame.is_null() && unsafe { (*frame).num } == number {
            return unsafe { &raw const (*frame).abs_ts };
        }
    }
    ptr::null()
}

static FUNCS: sys::packet_provider_funcs = sys::packet_provider_funcs {
    get_frame_ts: Some(frame_time),
    get_interface_name: None,
    get_interface_description: None,
    get_modified_block: None,
    get_process_id: None,
    get_process_name: None,
    get_process_uuid: None,
};

/// An open capture file.
struct File {
    wtap: *mut sys::wtap,
    filter: *mut sys::dfilter_t,
    file_type: c_int,
}

/// One session of the started engine.
pub(crate) struct Session {
    api: Api,
    frames: Box<Frames>,
    epan: *mut sys::epan_t,
    dissection: *mut sys::epan_dissect_t,
    columns: Box<sys::column_info>,
    record: Box<sys::wtap_rec>,
    file: Option<File>,
}

// SAFETY: Wireshark's state is the process's, not a thread's; a session's
// calls take `&mut self`, so they never overlap.
unsafe impl Send for Session {}

impl Session {
    pub(crate) fn open(config: &EngineConfig) -> Result<Self, EngineError> {
        let mut started = STARTED.lock().unwrap_or_else(PoisonError::into_inner);
        if OPEN.load(Ordering::Acquire) {
            return Err(EngineError::AlreadyOpen);
        }
        let columns = match &*started {
            Some(Ok(started)) if started.config == *config => started.columns,
            Some(Ok(_)) => return Err(EngineError::Configured),
            Some(Err(error)) => return Err(error.clone()),
            None => {
                let result = start(config);
                *started = Some(result.clone());
                result?.columns
            }
        };
        let api = api()?;
        // SAFETY: zeroed is how tshark's capture file starts its
        // `column_info` and `wtap_rec` before setting them up.
        let mut session = unsafe {
            Self {
                api,
                frames: Frames::new(),
                epan: null_mut(),
                dissection: null_mut(),
                columns: Box::new(core::mem::zeroed()),
                record: Box::new(core::mem::zeroed()),
                file: None,
            }
        };
        // SAFETY: Wireshark started; each structure is the session's own.
        unsafe {
            sys::build_column_format_array(&mut *session.columns, columns, true);
            (api.wtap_rec_init)(&mut *session.record, 1514);
            session.restart();
        }
        OPEN.store(true, Ordering::Release);
        Ok(session)
    }

    /// A fresh capture: frame numbers and conversations start over.
    ///
    /// # Safety
    ///
    /// Wireshark started.
    unsafe fn restart(&mut self) {
        // SAFETY: the caller's contract; the old dissection and session
        // are freed before their replacements are made.
        unsafe {
            if !self.dissection.is_null() {
                sys::epan_dissect_free(self.dissection);
            }
            if !self.epan.is_null() {
                sys::epan_free(self.epan);
            }
            self.frames = Frames::new();
            let provider = ptr::from_mut(&mut *self.frames).cast::<sys::packet_provider_data>();
            self.epan = sys::epan_new(provider, &FUNCS);
            self.dissection = sys::epan_dissect_new(self.epan, true, true);
        }
    }

    pub(crate) fn dissect(&mut self, data: &[u8], encapsulation: i32, time: Duration) -> Dissected {
        let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let record = &mut *self.record;
        // SAFETY: the session's record, set up as a packet wiretap read.
        unsafe {
            (self.api.wtap_rec_reset)(record);
            (self.api.wtap_setup_packet_rec)(record, encapsulation);
            record.presence_flags = sys::WTAP_HAS_TS | sys::WTAP_HAS_CAP_LEN;
            record.ts = sys::nstime_t {
                secs: sys::time_t::try_from(time.as_secs()).unwrap_or(sys::time_t::MAX),
                nsecs: c_int::try_from(time.subsec_nanos()).unwrap_or(0),
            };
            record.tsprec = sys::WTAP_TSPREC_NSEC as c_int;
            record.rec_header.packet_header.caplen = length;
            record.rec_header.packet_header.len = length;
            record.rec_header.packet_header.interface_id = 0;
            record.data.start = 0;
            record.data.first_free = 0;
            (self.api.ws_buffer_append)(&mut record.data, data.as_ptr(), length as usize);
            self.run(sys::WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, 0, null_mut())
        }
        .unwrap_or_default()
    }

    pub(crate) fn open_file(
        &mut self,
        path: &Path,
        display_filter: Option<&str>,
    ) -> Result<(), EngineError> {
        self.close_file();
        let filter = match display_filter.filter(|filter| !filter.trim().is_empty()) {
            Some(filter) => self.compile(filter)?,
            None => null_mut(),
        };
        let name = match path_bytes(path) {
            Some(name) => name,
            None => {
                // SAFETY: compiled above, not used.
                unsafe { free_filter(filter) };
                return Err(EngineError::File(format!(
                    "{}: not a valid path",
                    path.display()
                )));
            }
        };
        let (mut err, mut detail) = (0, null_mut());
        // SAFETY: a NUL-terminated path; wiretap fills the error slots.
        let wtap = unsafe {
            (self.api.wtap_open_offline)(
                name.as_ptr(),
                sys::WTAP_TYPE_AUTO,
                &mut err,
                &mut detail,
                false,
            )
        };
        if wtap.is_null() {
            // SAFETY: as above; `detail` is freed once read.
            unsafe { free_filter(filter) };
            let why = unsafe { wtap_error(&self.api, err, detail) };
            return Err(EngineError::File(format!("{}: {why}", path.display())));
        }
        // SAFETY: an open file, and the started engine.
        let file_type = unsafe { (self.api.wtap_file_type_subtype)(wtap) };
        unsafe { self.restart() };
        self.file = Some(File {
            wtap,
            filter,
            file_type,
        });
        Ok(())
    }

    pub(crate) fn next(&mut self) -> Result<Option<Dissected>, EngineError> {
        loop {
            let Some(file) = &self.file else {
                return Ok(None);
            };
            let (wtap, filter, file_type) = (file.wtap, file.filter, file.file_type);
            let (mut err, mut detail, mut offset) = (0, null_mut(), 0i64);
            let record = &mut *self.record;
            // SAFETY: the open file and the session's record.
            let read = unsafe {
                (self.api.wtap_rec_reset)(record);
                record.data.start = 0;
                record.data.first_free = 0;
                (self.api.wtap_read)(wtap, record, &mut err, &mut detail, &mut offset)
            };
            if !read {
                self.close_file();
                if err == 0 {
                    return Ok(None);
                }
                // SAFETY: `detail` is wiretap's, freed once read.
                return Err(EngineError::File(unsafe {
                    wtap_error(&self.api, err, detail)
                }));
            }
            // SAFETY: a record wiretap read, of the open file.
            if let Some(dissected) = unsafe { self.run(file_type, offset, filter) } {
                return Ok(Some(dissected));
            }
        }
    }

    fn compile(&self, filter: &str) -> Result<*mut sys::dfilter_t, EngineError> {
        let source = c_string(filter, EngineError::Filter)?;
        let (mut compiled, mut error) = (null_mut(), null_mut::<sys::df_error_t>());
        // SAFETY: a NUL-terminated filter; EPAN fills the out-slots.
        let ok = unsafe {
            sys::dfilter_compile_full(
                source.as_ptr(),
                &mut compiled,
                &mut error,
                sys::DF_EXPAND_MACROS | sys::DF_OPTIMIZE,
                c"libwireshark-engine".as_ptr(),
            )
        };
        if ok {
            return Ok(compiled);
        }
        let message = if error.is_null() {
            String::from("does not compile")
        } else {
            // SAFETY: EPAN's error, read then freed.
            unsafe {
                let message = text((*error).msg);
                sys::df_error_free(&mut error);
                message
            }
        };
        Err(EngineError::Filter(format!("{filter}: {message}")))
    }

    fn close_file(&mut self) {
        if let Some(file) = self.file.take() {
            // SAFETY: the file and filter this session opened.
            unsafe {
                (self.api.wtap_close)(file.wtap);
                free_filter(file.filter);
            }
        }
    }

    /// Dissects the frame in the session's record as tshark's single pass
    /// does; `None` when `filter` rejects it.
    ///
    /// # Safety
    ///
    /// The record holds a frame; `filter` is null or compiled.
    unsafe fn run(
        &mut self,
        file_type: c_int,
        offset: i64,
        filter: *mut sys::dfilter_t,
    ) -> Option<Dissected> {
        let frames = &mut *self.frames;
        frames.count += 1;
        // SAFETY: plain C data, set up by `frame_data_init`.
        let mut frame: sys::frame_data = unsafe { core::mem::zeroed() };
        // SAFETY: the caller's contract; every pointer is the session's.
        unsafe {
            sys::frame_data_init(
                &mut frame,
                frames.count,
                &*self.record,
                offset,
                frames.cumulative_bytes,
            );
            if !filter.is_null() {
                sys::epan_dissect_prime_with_dfilter(self.dissection, filter);
            }
            sys::col_custom_prime_edt(self.dissection, &mut *self.columns);
            sys::frame_data_set_before_dissect(
                &mut frame,
                &mut frames.elapsed,
                &mut frames.reference,
                frames.previous_displayed,
            );
            if ptr::eq(frames.reference, &frame) {
                frames.reference_frame = ptr::read(&frame);
                frames.reference = &frames.reference_frame;
            }
            sys::epan_dissect_run_with_taps(
                self.dissection,
                file_type,
                &mut *self.record,
                &mut frame,
                &mut *self.columns,
            );
            let passed = filter.is_null() || sys::dfilter_apply_edt(filter, self.dissection);
            let dissected = passed.then(|| {
                sys::epan_dissect_fill_in_columns(self.dissection, false, true);
                let dissected = Dissected {
                    frame: frames.count,
                    columns: columns(&self.columns),
                    tree: tree(&self.api, (*self.dissection).tree),
                };
                sys::frame_data_set_after_dissect(&mut frame, &mut frames.cumulative_bytes);
                frames.previous_displayed_frame = ptr::read(&frame);
                frames.previous_displayed = &frames.previous_displayed_frame;
                dissected
            });
            sys::epan_dissect_reset(self.dissection);
            sys::frame_data_destroy(&mut frame);
            dissected
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close_file();
        // SAFETY: the session's own structures, freed once.
        unsafe {
            sys::epan_dissect_free(self.dissection);
            sys::epan_free(self.epan);
            sys::col_cleanup(&mut *self.columns);
            (self.api.wtap_rec_cleanup)(&mut *self.record);
        }
        OPEN.store(false, Ordering::Release);
    }
}

/// # Safety
///
/// `filter` is null or compiled and unused after.
unsafe fn free_filter(filter: *mut sys::dfilter_t) {
    if !filter.is_null() {
        // SAFETY: the caller's contract.
        unsafe { sys::dfilter_free(filter) };
    }
}

/// `path` as wiretap takes it: UTF-8 on Windows, the bytes elsewhere.
fn path_bytes(path: &Path) -> Option<CString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        CString::new(path.as_os_str().as_bytes()).ok()
    }
    #[cfg(not(unix))]
    {
        CString::new(path.to_str()?).ok()
    }
}

/// The packet list's columns after `epan_dissect_fill_in_columns`.
fn columns(info: &sys::column_info) -> Vec<Column> {
    let count = usize::try_from(info.num_cols).unwrap_or(0);
    if info.columns.is_null() {
        return Vec::new();
    }
    (0..count)
        .map(|index| {
            // SAFETY: `columns` holds `num_cols` items, filled in.
            let column = unsafe { &*info.columns.add(index) };
            // SAFETY: Wireshark's NUL-terminated strings, or null.
            unsafe {
                Column {
                    title: text(column.col_title),
                    text: text(column.col_data),
                }
            }
        })
        .collect()
}

/// The items below `parent`, depth first.
///
/// # Safety
///
/// `parent` is null or a node of the current dissection.
unsafe fn tree(api: &Api, parent: *mut sys::proto_node) -> Vec<Node> {
    struct Walk<'a> {
        api: &'a Api,
        nodes: Vec<Node>,
    }
    unsafe extern "C" fn visit(node: *mut sys::proto_node, data: *mut c_void) {
        // SAFETY: `data` is the walk below; `node` an item of its tree.
        unsafe {
            let walk = &mut *data.cast::<Walk<'_>>();
            if let Some(node) = item(walk.api, node) {
                walk.nodes.push(node);
            }
        }
    }
    if parent.is_null() {
        return Vec::new();
    }
    let mut walk = Walk {
        api,
        nodes: Vec::new(),
    };
    // SAFETY: the caller's contract; `walk` outlives the call.
    unsafe {
        sys::proto_tree_children_foreach(parent, Some(visit), ptr::from_mut(&mut walk).cast())
    };
    walk.nodes
}

/// One item and those below it.
///
/// # Safety
///
/// `node` is an item of the current dissection.
unsafe fn item(api: &Api, node: *mut sys::proto_node) -> Option<Node> {
    // SAFETY: the caller's contract: a live item, its field and header.
    unsafe {
        let field = (*node).finfo;
        if field.is_null() || (*field).hfinfo.is_null() {
            return None;
        }
        let header = &*(*field).hfinfo;
        let (mut abbrev, mut name) = (text(header.abbrev), text(header.name));
        // A text item has the placeholder field `text`, "Text item".
        if abbrev == "text" && name == "Text item" {
            abbrev.clear();
            name.clear();
        }
        let label = if (*field).rep.is_null() {
            let mut label = [0 as c_char; sys::ITEM_LABEL_LENGTH as usize];
            sys::proto_item_fill_label(field, label.as_mut_ptr(), null_mut());
            text(label.as_ptr())
        } else {
            text((*(*field).rep).representation.as_ptr())
        };
        let value = if header.type_ == sys::ftenum_FT_NONE
            || header.type_ == sys::ftenum_FT_PROTOCOL
            || (*field).value.is_null()
        {
            None
        } else {
            take(
                api,
                sys::fvalue_to_string_repr(
                    null_mut(),
                    (*field).value,
                    sys::ftrepr_FTREPR_DISPLAY,
                    header.display,
                ),
            )
        };
        let flags = (*field).flags;
        Some(Node {
            abbrev,
            name,
            label,
            value,
            offset: i64::from((*field).start),
            length: i64::from((*field).length),
            hidden: flags & sys::FI_HIDDEN != 0,
            generated: flags & sys::FI_GENERATED != 0,
            children: tree(api, node),
        })
    }
}
