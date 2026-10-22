//! A plugin's capture file formats.
//!
//! The reader's structures are public from Wireshark 4.6, so the functions
//! are resolved from the running Wireshark and the registration is compiled
//! only for 4.6 on: a plugin for an older release line registers none.

use super::filters::PluginStatic;
use crate::file_type::FileType;

/// The table `plugin_register` hands to `wtap_register_plugin`.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct WtapPlugin {
    register_wtap_module: Option<extern "C" fn()>,
}

/// The `wtap_plugin` that registers the plugin's formats from `register`.
pub(crate) const fn wtap_plugin(register: extern "C" fn()) -> WtapPlugin {
    WtapPlugin {
        register_wtap_module: Some(register),
    }
}

/// One [`FileType`] of a plugin, type-erased.
#[derive(Debug)]
pub struct FileTypeSpec {
    #[cfg_attr(
        not(file_type_plugins),
        allow(dead_code, reason = "registered from 4.6")
    )]
    name: &'static str,
    #[cfg(file_type_plugins)]
    imp: imp::Spec,
}

impl FileTypeSpec {
    /// The format `F` describes, in the plugin `P` names.
    pub const fn of<F: FileType, P: PluginStatic>() -> Self {
        Self {
            name: F::NAME,
            #[cfg(file_type_plugins)]
            imp: imp::Spec::of::<F, P>(),
        }
    }
}

#[cfg(file_type_plugins)]
pub(crate) use imp::{Registered, register, register_plugin};

/// Before 4.6 there is nothing to register.
#[cfg(not(file_type_plugins))]
pub(crate) struct Registered;

#[cfg(not(file_type_plugins))]
pub(crate) fn register(_specs: &[FileTypeSpec]) -> Option<Registered> {
    None
}

#[cfg(not(file_type_plugins))]
pub(crate) fn register_plugin(_plugin: &'static WtapPlugin) {}

#[cfg(file_type_plugins)]
mod imp {
    use super::{FileTypeSpec, PluginStatic, WtapPlugin};
    use crate::__private::symbols::{function, loaded};
    use crate::file_type::{CaptureFile, FileApi, FileType, Record, WiretapError};
    use crate::sys;
    use alloc::boxed::Box;
    use alloc::ffi::CString;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use core::ffi::{c_char, c_int, c_uint, c_void};
    use core::panic::AssertUnwindSafe;
    use std::io;
    use std::panic::catch_unwind;

    type Open = unsafe extern "C" fn(
        *mut sys::wtap,
        *mut c_int,
        *mut *mut c_char,
    ) -> sys::wtap_open_return_val;
    type Read = unsafe extern "C" fn(
        *mut sys::wtap,
        *mut sys::wtap_rec,
        *mut c_int,
        *mut *mut c_char,
        *mut i64,
    ) -> bool;
    type SeekRead = unsafe extern "C" fn(
        *mut sys::wtap,
        i64,
        *mut sys::wtap_rec,
        *mut c_int,
        *mut *mut c_char,
    ) -> bool;
    type Close = unsafe extern "C" fn(*mut sys::wtap);

    /// The start of `struct wtap` (`wiretap/wtap_module.h`), up to the last
    /// field a reader sets. Fields after it differ between 4.6 releases, so
    /// the struct is only ever reached through Wireshark's pointer.
    #[repr(C)]
    struct Wtap {
        fh: *mut c_void,
        random_fh: *mut c_void,
        ispipe: bool,
        file_type_subtype: c_int,
        snapshot_length: c_uint,
        shb_hdrs: *mut c_void,
        shb_iface_to_global: *mut c_void,
        interface_data: *mut c_void,
        next_interface_data: c_uint,
        nrbs: *mut c_void,
        dsbs: *mut c_void,
        meta_events: *mut c_void,
        dpibs: *mut c_void,
        next_dpib_id: c_uint,
        pathname: *mut c_char,
        private: *mut c_void,
        wslua_data: *mut c_void,
        subtype_read: Option<Read>,
        subtype_seek_read: Option<SeekRead>,
        subtype_sequential_close: Option<Close>,
        subtype_close: Option<Close>,
        file_encap: c_int,
        file_tsprec: c_int,
    }

    #[derive(Debug)]
    pub(super) struct Spec {
        description: &'static str,
        extensions: &'static [&'static str],
        open: Open,
    }

    impl Spec {
        pub(super) const fn of<F: FileType, P: PluginStatic>() -> Self {
            Self {
                description: F::DESCRIPTION,
                extensions: F::EXTENSIONS,
                open: open::<F, P>,
            }
        }
    }

    /// The wiretap functions registration and reading need.
    #[derive(Clone, Copy, Debug)]
    struct Api {
        file: FileApi,
        has_open_info: unsafe extern "C" fn(*const c_char) -> bool,
        name_to_subtype: unsafe extern "C" fn(*const c_char) -> c_int,
        register_subtype: unsafe extern "C" fn(*const sys::file_type_subtype_info) -> c_int,
        register_open_info: unsafe extern "C" fn(*mut sys::open_info, bool),
        add_generated_idb: Option<unsafe extern "C" fn(*mut sys::wtap)>,
    }

    impl Api {
        fn load() -> Option<Self> {
            let wiretap = loaded("libwiretap.dll")?;
            let wsutil = loaded("libwsutil.dll")?;
            let glib = loaded("glib-2.0-0.dll")?;
            // SAFETY: each signature is the one the 4.6 headers declare; the
            // libraries are Wireshark's own and stay loaded for the process.
            unsafe {
                Some(Self {
                    file: FileApi {
                        read: function(&wiretap, b"file_read\0")?,
                        tell: function(&wiretap, b"file_tell\0")?,
                        seek: function(&wiretap, b"file_seek\0")?,
                        error: function(&wiretap, b"file_error\0")?,
                        assure_space: function(&wsutil, b"ws_buffer_assure_space\0")?,
                        strdup: function(&glib, b"g_strdup\0")?,
                        free: function(&glib, b"g_free\0")?,
                    },
                    has_open_info: function(&wiretap, b"wtap_has_open_info\0")?,
                    name_to_subtype: function(&wiretap, b"wtap_name_to_file_type_subtype\0")?,
                    register_subtype: function(&wiretap, b"wtap_register_file_type_subtype\0")?,
                    register_open_info: function(&wiretap, b"wtap_register_open_info\0")?,
                    add_generated_idb: function(&wiretap, b"wtap_add_generated_idb\0"),
                })
            }
        }
    }

    /// Hands the plugin's `wtap_plugin` table to Wireshark.
    pub(crate) fn register_plugin(plugin: &'static WtapPlugin) {
        let Some(wiretap) = loaded("libwiretap.dll") else {
            return;
        };
        // SAFETY: `wtap_register_plugin(const wtap_plugin *)`.
        let register: Option<unsafe extern "C" fn(*const WtapPlugin)> =
            unsafe { function(&wiretap, b"wtap_register_plugin\0") };
        if let Some(register) = register {
            // SAFETY: the table and its callback are statics of the plugin library.
            unsafe { register(plugin) };
        }
    }

    /// The formats registered with Wireshark: each spec's file type
    /// number, or `None` where the name was taken.
    pub(crate) struct Registered {
        api: Api,
        subtypes: Vec<(&'static str, c_int)>,
    }

    impl Registered {
        pub(crate) fn subtype(&self, name: &str) -> Option<c_int> {
            self.subtypes
                .iter()
                .find_map(|&(registered, subtype)| (registered == name).then_some(subtype))
        }
    }

    /// A leaked NUL-terminated copy, for Wireshark to keep.
    fn leak(text: &str) -> *const c_char {
        CString::new(text.replace('\0', ""))
            .unwrap_or_default()
            .into_raw()
    }

    /// Registers `specs` as file types and readers, skipping a name
    /// Wireshark already has: it aborts on a duplicate reader.
    pub(crate) fn register(specs: &[FileTypeSpec]) -> Option<Registered> {
        let api = Api::load()?;
        let blocks: &'static [sys::supported_block_type] =
            Box::leak(Box::new([sys::supported_block_type {
                type_: sys::wtap_block_type_t_WTAP_BLOCK_PACKET as _,
                support: sys::block_support_t_MULTIPLE_BLOCKS_SUPPORTED as _,
                num_supported_options: 0,
                supported_options: core::ptr::null(),
            }]));
        let mut subtypes = Vec::new();
        for spec in specs {
            let name = leak(spec.name);
            // SAFETY: lookups by a NUL-terminated name.
            let taken = unsafe { (api.has_open_info)(name) || (api.name_to_subtype)(name) != -1 };
            if taken {
                continue;
            }
            let extensions = spec.imp.extensions;
            // SAFETY: an all-zero `file_type_subtype_info` is valid (null
            // pointers, no callbacks); the fields a reader needs are set.
            let mut info: sys::file_type_subtype_info = unsafe { core::mem::zeroed() };
            info.description = leak(spec.imp.description);
            info.name = name;
            if let Some((first, rest)) = extensions.split_first() {
                info.default_file_extension = leak(first);
                if !rest.is_empty() {
                    info.additional_file_extensions = leak(&rest.join(";"));
                }
            }
            info.num_supported_blocks = blocks.len();
            info.supported_blocks = blocks.as_ptr();
            // SAFETY: Wireshark copies the record; its strings are leaked.
            let subtype = unsafe { (api.register_subtype)(&info) };
            if subtype < 0 {
                continue;
            }
            let open_info = Box::leak(Box::new(sys::open_info {
                name,
                type_: sys::wtap_open_type_OPEN_INFO_MAGIC as _,
                open_routine: Some(spec.imp.open),
                extensions: if extensions.is_empty() {
                    core::ptr::null()
                } else {
                    leak(&extensions.join(";"))
                },
                extensions_set: core::ptr::null_mut(),
                wslua_data: core::ptr::null_mut(),
            }));
            // SAFETY: the record is leaked; Wireshark fills `extensions_set`
            // and copies it.
            unsafe { (api.register_open_info)(open_info, false) };
            subtypes.push((spec.name, subtype));
        }
        Some(Registered { api, subtypes })
    }

    /// What an open file keeps in `wth->priv`.
    struct Opened<F> {
        format: F,
        api: Api,
    }

    /// The reader's open routine: [`FileType::open`] on the file's start.
    unsafe extern "C" fn open<F: FileType, P: PluginStatic>(
        wth: *mut sys::wtap,
        err: *mut c_int,
        err_info: *mut *mut c_char,
    ) -> sys::wtap_open_return_val {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (api, subtype) = {
                let state = P::plugin().file_type_state();
                let registered = state.as_ref()?;
                (registered.api, registered.subtype(F::NAME)?)
            };
            // SAFETY: Wireshark passes the file being opened.
            let wtap = unsafe { &mut *wth.cast::<Wtap>() };
            // SAFETY: `fh` is open and positioned at the file's start.
            let mut file = unsafe { CaptureFile::from_raw(wtap.fh, &api.file) };
            let format = match F::open(&mut file) {
                Ok(Some(format)) => format,
                Ok(None) => return Some(sys::wtap_open_return_val_WTAP_OPEN_NOT_MINE),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Some(sys::wtap_open_return_val_WTAP_OPEN_NOT_MINE);
                }
                Err(error) => {
                    // SAFETY: the callback's error outputs.
                    unsafe { report(&api.file, &error, err, err_info) };
                    return Some(sys::wtap_open_return_val_WTAP_OPEN_ERROR);
                }
            };
            wtap.file_type_subtype = subtype;
            wtap.file_encap = format.encapsulation().to_raw();
            wtap.file_tsprec = sys::WTAP_TSPREC_NSEC as c_int;
            wtap.snapshot_length = 0;
            wtap.subtype_read = Some(read::<F>);
            wtap.subtype_seek_read = Some(seek_read::<F>);
            wtap.subtype_close = Some(close::<F>);
            wtap.private = Box::into_raw(Box::new(Opened { format, api })).cast();
            if let Some(add_generated_idb) = api.add_generated_idb {
                // SAFETY: the file is set up as an open capture of one interface.
                unsafe { add_generated_idb(wth) };
            }
            Some(sys::wtap_open_return_val_WTAP_OPEN_MINE)
        }));
        result
            .ok()
            .flatten()
            .unwrap_or(sys::wtap_open_return_val_WTAP_OPEN_NOT_MINE)
    }

    /// Sequential reads: the record at the file's position.
    unsafe extern "C" fn read<F: FileType>(
        wth: *mut sys::wtap,
        rec: *mut sys::wtap_rec,
        err: *mut c_int,
        err_info: *mut *mut c_char,
        data_offset: *mut i64,
    ) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: a file this reader opened, so `priv` holds its state.
            let (wtap, opened) = unsafe { opened::<F>(wth) }?;
            // SAFETY: `fh` is the open file's sequential handle.
            let mut file = unsafe { CaptureFile::from_raw(wtap.fh, &opened.api.file) };
            // SAFETY: an output of the callback.
            unsafe { *data_offset = i64::try_from(file.position()).unwrap_or(0) };
            // SAFETY: the callback's record and error outputs.
            Some(unsafe { read_record(opened, &mut file, rec, err, err_info, true) })
        }))
        .ok()
        .flatten()
        .unwrap_or(false)
    }

    /// Random access: the record that starts at `seek_off`.
    unsafe extern "C" fn seek_read<F: FileType>(
        wth: *mut sys::wtap,
        seek_off: i64,
        rec: *mut sys::wtap_rec,
        err: *mut c_int,
        err_info: *mut *mut c_char,
    ) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: as in `read`.
            let (wtap, opened) = unsafe { opened::<F>(wth) }?;
            // SAFETY: `random_fh` is the open file's random-access handle.
            let mut file = unsafe { CaptureFile::from_raw(wtap.random_fh, &opened.api.file) };
            if let Err(error) = file.seek(seek_off) {
                // SAFETY: the callback's error outputs.
                unsafe { report(&opened.api.file, &error, err, err_info) };
                return Some(false);
            }
            // SAFETY: as in `read`.
            Some(unsafe { read_record(opened, &mut file, rec, err, err_info, false) })
        }))
        .ok()
        .flatten()
        .unwrap_or(false)
    }

    /// Drops the reader's state when Wireshark closes the file.
    unsafe extern "C" fn close<F: FileType>(wth: *mut sys::wtap) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: a file this reader opened.
            let Some(wtap) = (unsafe { wth.cast::<Wtap>().as_mut() }) else {
                return;
            };
            let private = core::mem::replace(&mut wtap.private, core::ptr::null_mut());
            if !private.is_null() {
                // SAFETY: `open` boxed it, and it is taken out once.
                drop(unsafe { Box::from_raw(private.cast::<Opened<F>>()) });
            }
        }));
    }

    /// # Safety
    ///
    /// `wth` is a file `open::<F, _>` accepted.
    unsafe fn opened<'a, F: FileType>(wth: *mut sys::wtap) -> Option<(&'a Wtap, &'a Opened<F>)> {
        // SAFETY: the caller's contract.
        let wtap = unsafe { wth.cast::<Wtap>().as_ref() }?;
        // SAFETY: `open` stored an `Opened<F>` there.
        let opened = unsafe { wtap.private.cast::<Opened<F>>().as_ref() }?;
        Some((wtap, opened))
    }

    /// [`FileType::read`] into `rec`, then the record's header from what it
    /// set. At the end of the file that is not an error only when
    /// `end_is_eof` (a sequential read).
    ///
    /// # Safety
    ///
    /// `rec`, `err` and `err_info` are the running read callback's.
    unsafe fn read_record<F: FileType>(
        opened: &Opened<F>,
        file: &mut CaptureFile<'_>,
        rec: *mut sys::wtap_rec,
        err: *mut c_int,
        err_info: *mut *mut c_char,
        end_is_eof: bool,
    ) -> bool {
        // SAFETY: the caller's contract.
        let Some(rec) = (unsafe { rec.as_mut() }) else {
            return false;
        };
        let rec_ptr: *mut sys::wtap_rec = rec;
        // SAFETY: the record of the running callback, for this call only.
        let mut record = unsafe { Record::from_raw(&mut *rec_ptr, &opened.api.file) };
        match opened.format.read(file, &mut record) {
            Ok(true) => {}
            Ok(false) => {
                // SAFETY: the callback's error output.
                unsafe {
                    *err = if end_is_eof {
                        0
                    } else {
                        sys::WTAP_ERR_SHORT_READ as c_int
                    };
                }
                return false;
            }
            Err(error) => {
                // SAFETY: the callback's error outputs.
                unsafe { report(&opened.api.file, &error, err, err_info) };
                return false;
            }
        }
        let (time, captured, original) = record.finish();
        // SAFETY: `record` is gone; the record is written through its pointer.
        let rec = unsafe { &mut *rec_ptr };
        rec.rec_type = sys::REC_TYPE_PACKET as _;
        rec.rec_type_name = c"Packet".as_ptr();
        rec.presence_flags = 0;
        if let Some(time) = time {
            rec.presence_flags |= sys::WTAP_HAS_TS;
            rec.ts.secs = time.as_secs().try_into().unwrap_or(sys::time_t::MAX);
            rec.ts.nsecs = time.subsec_nanos() as c_int;
            rec.tsprec = sys::WTAP_TSPREC_NSEC as c_int;
        }
        if original.is_some() {
            rec.presence_flags |= sys::WTAP_HAS_CAP_LEN;
        }
        // SAFETY: the packet member of the header union, for a packet record.
        let header = unsafe { &mut rec.rec_header.packet_header };
        header.pkt_encap = opened.format.encapsulation().to_raw();
        header.caplen = captured;
        header.len = original.unwrap_or(captured).max(captured);
        header.interface_id = 0;
        true
    }

    /// Hands `error` to Wireshark as a wiretap error code and message.
    ///
    /// # Safety
    ///
    /// `err` and `err_info` are a callback's error outputs.
    unsafe fn report(
        api: &FileApi,
        error: &io::Error,
        err: *mut c_int,
        err_info: *mut *mut c_char,
    ) {
        let (code, info) = match error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<WiretapError>())
        {
            Some(wiretap) => (wiretap.code, wiretap.info.clone()),
            None => match error.kind() {
                io::ErrorKind::UnexpectedEof => (sys::WTAP_ERR_SHORT_READ as c_int, None),
                io::ErrorKind::InvalidData => {
                    (sys::WTAP_ERR_BAD_FILE as c_int, Some(error.to_string()))
                }
                _ => (sys::WTAP_ERR_INTERNAL as c_int, Some(error.to_string())),
            },
        };
        // SAFETY: the caller's contract; Wireshark frees the message with `g_free`.
        unsafe {
            if !err.is_null() {
                *err = code;
            }
            if !err_info.is_null() {
                *err_info = match info {
                    Some(info) => {
                        let text = CString::new(info.replace('\0', "")).unwrap_or_default();
                        (api.strdup)(text.as_ptr())
                    }
                    None => core::ptr::null_mut(),
                };
            }
        }
    }
}
