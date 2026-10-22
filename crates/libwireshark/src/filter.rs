//! Display-filter functions: `myfunc(some.field) == ...` in a filter.
//!
//! Wireshark loads display-filter functions from plugins from 4.4 on; on an
//! older release line a plugin's functions are not registered.

use alloc::string::String;
use core::ffi::{CStr, c_char, c_void};
use core::marker::PhantomData;
use core::ptr::NonNull;

/// A function of one field, usable in display filters as `NAME(field)`.
///
/// Wireshark calls it once per occurrence of the field in the packet; the
/// filter matches when any result compares as asked. Register it with
/// [`plugin!`](crate::plugin)'s `filters = [...]`.
///
/// ```no_run
/// use libwireshark::{FieldValue, FilterFunction};
///
/// /// `port_class(udp.dstport) == "dynamic"`
/// struct PortClass;
///
/// impl FilterFunction for PortClass {
///     const NAME: &'static str = "port_class";
///     type Output = String;
///
///     fn call(value: &FieldValue<'_>) -> Option<String> {
///         let port = value.as_u64()?;
///         Some(match port {
///             0..1024 => "well-known",
///             1024..49152 => "registered",
///             _ => "dynamic",
///         }.to_owned())
///     }
/// }
///
/// libwireshark::plugin!(dissectors = [], filters = [PortClass]);
/// ```
pub trait FilterFunction: 'static {
    /// The function's name in filters: letters, digits and `_`, not
    /// starting with a digit.
    const NAME: &'static str;
    /// What it returns: `u32` or `String`.
    type Output: FilterOutput;

    /// The result for one value of the field, or `None` for none.
    fn call(value: &FieldValue<'_>) -> Option<Self::Output>;
}

/// A display-filter function's result type: `u32` or `String`.
pub trait FilterOutput: sealed::Sealed + 'static {}

impl FilterOutput for u32 {}
impl FilterOutput for String {}

pub(crate) mod sealed {
    /// How a result is handed back to Wireshark.
    pub trait Sealed {
        /// The built-in function whose argument check this kind reuses:
        /// `count` takes any one field and yields a number, `string` any
        /// one field and yields text.
        const CHECKER: &'static core::ffi::CStr;
        /// Whether the result is text.
        const TEXT: bool;
        /// The result as a number, or as text.
        fn into_parts(self) -> (u32, Option<alloc::string::String>);
    }

    impl Sealed for u32 {
        const CHECKER: &'static core::ffi::CStr = c"count";
        const TEXT: bool = false;
        fn into_parts(self) -> (u32, Option<alloc::string::String>) {
            (self, None)
        }
    }

    impl Sealed for alloc::string::String {
        const CHECKER: &'static core::ffi::CStr = c"string";
        const TEXT: bool = true;
        fn into_parts(self) -> (u32, Option<alloc::string::String>) {
            (0, Some(self))
        }
    }
}

/// The libwireshark functions a field value is read through, resolved from
/// the running Wireshark.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ValueApi {
    pub(crate) type_ftenum: unsafe extern "C" fn(*const c_void) -> core::ffi::c_int,
    pub(crate) get_uinteger: unsafe extern "C" fn(*mut c_void) -> u32,
    pub(crate) get_sinteger: unsafe extern "C" fn(*mut c_void) -> i32,
    pub(crate) get_uinteger64: unsafe extern "C" fn(*mut c_void) -> u64,
    pub(crate) get_sinteger64: unsafe extern "C" fn(*mut c_void) -> i64,
    pub(crate) get_string: unsafe extern "C" fn(*const c_void) -> *const c_char,
    pub(crate) to_string_repr: unsafe extern "C" fn(
        *mut c_void,
        *const c_void,
        core::ffi::c_int,
        core::ffi::c_int,
    ) -> *mut c_char,
    pub(crate) g_free: unsafe extern "C" fn(*mut c_void),
}

/// One value of the field a filter function was given.
pub struct FieldValue<'a> {
    value: NonNull<c_void>,
    api: ValueApi,
    _call: PhantomData<&'a c_void>,
}

impl core::fmt::Debug for FieldValue<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("FieldValue").field(&self.to_text()).finish()
    }
}

/// The field types read as each Rust type, from the release line's bindings.
// bindgen types C enums as i32 on Windows and u32 elsewhere.
#[allow(clippy::unnecessary_cast)]
mod kinds {
    pub(super) const UNSIGNED_32: [u32; 5] = [
        crate::sys::ftenum_FT_CHAR as u32,
        crate::sys::ftenum_FT_UINT8 as u32,
        crate::sys::ftenum_FT_UINT16 as u32,
        crate::sys::ftenum_FT_UINT24 as u32,
        crate::sys::ftenum_FT_UINT32 as u32,
    ];
    pub(super) const UNSIGNED_64: [u32; 4] = [
        crate::sys::ftenum_FT_UINT40 as u32,
        crate::sys::ftenum_FT_UINT48 as u32,
        crate::sys::ftenum_FT_UINT56 as u32,
        crate::sys::ftenum_FT_UINT64 as u32,
    ];
    pub(super) const SIGNED_32: [u32; 4] = [
        crate::sys::ftenum_FT_INT8 as u32,
        crate::sys::ftenum_FT_INT16 as u32,
        crate::sys::ftenum_FT_INT24 as u32,
        crate::sys::ftenum_FT_INT32 as u32,
    ];
    pub(super) const SIGNED_64: [u32; 4] = [
        crate::sys::ftenum_FT_INT40 as u32,
        crate::sys::ftenum_FT_INT48 as u32,
        crate::sys::ftenum_FT_INT56 as u32,
        crate::sys::ftenum_FT_INT64 as u32,
    ];
    pub(super) const STRINGS: [u32; 4] = [
        crate::sys::ftenum_FT_STRING as u32,
        crate::sys::ftenum_FT_STRINGZ as u32,
        crate::sys::ftenum_FT_UINT_STRING as u32,
        crate::sys::ftenum_FT_STRINGZPAD as u32,
    ];
}

use kinds::{SIGNED_32, SIGNED_64, STRINGS, UNSIGNED_32, UNSIGNED_64};

impl<'a> FieldValue<'a> {
    /// # Safety
    ///
    /// `value` is an `fvalue_t` of the running filter call, and `api` was
    /// resolved from the running Wireshark.
    pub(crate) unsafe fn from_raw(value: NonNull<c_void>, api: ValueApi) -> Self {
        Self {
            value,
            api,
            _call: PhantomData,
        }
    }

    fn kind(&self) -> u32 {
        // SAFETY: a live fvalue of the running call (see `from_raw`).
        unsafe { (self.api.type_ftenum)(self.value.as_ptr()) as u32 }
    }

    /// The value of an unsigned integer field.
    pub fn as_u64(&self) -> Option<u64> {
        let kind = self.kind();
        // SAFETY: each getter is called only for the field types it reads.
        unsafe {
            if UNSIGNED_32.contains(&kind) {
                Some(u64::from((self.api.get_uinteger)(self.value.as_ptr())))
            } else if UNSIGNED_64.contains(&kind) {
                Some((self.api.get_uinteger64)(self.value.as_ptr()))
            } else {
                None
            }
        }
    }

    /// The value of a signed integer field.
    pub fn as_i64(&self) -> Option<i64> {
        let kind = self.kind();
        // SAFETY: as in `as_u64`.
        unsafe {
            if SIGNED_32.contains(&kind) {
                Some(i64::from((self.api.get_sinteger)(self.value.as_ptr())))
            } else if SIGNED_64.contains(&kind) {
                Some((self.api.get_sinteger64)(self.value.as_ptr()))
            } else {
                None
            }
        }
    }

    /// The value of a text field; `None` for other types, or text that is
    /// not UTF-8.
    pub fn as_str(&self) -> Option<&'a str> {
        if !STRINGS.contains(&self.kind()) {
            return None;
        }
        // SAFETY: a text fvalue's string lives as long as the fvalue.
        let text = unsafe { (self.api.get_string)(self.value.as_ptr()) };
        if text.is_null() {
            return None;
        }
        // SAFETY: Wireshark's strings are NUL-terminated.
        unsafe { CStr::from_ptr(text) }.to_str().ok()
    }

    /// The value as Wireshark displays it, for any field type.
    pub fn to_text(&self) -> String {
        // SAFETY: a NULL scope allocates with GLib; the result is freed below.
        let text =
            unsafe { (self.api.to_string_repr)(core::ptr::null_mut(), self.value.as_ptr(), 0, 0) };
        if text.is_null() {
            return String::new();
        }
        // SAFETY: NUL-terminated, then freed exactly once with GLib's free.
        unsafe {
            let owned = CStr::from_ptr(text).to_string_lossy().into_owned();
            (self.api.g_free)(text.cast());
            owned
        }
    }
}
