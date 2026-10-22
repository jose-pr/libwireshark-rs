//! A plugin's display-filter functions.
//!
//! The functions exist from Wireshark 4.4, so they are resolved from the
//! running Wireshark instead of linked: a plugin for an older release line
//! still loads, and simply registers none.

use super::Plugin;
use crate::filter::sealed::Sealed;
use crate::filter::{FieldValue, FilterFunction, FilterOutput, ValueApi};
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::panic::AssertUnwindSafe;
use core::ptr::NonNull;
use std::panic::catch_unwind;

/// How a filter function's generic callback reaches its plugin's static:
/// a display-filter callback carries no data pointer.
pub trait PluginStatic: 'static {
    /// The plugin's `Plugin`.
    fn plugin() -> &'static Plugin;
}

type Function = unsafe extern "C" fn(*mut GSList, u32, *mut c_void) -> bool;

/// One [`FilterFunction`] of a plugin, type-erased.
#[derive(Debug)]
pub struct FilterSpec {
    name: &'static str,
    checker: &'static CStr,
    text: bool,
    function: Function,
}

impl FilterSpec {
    /// The function `F` describes, in the plugin `P` names.
    pub const fn of<F: FilterFunction, P: PluginStatic>() -> Self {
        Self {
            name: F::NAME,
            checker: <F::Output as Sealed>::CHECKER,
            text: <F::Output as Sealed>::TEXT,
            function: call::<F, P>,
        }
    }
}

/// GLib's singly linked list node.
#[repr(C)]
pub(crate) struct GSList {
    data: *mut c_void,
    next: *mut GSList,
}

/// GLib's pointer array.
#[repr(C)]
struct GPtrArray {
    pdata: *mut *mut c_void,
    len: c_uint,
}

/// `df_func_def_t`, identical in every release line that has it (4.4 on).
#[repr(C)]
struct DfFuncDef {
    name: *const c_char,
    function: Option<Function>,
    min_nargs: c_uint,
    max_nargs: c_uint,
    return_ftype: c_int,
    semcheck_param_function: *const c_void,
}

/// `dfilter_plugin`.
#[repr(C)]
#[derive(Debug)]
pub struct DfilterPlugin {
    init: Option<extern "C" fn()>,
    cleanup: Option<extern "C" fn()>,
}

/// The table `plugin_register` hands to `dfilter_plugins_register`.
pub const fn dfilter_plugin(init: extern "C" fn(), cleanup: extern "C" fn()) -> DfilterPlugin {
    DfilterPlugin {
        init: Some(init),
        cleanup: Some(cleanup),
    }
}

/// The libwireshark and GLib functions filter functions need.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Api {
    register: unsafe extern "C" fn(*mut DfFuncDef) -> bool,
    deregister: unsafe extern "C" fn(*mut DfFuncDef) -> bool,
    lookup: unsafe extern "C" fn(*const c_char) -> *mut DfFuncDef,
    cell_append: unsafe extern "C" fn(*mut c_void, *mut c_void),
    fvalue_new: unsafe extern "C" fn(c_int) -> *mut c_void,
    set_uinteger: unsafe extern "C" fn(*mut c_void, u32),
    set_string: unsafe extern "C" fn(*mut c_void, *const c_char),
    pub(crate) value: ValueApi,
}

/// A process-wide library handle: libwireshark's and GLib's symbols.
fn symbols(windows_dll: &str) -> Option<libloading::Library> {
    #[cfg(windows)]
    {
        libloading::os::windows::Library::open_already_loaded(windows_dll)
            .ok()
            .map(Into::into)
    }
    #[cfg(not(windows))]
    {
        let _ = windows_dll;
        Some(libloading::os::unix::Library::this().into())
    }
}

impl Api {
    /// Resolves the functions, or `None` before Wireshark 4.4.
    fn load() -> Option<Self> {
        let wireshark = symbols("libwireshark.dll")?;
        let glib = symbols("glib-2.0-0.dll")?;
        // SAFETY: each symbol is resolved with the signature its 4.4+ header
        // declares; the libraries stay loaded for the process.
        unsafe {
            let api = Self {
                register: *wireshark.get(b"df_func_register\0").ok()?,
                deregister: *wireshark.get(b"df_func_deregister\0").ok()?,
                lookup: *wireshark.get(b"df_func_lookup\0").ok()?,
                cell_append: *wireshark.get(b"df_cell_append\0").ok()?,
                fvalue_new: *wireshark.get(b"fvalue_new\0").ok()?,
                set_uinteger: *wireshark.get(b"fvalue_set_uinteger\0").ok()?,
                set_string: *wireshark.get(b"fvalue_set_string\0").ok()?,
                value: ValueApi {
                    type_ftenum: *wireshark.get(b"fvalue_type_ftenum\0").ok()?,
                    get_uinteger: *wireshark.get(b"fvalue_get_uinteger\0").ok()?,
                    get_sinteger: *wireshark.get(b"fvalue_get_sinteger\0").ok()?,
                    get_uinteger64: *wireshark.get(b"fvalue_get_uinteger64\0").ok()?,
                    get_sinteger64: *wireshark.get(b"fvalue_get_sinteger64\0").ok()?,
                    get_string: *wireshark.get(b"fvalue_get_string\0").ok()?,
                    to_string_repr: *wireshark.get(b"fvalue_to_string_repr\0").ok()?,
                    g_free: *glib.get(b"g_free\0").ok()?,
                },
            };
            core::mem::forget(wireshark);
            core::mem::forget(glib);
            Some(api)
        }
    }
}

/// Hands the plugin's `dfilter_plugin` table to Wireshark, when it takes
/// display-filter plugins (4.4 on).
pub(crate) fn register_plugin(plugin: &'static DfilterPlugin) {
    let Some(wireshark) = symbols("libwireshark.dll") else {
        return;
    };
    // SAFETY: `dfilter_plugins_register(const dfilter_plugin *)` in 4.4+.
    let register = unsafe {
        wireshark.get::<unsafe extern "C" fn(*const DfilterPlugin)>(b"dfilter_plugins_register\0")
    };
    if let Ok(register) = register {
        // SAFETY: the table and its callbacks are statics of the plugin library.
        unsafe { register(plugin) };
    }
    core::mem::forget(wireshark);
}

/// The functions registered with Wireshark, kept to deregister them.
pub(crate) struct Registered {
    pub(crate) api: Api,
    definitions: Vec<NonNull<DfFuncDef>>,
}

// SAFETY: the definitions are leaked records only Wireshark reads; the
// plugin's mutex serialises registration and cleanup.
unsafe impl Send for Registered {}

/// Registers `specs` with the argument checks of Wireshark's `count` and
/// `string`, so every check (and any error it raises) stays in C.
pub(crate) fn register(specs: &[FilterSpec]) -> Option<Registered> {
    let api = Api::load()?;
    let mut definitions = Vec::new();
    for spec in specs {
        // SAFETY: looks up a built-in function by its NUL-terminated name.
        let Some(builtin) = (unsafe { (api.lookup)(spec.checker.as_ptr()).as_ref() }) else {
            continue;
        };
        let name = CString::new(spec.name.replace('\0', "")).unwrap_or_default();
        let definition = NonNull::from(Box::leak(Box::new(DfFuncDef {
            name: name.into_raw(),
            function: Some(spec.function),
            min_nargs: 1,
            max_nargs: 1,
            return_ftype: if spec.text {
                crate::sys::ftenum_FT_STRING as c_int
            } else {
                crate::sys::ftenum_FT_UINT32 as c_int
            },
            semcheck_param_function: builtin.semcheck_param_function,
        })));
        // SAFETY: the definition and its name are leaked; Wireshark keeps them.
        if unsafe { (api.register)(definition.as_ptr()) } {
            definitions.push(definition);
        }
    }
    Some(Registered { api, definitions })
}

impl Registered {
    pub(crate) fn deregister(&self) {
        for definition in &self.definitions {
            // SAFETY: each was registered and stays allocated.
            unsafe { (self.api.deregister)(definition.as_ptr()) };
        }
    }
}

/// A filter function's callback: `F::call` on every value of its argument.
unsafe extern "C" fn call<F: FilterFunction, P: PluginStatic>(
    stack: *mut GSList,
    _arg_count: u32,
    retval: *mut c_void,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let api = P::plugin().filter_api()?;
        // SAFETY: Wireshark passes the argument stack: one entry, a
        // `GPtrArray` of the field's values (or NULL when it has none).
        let values = unsafe { stack.as_ref()?.data.cast::<GPtrArray>().as_ref()? };
        let mut appended = false;
        for index in 0..values.len as usize {
            // SAFETY: `index` is within the array's length.
            let Some(value) = NonNull::new(unsafe { *values.pdata.add(index) }) else {
                continue;
            };
            // SAFETY: a value of the running call; `api` was resolved here.
            let value = unsafe { FieldValue::from_raw(value, api.value) };
            let Some(result) = F::call(&value) else {
                continue;
            };
            // SAFETY: `retval` is the call's result cell; the new fvalue is
            // owned by it once appended.
            unsafe { append(&api, retval, result) };
            appended = true;
        }
        Some(appended)
    }))
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// # Safety
///
/// `retval` is the running call's result cell.
unsafe fn append<T: FilterOutput>(api: &Api, retval: *mut c_void, result: T) {
    let (number, text) = result.into_parts();
    // SAFETY: the caller's contract; Wireshark copies the string.
    unsafe {
        let value = match text {
            Some(text) => {
                let value = (api.fvalue_new)(crate::sys::ftenum_FT_STRING as c_int);
                let text = CString::new(text.replace('\0', "")).unwrap_or_default();
                (api.set_string)(value, text.as_ptr());
                value
            }
            None => {
                let value = (api.fvalue_new)(crate::sys::ftenum_FT_UINT32 as c_int);
                (api.set_uinteger)(value, number);
                value
            }
        };
        (api.cell_append)(retval, value);
    }
}
