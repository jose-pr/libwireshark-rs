use crate::bindings;
use crate::utils::{cstr, get_static_cstring, raw_ptr};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ffi::CStr;

pub static mut PREFS: Lazy<HashMap<&'static str, PrefValue>> = Lazy::new(|| HashMap::new());

#[derive(Clone)]
pub struct GBool(pub bindings::gboolean);
impl PartialEq<bool> for GBool {
    fn eq(&self, other: &bool) -> bool {
        match other {
            true => self.0 != bindings::FALSE as i32,
            false => self.0 == bindings::FALSE as i32,
        }
    }
}
#[derive(Clone)]
pub struct ModulePref {
    pub value_type: PrefValue,
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}
pub struct Value<T> {
    pub info: T,
    ptr: *mut std::ffi::c_void,
}
impl<T> Value<T> {
    pub fn new(info: T) -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            info,
        }
    }
}

impl Value<ModulePref> {
    pub fn get_current_value(&self) -> PrefValue {
        unsafe {
            match &self.info.value_type {
                PrefValue::Boolean(..) => {
                    let ptr = self.ptr as *const i32;
                    PrefValue::Boolean(&*ptr != &0i32)
                }
                PrefValue::Uint(_, b) => {
                    let ptr = self.ptr as *const u32;
                    PrefValue::Uint((&*ptr).clone(), b.clone())
                }
                PrefValue::String(_) => {
                    let ptr = self.ptr as *const *const i8;
                    PrefValue::String(String::from(CStr::from_ptr(*ptr).to_str().unwrap()))
                }
                PrefValue::FileName(_, b) => {
                    let ptr = self.ptr as *const *const i8;
                    PrefValue::FileName(
                        String::from(CStr::from_ptr(*ptr).to_str().unwrap()),
                        b.clone(),
                    )
                }
                PrefValue::Directory(_) => {
                    let ptr = self.ptr as *const *const i8;
                    PrefValue::Directory(String::from(CStr::from_ptr(*ptr).to_str().unwrap()))
                }
                PrefValue::StaticText() => PrefValue::StaticText(),
                _ => todo!(),
            }
        }
    }
    pub fn register(&mut self, module: *mut bindings::pref_module) {
        unsafe {
            match &self.info.value_type {
                PrefValue::Boolean(b) => {
                    let ptr = raw_ptr(if false == *b { 0 } else { 1 });
                    self.ptr = ptr as *mut std::ffi::c_void;
                    bindings::prefs_register_bool_preference(
                        module,
                        get_static_cstring(self.info.name),
                        get_static_cstring(self.info.title),
                        get_static_cstring(self.info.description),
                        ptr,
                    )
                }
                PrefValue::Uint(v, b) => {
                    let ptr = raw_ptr(v.clone());
                    self.ptr = ptr as *mut std::ffi::c_void;
                    bindings::prefs_register_uint_preference(
                        module,
                        get_static_cstring(self.info.name),
                        get_static_cstring(self.info.title),
                        get_static_cstring(self.info.description),
                        b.clone(),
                        ptr,
                    )
                }
                PrefValue::String(s) => {
                    let ptr = raw_ptr(*cstr::new(s.clone()));
                    self.ptr = ptr as *mut std::ffi::c_void;
                    bindings::prefs_register_string_preference(
                        module,
                        get_static_cstring(self.info.name),
                        get_static_cstring(self.info.title),
                        get_static_cstring(self.info.description),
                        ptr,
                    )
                }
                PrefValue::FileName(s, b) => {
                    let ptr = raw_ptr(*cstr::new(s.clone()));
                    self.ptr = ptr as *mut std::ffi::c_void;
                    bindings::prefs_register_filename_preference(
                        module,
                        get_static_cstring(self.info.name),
                        get_static_cstring(self.info.title),
                        get_static_cstring(self.info.description),
                        ptr,
                        if *b == false { 0 } else { 1 },
                    )
                }
                PrefValue::Directory(s) => {
                    let ptr = raw_ptr(*cstr::new(s.clone()));
                    self.ptr = ptr as *mut std::ffi::c_void;
                    bindings::prefs_register_directory_preference(
                        module,
                        get_static_cstring(self.info.name),
                        get_static_cstring(self.info.title),
                        get_static_cstring(self.info.description),
                        ptr,
                    )
                }
                PrefValue::StaticText() => bindings::prefs_register_static_text_preference(
                    module,
                    get_static_cstring(self.info.name),
                    get_static_cstring(self.info.title),
                    get_static_cstring(self.info.description),
                ),
            }
        };
    }
}

#[derive(Clone)]
pub enum PrefValue {
    Boolean(bool),
    Uint(bindings::guint, bindings::guint),
    String(String),
    FileName(String, bool),
    Directory(String),
    StaticText(),
}

/*

extern "C" {
    pub fn prefs_register_enum_preference(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
        title: *const ::std::os::raw::c_char,
        description: *const ::std::os::raw::c_char,
        var: *mut gint,
        enumvals: *const enum_val_t,
        radio_buttons: gboolean,
    );
}

extern "C" {
    pub fn prefs_register_range_preference(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
        title: *const ::std::os::raw::c_char,
        description: *const ::std::os::raw::c_char,
        var: *mut *mut range_t,
        max_value: guint32,
    );
}
extern "C" {
    pub fn prefs_register_uat_preference(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
        title: *const ::std::os::raw::c_char,
        description: *const ::std::os::raw::c_char,
        uat: *mut epan_uat,
    );
}
extern "C" {
    pub fn prefs_register_uat_preference_qt(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
        title: *const ::std::os::raw::c_char,
        description: *const ::std::os::raw::c_char,
        uat: *mut epan_uat,
    );
}
extern "C" {
    pub fn prefs_register_color_preference(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
        title: *const ::std::os::raw::c_char,
        description: *const ::std::os::raw::c_char,
        color: *mut color_t,
    );
}
extern "C" {
    pub fn prefs_register_custom_preference(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
        title: *const ::std::os::raw::c_char,
        description: *const ::std::os::raw::c_char,
        custom_cbs: *mut pref_custom_cbs,
        custom_data: *mut *mut ::std::os::raw::c_void,
    );
}
extern "C" {
    pub fn prefs_register_decode_as_range_preference(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
        title: *const ::std::os::raw::c_char,
        description: *const ::std::os::raw::c_char,
        var: *mut *mut range_t,
        max_value: guint32,
    );
}
extern "C" {
    pub fn prefs_register_decode_as_preference(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
        title: *const ::std::os::raw::c_char,
        description: *const ::std::os::raw::c_char,
        var: *mut guint,
    );
}
extern "C" {
    pub fn prefs_register_obsolete_preference(
        module: *mut module_t,
        name: *const ::std::os::raw::c_char,
    );
}
 */
