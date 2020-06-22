use crate::bindings;
use crate::utils::get_static_cstring;
pub struct GBool(pub bindings::gboolean);
impl PartialEq<bool> for GBool {
    fn eq(&self, other: &bool) -> bool {
        match other {
            true => self.0 != bindings::FALSE as i32,
            false => self.0 == bindings::FALSE as i32,
        }
    }
}
pub struct ModulePref {
    pub valute_type: PrefsValueType,
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

impl ModulePref {
    pub fn register(&mut self, module: *mut bindings::pref_module) {
        match &mut self.valute_type {
            PrefsValueType::Boolean(b) => unsafe {
                bindings::prefs_register_bool_preference(
                    module,
                    get_static_cstring(self.name),
                    get_static_cstring(self.title),
                    get_static_cstring(self.description),
                    &mut b.0,
                )
            },
            PrefsValueType::Uint(b, v) => unsafe {
                bindings::prefs_register_uint_preference(
                    module,
                    get_static_cstring(self.name),
                    get_static_cstring(self.title),
                    get_static_cstring(self.description),
                    *b,
                    v,
                )
            },
            PrefsValueType::String(s) => unsafe {
                bindings::prefs_register_string_preference(
                    module,
                    get_static_cstring(self.name),
                    get_static_cstring(self.title),
                    get_static_cstring(self.description),
                    s,
                )
            },
            PrefsValueType::FileName(s,b) => unsafe {
                bindings::prefs_register_filename_preference(
                    module,
                    get_static_cstring(self.name),
                    get_static_cstring(self.title),
                    get_static_cstring(self.description),
                    s,
                    b.0
                )
            },
            PrefsValueType::Directory(s) => unsafe {
                bindings::prefs_register_directory_preference(
                    module,
                    get_static_cstring(self.name),
                    get_static_cstring(self.title),
                    get_static_cstring(self.description),
                    s,
                )
            },
            PrefsValueType::StaticText() => unsafe {
                bindings::prefs_register_static_text_preference(
                    module,
                    get_static_cstring(self.name),
                    get_static_cstring(self.title),
                    get_static_cstring(self.description),
                )
            },
        }
    }
}
pub enum PrefsValueType {
    Boolean(GBool),
    Uint(bindings::guint, bindings::guint),
    String(*const ::std::os::raw::c_char),
    FileName(*const ::std::os::raw::c_char,GBool),
    Directory(*const ::std::os::raw::c_char),
    StaticText()
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
