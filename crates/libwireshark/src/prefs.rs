use crate::bindings;
use crate::utils::get_static_cstring;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

static GLIB_LIBRARY: OnceCell<libloading::Library> = OnceCell::new();

fn glib_library() -> &'static libloading::Library {
    GLIB_LIBRARY.get_or_init(|| {
        #[cfg(target_os = "windows")]
        let name = "glib-2.0-0.dll";
        #[cfg(target_os = "macos")]
        let name = "libglib-2.0.0.dylib";
        #[cfg(all(unix, not(target_os = "macos")))]
        let name = "libglib-2.0.so.0";
        // SAFETY: Wireshark loads the matching GLib runtime as a dependency;
        // retain this handle for the lifetime of every resolved function call.
        unsafe { libloading::Library::new(name) }.unwrap_or_else(|error| {
            panic!("could not load Wireshark's GLib runtime {name}: {error}")
        })
    })
}

unsafe fn glib_strdup(value: *const c_char) -> *mut c_char {
    // SAFETY: `GLIB_LIBRARY` retains the loaded module and this signature is
    // the documented GLib declaration for g_strdup.
    let function = unsafe {
        *glib_library()
            .get::<unsafe extern "C" fn(*const c_char) -> *mut c_char>(b"g_strdup\0")
            .expect("Wireshark's GLib runtime does not export g_strdup")
    };
    // SAFETY: `value` is a valid NUL-terminated string and `function` has the
    // signature declared by GLib.
    unsafe { function(value) }
}

unsafe fn glib_free(value: *mut std::ffi::c_void) {
    // SAFETY: `GLIB_LIBRARY` retains the loaded module and this signature is
    // the documented GLib declaration for g_free.
    let function = unsafe {
        *glib_library()
            .get::<unsafe extern "C" fn(*mut std::ffi::c_void)>(b"g_free\0")
            .expect("Wireshark's GLib runtime does not export g_free")
    };
    // SAFETY: The pointer was allocated by GLib and is freed exactly once.
    unsafe { function(value) }
}

/// A snapshot of the values currently registered with a protocol module.
pub type PreferenceMap = HashMap<&'static str, PrefValue>;

/// Error returned when a preference value does not match its Rust field type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreferenceError {
    /// The map contains a value with a different kind than the declared field.
    WrongKind,
}

impl std::fmt::Display for PreferenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongKind => f.write_str("preference value has the wrong kind"),
        }
    }
}

impl std::error::Error for PreferenceError {}

/// Converts a Rust preference field to and from Wireshark preference values.
pub trait PreferenceValue: Default + Sized {
    /// Returns the Wireshark preference kind and its default value.
    fn to_pref_value(&self) -> PrefValue;

    /// Reads a value of this field's kind.
    fn from_pref_value(value: &PrefValue) -> Result<Self, PreferenceError>;
}

impl PreferenceValue for bool {
    fn to_pref_value(&self) -> PrefValue {
        PrefValue::Boolean(*self)
    }

    fn from_pref_value(value: &PrefValue) -> Result<Self, PreferenceError> {
        if let PrefValue::Boolean(value) = value {
            Ok(*value)
        } else {
            Err(PreferenceError::WrongKind)
        }
    }
}

impl PreferenceValue for u32 {
    fn to_pref_value(&self) -> PrefValue {
        PrefValue::Uint(*self, 10)
    }

    fn from_pref_value(value: &PrefValue) -> Result<Self, PreferenceError> {
        if let PrefValue::Uint(value, _) = value {
            Ok(*value)
        } else {
            Err(PreferenceError::WrongKind)
        }
    }
}

impl PreferenceValue for String {
    fn to_pref_value(&self) -> PrefValue {
        PrefValue::String(self.clone())
    }

    fn from_pref_value(value: &PrefValue) -> Result<Self, PreferenceError> {
        match value {
            PrefValue::String(value) => Ok(value.clone()),
            PrefValue::FileName(value, _) | PrefValue::Directory(value) => Ok(value.clone()),
            _ => Err(PreferenceError::WrongKind),
        }
    }
}

/// A struct that describes and reads a protocol's typed preferences.
pub trait Preferences: Default + Sized {
    /// Creates the preference declarations registered with Wireshark.
    fn module_preferences() -> Vec<ModulePref>;

    /// Builds a typed snapshot from values currently registered by Wireshark.
    fn from_values(values: &PreferenceMap) -> Result<Self, PreferenceError>;
}

/// Empty preference configuration for protocols without user preferences.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPreferences;

impl Preferences for NoPreferences {
    fn module_preferences() -> Vec<ModulePref> {
        Vec::new()
    }
    fn from_values(_: &PreferenceMap) -> Result<Self, PreferenceError> {
        Ok(Self)
    }
}

#[derive(Clone)]
pub struct GBool(pub bindings::gboolean);

impl PartialEq<bool> for GBool {
    fn eq(&self, other: &bool) -> bool {
        (self.0 != bindings::FALSE as i32) == *other
    }
}

#[derive(Clone)]
pub struct ModulePref {
    pub value_type: PrefValue,
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

enum PreferenceStorage {
    Boolean(Box<bool>),
    Uint(Box<bindings::guint>),
    String(Box<*const c_char>),
}

pub struct Value<T> {
    pub info: T,
    storage: Option<PreferenceStorage>,
}

impl<T> Value<T> {
    pub fn new(info: T) -> Self {
        Self {
            info,
            storage: None,
        }
    }
}

impl Value<ModulePref> {
    /// Reads the current value in Wireshark's registered preference slot.
    ///
    /// The slot is owned by this `Value` and remains stable while Wireshark
    /// retains the registration. String values are allocated by GLib.
    pub(crate) fn get_current_value(&self) -> PrefValue {
        match (&self.info.value_type, &self.storage) {
            (PrefValue::Boolean(_), Some(PreferenceStorage::Boolean(value))) => {
                PrefValue::Boolean(**value)
            }
            (PrefValue::Uint(_, base), Some(PreferenceStorage::Uint(value))) => {
                PrefValue::Uint(**value, *base)
            }
            (PrefValue::String(_), Some(PreferenceStorage::String(value))) => {
                PrefValue::String(read_string(**value))
            }
            (PrefValue::FileName(_, for_writing), Some(PreferenceStorage::String(value))) => {
                PrefValue::FileName(read_string(**value), *for_writing)
            }
            (PrefValue::Directory(_), Some(PreferenceStorage::String(value))) => {
                PrefValue::Directory(read_string(**value))
            }
            (PrefValue::StaticText(), _) => PrefValue::StaticText(),
            (default, _) => default.clone(),
        }
    }

    /// Registers this preference in a Wireshark module.
    ///
    /// # Safety
    /// `module` must be a live module handle returned by Wireshark.
    pub unsafe fn register(&mut self, module: *mut bindings::pref_module) {
        let name = get_static_cstring(self.info.name);
        let title = get_static_cstring(self.info.title);
        let description = get_static_cstring(self.info.description);
        // SAFETY: Caller guarantees a live module; stored values have stable addresses for Wireshark.
        unsafe {
            match &self.info.value_type {
                PrefValue::Boolean(default) => {
                    let mut value = Box::new(*default);
                    bindings::prefs_register_bool_preference(
                        module,
                        name,
                        title,
                        description,
                        &mut *value,
                    );
                    self.storage = Some(PreferenceStorage::Boolean(value));
                }
                PrefValue::Uint(default, base) => {
                    let mut value = Box::new(*default);
                    bindings::prefs_register_uint_preference(
                        module,
                        name,
                        title,
                        description,
                        *base,
                        &mut *value,
                    );
                    self.storage = Some(PreferenceStorage::Uint(value));
                }
                PrefValue::String(default) => {
                    let mut value = Box::new(duplicate_string(default));
                    bindings::prefs_register_string_preference(
                        module,
                        name,
                        title,
                        description,
                        &mut *value,
                    );
                    self.storage = Some(PreferenceStorage::String(value));
                }
                PrefValue::FileName(default, for_writing) => {
                    let mut value = Box::new(duplicate_string(default));
                    bindings::prefs_register_filename_preference(
                        module,
                        name,
                        title,
                        description,
                        &mut *value,
                        *for_writing,
                    );
                    self.storage = Some(PreferenceStorage::String(value));
                }
                PrefValue::Directory(default) => {
                    let mut value = Box::new(duplicate_string(default));
                    bindings::prefs_register_directory_preference(
                        module,
                        name,
                        title,
                        description,
                        &mut *value,
                    );
                    self.storage = Some(PreferenceStorage::String(value));
                }
                PrefValue::StaticText() => {
                    bindings::prefs_register_static_text_preference(
                        module,
                        name,
                        title,
                        description,
                    );
                }
            }
        }
    }
}

impl Drop for PreferenceStorage {
    fn drop(&mut self) {
        if let PreferenceStorage::String(value) = self {
            let current = **value;
            if !current.is_null() {
                // `g_strdup` allocated this value and Wireshark replaces it
                // with other GLib-owned strings when preferences are edited.
                // SAFETY: This slot contains the current GLib-owned value for the registered preference.
                unsafe { glib_free(current.cast_mut().cast()) };
            }
        }
    }
}

// SAFETY: Preference pointers are only accessed through the plugin's serialized callback state.
unsafe impl Send for PreferenceStorage {}

fn duplicate_string(value: &str) -> *const c_char {
    let value = CString::new(value).expect("preference strings must not contain NUL bytes");
    // SAFETY: `value` is a valid NUL-terminated string for the duration of the copy.
    unsafe { glib_strdup(value.as_ptr()) }
}

fn read_string(value: *const c_char) -> String {
    if value.is_null() {
        return String::new();
    }
    // SAFETY: The caller supplies the current GLib-owned preference string while the slot is live.
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
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
