//! Preference slots Wireshark writes, and the GLib allocator string
//! preferences need.

use super::callbacks::Flag;
use crate::prefs::{Declaration, Value};
use crate::sys;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use core::ffi::{CStr, c_char};
use core::ptr::NonNull;

/// One registered preference and the storage Wireshark writes it to.
pub(crate) struct Slot {
    pub(crate) declaration: Declaration,
    storage: Storage,
}

enum Storage {
    /// Reads the flag, whose C type is `gboolean` before 4.0 and `bool` after.
    Bool(Box<dyn Fn() -> bool + Send>),
    Uint(NonNull<u32>),
    String(NonNull<*const c_char>),
}

/// A leaked slot pointer the reader closure may carry across threads.
struct FlagSlot<T>(NonNull<T>);

// SAFETY: the slot is leaked and only read, from callbacks the plugin's
// mutex serialises.
unsafe impl<T> Send for FlagSlot<T> {}

impl<T: Copy> FlagSlot<T> {
    fn read(&self) -> T {
        // SAFETY: the leaked slot stays valid; Wireshark writes it only from
        // the thread that runs the preference callbacks.
        unsafe { *self.0.as_ptr() }
    }
}

type RegisterBool<T> =
    unsafe extern "C" fn(*mut sys::module_t, *const c_char, *const c_char, *const c_char, *mut T);

/// Registers a boolean preference with the slot type `register` declares.
///
/// # Safety
///
/// `module` is a live preference module and the strings live for the process.
unsafe fn register_bool<T: Flag>(
    register: RegisterBool<T>,
    module: *mut sys::module_t,
    [name, title, description]: [*const c_char; 3],
    default: bool,
) -> Box<dyn Fn() -> bool + Send> {
    let slot = NonNull::from(Box::leak(Box::new(if default {
        T::TRUE
    } else {
        T::FALSE
    })));
    // SAFETY: the caller's contract; the slot is leaked so it outlives the module.
    unsafe { register(module, name, title, description, slot.as_ptr()) };
    let slot = FlagSlot(slot);
    Box::new(move || slot.read() != T::FALSE)
}

impl Slot {
    pub(crate) fn register(
        module: *mut sys::module_t,
        declaration: Declaration,
        glib: Option<&Glib>,
    ) -> Option<Self> {
        let cstring = |text: &str| CString::new(text.replace('\0', "")).unwrap_or_default();
        // Wireshark keeps these pointers in the module for the process.
        let name = cstring(declaration.name()).into_raw();
        let title = cstring(declaration.title()).into_raw();
        let description = cstring(declaration.description()).into_raw();
        let storage = match declaration.default_value() {
            // SAFETY: `module` is live and the strings are leaked.
            Value::Bool(default) => Storage::Bool(unsafe {
                register_bool(
                    sys::prefs_register_bool_preference,
                    module,
                    [name, title, description].map(<*mut c_char>::cast_const),
                    *default,
                )
            }),
            Value::Uint(default) => {
                let slot = NonNull::from(Box::leak(Box::new(*default)));
                // SAFETY: as above.
                unsafe {
                    sys::prefs_register_uint_preference(
                        module,
                        name,
                        title,
                        description,
                        declaration.base(),
                        slot.as_ptr(),
                    );
                }
                Storage::Uint(slot)
            }
            Value::String(default) => {
                let glib = glib?;
                let default = glib.strdup(&cstring(default));
                let slot = NonNull::from(Box::leak(Box::new(default.cast_const())));
                // SAFETY: as above; Wireshark replaces and frees the string
                // through GLib, which allocated it.
                unsafe {
                    sys::prefs_register_string_preference(
                        module,
                        name,
                        title,
                        description,
                        slot.as_ptr(),
                    )
                };
                Storage::String(slot)
            }
        };
        Some(Self {
            declaration,
            storage,
        })
    }

    pub(crate) fn read(&self) -> Value {
        // SAFETY: the slots are leaked, so they stay valid; Wireshark writes
        // them only from the main thread, which also runs these callbacks.
        unsafe {
            match self.storage {
                Storage::Bool(ref read) => Value::Bool(read()),
                Storage::Uint(slot) => Value::Uint(*slot.as_ptr()),
                Storage::String(slot) => {
                    let text = *slot.as_ptr();
                    Value::String(if text.is_null() {
                        String::new()
                    } else {
                        CStr::from_ptr(text).to_string_lossy().into_owned()
                    })
                }
            }
        }
    }
}

/// GLib's allocator, which Wireshark uses for string preferences. Resolved
/// at run time so a plugin needs no GLib import library.
pub(crate) struct Glib {
    library: libloading::Library,
}

impl Glib {
    pub(crate) fn load() -> Option<Self> {
        // The process's own symbols first: Wireshark is linked against GLib,
        // which a name lookup can miss when it lives outside the loader's
        // default paths (Homebrew's /opt/homebrew/lib).
        #[cfg(unix)]
        {
            let library: libloading::Library = libloading::os::unix::Library::this().into();
            // SAFETY: only checks that the symbol exists.
            if unsafe { library.get::<unsafe extern "C" fn()>(b"g_strdup\0") }.is_ok() {
                return Some(Self { library });
            }
        }
        #[cfg(target_os = "windows")]
        const NAME: &str = "glib-2.0-0.dll";
        #[cfg(target_os = "macos")]
        const NAME: &str = "libglib-2.0.0.dylib";
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        const NAME: &str = "libglib-2.0.so.0";
        // SAFETY: Wireshark has already loaded this library; loading it again
        // runs no initialiser and returns the same module.
        let library = unsafe { libloading::Library::new(NAME) }.ok()?;
        Some(Self { library })
    }

    pub(crate) fn strdup(&self, text: &CStr) -> *mut c_char {
        // SAFETY: `g_strdup` has this signature in every GLib 2 release.
        let Ok(strdup) = (unsafe {
            self.library
                .get::<unsafe extern "C" fn(*const c_char) -> *mut c_char>(b"g_strdup\0")
        }) else {
            return core::ptr::null_mut();
        };
        // SAFETY: `text` is NUL-terminated and live for the call.
        unsafe { strdup(text.as_ptr()) }
    }
}

impl core::fmt::Debug for Glib {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Glib")
    }
}
