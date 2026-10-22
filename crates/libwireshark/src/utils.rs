use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

pub fn get_static_cstring(string: &'static str) -> *const i8 {
    static STRINGS: Lazy<Mutex<HashMap<&'static str, CString>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));
    let mut strings = STRINGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    strings
        .entry(string)
        .or_insert_with(|| {
            CString::new(string).expect("Wireshark names must not contain NUL bytes")
        })
        .as_ptr()
}
