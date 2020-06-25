#[repr(C)]
pub struct cstr(pub *const i8);
unsafe impl Sync for cstr {}
pub fn raw_ptr<T>(o: T) -> *mut T {
    Box::into_raw(Box::new(o))
}

impl cstr {
    ///Creates static cstring***
    pub fn new<S: Into<Vec<u8>>>(string: S) -> Self {
        cstr(Box::leak(std::ffi::CString::new(string).unwrap().into_boxed_c_str()).as_ptr())
    }
}

pub fn get_static_cstring(string: &'static str) -> *const i8 {
    Box::leak(std::ffi::CString::new(string).unwrap().into_boxed_c_str()).as_ptr()
}

impl std::ops::Deref for cstr {
    type Target = *const i8;
    fn deref(&self) -> &*const i8 {
        &self.0
    }
}
#[macro_export]
macro_rules! cstr {
    ($s:expr) => {
        $crate::utils::cstr(concat!($s, "\0") as *const str as *const [i8] as *const i8)
    };
}

#[macro_export]
macro_rules! create_protocol_plugin {
    ($proto:expr) => {
        #[no_mangle]
        #[used]
        pub static plugin_version: $crate::utils::cstr = $crate::cstr!(env!("CARGO_PKG_VERSION"));
        #[no_mangle]
        #[used]
        pub static plugin_want_major: u32 = $crate::bindings::VERSION_MAJOR;
        #[no_mangle]
        #[used]
        pub static plugin_want_minor: u32 = $crate::bindings::VERSION_MINOR;

        #[no_mangle]
        pub unsafe extern "C" fn plugin_register() {
            $crate::PROTO_PLUGIN = Some($crate::ProtocolPlugin::new($proto()));
            $crate::plugin_register();
        }
    };
}
