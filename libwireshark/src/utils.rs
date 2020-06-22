#[repr(C)]
pub struct cstr(pub *const i8);
unsafe impl Sync for cstr {}

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
macro_rules! wireshark_plugin {
    ($plugin:ident) => {
        #[no_mangle]
        #[used]
        pub static plugin_version: $crate::utils::cstr = $crate::cstr!(env!("CARGO_PKG_VERSION"));
        #[no_mangle]
        #[used]
        pub static plugin_want_major: u32 = $crate::bindings::VERSION_MAJOR;
        #[no_mangle]
        #[used]
        pub static plugin_want_minor: u32 = $crate::bindings::VERSION_MINOR;

        unsafe extern "C" fn register_protoinfo() {
            $plugin.register();
        }
        unsafe extern "C" fn register_handoff() {
            $plugin.handoff();
        }

        static __proto_plugin__: $crate::bindings::proto_plugin = $crate::bindings::proto_plugin {
            register_protoinfo: Some(register_protoinfo),
            register_handoff: Some(register_handoff),
        };

        #[no_mangle]
        pub unsafe extern "C" fn plugin_register() {
            $crate::bindings::proto_register_plugin(&__proto_plugin__);
        }
    };
}
