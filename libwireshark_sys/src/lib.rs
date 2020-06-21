#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_variables)]

include!("bindings.rs");

#[repr(C)]
pub struct cstr(pub *const i8);
unsafe impl Sync for cstr {}
impl std::ops::Deref for cstr {
    type Target = *const i8;
    fn deref(&self) -> &*const i8 {
        &self.0
    }
}
#[macro_export] 
macro_rules! cstr {
    ($s:expr) => {
        $crate::cstr(concat!($s, "\0") as *const str as *const [i8] as *const i8)
    };
}

#[macro_export] 
macro_rules! wireshark_plugin {
    ($proto_info:expr, $handoff:expr) => {
        #[no_mangle]
        #[used]
        pub static plugin_version: $crate::cstr = $crate::cstr!(env!("CARGO_PKG_VERSION"));        
        #[no_mangle]
        #[used]
        pub static plugin_want_major: u32 = $crate::VERSION_MAJOR;
        #[no_mangle]
        #[used]
        pub static plugin_want_minor: u32 = $crate::VERSION_MINOR;

        unsafe extern "C" fn register_protoinfo() {
            $proto_info
        }
        unsafe extern "C" fn register_handoff() {
            $handoff
        }

        static __proto_plugin__:$crate::proto_plugin = $crate::proto_plugin  {
            register_protoinfo:Some(register_protoinfo),
            register_handoff:Some(register_handoff)
        };        

        #[no_mangle]
        pub unsafe extern "C" fn plugin_register() {
            $crate::proto_register_plugin(&__proto_plugin__);
        }
    };
}