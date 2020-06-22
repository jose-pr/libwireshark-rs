#![allow(unused_variables)]
pub use libwireshark_sys as bindings;
pub mod utils;
use utils::get_static_cstring;
pub mod prefs;
use prefs::ModulePref;
pub enum DissectorAdd {
    Uint(&'static str, u32, bool),
}
impl DissectorAdd {
    pub fn register(&self, dissector: *mut bindings::dissector_handle) {
        match self {
            DissectorAdd::Uint(name, val, with_pref) => unsafe {
                if *with_pref {
                    bindings::dissector_add_uint_with_preference(
                        get_static_cstring(*name),
                        *val,
                        dissector,
                    );
                } else {
                    bindings::dissector_add_uint(get_static_cstring(*name), *val, dissector);
                }
            },
        }
    }
}

type Disector = extern "C" fn(
    tvb: *mut bindings::tvbuff_t,
    pinfo: *mut bindings::packet_info,
    proto_tree: *mut bindings::proto_tree,
    call_back: *mut std::os::raw::c_void,
) -> std::os::raw::c_int;

pub struct DissectorProtocol {
    pub name: &'static str,
    pub short_name: &'static str,
    pub filter_name: &'static str,
    pub proto_handle: Option<i32>,
    pub prefs_handle: Option<*mut bindings::pref_module>,
    pub dissector_handle: Option<*mut bindings::dissector_handle>,
    pub dissector_adds: Vec<DissectorAdd>,
    pub prefs: Vec<ModulePref>,
    pub dissector: Disector,
}
impl Default for DissectorProtocol {
    fn default() -> Self {
        extern "C" fn dissector(
            tvb: *mut bindings::tvbuff_t,
            pinfo: *mut bindings::packet_info,
            _proto_tree: *mut bindings::proto_tree,
            _arg4: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int {
            0
        }

        Self {
            name: "",
            short_name: "",
            filter_name: "",
            proto_handle: None,
            prefs_handle: None,
            dissector_handle: None,
            dissector_adds: vec![],
            prefs: vec![],
            dissector,
        }
    }
}
impl DissectorProtocol {
    pub fn handoff(&mut self) {
        unsafe {
            self.dissector_handle = Some(bindings::create_dissector_handle(
                Some(self.dissector),
                self.proto_handle.unwrap(),
            ));
        }
        for add in &self.dissector_adds {
            add.register(self.dissector_handle.unwrap());
        }
    }
    pub fn register(&mut self) {
        unsafe {
            self.proto_handle = Some(bindings::proto_register_protocol(
                get_static_cstring(self.name),
                get_static_cstring(self.short_name),
                get_static_cstring(self.filter_name),
            ));
            let prefs = bindings::prefs_register_protocol(self.proto_handle.unwrap(), None);

            self.prefs_handle = Some(bindings::prefs_register_protocol(
                self.proto_handle.unwrap(),
                None,
            ));
            for pref in self.prefs.iter_mut() {
                pref.register(self.prefs_handle.unwrap());
            }
        }
    }
}
