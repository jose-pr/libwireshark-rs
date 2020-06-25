#![allow(unused_variables)]
pub use libwireshark_sys as bindings;
pub mod dissector;
pub mod utils;
use crate::dissector::DissectorAdd;
use std::ffi::CString;
use utils::cstr;
pub mod header;
pub mod prefs;
use once_cell::sync::{Lazy, OnceCell};
use prefs::ModulePref;

pub struct Protocol {
    pub name: &'static str,
    pub short_name: &'static str,
    pub filter_name: &'static str,
    pub prefs: Vec<ModulePref>,
    pub dissect_on: Vec<DissectorAdd>,
    pub header_fields: Vec<header::HeaderFieldInfo>,
    pub dissect: fn(
        prefs: &std::collections::HashMap<&'static str, prefs::PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int,
}

pub struct ProtocolPlugin {
    name: CString,
    short_name: CString,
    filter_name: CString,
    header_fields: Vec<(Box<i32>, header::HeaderFieldInfo)>,
    preferences: Vec<prefs::Value<ModulePref>>,
    dissector: fn(
        prefs: &std::collections::HashMap<&'static str, prefs::PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int,
    dissect_on: Vec<DissectorAdd>,
    proto_handle: i32,
    dissector_handle: Option<*mut bindings::dissector_handle>,
    prefs_handle: Option<*mut bindings::pref_module>,
}
impl ProtocolPlugin {
    pub fn new(proto: Protocol) -> Self {
        Self {
            name: CString::new(proto.name).unwrap(),
            short_name: CString::new(proto.short_name).unwrap(),
            filter_name: CString::new(proto.filter_name).unwrap(),
            dissect_on: proto.dissect_on,
            preferences: proto
                .prefs
                .iter()
                .cloned()
                .map(|p| prefs::Value::new(p))
                .collect(),
            header_fields: proto
                .header_fields
                .iter()
                .cloned()
                .map(|f| (Box::new(-1i32), f))
                .collect(),
            dissector: proto.dissect,
            proto_handle: -1i32,
            prefs_handle: None,
            dissector_handle: None,
        }
    }
    #[inline(always)]
    fn dissect(
        &self,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> i32 {
        let prefs = self
            .preferences
            .iter()
            .fold(std::collections::HashMap::new(), |mut map, v| {
                map.insert(v.info.name, v.get_current_value());
                map
            });
        (self.dissector)(&prefs, tvb, pinfo, proto_tree, call_back)
    }
    fn register_handoff(&mut self) {
        pub unsafe extern "C" fn dissector(
            tvb: *mut bindings::tvbuff_t,
            pinfo: *mut bindings::packet_info,
            proto_tree: *mut bindings::proto_tree,
            call_back: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int {
            match &PROTO_PLUGIN {
                Some(plugin) => plugin.dissect(tvb, pinfo, proto_tree, call_back),
                None => 0,
            }
        }
        unsafe {
            self.dissector_handle = Some(bindings::create_dissector_handle(
                Some(dissector),
                self.proto_handle.clone(),
            ));
        }
        for add in &self.dissect_on {
            add.register(self.dissector_handle.unwrap());
        }
    }
    fn register_protoinfo(&mut self) {
        unsafe {
            self.proto_handle = bindings::proto_register_protocol(
                self.name.as_ptr(),
                self.short_name.as_ptr(),
                self.filter_name.as_ptr(),
            );
            self.prefs_handle = Some(bindings::prefs_register_protocol(self.proto_handle, None));
        }
        header::register_fields(self.proto_handle, &mut self.header_fields);

        for pref in &mut self.preferences {
            pref.register(self.prefs_handle.unwrap());
        }
    }
}

pub static mut PROTO_PLUGIN: Option<ProtocolPlugin> = None;

pub unsafe fn plugin_register() {
    unsafe extern "C" fn register_protoinfo() {
        match &mut PROTO_PLUGIN {
            Some(plugin) => plugin.register_protoinfo(),
            None => {}
        }
    }
    unsafe extern "C" fn register_handoff() {
        match &mut PROTO_PLUGIN {
            Some(plugin) => plugin.register_handoff(),
            None => {}
        }
    }
    static PLUGIN: bindings::proto_plugin = bindings::proto_plugin {
        register_protoinfo: Some(register_protoinfo),
        register_handoff: Some(register_handoff),
    };
    bindings::proto_register_plugin(&PLUGIN);
}
