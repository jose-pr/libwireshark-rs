#![allow(unused_variables)]
pub use libwireshark_sys as bindings;
pub mod dissector;
pub mod utils;
use crate::dissector::DissectorAdd;
use utils::cstr;
pub mod prefs;
use once_cell::sync::OnceCell;
use prefs::ModulePref;
pub struct ProtocolId {
    pub name: &'static str,
    pub short_name: &'static str,
    pub filter_name: &'static str,
}
pub trait ProtoPlugin
where
    Self: Send + Sync + 'static,
{
    fn get_protocol_id(&self) -> ProtocolId;
    fn get_prefs(&self) -> Vec<ModulePref>;
    fn get_dissector_adds(&self) -> Vec<DissectorAdd>;
    fn dissect(
        &self,
        prefs: &std::collections::HashMap<&'static str, prefs::PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int;
}


pub trait Protocol where
Self: Send + Sync + 'static + Sized {
    const NAME:&'static str;
    const SHORT_NAME: &'static str;
    const FILTER_NAME: &'static str;
    fn prefs() -> Vec<ModulePref>;
    fn dissect_on() -> Vec<DissectorAdd>;
    fn dissect(
        prefs: &std::collections::HashMap<&'static str, prefs::PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int;
}
pub struct GenericPlugin<T:Protocol>(pub std::marker::PhantomData<T>); 

impl<T:Protocol> ProtoPlugin for GenericPlugin<T> {
    fn get_protocol_id(&self) -> ProtocolId {
        ProtocolId {
            name:T::NAME,
            short_name:T::SHORT_NAME,
            filter_name:T::FILTER_NAME
        }
    }
    fn get_prefs(&self) -> Vec<ModulePref> {
        T::prefs()
    }
    fn get_dissector_adds(&self) -> Vec<DissectorAdd> {
        T::dissect_on()
    }
    fn dissect(
        &self,
        prefs: &std::collections::HashMap<&'static str, prefs::PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int{
        T::dissect(prefs, tvb, pinfo, proto_tree, call_back)
    }
}



pub static PROTO_PLUGIN: OnceCell<&'static dyn ProtoPlugin> = OnceCell::new();
pub static mut PROTO_HANDLE: i32 = -1;
pub static mut DISSECTOR_HANDLE: Option<*mut bindings::dissector_handle> = None;
pub static mut PREFS_HANDLE: Option<*mut bindings::pref_module> = None;

pub unsafe fn plugin_register() {
    unsafe extern "C" fn register_protoinfo() {
        let plugin = *PROTO_PLUGIN.get().expect("Not Set");
        let proto = plugin.get_protocol_id();
        PROTO_HANDLE = bindings::proto_register_protocol(
            *cstr::new(proto.name),
            *cstr::new(proto.short_name),
            *cstr::new(proto.filter_name),
        );
        PREFS_HANDLE = Some(bindings::prefs_register_protocol(PROTO_HANDLE, None));

        for pref in plugin.get_prefs() {
            pref.register(PREFS_HANDLE.unwrap());
        }
    }
    unsafe extern "C" fn register_handoff() {
        let plugin = *PROTO_PLUGIN.get().expect("Not Set");
        pub unsafe extern "C" fn dissector(
            tvb: *mut bindings::tvbuff_t,
            pinfo: *mut bindings::packet_info,
            proto_tree: *mut bindings::proto_tree,
            call_back: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int {
            let plugin = *PROTO_PLUGIN.get().expect("Not Set");
            plugin.dissect(&prefs::PREFS, tvb, pinfo, proto_tree, call_back)
        }
        DISSECTOR_HANDLE = Some(bindings::create_dissector_handle(
            Some(dissector),
            PROTO_HANDLE,
        ));
        for add in plugin.get_dissector_adds().iter() {
            add.register(DISSECTOR_HANDLE.unwrap());
        }
    }
    static _PROTO_PLUGIN: bindings::proto_plugin = bindings::proto_plugin {
        register_protoinfo: Some(register_protoinfo),
        register_handoff: Some(register_handoff),
    };
    bindings::proto_register_plugin(&_PROTO_PLUGIN);
}
