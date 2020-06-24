#![allow(unused_variables)]
use libwireshark::prefs::{GBool, ModulePref, PrefValue};
use libwireshark::{bindings, register_plugin, ProtocolId, ProtoPlugin};

#[derive(Debug)]
struct FooProtocol;
impl ProtoPlugin for FooProtocol {
    fn get_protocol_id(&self) -> ProtocolId {
        ProtocolId {
            name:"FOO PROTOCOL",
            short_name:"FOO",
            filter_name:"foo"
        }
    }
    fn get_prefs(&self) -> Vec<ModulePref>{
        vec![
            ModulePref {
                value: PrefValue::Boolean(GBool(0)),
                name: "bool_pref",
                title: "Test Boolean Preference",
                description: "bool_pref Description",
            },
            ModulePref {
                value: PrefValue::String(std::ffi::CString::new("stringy").unwrap().as_ptr()),
                name: "str_pref",
                title: "Test String Preference",
                description: "bool_str Description",
            },
            ModulePref {
                value: PrefValue::Uint(10, 10),
                name: "uint_pref",
                title: "Test Uint Preference",
                description: "uint_pref Description",
            },
            ModulePref {
                value: PrefValue::StaticText(),
                name: "static_pref",
                title: "Test Static Text Preference",
                description: "Static Text Description",
            },
        ]
    }
    fn get_dissector_adds(&self) ->Vec<libwireshark::dissector::DissectorAdd> {
        vec![libwireshark::dissector::DissectorAdd::Uint("udp.port", 111, true)]
    }
    fn dissect(
        &self,
        prefs: &std::collections::HashMap<&'static str, PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int {
        0
    }
}
static INSTANCE: FooProtocol = FooProtocol {};
register_plugin!(INSTANCE);
