#![allow(unused_variables)]
use libwireshark::prefs::{GBool, ModulePref, PrefValue};
use libwireshark::{bindings, register_protocol, Protocol};
struct FooProtocol {}
impl Protocol for FooProtocol {
    const NAME:&'static str = "FOO";
    const SHORT_NAME: &'static str = "F";
    const FILTER_NAME: &'static str = "foo";

    fn prefs() -> Vec<ModulePref>{
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
    fn dissect_on() ->Vec<libwireshark::dissector::DissectorAdd> {
        vec![libwireshark::dissector::DissectorAdd::Uint("udp.port", 111, true)]
    }
    fn dissect(
        prefs: &std::collections::HashMap<&'static str, PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int {
        0
    }
}
register_protocol!(FooProtocol);
