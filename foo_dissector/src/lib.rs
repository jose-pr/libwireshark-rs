use libwireshark::prefs::{GBool, ModulePref, PrefsValueType};
use libwireshark::{bindings, wireshark_plugin, DissectorAdd, DissectorProtocol};
use once_cell::sync::Lazy;

extern "C" fn dissector(
    tvb: *mut bindings::tvbuff_t,
    pinfo: *mut bindings::packet_info,
    _proto_tree: *mut bindings::proto_tree,
    _arg4: *mut std::os::raw::c_void,
) -> std::os::raw::c_int {
    0
}

static mut FOO_DISSECTOR: Lazy<DissectorProtocol> = Lazy::new(|| DissectorProtocol {
    name: "Foos Protocol",
    short_name: "FOO1",
    filter_name: "foos",
    prefs: vec![ModulePref {
        valute_type: PrefsValueType::Boolean(GBool(0)),
        name: "bool_pref",
        title: "Test Boolean Preference",
        description: "bool_pref Description",
    },
    ModulePref {
        valute_type: PrefsValueType::String(std::ffi::CString::new("stringy").unwrap().as_ptr()),
        name: "str_pref",
        title: "Test String Preference",
        description: "bool_str Description",
    },ModulePref {
        valute_type: PrefsValueType::Uint(10,10),
        name: "uint_pref",
        title: "Test Uint Preference",
        description: "uint_pref Description",
    },ModulePref {
        valute_type: PrefsValueType::StaticText(),
        name: "static_pref",
        title: "Test Boolean Preference",
        description: "bool_pref Description",
    }],
    dissector_adds: vec![DissectorAdd::Uint("udp.port", 111, true)],
    dissector,
    ..DissectorProtocol::default()
});
wireshark_plugin!(FOO_DISSECTOR);
