use libwireshark::{
    wireshark_plugin, bindings, DissectorAdd, DissectorProtocol, GBool, ModulePref, PrefsValueType,
};
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
    }],
    dissector_adds: vec![DissectorAdd::Uint("udp.port", 111, true)],
    dissector,
    ..DissectorProtocol::default()
});
wireshark_plugin!(FOO_DISSECTOR);
