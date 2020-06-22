use libwireshark::{
    wireshark_plugin, DissectorAdd, DissectorProtocol, GBool, ModulePref, PrefsValueType,
};
use once_cell::sync::Lazy;

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
    ..DissectorProtocol::default()
});
wireshark_plugin!(FOO_DISSECTOR);
