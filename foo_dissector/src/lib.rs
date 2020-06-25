#![allow(unused_variables)]
use libwireshark::header::HeaderFieldInfo;
use libwireshark::prefs::{GBool, ModulePref, PrefValue};
use libwireshark::{bindings, create_protocol_plugin, Protocol};

fn dissect(
    prefs: &std::collections::HashMap<&'static str, PrefValue>,
    tvb: *mut bindings::tvbuff_t,
    pinfo: *mut bindings::packet_info,
    proto_tree: *mut bindings::proto_tree,
    call_back: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    0
}

create_protocol_plugin!(|| Protocol {
    name: "FOO2",
    short_name: "foos",
    filter_name: "foton",
    prefs: vec![
        ModulePref {
           value_type: PrefValue::Boolean(GBool(0)),
            name: "bool_pref",
            title: "Test Boolean Preference",
            description: "bool_pref Description",
        },
        ModulePref::n {
           value_type: PrefValue::String(std::ffi::CString::new("stringy").unwrap().as_ptr()),
            name: "str_pref",
            title: "Test String Preference",
            description: "bool_str Description",
        },
        ModulePref {
           value_type: PrefValue::Uint(10, 10),
            name: "uint_pref",
            title: "Test Uint Preference",
            description: "uint_pref Description",
        },
        ModulePref {
           value_type: PrefValue::StaticText(),
            name: "static_pref",
            title: "Test Static Text Preference",
            description: "Static Text Description",
        },
    ],
    dissect_on: vec![libwireshark::dissector::DissectorAdd::Uint(
        "udp.port", 111, true,
    )],
    header_fields: vec![HeaderFieldInfo {
        name: "version",
        abbrev: "foton.version",
        display: 0,
        bitmask: 0,
        blurb: "SUP",
        type_: 0
    }],
    dissect
});

/*
name: "FOO2",
short_name: "foos",
filter_name: "foton",
prefs: &[
    ModulePref {
       value_type: PrefValue::Boolean(GBool(0)),
        name: "bool_pref",
        title: "Test Boolean Preference",
        description: "bool_pref Description",
    },
/*    ModulePref {
       value_type: PrefValue::String(std::ffi::CString::new("stringy").unwrap().as_ptr()),
        name: "str_pref",
        title: "Test String Preference",
        description: "bool_str Description",
    },
    ModulePref {
       value_type: PrefValue::Uint(10, 10),
        name: "uint_pref",
        title: "Test Uint Preference",
        description: "uint_pref Description",
    },
    ModulePref {
       value_type: PrefValue::StaticText(),
        name: "static_pref",
        title: "Test Static Text Preference",
        description: "Static Text Description",
    },*/
],
dissect_on: &[libwireshark::dissector::DissectorAdd::Uint(
    "udp.port", 111, true,
)],
header_fields:&[],
dissect: |prefs: &std::collections::HashMap<&'static str, PrefValue>,
          tvb: *mut bindings::tvbuff_t,
          pinfo: *mut bindings::packet_info,
          proto_tree: *mut bindings::proto_tree,
          call_back: *mut std::ffi::c_void|
 -> std::os::raw::c_int { 0 },*/
