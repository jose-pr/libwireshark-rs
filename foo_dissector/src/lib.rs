use libwireshark_sys::{wireshark_plugin,  proto_register_protocol, cstr, prefs_register_protocol, dissector_handle_t, prefs_register_bool_preference, create_dissector_handle, dissector_add_uint, dissector_add_uint_with_preference};

//UNSAFE but code is only called once, good enogh for me.
static mut PROTO_HANDLE:Option<i32> = None;
static mut CONFIG_BOOL:i32 = 0;
//Default values
const FOO_PORT_TCP: u32 = 1234;
const FOO_PORT_UDP: u32 = 1234;

//Maybe function/macro to generate prefences from struct? Deal with all unsage code there?
//Read values from Config.toml , right know only version is read get the description and name? Use metadata?
wireshark_plugin!({
    PROTO_HANDLE = Some(proto_register_protocol(*cstr!("FOO Protocol"), *cstr!("FOO"), *cstr!("foo")));
    let prefs = prefs_register_protocol(PROTO_HANDLE.unwrap(), None);
    prefs_register_bool_preference(prefs, *cstr!("bool_opt"),
    *cstr!("Bool Preference Option"),
    *cstr!(".... blah blah blah... \n blah.. blah"),
    &mut CONFIG_BOOL);
} , {

    let foo_handle: dissector_handle_t;
    foo_handle = create_dissector_handle(Some(dissect_foo), PROTO_HANDLE.unwrap());
    dissector_add_uint(*cstr!("udp.port"), FOO_PORT_UDP, foo_handle);
    dissector_add_uint_with_preference(*cstr!("tcp.port"), FOO_PORT_TCP, foo_handle);
});

//create some nice wrapper functions.
unsafe extern "C" fn dissect_foo(
    tvb: *mut libwireshark_sys::tvbuff_t,
    pinfo: *mut libwireshark_sys::packet_info,
    _proto_tree: *mut libwireshark_sys::proto_tree,
    _arg4: *mut std::os::raw::c_void,
) -> std::os::raw::c_int {
    libwireshark_sys::col_set_str((&*pinfo).cinfo, libwireshark_sys::COL_PROTOCOL, *cstr!("FOO"));
    /* Clear the info column */
    libwireshark_sys::col_clear((&*pinfo).cinfo, libwireshark_sys::COL_INFO);

    return libwireshark_sys::tvb_captured_length(tvb) as i32;
}