//static int hf_lwm_fcf = -1;
//static int hf_lwm_fcf_ack_req = -1;
//static int hf_lwm_fcf_security = -1;

//static const value_string lwm_cmd_names[] = {
//{ 0x00, “Acknowledgment frame” },
//{ 0x01, “Route Error” },
//{ 0, NULL }
//};


use crate::bindings;
#[macro_use]
use crate::cstr;

struct HeaderField {

}

/* Type-check that 'x' is compatible with 'type', should give compiler warnings otherwise. */
//#define cast_same(type, x) (0 ? (type)0 : (x))

/** Make a const value_string[] look like a _value_string pointer, used to set header_field_info.strings */
//#define VALS(x)     (cast_same(const struct _value_string*, (x)))

fn test(){
    let test = "";
    //static const value_string lwm_cmd_names[] = {
//{ 0x00, “Acknowledgment frame” },
//{ 0x01, “Route Error” },
//{ 0, NULL }
//};


}
/*
static hf_register_info hf[] = {
{ &hf_lwm_fcf,
{ “Frame control field”, “lwm.fcf”, FT_UINT8, BASE_HEX, VALS(lwm_fcf_names), 0x0,
“Control information for the frame.”, HFILL }},

{ &hf_lwm_fcf_ack_req,
{ “Acknowledgment Request”, “lwm.ack_req”, FT_BOOLEAN, 8, NULL, 0x80,
“Whether an acknowledgment is required from the destination node.”, HFILL }},

…
}
/* Subtrees */
static gint *ett[] = {
&ett_lwm,
&ett_lwm_cmd_tree
};

/* Register protocol name and description. */
proto_lwm = proto_register_protocol(“Lightweight Mesh”, “LwMesh”, “lwm”);

/* Register header fields and subtrees. */
proto_register_field_array(proto_lwm, hf, array_length(hf));
proto_register_subtree_array(ett, array_length(ett));

/* Register dissector with Wireshark. */
register_dissector(“lwm”, dissect_lwm, proto_lwm);
*/