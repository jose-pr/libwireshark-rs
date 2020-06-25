use crate::bindings;
use crate::utils::cstr;
use std::collections::HashMap;
#[derive(Clone, Debug)]
pub struct HeaderFieldInfo {
    pub name: &'static str,
    pub abbrev: &'static str,
    pub type_: i32,
    pub display: i32,
    //strings
    pub bitmask: u64,
    pub blurb: &'static str,
}
pub fn register_fields<Arr: AsMut<[(Box<i32>, HeaderFieldInfo)]>>(proto_id: i32, fields: &mut Arr) {
    // let hf = Vec::<bindings::header_field_info>::with_capacity(fields.len());
    let hf: Vec<bindings::hf_register_info> = fields
        .as_mut()
        .iter_mut()
        .map(|(id, field)| bindings::hf_register_info {
            p_id: id.as_mut() as *mut i32,
            hfinfo: bindings::header_field_info {
                name: *cstr::new(field.name),
                abbrev: *cstr::new(field.abbrev),
                r#type: field.type_,
                display: field.display,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: *cstr::new(field.blurb),
                id: -1,
                parent: 0,
                ref_type: bindings::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        })
        .collect();
    let len = hf.len() as i32;
    let hf = Box::into_raw(hf.into_boxed_slice()) as *mut bindings::hf_register_info;

    unsafe {
        bindings::proto_register_field_array(proto_id, hf, len);
    }
}
