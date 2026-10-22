use crate::bindings;
use std::ffi::CString;

/// Provides the registered display-filter fields for a protocol header.
pub trait Header {
    /// Returns field descriptors in registration order.
    fn fields() -> &'static [HeaderFieldInfo];

    /// Adds the values in this decoded header to the current packet tree.
    fn add_to(
        &self,
        packet: &mut crate::dissector::PacketView<'_>,
    ) -> Result<(), crate::dissector::PacketFieldError>;
}

/// Header type for protocols without registered display-filter fields.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHeader;

impl Header for NoHeader {
    fn fields() -> &'static [HeaderFieldInfo] {
        &[]
    }

    fn add_to(
        &self,
        _: &mut crate::dissector::PacketView<'_>,
    ) -> Result<(), crate::dissector::PacketFieldError> {
        Ok(())
    }
}

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
/// Registers the fields for a protocol with Wireshark.
///
/// # Safety
/// `proto_id` must be a live protocol identifier returned by Wireshark.
pub unsafe fn register_fields<Arr: AsMut<[(Box<i32>, HeaderFieldInfo)]>>(
    proto_id: i32,
    fields: &mut Arr,
) -> (Vec<bindings::hf_register_info>, Vec<CString>) {
    let mut strings = Vec::with_capacity(fields.as_mut().len() * 3);
    let hf: Vec<bindings::hf_register_info> = fields
        .as_mut()
        .iter_mut()
        .map(|(id, field)| {
            let name = CString::new(field.name).expect("field names must not contain NUL bytes");
            let abbrev =
                CString::new(field.abbrev).expect("field filters must not contain NUL bytes");
            let blurb =
                CString::new(field.blurb).expect("field descriptions must not contain NUL bytes");
            let info = bindings::header_field_info {
                name: name.as_ptr(),
                abbrev: abbrev.as_ptr(),
                type_: field.type_,
                display: field.display,
                strings: std::ptr::null(),
                bitmask: field.bitmask,
                blurb: blurb.as_ptr(),
                id: -1,
                parent: 0,
                ref_type: bindings::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            };
            strings.extend([name, abbrev, blurb]);
            bindings::hf_register_info {
                p_id: id.as_mut() as *mut i32,
                hfinfo: info,
            }
        })
        .collect();
    let len = hf.len() as i32;
    // SAFETY: Caller supplies a live protocol ID; descriptors and strings are retained by ProtocolPlugin.
    unsafe {
        bindings::proto_register_field_array(
            proto_id,
            hf.as_ptr() as *mut bindings::hf_register_info,
            len,
        );
    }
    (hf, strings)
}
