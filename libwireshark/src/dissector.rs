use crate::bindings;
use crate::utils::get_static_cstring;
#[derive(Debug, Clone)]
pub enum DissectorAdd {
    Uint(&'static str, u32, bool),
}
impl DissectorAdd {
    pub fn register(&self, dissector: *mut bindings::dissector_handle) {
        match self {
            DissectorAdd::Uint(name, val, with_pref) => unsafe {
                if *with_pref {
                    bindings::dissector_add_uint_with_preference(
                        get_static_cstring(*name),
                        *val,
                        dissector,
                    );
                } else {
                    bindings::dissector_add_uint(get_static_cstring(*name), *val, dissector);
                }
            },
        }
    }
}
