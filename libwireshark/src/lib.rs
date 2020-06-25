#![allow(unused_variables)]
pub use libwireshark_sys as bindings;
pub mod dissector;
pub mod utils;
use crate::dissector::DissectorAdd;
use utils::cstr;
pub mod prefs;
pub mod header;
use once_cell::sync::{Lazy,OnceCell};
use prefs::ModulePref;
use std::ops::Deref;
pub struct ProtocolId {
    pub name: &'static str,
    pub short_name: &'static str,
    pub filter_name: &'static str,
}
pub trait ProtoPlugin
where
    Self: Send + Sync + 'static,
{
    fn get_protocol_id(&self) -> ProtocolId;
    fn get_prefs(&self) -> Vec<ModulePref>;
    fn get_dissector_adds(&self) -> Vec<DissectorAdd>;
    fn dissect(
        &self,
        prefs: &std::collections::HashMap<&'static str, prefs::PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int;
}


pub trait Protocol where
Self: Send + Sync + 'static + Sized {
    const NAME:&'static str;
    const SHORT_NAME: &'static str;
    const FILTER_NAME: &'static str;
    fn prefs() -> Vec<ModulePref>;
    fn dissect_on() -> Vec<DissectorAdd>;
    fn dissect(
        prefs: &std::collections::HashMap<&'static str, prefs::PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int;
}
pub struct GenericPlugin<T:Protocol>(pub std::marker::PhantomData<T>); 

impl<T:Protocol> ProtoPlugin for GenericPlugin<T> {
    fn get_protocol_id(&self) -> ProtocolId {
        ProtocolId {
            name:T::NAME,
            short_name:T::SHORT_NAME,
            filter_name:T::FILTER_NAME
        }
    }
    fn get_prefs(&self) -> Vec<ModulePref> {
        T::prefs()
    }
    fn get_dissector_adds(&self) -> Vec<DissectorAdd> {
        T::dissect_on()
    }
    fn dissect(
        &self,
        prefs: &std::collections::HashMap<&'static str, prefs::PrefValue>,
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        proto_tree: *mut bindings::proto_tree,
        call_back: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int{
        T::dissect(prefs, tvb, pinfo, proto_tree, call_back)
    }
}
#[repr(C)]
struct I32(pub *mut i32);
static mut field_a:I32 = I32(-1i32 as *mut i32);
impl Deref for I32 {
    type Target = *mut i32;
    fn deref(&self) -> &*mut i32 {
        &self.0
    }
    
}
/*
* HFILL initializes all the "set by proto routines" fields in a
* _header_field_info. If new fields are added or removed, it should
* be changed as necessary.

#define HFILL -1, 0, HF_REF_TYPE_NONE, -1, NULL

#define HFILL_INIT(hf)   \
   (hf).hfinfo.id                = -1;   \
   (hf).hfinfo.parent            = 0;   \
   (hf).hfinfo.ref_type          = HF_REF_TYPE_NONE;   \
   (hf).hfinfo.same_name_prev_id = -1;   \
   (hf).hfinfo.same_name_next    = NULL;
   /** Contains the field information for the proto_item. */
struct _header_field_info {
    /* ---------- set by dissector --------- */
    const char        *name;              /**< [FIELDNAME] full name of this field */
    const char        *abbrev;            /**< [FIELDABBREV] abbreviated name of this field */
    enum ftenum        type;              /**< [FIELDTYPE] field type, one of FT_ (from ftypes.h) */
    int                display;           /**< [FIELDDISPLAY] one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask */
    const void        *strings;           /**< [FIELDCONVERT] value_string, val64_string, range_string or true_false_string,
                                               typically converted by VALS(), RVALS() or TFS().
                                               If this is an FT_PROTOCOL or BASE_PROTOCOL_INFO then it points to the
                                               associated protocol_t structure */
    guint64            bitmask;           /**< [BITMASK] bitmask of interesting bits */
    const char        *blurb;             /**< [FIELDDESCR] Brief description of field */

    /* ------- set by proto routines (prefilled by HFILL macro, see below) ------ */
    int                id;                /**< Field ID */
    int                parent;            /**< parent protocol tree */
    hf_ref_type        ref_type;          /**< is this field referenced by a filter */
    int                same_name_prev_id; /**< ID of previous hfinfo with same abbrev */
    header_field_info *same_name_next;    /**< Link to next hfinfo with same abbrev */
};
  
   */


pub static PROTO_PLUGIN: OnceCell<&'static dyn ProtoPlugin> = OnceCell::new();
pub static mut PROTO_HANDLE: i32 = -1;
pub static mut DISSECTOR_HANDLE: Option<*mut bindings::dissector_handle> = None;
pub static mut PREFS_HANDLE: Option<*mut bindings::pref_module> = None;
pub unsafe fn plugin_register() {
    unsafe extern "C" fn register_protoinfo() {
        let plugin = *PROTO_PLUGIN.get().expect("Not Set");
        let proto = plugin.get_protocol_id();
        PROTO_HANDLE = bindings::proto_register_protocol(
            *cstr::new(proto.name),
            *cstr::new(proto.short_name),
            *cstr::new(proto.filter_name),
        );
        println!("test123");
          let field = Box::new(-1i32);
          let field = Box::into_raw(field);
          let test = bindings::hf_register_info{
               p_id:field,
               hfinfo: bindings::header_field_info {
                   name: *cstr::new("version"),
                   abbrev: *cstr::new("foton.version"),
                   r#type: bindings::ftenum_FT_STRING, 
                   display: bindings::field_display_e_BASE_NONE, 
                   strings: std::ptr::null(),// names.as_ptr() as *const std::ffi::c_void,
                   bitmask: 0,
                   blurb:  *cstr::new("foton version"),
                   id: -1,
                   parent: 0,
                   ref_type:bindings::hf_ref_type_HF_REF_TYPE_NONE,
                   same_name_prev_id:-1,
                   same_name_next:std::ptr::null_mut(),
           
               }
           };
           let test = Box::new(test);
           let test = Box::into_raw(test);
         //  let ptr:*mut bindings::hf_register_info = test as _;
        //   let test = Box::leak(test);
        bindings::proto_register_field_array(PROTO_HANDLE, test, 1 as i32);
     //   bindings::proto_register_subtree_array(ett.as_mut_ptr(), 1);

    //    PREFS_HANDLE = Some(bindings::prefs_register_protocol(PROTO_HANDLE, None));
    //    for pref in plugin.get_prefs() {
    //        pref.register(PREFS_HANDLE.unwrap());
    //    }
    }
    unsafe extern "C" fn register_handoff() {
        let plugin = *PROTO_PLUGIN.get().expect("Not Set");
        pub unsafe extern "C" fn dissector(
            tvb: *mut bindings::tvbuff_t,
            pinfo: *mut bindings::packet_info,
            proto_tree: *mut bindings::proto_tree,
            call_back: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int {
            let plugin = *PROTO_PLUGIN.get().expect("Not Set");
            plugin.dissect(&prefs::PREFS, tvb, pinfo, proto_tree, call_back)
        }
        DISSECTOR_HANDLE = Some(bindings::create_dissector_handle(
            Some(dissector),
            PROTO_HANDLE,
        ));
   //     for add in plugin.get_dissector_adds().iter() {
   //         add.register(DISSECTOR_HANDLE.unwrap());
   //     }
    }
    static _PROTO_PLUGIN: bindings::proto_plugin = bindings::proto_plugin {
        register_protoinfo: Some(register_protoinfo),
        register_handoff: Some(register_handoff),
    };
    bindings::proto_register_plugin(&_PROTO_PLUGIN);
}
