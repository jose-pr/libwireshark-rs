//! One protocol's registration with EPAN and the state it keeps for the
//! process: names, fields, subtree, expert entries, preferences, handle and
//! bindings.

use super::Callbacks;
use super::callbacks::{self, heuristic_pointer, trampoline};
use super::preferences::{Glib, Slot};
use super::protocol::{Erased, Implementation, Protocol};
use crate::dissector::{Binding, Target};
use crate::expert::Expert;
use crate::header::{Base, FieldInfo, FieldType};
use crate::packet::{Registered, RegisteredExpert, RegisteredField};
use crate::prefs::PreferenceMap;
use crate::sys;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// What a dissector callback reads, fixed once registration is done; boxed
/// so its address can be the callback's data.
pub(crate) struct Shared {
    pub(crate) registered: Registered,
    pub(crate) preferences: Mutex<Option<Arc<Erased>>>,
    /// The header length of messages framed over TCP, if framed.
    pub(crate) framing_header: Option<usize>,
    pub(crate) imp: &'static dyn Implementation,
    /// Whether [`Dissector::dissect_on`](crate::Dissector::dissect_on)
    /// currently asks for the post-dissector. Wireshark cannot remove a
    /// plugin's post-dissector, so turning it off is this flag.
    pub(crate) post_active: AtomicBool,
}

pub(crate) struct Runtime {
    spec: &'static Protocol,
    callbacks: Callbacks,
    shared: Box<Shared>,
    names: [CString; 3],
    _field_strings: Vec<CString>,
    _field_registrations: Vec<sys::hf_register_info>,
    _value_strings: Vec<Box<[sys::value_string]>>,
    _ett: Box<c_int>,
    _experts: Box<[sys::expert_field]>,
    _expert_registrations: Vec<sys::ei_register_info>,
    slots: Vec<Slot>,
    handle: Option<NonNull<sys::dissector_handle>>,
    /// The second handle a post-dissector runs through, created when needed.
    post_handle: Option<NonNull<sys::dissector_handle>>,
    attached: Vec<Binding>,
    /// Strings Wireshark may keep a pointer to after an entry is removed.
    retained: Vec<CString>,
}

// SAFETY: the raw pointers are Wireshark handles and registration storage
// reached only through `Plugin`'s mutex, from EPAN's registration and
// preference callbacks.
unsafe impl Send for Runtime {}

fn cstring(text: &str) -> CString {
    CString::new(text.replace('\0', "")).unwrap_or_default()
}

impl Runtime {
    /// Registers `spec`, or returns `None` when one of its names is taken:
    /// Wireshark aborts the process on a duplicate, so the protocol is left
    /// out instead.
    pub(crate) fn register(
        spec: &'static Protocol,
        callbacks: Callbacks,
        glib: Option<&Glib>,
    ) -> Option<Self> {
        let names = [
            cstring(spec.name),
            cstring(spec.short_name),
            cstring(spec.filter_name),
        ];
        if names_taken(&names) {
            eprintln!(
                "libwireshark: protocol {:?} ({}) not registered: Wireshark has one of its names",
                spec.name, spec.filter_name
            );
            return None;
        }
        // SAFETY: the names are retained by this runtime for the process.
        let proto = unsafe {
            sys::proto_register_protocol(names[0].as_ptr(), names[1].as_ptr(), names[2].as_ptr())
        };

        let infos = spec.imp.fields();
        let abbrevs = infos
            .iter()
            .map(|field| full_abbrev(spec.filter_name, field.abbrev()))
            .collect::<Vec<_>>();
        let mut ids = alloc::vec![-1 as c_int; infos.len()].into_boxed_slice();
        let mut strings = Vec::with_capacity(infos.len() * 3);
        let mut registrations = Vec::with_capacity(infos.len());
        let mut value_strings = Vec::new();
        for ((info, abbrev), id) in infos.iter().zip(&abbrevs).zip(ids.iter_mut()) {
            let [name, abbrev, blurb] = [info.name(), abbrev.as_str(), info.blurb()].map(cstring);
            let mut hfinfo = header_field_info(info, &name, &abbrev, &blurb);
            if let Some(values) = info.values()
                && info.kind().width().is_some_and(|width| width <= 4)
            {
                let table = value_string_table(values, &mut strings);
                hfinfo.strings = table.as_ptr().cast();
                value_strings.push(table);
            }
            registrations.push(sys::hf_register_info { p_id: id, hfinfo });
            strings.extend([name, abbrev, blurb]);
        }
        if !registrations.is_empty() {
            // SAFETY: the array, its strings and the id slots are retained by
            // this runtime for the process; Wireshark keeps pointers to them.
            unsafe {
                sys::proto_register_field_array(
                    proto,
                    registrations.as_mut_ptr(),
                    registrations.len() as c_int,
                );
            }
        }

        let mut ett = Box::new(-1 as c_int);
        let indices = [&mut *ett as *mut c_int];
        // SAFETY: Wireshark writes the subtree id through the pointer during the call.
        unsafe { sys::proto_register_subtree_array(indices.as_ptr(), 1) };

        // SAFETY: the filter name is retained for the process; Wireshark
        // keeps the pointer as the tap's name.
        let tap = unsafe { sys::register_tap(names[2].as_ptr()) };

        let (experts, expert_registrations, registered_experts) =
            register_experts(proto, spec.filter_name, spec.experts, &mut strings);

        // SAFETY: `proto` was just registered; `apply` is a static function.
        let module =
            unsafe { sys::prefs_register_protocol(proto, Some(trampoline(callbacks.apply))) };
        let slots = spec
            .imp
            .declarations()
            .into_iter()
            .filter_map(|declaration| Slot::register(module, declaration, glib))
            .collect();

        let fields = infos
            .iter()
            .zip(abbrevs)
            .zip(ids.iter())
            .map(|((info, abbrev), id)| RegisteredField {
                abbrev,
                id: *id,
                kind: info.kind(),
            })
            .collect();
        let shared = Box::new(Shared {
            registered: Registered {
                proto,
                ett: *ett,
                filter: spec.filter_name,
                short_name: names[1].clone(),
                fields,
                experts: registered_experts,
                conversations: Mutex::new(HashMap::new()),
                tap,
                tapped: Mutex::new((0, Vec::new())),
            },
            preferences: Mutex::new(None),
            framing_header: spec.imp.framing_header(),
            imp: spec.imp,
            post_active: AtomicBool::new(false),
        });
        let mut runtime = Self {
            spec,
            callbacks,
            shared,
            names,
            _field_strings: strings,
            _field_registrations: registrations,
            _value_strings: value_strings,
            _ett: ett,
            _experts: experts,
            _expert_registrations: expert_registrations,
            slots,
            handle: None,
            post_handle: None,
            attached: Vec::new(),
            retained: Vec::new(),
        };
        runtime.reload();
        Some(runtime)
    }

    pub(crate) fn reload(&mut self) {
        let values = self
            .slots
            .iter()
            .map(|slot| (slot.declaration.name(), slot.read()))
            .collect::<PreferenceMap>();
        let loaded = self.spec.imp.load(&values);
        let mut preferences = self
            .shared
            .preferences
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Values that do not convert keep the last good snapshot.
        if loaded.is_some() || preferences.is_none() {
            *preferences = loaded;
        }
    }

    pub(crate) fn handoff(&mut self) {
        if self.handle.is_none() {
            let data = core::ptr::from_ref(&*self.shared)
                .cast_mut()
                .cast::<c_void>();
            // SAFETY: the name is retained, and `data` points at the boxed
            // `Shared`, which lives for the process.
            let handle = unsafe {
                sys::register_dissector_with_data(
                    self.names[2].as_ptr(),
                    Some(callbacks::dissector),
                    self.shared.registered.proto,
                    data,
                )
            };
            self.handle = NonNull::new(handle);
        }
        self.attach();
    }

    /// This protocol's `Shared` when `name` is its short name: how a
    /// heuristic callback, which carries no data, finds its protocol.
    /// The registered protocol's display-filter name.
    pub(crate) fn filter_name(&self) -> &'static str {
        self.spec.filter_name
    }

    pub(crate) fn named(&self, name: *const c_char) -> Option<NonNull<Shared>> {
        if name.is_null() {
            return None;
        }
        // SAFETY: Wireshark sets `current_proto` to a protocol's short name.
        let name = unsafe { CStr::from_ptr(name) };
        (name == self.names[1].as_c_str()).then(|| NonNull::from(&*self.shared))
    }

    pub(crate) fn clear_conversations(&self) {
        self.shared
            .registered
            .conversations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Brings the bindings in line with [`Dissector::dissect_on`](crate::Dissector::dissect_on).
    pub(crate) fn attach(&mut self) {
        let Some(handle) = self.handle else {
            return;
        };
        let wanted = match &*self
            .shared
            .preferences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            Some(preferences) => self.spec.imp.dissect_on(&**preferences),
            None => Vec::new(),
        };
        let stale = self
            .attached
            .iter()
            .filter(|binding| !wanted.contains(binding))
            .copied()
            .collect::<Vec<_>>();
        for binding in stale {
            self.detach(handle, binding);
        }
        self.attached.retain(|binding| wanted.contains(binding));
        for binding in wanted {
            if !self.attached.contains(&binding) {
                self.add(handle, binding);
                self.attached.push(binding);
            }
        }
    }

    fn add(&mut self, handle: NonNull<sys::dissector_handle>, binding: Binding) {
        let proto = self.shared.registered.proto;
        match binding.0 {
            Target::Uint { table, value } => {
                let name = self.retain(table);
                // Wireshark aborts on an integer entry in a table keyed by
                // something else.
                if !integer_table(name) {
                    eprintln!(
                        "libwireshark: {}: {table:?} is not a dissector table keyed by integers",
                        self.spec.filter_name
                    );
                    return;
                }
                // SAFETY: `handle` is live and `name` is retained.
                unsafe { sys::dissector_add_uint(name, value, handle.as_ptr()) };
            }
            Target::Heuristic { list } => {
                let internal = self.retain(&alloc::format!("{}_{list}", self.spec.filter_name));
                let list = self.retain(list);
                let display = self.names[0].as_ptr();
                // SAFETY: the strings are retained for the process and
                // `heuristic` is the plugin's static callback.
                unsafe {
                    sys::heur_dissector_add(
                        list,
                        heuristic_pointer(self.callbacks.heuristic),
                        display,
                        internal,
                        proto,
                        sys::heuristic_enable_e_HEURISTIC_ENABLE,
                    );
                }
            }
            Target::Postdissector => {
                if self.post_handle.is_none()
                    && let Some(post) = self.post_handle()
                {
                    // SAFETY: `post` is live; registered once for the process.
                    unsafe { sys::register_postdissector(post.as_ptr()) };
                }
                self.shared.post_active.store(true, Ordering::Relaxed);
            }
        }
    }

    /// The post-dissector handle, registered as `<filter>_post` on first use.
    fn post_handle(&mut self) -> Option<NonNull<sys::dissector_handle>> {
        if self.post_handle.is_none() {
            let name = self.retain(&alloc::format!("{}_post", self.spec.filter_name));
            let data = core::ptr::from_ref(&*self.shared)
                .cast_mut()
                .cast::<c_void>();
            // SAFETY: as for the main handle in `handoff`.
            let handle = unsafe {
                sys::register_dissector_with_data(
                    name,
                    Some(callbacks::postdissector),
                    self.shared.registered.proto,
                    data,
                )
            };
            self.post_handle = NonNull::new(handle);
        }
        self.post_handle
    }

    fn detach(&mut self, handle: NonNull<sys::dissector_handle>, binding: Binding) {
        let proto = self.shared.registered.proto;
        match binding.0 {
            Target::Uint { table, value } => {
                let table = self.retain(table);
                // SAFETY: the entry was added on this live handle.
                unsafe { sys::dissector_delete_uint(table, value, handle.as_ptr()) };
            }
            Target::Heuristic { list } => {
                let list = self.retain(list);
                // SAFETY: the same list, callback and protocol it was added with.
                unsafe {
                    sys::heur_dissector_delete(
                        list,
                        heuristic_pointer(self.callbacks.heuristic),
                        proto,
                    )
                };
            }
            // `deregister_postdissector` is internal to libwireshark.
            Target::Postdissector => self.shared.post_active.store(false, Ordering::Relaxed),
        }
    }

    /// `text` as a C string kept for the process; Wireshark keeps pointers
    /// to table and list names.
    fn retain(&mut self, text: &str) -> *const c_char {
        if let Some(kept) = self
            .retained
            .iter()
            .find(|kept| kept.as_bytes() == text.as_bytes())
        {
            return kept.as_ptr();
        }
        self.retained.push(cstring(text));
        self.retained
            .last()
            .map_or(core::ptr::null(), |kept| kept.as_ptr())
    }
}

/// Whether Wireshark already has a protocol with one of `[name, short_name,
/// filter_name]`, or a preference module named like the filter.
/// Whether `name` is a dissector table keyed by an unsigned integer.
// bindgen types C enums as i32 on Windows and u32 elsewhere.
#[allow(clippy::unnecessary_cast)]
fn integer_table(name: *const c_char) -> bool {
    // SAFETY: `name` is NUL-terminated; these only look the table up.
    unsafe {
        if sys::find_dissector_table(name).is_null() {
            return false;
        }
        let kind = sys::get_dissector_table_selector_type(name) as u32;
        [
            sys::ftenum_FT_UINT8 as u32,
            sys::ftenum_FT_UINT16 as u32,
            sys::ftenum_FT_UINT24 as u32,
            sys::ftenum_FT_UINT32 as u32,
        ]
        .contains(&kind)
    }
}

fn names_taken([name, short_name, filter_name]: &[CString; 3]) -> bool {
    // SAFETY: the names are NUL-terminated; these only look names up.
    unsafe {
        callbacks::is_true(sys::proto_name_already_registered(name.as_ptr()))
            || sys::proto_get_id_by_short_name(short_name.as_ptr()) >= 0
            || sys::proto_get_id_by_filter_name(filter_name.as_ptr()) >= 0
            || !sys::prefs_find_module(filter_name.as_ptr()).is_null()
    }
}

/// Registers `experts` for `proto`; returns their storage, the registration
/// array (both kept for the process) and their lookup entries.
fn register_experts(
    proto: c_int,
    filter: &str,
    experts: &[Expert],
    strings: &mut Vec<CString>,
) -> (
    Box<[sys::expert_field]>,
    Vec<sys::ei_register_info>,
    Box<[RegisteredExpert]>,
) {
    let mut storage = experts
        .iter()
        .map(|_| sys::expert_field { ei: -1, hf: -1 })
        .collect::<Box<[_]>>();
    let mut registrations = Vec::with_capacity(experts.len());
    let mut registered = Vec::with_capacity(experts.len());
    for (expert, field) in experts.iter().zip(storage.iter_mut()) {
        let abbrev = full_abbrev(filter, expert.abbrev());
        let [name, summary] = [abbrev.as_str(), expert.summary()].map(cstring);
        // SAFETY: an all-zero ei_register_info is valid C (null pointers, zero
        // integers); the fields Wireshark reads are set below, as `EXPFILL` does.
        let mut registration: sys::ei_register_info = unsafe { core::mem::zeroed() };
        registration.ids = field;
        registration.eiinfo.name = name.as_ptr();
        registration.eiinfo.group = expert.group().bits() as _;
        registration.eiinfo.severity = expert.severity().bits() as _;
        registration.eiinfo.summary = summary.as_ptr();
        registration.eiinfo.hf_info.hfinfo.id = -1;
        registration.eiinfo.hf_info.hfinfo.same_name_prev_id = -1;
        registrations.push(registration);
        registered.push(RegisteredExpert {
            abbrev,
            field: NonNull::from(field),
        });
        strings.extend([name, summary]);
    }
    if !registrations.is_empty() {
        // SAFETY: `proto` is registered; the array, its strings and the
        // storage are retained by the runtime for the process.
        unsafe {
            let module = sys::expert_register_protocol(proto);
            sys::expert_register_field_array(
                module,
                registrations.as_mut_ptr(),
                registrations.len() as c_int,
            );
        }
    }
    (storage, registrations, registered.into_boxed_slice())
}

/// `values` as a C `value_string` array ending in `{0, NULL}`; the names
/// are kept in `strings`.
fn value_string_table(
    values: &[(u32, &str)],
    strings: &mut Vec<CString>,
) -> Box<[sys::value_string]> {
    let mut table = Vec::with_capacity(values.len() + 1);
    for (value, name) in values {
        let name = cstring(name);
        table.push(sys::value_string {
            value: *value,
            strptr: name.as_ptr(),
        });
        strings.push(name);
    }
    table.push(sys::value_string {
        value: 0,
        strptr: core::ptr::null(),
    });
    table.into_boxed_slice()
}

/// `abbrev` under the protocol's filter name unless it already is.
pub(crate) fn full_abbrev(filter: &str, abbrev: &str) -> String {
    let qualified = abbrev == filter
        || abbrev
            .strip_prefix(filter)
            .is_some_and(|rest| rest.starts_with('.'));
    if qualified {
        abbrev.to_string()
    } else {
        alloc::format!("{filter}.{abbrev}")
    }
}

fn header_field_info(
    info: &FieldInfo,
    name: &CStr,
    abbrev: &CStr,
    blurb: &CStr,
) -> sys::header_field_info {
    // SAFETY: an all-zero header_field_info is valid C (null pointers, zero
    // integers); every field Wireshark reads before registration is set below.
    let mut field: sys::header_field_info = unsafe { core::mem::zeroed() };
    field.name = name.as_ptr();
    field.abbrev = abbrev.as_ptr();
    field.type_ = field_type(info.kind()) as _;
    field.display = if info.kind().width().is_some() {
        base(info.base()) as _
    } else if info.kind() == FieldType::Bool && info.bitmask() != 0 {
        // A masked boolean's display is the width in bits of its byte.
        8
    } else {
        sys::field_display_e_BASE_NONE as _
    };
    field.bitmask = info.bitmask();
    field.blurb = if info.blurb().is_empty() {
        core::ptr::null()
    } else {
        blurb.as_ptr()
    };
    field.id = -1;
    field.same_name_prev_id = -1;
    field
}

// bindgen types C enums as i32 on Windows and u32 elsewhere.
#[allow(clippy::unnecessary_cast)]
fn field_type(kind: FieldType) -> u32 {
    (match kind {
        FieldType::U8 => sys::ftenum_FT_UINT8,
        FieldType::U16 => sys::ftenum_FT_UINT16,
        FieldType::U24 => sys::ftenum_FT_UINT24,
        FieldType::U32 => sys::ftenum_FT_UINT32,
        FieldType::U64 => sys::ftenum_FT_UINT64,
        FieldType::I8 => sys::ftenum_FT_INT8,
        FieldType::I16 => sys::ftenum_FT_INT16,
        FieldType::I24 => sys::ftenum_FT_INT24,
        FieldType::I32 => sys::ftenum_FT_INT32,
        FieldType::I64 => sys::ftenum_FT_INT64,
        FieldType::Bool => sys::ftenum_FT_BOOLEAN,
        FieldType::Bytes => sys::ftenum_FT_BYTES,
        FieldType::String => sys::ftenum_FT_STRING,
        FieldType::Ipv4 => sys::ftenum_FT_IPv4,
        FieldType::Ipv6 => sys::ftenum_FT_IPv6,
        FieldType::Ether => sys::ftenum_FT_ETHER,
        FieldType::None => sys::ftenum_FT_NONE,
    }) as u32
}

// bindgen types C enums as i32 on Windows and u32 elsewhere.
#[allow(clippy::unnecessary_cast)]
fn base(base: Base) -> u32 {
    (match base {
        Base::None => sys::field_display_e_BASE_NONE,
        Base::Dec => sys::field_display_e_BASE_DEC,
        Base::Hex => sys::field_display_e_BASE_HEX,
        Base::Oct => sys::field_display_e_BASE_OCT,
        Base::DecHex => sys::field_display_e_BASE_DEC_HEX,
        Base::HexDec => sys::field_display_e_BASE_HEX_DEC,
    }) as u32
}

#[cfg(test)]
mod tests {
    use super::{full_abbrev, value_string_table};

    #[test]
    fn abbreviations_are_placed_under_the_protocol_once() {
        assert_eq!(full_abbrev("foo", "version"), "foo.version");
        assert_eq!(full_abbrev("foo", "foo.version"), "foo.version");
        assert_eq!(full_abbrev("foo", "flags.syn"), "foo.flags.syn");
        assert_eq!(full_abbrev("foo", "foobar"), "foo.foobar");
        assert_eq!(full_abbrev("foo", "foo"), "foo");
    }

    #[test]
    fn a_value_string_table_ends_with_wiresharks_terminator() {
        let mut strings = Vec::new();
        let table = value_string_table(&[(1, "hello"), (2, "data")], &mut strings);
        assert_eq!(table.len(), 3);
        assert_eq!(table[1].value, 2);
        assert!(table[2].strptr.is_null(), "the last entry is {{0, NULL}}");
        // SAFETY: the names are kept in `strings`, alive for this test.
        let name = unsafe { core::ffi::CStr::from_ptr(table[0].strptr) };
        assert_eq!(name.to_str(), Ok("hello"));
        assert_eq!(strings.len(), 2);
    }
}
