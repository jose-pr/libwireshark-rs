//! What [`plugin!`](crate::plugin) expands to call: the plugin's state,
//! registration with EPAN, and the C callbacks that reach the dissectors.
//!
//! Everything here is `#[doc(hidden)]`; a plugin names only the macro.

use crate::dissector::{Binding, Dissector};
use crate::header::{Base, FieldInfo, FieldType, Header};
use crate::packet::{PacketView, Registered, RegisteredField};
use crate::prefs::{Declaration, PreferenceMap, Preferences, Value};
use crate::sys;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::any::Any;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::panic::AssertUnwindSafe;
use core::ptr::NonNull;
use std::panic::catch_unwind;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// For derive expansions, which cannot assume `extern crate alloc`.
pub use alloc::vec::Vec;

/// `plugin_describe`'s answer: this library holds dissectors.
pub const DESCRIBE_DISSECTOR: u32 = 1;

/// The release line the plugin is built for, checked by Wireshark's loader.
pub const WANT_MAJOR: c_int = sys::VERSION_MAJOR as c_int;
/// See [`WANT_MAJOR`].
pub const WANT_MINOR: c_int = sys::VERSION_MINOR as c_int;

/// `version` followed by a NUL, for the `plugin_version` export.
///
/// # Panics
///
/// At compile time, when `N` is not `version.len() + 1`.
pub const fn nul_terminated<const N: usize>(version: &str) -> [u8; N] {
    let source = version.as_bytes();
    assert!(source.len() + 1 == N, "N is the version's length plus one");
    let mut bytes = [0u8; N];
    let mut index = 0;
    while index < source.len() {
        bytes[index] = source[index];
        index += 1;
    }
    bytes
}

/// The registration table `plugin_register` hands to Wireshark.
pub const fn proto_plugin(
    register_protoinfo: extern "C" fn(),
    register_handoff: extern "C" fn(),
) -> sys::proto_plugin {
    sys::proto_plugin {
        register_protoinfo: Some(register_protoinfo),
        register_handoff: Some(register_handoff),
    }
}

/// Registers the plugin's table with Wireshark.
pub fn register(plugin: &'static sys::proto_plugin) {
    // SAFETY: the table and its callbacks are statics of the plugin library.
    unsafe { sys::proto_register_plugin(plugin) };
}

type Erased = dyn Any + Send + Sync;

/// One protocol of a plugin, as the type-erased functions of its [`Dissector`].
#[derive(Debug)]
pub struct Protocol {
    name: &'static str,
    short_name: &'static str,
    filter_name: &'static str,
    declarations: fn() -> Vec<Declaration>,
    fields: fn() -> &'static [FieldInfo],
    load: fn(&PreferenceMap) -> Option<Arc<Erased>>,
    dissect_on: fn(&Erased) -> Vec<Binding>,
    dissect: fn(&Erased, &mut PacketView<'_>) -> Option<usize>,
}

impl Protocol {
    /// The protocol `D` describes.
    pub const fn of<D: Dissector>() -> Self {
        Self {
            name: D::NAME,
            short_name: D::SHORT_NAME,
            filter_name: D::FILTER_NAME,
            declarations: <D::Preferences as Preferences>::declarations,
            fields: <D::Header as Header>::fields,
            load: load::<D>,
            dissect_on: dissect_on::<D>,
            dissect: dissect::<D>,
        }
    }
}

fn load<D: Dissector>(values: &PreferenceMap) -> Option<Arc<Erased>> {
    let preferences = D::Preferences::from_values(values).ok()?;
    Some(Arc::new(preferences))
}

fn dissect_on<D: Dissector>(preferences: &Erased) -> Vec<Binding> {
    preferences
        .downcast_ref::<D::Preferences>()
        .map(D::dissect_on)
        .unwrap_or_default()
}

fn dissect<D: Dissector>(preferences: &Erased, packet: &mut PacketView<'_>) -> Option<usize> {
    let preferences = preferences.downcast_ref::<D::Preferences>()?;
    let result = D::dissect(preferences, packet)?;
    packet.accept(result.size);
    // A field that cannot be added (no tree, a short capture) leaves the
    // rest of the dissection standing, as Wireshark's own dissectors do.
    let _ = packet.add_header(&result.header);
    if let Some(info) = &result.info {
        packet.set_info(info);
    }
    Some(result.size)
}

/// A plugin's protocols and their registration state.
pub struct Plugin {
    protocols: &'static [Protocol],
    state: Mutex<Vec<Runtime>>,
}

impl core::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plugin")
            .field("protocols", &self.protocols)
            .finish_non_exhaustive()
    }
}

impl Plugin {
    /// A plugin of `protocols`, registered when Wireshark loads it.
    pub const fn new(protocols: &'static [Protocol]) -> Self {
        Self {
            protocols,
            state: Mutex::new(Vec::new()),
        }
    }

    fn state(&self) -> MutexGuard<'_, Vec<Runtime>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wireshark's `register_protoinfo`: protocols, fields and preferences.
    /// `apply` is the plugin's preferences callback.
    pub fn register_protoinfo(&'static self, apply: extern "C" fn()) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let glib = Glib::load();
            let mut state = self.state();
            if !state.is_empty() {
                return;
            }
            for spec in self.protocols {
                state.push(Runtime::register(spec, apply, glib.as_ref()));
            }
            // Wireshark frees `g_strdup`'d preference defaults through GLib,
            // so the library stays loaded for the process.
            core::mem::forget(glib);
        }));
    }

    /// Wireshark's `register_handoff`: dissector handles and table entries.
    pub fn register_handoff(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            for runtime in self.state().iter_mut() {
                runtime.handoff();
            }
        }));
    }

    /// The preferences callback: reloads every protocol's typed preferences
    /// and re-evaluates its table entries.
    pub fn apply_preferences(&'static self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            for runtime in self.state().iter_mut() {
                runtime.reload();
                runtime.attach();
            }
        }));
    }
}

/// What a dissector callback reads, fixed once fields are registered; boxed
/// so its address can be the callback's data.
struct Shared {
    registered: Registered,
    preferences: Mutex<Option<Arc<Erased>>>,
    dissect: fn(&Erased, &mut PacketView<'_>) -> Option<usize>,
}

struct Runtime {
    spec: &'static Protocol,
    shared: Box<Shared>,
    _names: [CString; 3],
    _field_strings: Vec<CString>,
    _field_registrations: Vec<sys::hf_register_info>,
    _ett: Box<c_int>,
    slots: Vec<Slot>,
    handle: Option<NonNull<sys::dissector_handle>>,
    attached: Vec<(Binding, CString)>,
}

// SAFETY: the raw pointers are Wireshark handles and registration storage
// reached only through `Plugin`'s mutex, from EPAN's registration and
// preference callbacks.
unsafe impl Send for Runtime {}

impl Runtime {
    fn register(spec: &'static Protocol, apply: extern "C" fn(), glib: Option<&Glib>) -> Self {
        let cstring = |text: &str| CString::new(text.replace('\0', "")).unwrap_or_default();
        let names = [
            cstring(spec.name),
            cstring(spec.short_name),
            cstring(spec.filter_name),
        ];
        // SAFETY: the names are retained by this runtime for the process.
        let proto = unsafe {
            sys::proto_register_protocol(names[0].as_ptr(), names[1].as_ptr(), names[2].as_ptr())
        };

        let infos = (spec.fields)();
        let abbrevs = infos
            .iter()
            .map(|field| full_abbrev(spec.filter_name, field.abbrev()))
            .collect::<Vec<_>>();
        let mut ids = alloc::vec![-1 as c_int; infos.len()].into_boxed_slice();
        let mut strings = Vec::with_capacity(infos.len() * 3);
        let mut registrations = Vec::with_capacity(infos.len());
        for ((info, abbrev), id) in infos.iter().zip(&abbrevs).zip(ids.iter_mut()) {
            let [name, abbrev, blurb] = [info.name(), abbrev.as_str(), info.blurb()].map(cstring);
            registrations.push(sys::hf_register_info {
                p_id: id,
                hfinfo: header_field_info(info, &name, &abbrev, &blurb),
            });
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

        // SAFETY: `proto` was just registered; `apply` is a static function.
        let module = unsafe { sys::prefs_register_protocol(proto, Some(apply_trampoline(apply))) };
        let slots = (spec.declarations)()
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
            },
            preferences: Mutex::new(None),
            dissect: spec.dissect,
        });
        let mut runtime = Self {
            spec,
            shared,
            _names: names,
            _field_strings: strings,
            _field_registrations: registrations,
            _ett: ett,
            slots,
            handle: None,
            attached: Vec::new(),
        };
        runtime.reload();
        runtime
    }

    fn reload(&mut self) {
        let values = self
            .slots
            .iter()
            .map(|slot| (slot.declaration.name(), slot.read()))
            .collect::<PreferenceMap>();
        let loaded = (self.spec.load)(&values);
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

    fn handoff(&mut self) {
        if self.handle.is_none() {
            let data = (&*self.shared as *const Shared).cast_mut().cast::<c_void>();
            // SAFETY: the name is retained, and `data` points at the boxed
            // `Shared`, which lives for the process.
            let handle = unsafe {
                sys::register_dissector_with_data(
                    self._names[2].as_ptr(),
                    Some(dissector_callback),
                    self.shared.registered.proto,
                    data,
                )
            };
            self.handle = NonNull::new(handle);
        }
        self.attach();
    }

    /// Brings the table entries in line with [`Dissector::dissect_on`].
    fn attach(&mut self) {
        let Some(handle) = self.handle else {
            return;
        };
        let wanted = match &*self
            .shared
            .preferences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            Some(preferences) => (self.spec.dissect_on)(&**preferences),
            None => Vec::new(),
        };
        self.attached.retain(|(binding, table)| {
            let keep = wanted.contains(binding);
            if !keep {
                // SAFETY: the entry was added on this live handle.
                unsafe {
                    sys::dissector_delete_uint(table.as_ptr(), binding.value(), handle.as_ptr())
                };
            }
            keep
        });
        for binding in wanted {
            if self
                .attached
                .iter()
                .any(|(attached, _)| *attached == binding)
            {
                continue;
            }
            let Ok(table) = CString::new(binding.table()) else {
                continue;
            };
            // SAFETY: `handle` is live and `table` is retained while attached.
            unsafe { sys::dissector_add_uint(table.as_ptr(), binding.value(), handle.as_ptr()) };
            self.attached.push((binding, table));
        }
    }
}

/// `abbrev` under the protocol's filter name unless it already is.
fn full_abbrev(filter: &str, abbrev: &str) -> String {
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

/// `extern "C" fn()` as the `unsafe extern "C" fn()` the C API declares.
fn apply_trampoline(apply: extern "C" fn()) -> unsafe extern "C" fn() {
    apply
}

unsafe extern "C" fn dissector_callback(
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
    _data: *mut c_void,
    callback_data: *mut c_void,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let shared = NonNull::new(callback_data.cast::<Shared>())?;
        // SAFETY: the callback data is the boxed `Shared` registered with
        // this handle, which lives for the process.
        let shared = unsafe { shared.as_ref() };
        let preferences = shared
            .preferences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()?;
        // SAFETY: these are the arguments of the running dissector callback.
        let mut packet = unsafe { PacketView::from_raw(tvb, pinfo, tree, &shared.registered) }?;
        let size = (shared.dissect)(&*preferences, &mut packet)?;
        Some(c_int::try_from(size).unwrap_or(c_int::MAX))
    }))
    .ok()
    .flatten()
    .unwrap_or(0)
}

/// One registered preference and the storage Wireshark writes it to.
struct Slot {
    declaration: Declaration,
    storage: Storage,
}

enum Storage {
    /// Reads the flag, whose C type is `gboolean` before 4.0 and `bool` after.
    Bool(Box<dyn Fn() -> bool + Send>),
    Uint(NonNull<u32>),
    String(NonNull<*const c_char>),
}

/// The C type of a boolean preference slot.
trait Flag: Copy + PartialEq + 'static {
    const FALSE: Self;
    const TRUE: Self;
}

impl Flag for bool {
    const FALSE: Self = false;
    const TRUE: Self = true;
}

impl Flag for c_int {
    const FALSE: Self = 0;
    const TRUE: Self = 1;
}

/// A leaked slot pointer the reader closure may carry across threads.
struct FlagSlot<T>(NonNull<T>);

// SAFETY: the slot is leaked and only read, from callbacks the plugin's
// mutex serialises.
unsafe impl<T> Send for FlagSlot<T> {}

impl<T: Copy> FlagSlot<T> {
    fn read(&self) -> T {
        // SAFETY: the leaked slot stays valid; Wireshark writes it only from
        // the thread that runs the preference callbacks.
        unsafe { *self.0.as_ptr() }
    }
}

type RegisterBool<T> =
    unsafe extern "C" fn(*mut sys::module_t, *const c_char, *const c_char, *const c_char, *mut T);

/// Registers a boolean preference with the slot type `register` declares.
///
/// # Safety
///
/// `module` is a live preference module and the strings live for the process.
unsafe fn register_bool<T: Flag>(
    register: RegisterBool<T>,
    module: *mut sys::module_t,
    [name, title, description]: [*const c_char; 3],
    default: bool,
) -> Box<dyn Fn() -> bool + Send> {
    let slot = NonNull::from(Box::leak(Box::new(if default {
        T::TRUE
    } else {
        T::FALSE
    })));
    // SAFETY: the caller's contract; the slot is leaked so it outlives the module.
    unsafe { register(module, name, title, description, slot.as_ptr()) };
    let slot = FlagSlot(slot);
    Box::new(move || slot.read() != T::FALSE)
}

impl Slot {
    fn register(
        module: *mut sys::module_t,
        declaration: Declaration,
        glib: Option<&Glib>,
    ) -> Option<Self> {
        let cstring = |text: &str| CString::new(text.replace('\0', "")).unwrap_or_default();
        // Wireshark keeps these pointers in the module for the process.
        let name = cstring(declaration.name()).into_raw();
        let title = cstring(declaration.title()).into_raw();
        let description = cstring(declaration.description()).into_raw();
        let storage = match declaration.default_value() {
            // SAFETY: `module` is live and the strings are leaked.
            Value::Bool(default) => Storage::Bool(unsafe {
                register_bool(
                    sys::prefs_register_bool_preference,
                    module,
                    [name, title, description].map(<*mut c_char>::cast_const),
                    *default,
                )
            }),
            Value::Uint(default) => {
                let slot = NonNull::from(Box::leak(Box::new(*default)));
                // SAFETY: as above.
                unsafe {
                    sys::prefs_register_uint_preference(
                        module,
                        name,
                        title,
                        description,
                        declaration.base(),
                        slot.as_ptr(),
                    );
                }
                Storage::Uint(slot)
            }
            Value::String(default) => {
                let glib = glib?;
                let default = glib.strdup(&cstring(default));
                let slot = NonNull::from(Box::leak(Box::new(default.cast_const())));
                // SAFETY: as above; Wireshark replaces and frees the string
                // through GLib, which allocated it.
                unsafe {
                    sys::prefs_register_string_preference(
                        module,
                        name,
                        title,
                        description,
                        slot.as_ptr(),
                    )
                };
                Storage::String(slot)
            }
        };
        Some(Self {
            declaration,
            storage,
        })
    }

    fn read(&self) -> Value {
        // SAFETY: the slots are leaked, so they stay valid; Wireshark writes
        // them only from the main thread, which also runs these callbacks.
        unsafe {
            match self.storage {
                Storage::Bool(ref read) => Value::Bool(read()),
                Storage::Uint(slot) => Value::Uint(*slot.as_ptr()),
                Storage::String(slot) => {
                    let text = *slot.as_ptr();
                    Value::String(if text.is_null() {
                        String::new()
                    } else {
                        CStr::from_ptr(text).to_string_lossy().into_owned()
                    })
                }
            }
        }
    }
}

/// GLib's allocator, which Wireshark uses for string preferences. Resolved
/// at run time so a plugin needs no GLib import library.
struct Glib {
    library: libloading::Library,
}

impl Glib {
    fn load() -> Option<Self> {
        #[cfg(target_os = "windows")]
        const NAME: &str = "glib-2.0-0.dll";
        #[cfg(target_os = "macos")]
        const NAME: &str = "libglib-2.0.0.dylib";
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        const NAME: &str = "libglib-2.0.so.0";
        // SAFETY: Wireshark has already loaded this library; loading it again
        // runs no initialiser and returns the same module.
        let library = unsafe { libloading::Library::new(NAME) }.ok()?;
        Some(Self { library })
    }

    fn strdup(&self, text: &CStr) -> *mut c_char {
        // SAFETY: `g_strdup` has this signature in every GLib 2 release.
        let Ok(strdup) = (unsafe {
            self.library
                .get::<unsafe extern "C" fn(*const c_char) -> *mut c_char>(b"g_strdup\0")
        }) else {
            return core::ptr::null_mut();
        };
        // SAFETY: `text` is NUL-terminated and live for the call.
        unsafe { strdup(text.as_ptr()) }
    }
}

impl core::fmt::Debug for Glib {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Glib")
    }
}
