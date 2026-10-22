#![allow(unused_variables)]
extern crate self as libwireshark;

#[cfg(feature = "macros")]
pub use libwireshark_macros::wireshark_plugin;

pub use libwireshark_sys as bindings;
pub mod dissector;
pub mod utils;
pub use dissector::{DissectResult, DissectorAdd, PacketFieldError, PacketView};
pub mod header;
pub use header::{Header, HeaderFieldInfo, NoHeader};
pub mod prefs;
#[cfg(feature = "macros")]
pub use libwireshark_macros::{Header, Preferences};
use once_cell::sync::OnceCell;
use prefs::ModulePref;
pub use prefs::{NoPreferences, PreferenceError, PreferenceMap, PreferenceValue, Preferences};
use std::ffi::CString;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

type ProtocolDissector = fn(&PreferenceMap, PacketView<'_>) -> std::os::raw::c_int;
type DissectorContext = (
    ProtocolDissector,
    PreferenceMap,
    std::collections::HashMap<&'static str, (i32, i32)>,
);

pub struct Protocol {
    pub name: &'static str,
    pub short_name: &'static str,
    pub filter_name: &'static str,
    pub prefs: Vec<ModulePref>,
    pub dissect_on: &'static [DissectorAdd],
    /// Recomputes table bindings after Wireshark applies protocol preferences.
    pub resolve_dissector_tables:
        Option<fn(&PreferenceMap) -> Result<Vec<DissectorAdd>, prefs::PreferenceError>>,
    pub header_fields: &'static [header::HeaderFieldInfo],
    pub dissect: fn(prefs: &PreferenceMap, packet: PacketView<'_>) -> std::os::raw::c_int,
}

/// Metadata that applies to the shared plugin library rather than one protocol.
#[derive(Clone, Copy, Debug, Default)]
pub struct PluginOptions {
    /// Version string exported to Wireshark. `None` uses the Cargo package version.
    pub version: Option<&'static str>,
}

/// A statically declared protocol factory owned by a plugin.
#[derive(Clone, Copy)]
pub struct ProtocolRegistration {
    build: fn() -> Protocol,
}

impl ProtocolRegistration {
    /// Registers a protocol described by a [`Dissector`] implementation.
    pub const fn dissector<D: Dissector>() -> Self {
        Self { build: D::protocol }
    }

    /// Registers a protocol produced by a custom builder function.
    pub const fn custom(build: fn() -> Protocol) -> Self {
        Self { build }
    }

    fn build_protocol(self) -> Protocol {
        (self.build)()
    }
}

/// A Wireshark plugin library, which may register multiple protocols.
///
/// Each protocol may expose one or more table attachments through its
/// [`Dissector::DISSECT_ON`] declaration.
pub trait WiresharkPlugin: 'static {
    /// Plugin-wide metadata. Protocol preferences belong to each protocol.
    const OPTIONS: PluginOptions = PluginOptions { version: None };

    /// Lists the protocols registered by this plugin library.
    fn protocols() -> &'static [ProtocolRegistration];
}

/// Describes a Rust dissector and adapts it to Wireshark's protocol descriptor.
///
/// Implementations use an associated [`prefs::Preferences`] type so the
/// callback receives a checked, typed snapshot of Wireshark's live settings.
pub trait Dissector: Sized + 'static {
    /// The typed preferences used by this dissector.
    type Preferences: prefs::Preferences;
    /// The struct that describes this protocol's registered filter fields.
    type Header: header::Header;

    /// Long protocol name shown by Wireshark.
    const NAME: &'static str;
    /// Short protocol name shown in packet lists.
    const SHORT_NAME: &'static str;
    /// Display-filter abbreviation.
    const FILTER_NAME: &'static str;
    /// Static dissector-table registrations for protocols with fixed bindings.
    const DISSECT_ON: &'static [DissectorAdd] = &[];
    /// Enables recalculating bindings in `dissect_on` after preferences change.
    const PREFERENCE_DRIVEN_DISSECT_ON: bool = false;

    /// Decodes a packet using the current preference snapshot.
    ///
    /// Return `None` when the packet does not match this protocol. The runtime
    /// applies a successful result's header, Info text, and consumed size.
    /// Mutate `packet` directly only for protocol-tree items that are not
    /// represented by the associated header.
    fn dissect(
        preferences: &Self::Preferences,
        packet: &mut PacketView<'_>,
    ) -> Option<DissectResult<Self::Header>>;

    /// Computes table attachments from the current preferences.
    ///
    /// Wireshark calls the preferences apply callback after settings change.
    /// Fixed bindings can use [`Self::DISSECT_ON`].
    fn dissect_on(preferences: &Self::Preferences) -> Vec<DissectorAdd> {
        let _ = preferences;
        Self::DISSECT_ON.to_vec()
    }

    /// Produces the descriptor consumed by the runtime registration layer.
    fn protocol() -> Protocol {
        Protocol {
            name: Self::NAME,
            short_name: Self::SHORT_NAME,
            filter_name: Self::FILTER_NAME,
            prefs: Self::Preferences::module_preferences(),
            dissect_on: Self::DISSECT_ON,
            resolve_dissector_tables: if Self::PREFERENCE_DRIVEN_DISSECT_ON {
                Some(resolve_dissector_tables::<Self>)
            } else {
                None
            },
            header_fields: Self::Header::fields(),
            dissect: dispatch::<Self>,
        }
    }
}

fn resolve_dissector_tables<D: Dissector>(
    values: &PreferenceMap,
) -> Result<Vec<DissectorAdd>, prefs::PreferenceError> {
    let preferences = D::Preferences::from_values(values)?;
    Ok(D::dissect_on(&preferences))
}

fn dispatch<D: Dissector>(values: &PreferenceMap, packet: PacketView<'_>) -> std::os::raw::c_int {
    match D::Preferences::from_values(values) {
        Ok(preferences) => {
            let mut packet = packet;
            let Some(result) = D::dissect(&preferences, &mut packet) else {
                return 0;
            };
            let _ = packet.add_header(&result.header);
            if let Some(info) = result.info {
                let _ = packet.add_info(&info);
            }
            std::os::raw::c_int::try_from(result.size).unwrap_or(std::os::raw::c_int::MAX)
        }
        Err(_) => 0,
    }
}

pub struct ProtocolPlugin {
    name: CString,
    short_name: CString,
    filter_name: CString,
    header_fields: Vec<(Box<i32>, header::HeaderFieldInfo)>,
    registered_header_fields: Vec<bindings::hf_register_info>,
    header_field_strings: Vec<CString>,
    preferences: Vec<prefs::Value<ModulePref>>,
    dissector: ProtocolDissector,
    dissect_on: Vec<DissectorAdd>,
    resolve_dissector_tables:
        Option<fn(&PreferenceMap) -> Result<Vec<DissectorAdd>, prefs::PreferenceError>>,
    active_dissector_tables: Vec<DissectorAdd>,
    proto_handle: i32,
    dissector_handle: Option<*mut bindings::dissector_handle>,
    prefs_handle: Option<*mut bindings::pref_module>,
    callback_context: Box<usize>,
}

impl ProtocolPlugin {
    pub fn new(proto: Protocol) -> Self {
        Self::with_index(proto, 0)
    }

    fn with_index(proto: Protocol, protocol_index: usize) -> Self {
        Self {
            name: CString::new(proto.name).unwrap(),
            short_name: CString::new(proto.short_name).unwrap(),
            filter_name: CString::new(proto.filter_name).unwrap(),
            dissect_on: proto.dissect_on.to_vec(),
            resolve_dissector_tables: proto.resolve_dissector_tables,
            active_dissector_tables: Vec::new(),
            preferences: proto.prefs.iter().cloned().map(prefs::Value::new).collect(),
            header_fields: proto
                .header_fields
                .iter()
                .cloned()
                .map(|f| (Box::new(-1i32), f))
                .collect(),
            registered_header_fields: Vec::new(),
            header_field_strings: Vec::new(),
            dissector: proto.dissect,
            proto_handle: -1i32,
            prefs_handle: None,
            dissector_handle: None,
            callback_context: Box::new(protocol_index),
        }
    }
    fn dissector_and_preferences(&self) -> DissectorContext {
        let prefs = self.current_preferences();
        let fields = self
            .header_fields
            .iter()
            .map(|(id, field)| (field.abbrev, (**id, field.type_)))
            .collect();
        (self.dissector, prefs, fields)
    }

    fn current_preferences(&self) -> PreferenceMap {
        self.preferences
            .iter()
            .fold(PreferenceMap::new(), |mut values, preference| {
                values.insert(preference.info.name, preference.get_current_value());
                values
            })
    }

    fn register_handoff(&mut self) {
        if self.dissector_handle.is_none() {
            let callback_data = (&mut *self.callback_context as *mut usize).cast();
            // SAFETY: The protocol handle, callback, callback data, and name are retained for the plugin lifetime.
            unsafe {
                self.dissector_handle = Some(bindings::register_dissector_with_data(
                    self.filter_name.as_ptr(),
                    Some(dissector),
                    self.proto_handle,
                    callback_data,
                ));
            }
        }
        let values = self.current_preferences();
        let bindings = match self.resolve_dissector_tables {
            Some(resolve) => match resolve(&values) {
                Ok(bindings) => bindings,
                Err(_) => return,
            },
            None => self.dissect_on.clone(),
        };
        if bindings == self.active_dissector_tables {
            return;
        }
        let handle = self
            .dissector_handle
            .expect("dissector handle is initialized");
        for previous in &self.active_dissector_tables {
            // SAFETY: The old mapping was registered on this live handle.
            unsafe { previous.unregister(handle) };
        }
        for add in &bindings {
            // SAFETY: `handle` is the live handle retained for this protocol.
            unsafe { add.register(handle) };
        }
        self.active_dissector_tables = bindings;
    }
    fn register_protoinfo(&mut self) {
        // SAFETY: Protocol and preference registration use live handles returned by Wireshark.
        unsafe {
            self.proto_handle = bindings::proto_register_protocol(
                self.name.as_ptr(),
                self.short_name.as_ptr(),
                self.filter_name.as_ptr(),
            );
            self.prefs_handle = Some(bindings::prefs_register_protocol(
                self.proto_handle,
                self.resolve_dissector_tables
                    .map(|_| preferences_changed as unsafe extern "C" fn()),
            ));
        }
        // SAFETY: `proto_handle` was returned by `proto_register_protocol` above.
        let (fields, strings) =
            unsafe { header::register_fields(self.proto_handle, &mut self.header_fields) };
        self.registered_header_fields = fields;
        self.header_field_strings = strings;

        for pref in &mut self.preferences {
            // SAFETY: `prefs_handle` was returned by Wireshark for this registered protocol.
            unsafe { pref.register(self.prefs_handle.unwrap()) };
        }
    }
}

struct PluginState(Vec<ProtocolPlugin>);

// The plugin state is stored only in PROTO_PLUGIN and all access is made while
// holding its mutex. Retained opaque handles are passed to EPAN only from
// those serialized callbacks.
// SAFETY: Plugin state is accessed only while holding its global mutex; EPAN callbacks are serialized.
unsafe impl Send for PluginState {}

static PROTO_PLUGIN: OnceCell<Mutex<PluginState>> = OnceCell::new();

unsafe extern "C" fn dissector(
    tvb: *mut bindings::tvbuff_t,
    pinfo: *mut bindings::packet_info,
    proto_tree: *mut bindings::proto_tree,
    _call_data: *mut std::os::raw::c_void,
    callback_data: *mut std::os::raw::c_void,
) -> std::os::raw::c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(callback_data) = std::ptr::NonNull::new(callback_data.cast::<usize>()) else {
            return 0;
        };
        // SAFETY: The callback data points to the boxed protocol index retained by PluginState.
        let protocol_index = unsafe { *callback_data.as_ref() };
        let Some(plugin) = PROTO_PLUGIN.get() else {
            return 0;
        };
        let context = {
            let plugin = plugin
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(protocol) = plugin.0.get(protocol_index) else {
                return 0;
            };
            protocol.dissector_and_preferences()
        };
        let (dissector, prefs, fields) = context;
        let Some(packet) =
            // SAFETY: Wireshark owns these callback arguments and keeps them valid until the dissector returns.
            (unsafe { PacketView::from_raw(tvb, pinfo, proto_tree, fields) })
        else {
            return 0;
        };
        dissector(&prefs, packet)
    }))
    .unwrap_or(0)
}

unsafe extern "C" fn preferences_changed() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(plugin) = PROTO_PLUGIN.get() {
            let mut plugin = plugin
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for protocol in &mut plugin.0 {
                protocol.register_handoff();
            }
        }
    }));
}

#[doc(hidden)]
pub fn __initialize_plugin<P: WiresharkPlugin>() -> bool {
    let protocols = P::protocols()
        .iter()
        .copied()
        .map(|registration| registration.build_protocol())
        .enumerate()
        .map(|(index, protocol)| ProtocolPlugin::with_index(protocol, index))
        .collect();
    PROTO_PLUGIN.set(Mutex::new(PluginState(protocols))).is_ok()
}

#[doc(hidden)]
pub fn __initialize_protocol(protocol: Protocol) -> bool {
    PROTO_PLUGIN
        .set(Mutex::new(PluginState(vec![ProtocolPlugin::new(protocol)])))
        .is_ok()
}

/// Registers this plugin's protocol and handoff callbacks with Wireshark.
///
/// # Safety
/// Call only from the plugin entry point while Wireshark is loading this plugin.
pub unsafe fn plugin_register() {
    unsafe extern "C" fn register_protoinfo() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Some(plugin) = PROTO_PLUGIN.get() {
                let mut plugin = plugin
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for protocol in &mut plugin.0 {
                    protocol.register_protoinfo();
                }
            }
        }));
    }
    unsafe extern "C" fn register_handoff() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Some(plugin) = PROTO_PLUGIN.get() {
                let mut plugin = plugin
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for protocol in &mut plugin.0 {
                    protocol.register_handoff();
                }
            }
        }));
    }
    static PLUGIN: bindings::proto_plugin = bindings::proto_plugin {
        register_protoinfo: Some(register_protoinfo),
        register_handoff: Some(register_handoff),
    };
    // SAFETY: `PLUGIN` and its callback functions have static lifetime for Wireshark's registration.
    unsafe { bindings::proto_register_plugin(&PLUGIN) };
}
