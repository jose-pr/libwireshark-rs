//! A plugin's [`Tap`]s: their `-z` entries, listeners and callbacks.

use super::Plugin;
use crate::dynamic::{self, DynamicTap, TapFactory};
use crate::sys;
use crate::tap::{Tap, TapPacket};
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use core::any::Any;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::panic::AssertUnwindSafe;
use core::ptr::NonNull;
use std::io::Write;
use std::panic::catch_unwind;
use std::sync::{Mutex, PoisonError};

/// One [`Tap`] of a plugin, type-erased.
#[derive(Debug)]
pub struct TapSpec {
    pub(crate) name: &'static str,
    pub(crate) tap: &'static str,
    new: fn() -> Box<dyn DynamicTap>,
}

impl TapSpec {
    /// The tap `T` describes.
    pub const fn of<T: Tap>() -> Self {
        Self {
            name: T::NAME,
            tap: T::TAP,
            new: new::<T>,
        }
    }
}

/// A tap of either kind, as registration reads it.
#[derive(Clone, Copy)]
pub(crate) struct Listed {
    pub(crate) name: &'static str,
    pub(crate) tap: &'static str,
    new: &'static TapFactory,
}

impl From<&'static TapSpec> for Listed {
    fn from(spec: &'static TapSpec) -> Self {
        Self {
            name: spec.name,
            tap: spec.tap,
            new: &spec.new,
        }
    }
}

impl From<&'static dynamic::Tap> for Listed {
    fn from(tap: &'static dynamic::Tap) -> Self {
        Self {
            name: tap.name,
            tap: tap.tap,
            new: &*tap.new,
        }
    }
}

fn new<T: Tap>() -> Box<dyn DynamicTap> {
    Box::new(Static(T::default()))
}

/// A static [`Tap`] as the state of a listener.
struct Static<T>(T);

impl<T: Tap> DynamicTap for Static<T> {
    fn packet(&mut self, packet: &TapPacket<'_>) {
        self.0.packet(packet);
    }

    fn draw(&self) -> String {
        self.0.draw()
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

/// What `register_stat_tap_ui` hands back to the init callback.
struct Entry {
    spec: Listed,
    plugin: &'static Plugin,
}

/// A running listener: one `-z` invocation's state.
struct Listener {
    /// Whether the tap is a protocol of this plugin, whose data is ours.
    ours: bool,
    state: Mutex<Box<dyn DynamicTap>>,
}

fn leak(text: &str) -> *const c_char {
    CString::new(text.replace('\0', ""))
        .unwrap_or_default()
        .into_raw()
        .cast_const()
}

/// Offers `spec` as `-z <name>`; called from the plugin's tap registration.
pub(crate) fn register(spec: Listed, plugin: &'static Plugin) {
    let name = leak(spec.name);
    let ui = Box::leak(Box::new(sys::stat_tap_ui {
        // REGISTER_STAT_GROUP_GENERIC, whose constant's name differs by release line.
        group: 3,
        title: name,
        cli_string: name,
        tap_init_cb: <sys::stat_tap_init_cb as InitCallback>::ours(),
        nparams: 0,
        params: core::ptr::null_mut(),
    }));
    let entry = Box::leak(Box::new(Entry { spec, plugin }));
    // SAFETY: `ui`, its strings and `entry` are leaked: Wireshark keeps them
    // for the process.
    unsafe { sys::register_stat_tap_ui(ui, core::ptr::from_mut(entry).cast()) };
}

/// The return type of the `-z` init callback: none before 4.0, `bool` after.
pub(crate) trait InitReturn {
    fn ok() -> Self;
}

impl InitReturn for () {
    fn ok() -> Self {}
}

impl InitReturn for bool {
    fn ok() -> Self {
        true
    }
}

impl InitReturn for c_int {
    fn ok() -> Self {
        1
    }
}

/// The init callback whose signature the binding declares.
pub(crate) trait InitCallback {
    fn ours() -> Self;
}

impl<R: InitReturn> InitCallback for Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> R> {
    fn ours() -> Self {
        Some(init::<R>)
    }
}

/// `-z <name>[,<filter>]`: starts a listener on the spec's tap.
unsafe extern "C" fn init<R: InitReturn>(argument: *const c_char, userdata: *mut c_void) -> R {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `userdata` is the leaked `Entry` registered with this entry.
        let Some(entry) = (unsafe { userdata.cast::<Entry>().as_ref() }) else {
            return;
        };
        let argument = if argument.is_null() {
            String::new()
        } else {
            // SAFETY: Wireshark passes the NUL-terminated `-z` argument.
            unsafe { CStr::from_ptr(argument) }
                .to_string_lossy()
                .into_owned()
        };
        let filter = argument
            .strip_prefix(entry.spec.name)
            .and_then(|rest| rest.strip_prefix(','))
            .filter(|filter| !filter.is_empty());
        // Only a protocol that registered: one whose name was taken is
        // another's, and so is its tap data.
        let ours = entry.plugin.registered(entry.spec.tap);
        let listener = Box::leak(Box::new(Listener {
            ours,
            state: Mutex::new((entry.spec.new)()),
        }));
        let filter = filter.map_or(core::ptr::null(), leak);
        // SAFETY: the tap name, filter and listener are leaked; the
        // callbacks match the binding's types.
        let error = unsafe {
            sys::register_tap_listener(
                leak(entry.spec.tap),
                core::ptr::from_mut(listener).cast(),
                filter,
                0,
                Some(reset),
                <sys::tap_packet_cb as PacketCallback>::ours(),
                Some(draw),
                None,
            )
        };
        // SAFETY: a non-null result is a GString describing the error.
        if let Some(error) = unsafe { error.as_ref() } {
            let message = if error.str_.is_null() {
                String::new()
            } else {
                // SAFETY: the GString's text is NUL-terminated.
                unsafe { CStr::from_ptr(error.str_) }
                    .to_string_lossy()
                    .into_owned()
            };
            // The `-z` caller has nowhere else to see why its statistic is missing.
            let _ = writeln!(
                std::io::stderr(),
                "{}: cannot listen to tap {}: {message}",
                entry.spec.name,
                entry.spec.tap
            );
        }
    }));
    R::ok()
}

fn listener<'a>(tapdata: *mut c_void) -> Option<&'a Listener> {
    // SAFETY: `tapdata` is the leaked `Listener` registered with this tap.
    unsafe { tapdata.cast::<Listener>().as_ref() }
}

unsafe extern "C" fn reset(tapdata: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(listener) = listener(tapdata) {
            listener
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .reset();
        }
    }));
}

unsafe extern "C" fn draw(tapdata: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(listener) = listener(tapdata) else {
            return;
        };
        let report = listener
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .draw();
        // tshark writes through C's buffered stdout: flush it so the report
        // lands after what it printed before.
        // SAFETY: `fflush(NULL)` flushes every C output stream.
        unsafe { sys::fflush(core::ptr::null_mut()) };
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(report.as_bytes());
        let _ = stdout.flush();
    }));
}

/// The packet callback whose signature the binding declares: four
/// arguments before 4.0, five (with tap flags) after.
pub(crate) trait PacketCallback {
    fn ours() -> Self;
}

type PacketPointer3 = unsafe extern "C" fn(
    *mut c_void,
    *mut sys::packet_info,
    *mut sys::epan_dissect_t,
    *const c_void,
) -> sys::tap_packet_status;

type PacketPointer4<F> = unsafe extern "C" fn(
    *mut c_void,
    *mut sys::packet_info,
    *mut sys::epan_dissect_t,
    *const c_void,
    F,
) -> sys::tap_packet_status;

impl PacketCallback for Option<PacketPointer3> {
    fn ours() -> Self {
        Some(packet3)
    }
}

impl<F> PacketCallback for Option<PacketPointer4<F>> {
    fn ours() -> Self {
        Some(packet4::<F>)
    }
}

unsafe extern "C" fn packet3(
    tapdata: *mut c_void,
    pinfo: *mut sys::packet_info,
    _edt: *mut sys::epan_dissect_t,
    data: *const c_void,
) -> sys::tap_packet_status {
    // SAFETY: Wireshark's arguments for this tap packet.
    unsafe { packet(tapdata, pinfo, data) }
}

unsafe extern "C" fn packet4<F>(
    tapdata: *mut c_void,
    pinfo: *mut sys::packet_info,
    _edt: *mut sys::epan_dissect_t,
    data: *const c_void,
    _flags: F,
) -> sys::tap_packet_status {
    // SAFETY: Wireshark's arguments for this tap packet.
    unsafe { packet(tapdata, pinfo, data) }
}

/// # Safety
///
/// The arguments are those of the running tap packet callback.
unsafe fn packet(
    tapdata: *mut c_void,
    pinfo: *mut sys::packet_info,
    data: *const c_void,
) -> sys::tap_packet_status {
    catch_unwind(AssertUnwindSafe(|| {
        let listener = listener(tapdata)?;
        let pinfo = NonNull::new(pinfo)?;
        let data = if listener.ours {
            // SAFETY: a protocol of this plugin queued a pointer to a boxed
            // value it keeps until the next frame.
            unsafe { data.cast::<Box<dyn Any + Send>>().as_ref() }.map(|value| &**value)
        } else {
            None
        };
        // SAFETY: `pinfo` is valid for this callback.
        let packet = unsafe { TapPacket::from_raw(pinfo, data) };
        listener
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .packet(&packet);
        Some(())
    }))
    .ok()
    .flatten()
    .map_or(sys::tap_packet_status_TAP_PACKET_DONT_REDRAW, |()| {
        sys::tap_packet_status_TAP_PACKET_REDRAW
    })
}
