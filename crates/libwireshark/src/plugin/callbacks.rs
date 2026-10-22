//! The C callbacks Wireshark calls during dissection.

use super::runtime::Shared;
use crate::packet::PacketView;
use crate::sys;
use core::ffi::{c_int, c_uint, c_void};
use core::panic::AssertUnwindSafe;
use core::ptr::NonNull;
use std::panic::catch_unwind;
use std::sync::PoisonError;

/// A C callback's return type, read from the binding's function pointer type
/// so the plugin's own callbacks match every release line.
pub trait CallbackReturn {
    /// What the callback returns.
    type Output;
}

impl<R> CallbackReturn
    for Option<
        unsafe extern "C" fn(
            *mut sys::tvbuff_t,
            *mut sys::packet_info,
            *mut sys::proto_tree,
            *mut c_void,
        ) -> R,
    >
{
    type Output = R;
}

/// What a heuristic dissector returns: `gboolean` before 4.0, `bool` after.
pub type HeuristicResult = <sys::heur_dissector_t as CallbackReturn>::Output;

/// The plugin's heuristic callback.
pub type HeuristicFn = extern "C" fn(
    *mut sys::tvbuff_t,
    *mut sys::packet_info,
    *mut sys::proto_tree,
    *mut c_void,
) -> HeuristicResult;

/// `accepted` as the heuristic callback's return type.
pub fn heuristic_result(accepted: bool) -> HeuristicResult {
    flag(accepted)
}

/// A C boolean: `gboolean` (an `int`) before 4.0, `bool` after.
pub(crate) trait Flag: Copy + PartialEq + 'static {
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

/// Whether a C boolean of either type is true.
pub(crate) fn is_true<T: Flag>(value: T) -> bool {
    value != T::FALSE
}

/// `value` as whichever C boolean the call site expects.
pub(crate) fn flag<T: Flag>(value: bool) -> T {
    if value { T::TRUE } else { T::FALSE }
}

/// `extern "C" fn()` as the `unsafe extern "C" fn()` the C API declares.
pub(crate) fn trampoline(callback: extern "C" fn()) -> unsafe extern "C" fn() {
    callback
}

/// The heuristic callback as the binding's `heur_dissector_t`.
pub(crate) fn heuristic_pointer(callback: HeuristicFn) -> sys::heur_dissector_t {
    let callback: unsafe extern "C" fn(
        *mut sys::tvbuff_t,
        *mut sys::packet_info,
        *mut sys::proto_tree,
        *mut c_void,
    ) -> HeuristicResult = callback;
    Some(callback)
}

/// Dissects one packet for the protocol `shared` belongs to: message by
/// message for a protocol framed over TCP, else directly. Returns the bytes consumed.
///
/// # Safety
///
/// The arguments are those of the running dissector callback.
pub(crate) unsafe fn dissect(
    shared: &Shared,
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
) -> Option<usize> {
    // SAFETY: the caller's contract.
    unsafe { dissect_as(shared, tvb, pinfo, tree, false) }
}

/// [`dissect`], or as a post-dissector when `post`: no framing, and the
/// columns lower layers wrote are kept.
///
/// # Safety
///
/// As [`dissect`].
unsafe fn dissect_as(
    shared: &Shared,
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
    post: bool,
) -> Option<usize> {
    if let Some(header_len) = shared.framing_header
        && !post
        // SAFETY: the caller's contract.
        && unsafe { pinfo.as_ref() }.is_some_and(|pinfo| pinfo.ptype == sys::port_type_PT_TCP)
    {
        let data = core::ptr::from_ref(shared).cast_mut().cast::<c_void>();
        // SAFETY: the callbacks read `data` as the `Shared` it is, which
        // outlives the call; the other arguments are the caller's.
        unsafe {
            sys::tcp_dissect_pdus(
                tvb,
                pinfo,
                tree,
                flag(true),
                c_uint::try_from(header_len).ok()?,
                Some(message_len),
                Some(message),
                data,
            );
            return usize::try_from(sys::tvb_captured_length(tvb)).ok();
        }
    }
    // SAFETY: the caller's contract.
    unsafe { dissect_whole(shared, tvb, pinfo, tree, post) }
}

/// # Safety
///
/// As [`dissect`].
unsafe fn dissect_whole(
    shared: &Shared,
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
    post: bool,
) -> Option<usize> {
    let preferences = shared
        .preferences
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()?;
    // SAFETY: the caller's contract.
    let mut packet = unsafe { PacketView::from_raw(tvb, pinfo, tree, &shared.registered, post) }?;
    shared.imp.dissect(&*preferences, &mut packet)
}

/// The dissector registered for each protocol's handle; `callback_data` is
/// the protocol's boxed `Shared`.
pub(crate) unsafe extern "C" fn dissector(
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
    _data: *mut c_void,
    callback_data: *mut c_void,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let shared = NonNull::new(callback_data.cast::<Shared>())?;
        // SAFETY: the callback data is the boxed `Shared` registered with
        // this handle, which lives for the process; the rest are Wireshark's.
        let size = unsafe { dissect(shared.as_ref(), tvb, pinfo, tree) }?;
        Some(c_int::try_from(size).unwrap_or(c_int::MAX))
    }))
    .ok()
    .flatten()
    .unwrap_or(0)
}

/// The callback of a protocol's post-dissector handle.
pub(crate) unsafe extern "C" fn postdissector(
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
    _data: *mut c_void,
    callback_data: *mut c_void,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let shared = NonNull::new(callback_data.cast::<Shared>())?;
        // SAFETY: as in `dissector`.
        let shared = unsafe { shared.as_ref() };
        if !shared
            .post_active
            .load(core::sync::atomic::Ordering::Relaxed)
        {
            return None;
        }
        // SAFETY: as in `dissector`.
        let size = unsafe { dissect_as(shared, tvb, pinfo, tree, true) }?;
        Some(c_int::try_from(size).unwrap_or(c_int::MAX))
    }))
    .ok()
    .flatten()
    .unwrap_or(0)
}

/// `tcp_dissect_pdus`' length callback: the length of the message starting
/// at `offset`, from its fixed header. When the protocol cannot say (or
/// says less than the header), the rest of the segment: answering 0 would
/// wait for more data forever, and less than the header makes Wireshark
/// throw. The dissector then sees that rest as one message, and may
/// decline it.
unsafe extern "C" fn message_len(
    _pinfo: *mut sys::packet_info,
    tvb: *mut sys::tvbuff_t,
    offset: c_int,
    data: *mut c_void,
) -> c_uint {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `data` is the `Shared` passed to `tcp_dissect_pdus`.
        let shared = unsafe { NonNull::new(data.cast::<Shared>())?.as_ref() };
        let header_size = shared.framing_header?;
        let header_len = c_int::try_from(header_size).ok()?;
        // SAFETY: `tcp_dissect_pdus` calls this only with `header_len`
        // captured bytes at `offset`.
        let header = unsafe {
            let bytes = sys::tvb_get_ptr(tvb, offset, header_len);
            if bytes.is_null() {
                return None;
            }
            core::slice::from_raw_parts(bytes, header_size)
        };
        let len = shared
            .imp
            .message_len(header)
            .filter(|&len| len >= header_size)?;
        c_uint::try_from(len).ok()
    }))
    .ok()
    .flatten()
    .unwrap_or_else(|| {
        // SAFETY: `tvb` is the segment `tcp_dissect_pdus` is splitting.
        let rest = unsafe { sys::tvb_reported_length_remaining(tvb, offset) };
        c_uint::try_from(rest).unwrap_or(0)
    })
}

/// `tcp_dissect_pdus`' message callback: one whole message in its own buffer.
unsafe extern "C" fn message(
    tvb: *mut sys::tvbuff_t,
    pinfo: *mut sys::packet_info,
    tree: *mut sys::proto_tree,
    data: *mut c_void,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `data` is the `Shared` passed to `tcp_dissect_pdus`.
        let shared = unsafe { NonNull::new(data.cast::<Shared>())?.as_ref() };
        // SAFETY: Wireshark's arguments for the reassembled message.
        let size = unsafe { dissect_whole(shared, tvb, pinfo, tree, false) }?;
        Some(c_int::try_from(size).unwrap_or(c_int::MAX))
    }))
    .ok()
    .flatten()
    .unwrap_or(0)
}
