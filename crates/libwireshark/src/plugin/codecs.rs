//! A plugin's audio codecs.
//!
//! The codec interface is in libwsutil (libwscodecs in 3.0), so it is
//! resolved from the running Wireshark. From 4.2 each callback receives a
//! `codec_context_t` holding the decoder; before, the decoder itself.

use crate::__private::symbols::{function, loaded};
use crate::codec::{Codec, StreamFormat};
use crate::sys;
use alloc::boxed::Box;
use alloc::ffi::CString;
use core::ffi::{c_char, c_uint, c_void};
use core::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

/// The table `plugin_register` hands to `codecs_register_plugin`.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct CodecsPlugin {
    register_codec_module: Option<extern "C" fn()>,
}

/// The `codecs_plugin` that registers the plugin's codecs from `register`.
pub(crate) const fn codecs_plugin(register: extern "C" fn()) -> CodecsPlugin {
    CodecsPlugin {
        register_codec_module: Some(register),
    }
}

/// Whether this release line passes a `codec_context_t` (4.2 on).
const CONTEXT: bool = matches!(
    (sys::VERSION_MAJOR, sys::VERSION_MINOR),
    (5.., _) | (4, 2..)
);

/// `codec_context_t`, 4.2 on.
#[repr(C)]
struct Context {
    sample_rate: c_uint,
    channels: c_uint,
    fmtp_map: *mut c_void,
    decoder: *mut c_void,
}

/// One [`Codec`] of a plugin: its callbacks in both signatures.
#[derive(Debug)]
pub struct CodecSpec {
    name: &'static str,
    context: [Callback; 5],
    legacy: [Callback; 5],
}

/// A codec callback, cast to one type to be passed to `register_codec`.
type Callback = unsafe extern "C" fn();

impl CodecSpec {
    /// The codec `C` describes.
    pub const fn of<C: Codec>() -> Self {
        // SAFETY (for each cast): function pointers share one
        // representation; `register` passes each back as an untyped
        // pointer, and Wireshark calls it with its own signature.
        unsafe {
            Self {
                name: C::NAME,
                context: [
                    core::mem::transmute::<
                        unsafe extern "C" fn(*mut Context) -> *mut c_void,
                        Callback,
                    >(init::<C>),
                    core::mem::transmute::<unsafe extern "C" fn(*mut Context), Callback>(
                        release::<C>,
                    ),
                    core::mem::transmute::<unsafe extern "C" fn(*mut Context) -> c_uint, Callback>(
                        channels::<C>,
                    ),
                    core::mem::transmute::<unsafe extern "C" fn(*mut Context) -> c_uint, Callback>(
                        frequency::<C>,
                    ),
                    core::mem::transmute::<Decode<Context>, Callback>(decode::<C>),
                ],
                legacy: [
                    core::mem::transmute::<unsafe extern "C" fn() -> *mut c_void, Callback>(
                        legacy_init::<C>,
                    ),
                    core::mem::transmute::<unsafe extern "C" fn(*mut c_void), Callback>(
                        legacy_release::<C>,
                    ),
                    core::mem::transmute::<unsafe extern "C" fn(*mut c_void) -> c_uint, Callback>(
                        legacy_channels::<C>,
                    ),
                    core::mem::transmute::<unsafe extern "C" fn(*mut c_void) -> c_uint, Callback>(
                        legacy_frequency::<C>,
                    ),
                    core::mem::transmute::<Decode<c_void>, Callback>(legacy_decode::<C>),
                ],
            }
        }
    }
}

/// `codec_decode_fn` over a context (4.2 on) or a decoder.
type Decode<T> =
    unsafe extern "C" fn(*mut T, *const c_void, usize, *mut c_void, *mut usize) -> usize;

/// `register_codec`, its return read as a byte: `gboolean` before 4.2,
/// `bool` after.
type Register =
    unsafe extern "C" fn(*const c_char, Callback, Callback, Callback, Callback, Callback) -> u8;

fn wsutil() -> Option<libloading::Library> {
    loaded("libwsutil.dll").or_else(|| loaded("libwscodecs.dll"))
}

/// Hands the plugin's `codecs_plugin` table to Wireshark.
pub(crate) fn register_plugin(plugin: &'static CodecsPlugin) {
    let Some(library) = wsutil() else {
        return;
    };
    // SAFETY: `codecs_register_plugin(const codecs_plugin *)` in every line.
    let register: Option<unsafe extern "C" fn(*const CodecsPlugin)> =
        unsafe { function(&library, b"codecs_register_plugin\0") };
    if let Some(register) = register {
        // SAFETY: the table and its callback are statics of the plugin library.
        unsafe { register(plugin) };
    }
}

/// Registers `specs`; a name Wireshark already has is refused by it.
pub(crate) fn register(specs: &[CodecSpec]) {
    let Some(library) = wsutil() else {
        return;
    };
    // SAFETY: `register_codec`'s parameters are a name and five function
    // pointers in every release line; see `Register` for its result.
    let Some(register) = (unsafe { function::<Register>(&library, b"register_codec\0") }) else {
        return;
    };
    for spec in specs {
        // Wireshark keeps the name without copying it.
        let name = CString::new(spec.name.replace('\0', ""))
            .unwrap_or_default()
            .into_raw();
        let [init, release, channels, frequency, decode] =
            if CONTEXT { spec.context } else { spec.legacy };
        // SAFETY: the callbacks have the signatures of this release line.
        unsafe { register(name, init, release, channels, frequency, decode) };
    }
}

/// What a codec reports from a stream's `a=rtpmap`, 0 meaning unknown.
fn known(value: c_uint) -> Option<u32> {
    (value != 0).then_some(value)
}

/// A boxed decoder, or null if `C::new` panicked.
fn boxed<C: Codec>(format: &StreamFormat) -> *mut c_void {
    catch_unwind(|| Box::into_raw(Box::new(C::new(format))).cast()).unwrap_or(core::ptr::null_mut())
}

/// # Safety
///
/// `decoder` is null or a decoder `boxed::<C>` returned and not yet freed.
unsafe fn free<C: Codec>(decoder: *mut c_void) {
    if !decoder.is_null() {
        // SAFETY: the caller's contract.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            drop(unsafe { Box::from_raw(decoder.cast::<C>()) })
        }));
    }
}

/// `f` on the decoder, or `fallback` when there is none or it panics.
///
/// # Safety
///
/// As for [`free`], and no other reference to the decoder is live.
unsafe fn with<C: Codec, T>(decoder: *mut c_void, fallback: T, f: impl FnOnce(&mut C) -> T) -> T {
    // SAFETY: the caller's contract.
    let Some(decoder) = (unsafe { decoder.cast::<C>().as_mut() }) else {
        return fallback;
    };
    catch_unwind(AssertUnwindSafe(|| f(decoder))).unwrap_or(fallback)
}

/// `codec_decode`'s two calls: with no output, the bytes to allocate;
/// with one, the bytes decoded into it.
///
/// # Safety
///
/// `input` holds `input_len` bytes; `output`, when not null, holds
/// `*output_len` writable bytes.
unsafe fn decode_into<C: Codec>(
    decoder: &mut C,
    input: *const c_void,
    input_len: usize,
    output: *mut c_void,
    output_len: *mut usize,
) -> usize {
    let payload = if input.is_null() {
        &[][..]
    } else {
        // SAFETY: the caller's contract.
        unsafe { core::slice::from_raw_parts(input.cast::<u8>(), input_len) }
    };
    let sample = core::mem::size_of::<i16>();
    if output.is_null() || output_len.is_null() {
        return decoder.decoded_len(payload).saturating_mul(sample);
    }
    let output = output.cast::<i16>();
    if !output.is_aligned() {
        return 0;
    }
    // SAFETY: the caller's contract; the buffer is aligned for `i16`.
    let samples = unsafe { core::slice::from_raw_parts_mut(output, *output_len / sample) };
    let written = decoder.decode(payload, samples).min(samples.len()) * sample;
    // SAFETY: the caller's contract.
    unsafe { *output_len = written };
    written
}

unsafe extern "C" fn init<C: Codec>(context: *mut Context) -> *mut c_void {
    // SAFETY: Wireshark passes the stream's context.
    let Some(context) = (unsafe { context.as_ref() }) else {
        return core::ptr::null_mut();
    };
    boxed::<C>(&StreamFormat {
        sample_rate: known(context.sample_rate),
        channels: known(context.channels),
    })
}

/// The decoder `init` returned, which Wireshark stored in the context.
///
/// # Safety
///
/// `context` is null or the stream's context.
unsafe fn decoder(context: *mut Context) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { context.as_ref() }.map_or(core::ptr::null_mut(), |context| context.decoder)
}

unsafe extern "C" fn release<C: Codec>(context: *mut Context) {
    // SAFETY: Wireshark releases a context once; the decoder is cleared.
    unsafe {
        free::<C>(decoder(context));
        if let Some(context) = context.as_mut() {
            context.decoder = core::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn channels<C: Codec>(context: *mut Context) -> c_uint {
    // SAFETY: the stream's context, holding `init`'s decoder.
    unsafe { with::<C, _>(decoder(context), 0, |decoder| decoder.channels()) }
}

unsafe extern "C" fn frequency<C: Codec>(context: *mut Context) -> c_uint {
    // SAFETY: as in `channels`.
    unsafe { with::<C, _>(decoder(context), 0, |decoder| decoder.sample_rate()) }
}

unsafe extern "C" fn decode<C: Codec>(
    context: *mut Context,
    input: *const c_void,
    input_len: usize,
    output: *mut c_void,
    output_len: *mut usize,
) -> usize {
    // SAFETY: as in `channels`; the buffers are Wireshark's (`decode_into`).
    unsafe {
        with::<C, _>(decoder(context), 0, |decoder| {
            decode_into(decoder, input, input_len, output, output_len)
        })
    }
}

unsafe extern "C" fn legacy_init<C: Codec>() -> *mut c_void {
    boxed::<C>(&StreamFormat::default())
}

unsafe extern "C" fn legacy_release<C: Codec>(decoder: *mut c_void) {
    // SAFETY: Wireshark releases the decoder `legacy_init` returned, once.
    unsafe { free::<C>(decoder) }
}

unsafe extern "C" fn legacy_channels<C: Codec>(decoder: *mut c_void) -> c_uint {
    // SAFETY: the decoder `legacy_init` returned.
    unsafe { with::<C, _>(decoder, 0, |decoder| decoder.channels()) }
}

unsafe extern "C" fn legacy_frequency<C: Codec>(decoder: *mut c_void) -> c_uint {
    // SAFETY: as in `legacy_channels`.
    unsafe { with::<C, _>(decoder, 0, |decoder| decoder.sample_rate()) }
}

unsafe extern "C" fn legacy_decode<C: Codec>(
    decoder: *mut c_void,
    input: *const c_void,
    input_len: usize,
    output: *mut c_void,
    output_len: *mut usize,
) -> usize {
    // SAFETY: as in `legacy_channels`; the buffers are Wireshark's.
    unsafe {
        with::<C, _>(decoder, 0, |decoder| {
            decode_into(decoder, input, input_len, output, output_len)
        })
    }
}
