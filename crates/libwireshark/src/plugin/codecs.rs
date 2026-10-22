//! A plugin's audio codecs.
//!
//! The codec interface is in libwsutil (libwscodecs in 3.0), so it is
//! resolved from the running Wireshark. From 4.2 each callback receives a
//! `codec_context_t` holding the decoder; before, the decoder itself.

use super::PluginStatic;
use super::slots;
use crate::__private::symbols::{function, loaded};
use crate::codec::{Codec, StreamFormat};
use crate::dynamic::{self, DynamicCodec};
use crate::sys;
use alloc::boxed::Box;
use alloc::ffi::CString;
use core::ffi::{c_char, c_uint, c_void};
use core::panic::AssertUnwindSafe;
use std::io::Write as _;
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
pub(crate) struct Context {
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

/// `codec_init_fn` from 4.2: it carries no data pointer.
pub(crate) type ContextInit = unsafe extern "C" fn(*mut Context) -> *mut c_void;

/// `codec_init_fn` before 4.2.
pub(crate) type LegacyInit = unsafe extern "C" fn() -> *mut c_void;

/// The init callbacks of a plugin's run-time codec slots, in both
/// signatures.
#[derive(Debug)]
pub(crate) struct InitSlots {
    pub(crate) context: [ContextInit; slots::COUNT],
    pub(crate) legacy: [LegacyInit; slots::COUNT],
}

/// What a codec's callbacks decode with: a static codec, or a run-time
/// codec's decoder.
trait Decoder: 'static {
    fn sample_rate(&self) -> u32;
    fn channels(&self) -> u32;
    fn decoded_len(&self, payload: &[u8]) -> usize;
    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize;
}

impl<C: Codec> Decoder for C {
    fn sample_rate(&self) -> u32 {
        Codec::sample_rate(self)
    }

    fn channels(&self) -> u32 {
        Codec::channels(self)
    }

    fn decoded_len(&self, payload: &[u8]) -> usize {
        Codec::decoded_len(self, payload)
    }

    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize {
        Codec::decode(self, payload, samples)
    }
}

/// A run-time codec's decoder, boxed once more for a thin pointer.
type Dynamic = Box<dyn DynamicCodec>;

impl Decoder for Dynamic {
    fn sample_rate(&self) -> u32 {
        (**self).sample_rate()
    }

    fn channels(&self) -> u32 {
        (**self).channels()
    }

    fn decoded_len(&self, payload: &[u8]) -> usize {
        (**self).decoded_len(payload)
    }

    fn decode(&mut self, payload: &[u8], samples: &mut [i16]) -> usize {
        (**self).decode(payload, samples)
    }
}

impl CodecSpec {
    /// The codec `C` describes.
    pub const fn of<C: Codec>() -> Self {
        Self {
            name: C::NAME,
            context: callbacks::<C>(init::<C>),
            legacy: legacy_callbacks::<C>(legacy_init::<C>),
        }
    }
}

/// `init` and the callbacks over a `D`, cast for `register_codec`.
const fn callbacks<D: Decoder>(init: ContextInit) -> [Callback; 5] {
    // SAFETY (for each cast): function pointers share one representation;
    // `register` passes each back as an untyped pointer, and Wireshark calls
    // it with its own signature.
    unsafe {
        [
            core::mem::transmute::<ContextInit, Callback>(init),
            core::mem::transmute::<unsafe extern "C" fn(*mut Context), Callback>(release::<D>),
            core::mem::transmute::<unsafe extern "C" fn(*mut Context) -> c_uint, Callback>(
                channels::<D>,
            ),
            core::mem::transmute::<unsafe extern "C" fn(*mut Context) -> c_uint, Callback>(
                frequency::<D>,
            ),
            core::mem::transmute::<Decode<Context>, Callback>(decode::<D>),
        ]
    }
}

/// [`callbacks`] in the signatures before 4.2.
const fn legacy_callbacks<D: Decoder>(init: LegacyInit) -> [Callback; 5] {
    // SAFETY: as in `callbacks`.
    unsafe {
        [
            core::mem::transmute::<LegacyInit, Callback>(init),
            core::mem::transmute::<unsafe extern "C" fn(*mut c_void), Callback>(
                legacy_release::<D>,
            ),
            core::mem::transmute::<unsafe extern "C" fn(*mut c_void) -> c_uint, Callback>(
                legacy_channels::<D>,
            ),
            core::mem::transmute::<unsafe extern "C" fn(*mut c_void) -> c_uint, Callback>(
                legacy_frequency::<D>,
            ),
            core::mem::transmute::<Decode<c_void>, Callback>(legacy_decode::<D>),
        ]
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

/// Registers `specs`, then `dynamic` through `slots`; a name Wireshark
/// already has is refused by it.
pub(crate) fn register(specs: &[CodecSpec], dynamic: &[dynamic::Codec], slots: &InitSlots) {
    let Some(library) = wsutil() else {
        return;
    };
    // SAFETY: `register_codec`'s parameters are a name and five function
    // pointers in every release line; see `Register` for its result.
    let Some(register) = (unsafe { function::<Register>(&library, b"register_codec\0") }) else {
        return;
    };
    if dynamic.len() > slots.context.len() {
        // A plugin's loader has nowhere else to say what it left out.
        let _ = writeln!(
            std::io::stderr(),
            "libwireshark: {} codecs registered at run time; the first {} are kept",
            dynamic.len(),
            slots.context.len()
        );
    }
    let statics = specs
        .iter()
        .map(|spec| (spec.name, if CONTEXT { spec.context } else { spec.legacy }));
    let dynamics = dynamic
        .iter()
        .zip(slots.context.iter().zip(&slots.legacy))
        .map(|(codec, (&init, &legacy))| {
            let callbacks = if CONTEXT {
                callbacks::<Dynamic>(init)
            } else {
                legacy_callbacks::<Dynamic>(legacy)
            };
            (codec.name, callbacks)
        });
    for (name, [init, release, channels, frequency, decode]) in statics.chain(dynamics) {
        // Wireshark keeps the name without copying it.
        let name = CString::new(name.replace('\0', ""))
            .unwrap_or_default()
            .into_raw();
        // SAFETY: the callbacks have the signatures of this release line.
        unsafe { register(name, init, release, channels, frequency, decode) };
    }
}

/// What a codec reports from a stream's `a=rtpmap`, 0 meaning unknown.
fn known(value: c_uint) -> Option<u32> {
    (value != 0).then_some(value)
}

/// A boxed decoder, or null if `new` panicked.
fn boxed<D: Decoder>(new: impl FnOnce() -> D) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(|| Box::into_raw(Box::new(new())).cast()))
        .unwrap_or(core::ptr::null_mut())
}

/// The format a stream's context reports.
///
/// # Safety
///
/// `context` is null or the stream's context.
unsafe fn format(context: *mut Context) -> Option<StreamFormat> {
    // SAFETY: the caller's contract.
    let context = unsafe { context.as_ref() }?;
    Some(StreamFormat {
        sample_rate: known(context.sample_rate),
        channels: known(context.channels),
    })
}

/// # Safety
///
/// `decoder` is null or a decoder `boxed::<D>` returned and not yet freed.
unsafe fn free<D: Decoder>(decoder: *mut c_void) {
    if !decoder.is_null() {
        // SAFETY: the caller's contract.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            drop(unsafe { Box::from_raw(decoder.cast::<D>()) })
        }));
    }
}

/// `f` on the decoder, or `fallback` when there is none or it panics.
///
/// # Safety
///
/// As for [`free`], and no other reference to the decoder is live.
unsafe fn with<D: Decoder, T>(decoder: *mut c_void, fallback: T, f: impl FnOnce(&mut D) -> T) -> T {
    // SAFETY: the caller's contract.
    let Some(decoder) = (unsafe { decoder.cast::<D>().as_mut() }) else {
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
unsafe fn decode_into<D: Decoder>(
    decoder: &mut D,
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
    match unsafe { format(context) } {
        Some(format) => boxed(|| C::new(&format)),
        None => core::ptr::null_mut(),
    }
}

/// The init callback of run-time codec slot `N`.
pub(crate) unsafe extern "C" fn init_slot<P: PluginStatic, const N: usize>(
    context: *mut Context,
) -> *mut c_void {
    let Some(codec) = P::plugin().dynamic_codec(N) else {
        return core::ptr::null_mut();
    };
    // SAFETY: Wireshark passes the stream's context.
    match unsafe { format(context) } {
        Some(format) => boxed::<Dynamic>(|| (codec.new)(&format)),
        None => core::ptr::null_mut(),
    }
}

/// [`init_slot`] before 4.2.
pub(crate) unsafe extern "C" fn legacy_init_slot<P: PluginStatic, const N: usize>() -> *mut c_void {
    match P::plugin().dynamic_codec(N) {
        Some(codec) => boxed::<Dynamic>(|| (codec.new)(&StreamFormat::default())),
        None => core::ptr::null_mut(),
    }
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

unsafe extern "C" fn release<D: Decoder>(context: *mut Context) {
    // SAFETY: Wireshark releases a context once; the decoder is cleared.
    unsafe {
        free::<D>(decoder(context));
        if let Some(context) = context.as_mut() {
            context.decoder = core::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn channels<D: Decoder>(context: *mut Context) -> c_uint {
    // SAFETY: the stream's context, holding `init`'s decoder.
    unsafe { with::<D, _>(decoder(context), 0, |decoder| decoder.channels()) }
}

unsafe extern "C" fn frequency<D: Decoder>(context: *mut Context) -> c_uint {
    // SAFETY: as in `channels`.
    unsafe { with::<D, _>(decoder(context), 0, |decoder| decoder.sample_rate()) }
}

unsafe extern "C" fn decode<D: Decoder>(
    context: *mut Context,
    input: *const c_void,
    input_len: usize,
    output: *mut c_void,
    output_len: *mut usize,
) -> usize {
    // SAFETY: as in `channels`; the buffers are Wireshark's (`decode_into`).
    unsafe {
        with::<D, _>(decoder(context), 0, |decoder| {
            decode_into(decoder, input, input_len, output, output_len)
        })
    }
}

unsafe extern "C" fn legacy_init<C: Codec>() -> *mut c_void {
    boxed(|| C::new(&StreamFormat::default()))
}

unsafe extern "C" fn legacy_release<D: Decoder>(decoder: *mut c_void) {
    // SAFETY: Wireshark releases the decoder `legacy_init` returned, once.
    unsafe { free::<D>(decoder) }
}

unsafe extern "C" fn legacy_channels<D: Decoder>(decoder: *mut c_void) -> c_uint {
    // SAFETY: the decoder `legacy_init` returned.
    unsafe { with::<D, _>(decoder, 0, |decoder| decoder.channels()) }
}

unsafe extern "C" fn legacy_frequency<D: Decoder>(decoder: *mut c_void) -> c_uint {
    // SAFETY: as in `legacy_channels`.
    unsafe { with::<D, _>(decoder, 0, |decoder| decoder.sample_rate()) }
}

unsafe extern "C" fn legacy_decode<D: Decoder>(
    decoder: *mut c_void,
    input: *const c_void,
    input_len: usize,
    output: *mut c_void,
    output_len: *mut usize,
) -> usize {
    // SAFETY: as in `legacy_channels`; the buffers are Wireshark's.
    unsafe {
        with::<D, _>(decoder, 0, |decoder| {
            decode_into(decoder, input, input_len, output, output_len)
        })
    }
}
