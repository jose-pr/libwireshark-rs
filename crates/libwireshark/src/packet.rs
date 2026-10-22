//! One packet as a dissector sees it during Wireshark's callback.

use crate::header::{FieldType, Header};
use crate::sys;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use core::any::{Any, TypeId};
use core::ffi::c_int;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Per-conversation values, keyed by Wireshark's conversation index and the
/// value's type.
pub(crate) type Conversations = Mutex<HashMap<(u32, TypeId), Box<dyn Any + Send>>>;

/// Values published to the protocol's tap for one frame: tap listeners read
/// them when the frame's dissection ends, so they are kept until the next.
pub(crate) type Tapped = Mutex<(u32, Vec<Box<Box<dyn Any + Send>>>)>;

/// A protocol's registered state the packet view reads: its ids, fields,
/// expert entries and conversation values.
pub(crate) struct Registered {
    pub(crate) proto: c_int,
    pub(crate) ett: c_int,
    pub(crate) filter: &'static str,
    pub(crate) short_name: CString,
    pub(crate) fields: Box<[RegisteredField]>,
    pub(crate) experts: Box<[RegisteredExpert]>,
    pub(crate) conversations: Conversations,
    /// The tap named like the protocol's filter.
    pub(crate) tap: c_int,
    pub(crate) tapped: Tapped,
}

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered")
            .field("filter", &self.filter)
            .field("fields", &self.fields)
            .finish_non_exhaustive()
    }
}

/// An expert entry Wireshark assigned ids to, in storage it keeps a pointer to.
#[derive(Debug)]
pub(crate) struct RegisteredExpert {
    pub(crate) abbrev: String,
    pub(crate) field: NonNull<sys::expert_field>,
}

/// Whether `full` is `name`, or `<filter>.<name>`.
fn names(full: &str, filter: &str, name: &str) -> bool {
    full == name
        || full
            .strip_prefix(filter)
            .and_then(|rest| rest.strip_prefix('.'))
            == Some(name)
}

/// A field Wireshark assigned an id to.
#[derive(Debug)]
pub(crate) struct RegisteredField {
    pub(crate) abbrev: alloc::string::String,
    pub(crate) id: c_int,
    pub(crate) kind: FieldType,
}

impl Registered {
    /// The field named `name`: its full abbreviation, or the part after
    /// `<filter>.`.
    fn field(&self, name: &str) -> Result<&RegisteredField, PacketFieldError> {
        self.fields
            .iter()
            .find(|field| names(&field.abbrev, self.filter, name))
            .filter(|field| field.id >= 0)
            .ok_or(PacketFieldError::UnknownField)
    }

    /// The expert entry named `name`, like [`field`](Self::field).
    fn expert(&self, name: &str) -> Result<&RegisteredExpert, PacketFieldError> {
        self.experts
            .iter()
            .find(|expert| names(&expert.abbrev, self.filter, name))
            .ok_or(PacketFieldError::UnknownField)
    }
}

/// The packet a dissector is decoding: its captured bytes, its columns and
/// its place in the protocol tree.
///
/// It exists only during [`Dissector::dissect`](crate::Dissector::dissect)
/// and cannot leave it: it borrows Wireshark's buffers and is neither `Send`
/// nor `Sync`.
pub struct PacketView<'packet> {
    tvb: NonNull<sys::tvbuff_t>,
    pinfo: Option<NonNull<sys::packet_info>>,
    parent: Option<NonNull<sys::proto_tree>>,
    item: Option<NonNull<sys::proto_item>>,
    tree: Option<NonNull<sys::proto_tree>>,
    protocol: &'packet Registered,
    post: bool,
    _callback: PhantomData<&'packet mut sys::tvbuff_t>,
}

impl fmt::Debug for PacketView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketView")
            .field("protocol", &self.protocol.filter)
            .field("captured_len", &self.captured_len())
            .field("has_tree", &self.has_tree())
            .finish_non_exhaustive()
    }
}

impl<'packet> PacketView<'packet> {
    /// # Safety
    ///
    /// `tvb` and the non-null context pointers are the arguments of the
    /// dissector callback currently running, valid until it returns.
    pub(crate) unsafe fn from_raw(
        tvb: *mut sys::tvbuff_t,
        pinfo: *mut sys::packet_info,
        tree: *mut sys::proto_tree,
        protocol: &'packet Registered,
        post: bool,
    ) -> Option<Self> {
        Some(Self {
            tvb: NonNull::new(tvb)?,
            pinfo: NonNull::new(pinfo),
            parent: NonNull::new(tree),
            item: None,
            tree: None,
            protocol,
            post,
            _callback: PhantomData,
        })
    }

    /// The number of bytes captured for this packet.
    pub fn captured_len(&self) -> usize {
        // SAFETY: `tvb` is the callback's live buffer.
        let length = unsafe { sys::tvb_captured_length(self.tvb.as_ptr()) };
        usize::try_from(length).unwrap_or(0)
    }

    /// The packet's length on the wire, which may exceed what was captured.
    pub fn reported_len(&self) -> usize {
        // SAFETY: `tvb` is the callback's live buffer.
        let length = unsafe { sys::tvb_reported_length(self.tvb.as_ptr()) };
        usize::try_from(length).unwrap_or(0)
    }

    /// The captured bytes, for any parser that reads a slice.
    pub fn bytes(&self) -> &'packet [u8] {
        let length = self.captured_len();
        let Ok(native) = c_int::try_from(length) else {
            return &[];
        };
        if native == 0 {
            return &[];
        }
        // SAFETY: the whole captured range is requested, so Wireshark returns
        // `length` contiguous bytes that live until the callback returns.
        let data = unsafe { sys::tvb_get_ptr(self.tvb.as_ptr(), 0, native) };
        if data.is_null() {
            return &[];
        }
        // SAFETY: `data` points at `length` initialised bytes owned by the
        // callback's buffer, which outlives `'packet`.
        unsafe { core::slice::from_raw_parts(data, length) }
    }

    /// `N` bytes at `offset`, or `None` past the captured data.
    fn array<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        self.bytes()
            .get(offset..offset.checked_add(N)?)?
            .try_into()
            .ok()
    }

    /// The byte at `offset`.
    pub fn get_u8(&self, offset: usize) -> Option<u8> {
        self.bytes().get(offset).copied()
    }

    /// A big-endian (network order) `u16` at `offset`.
    pub fn get_u16_be(&self, offset: usize) -> Option<u16> {
        self.array(offset).map(u16::from_be_bytes)
    }

    /// A little-endian `u16` at `offset`.
    pub fn get_u16_le(&self, offset: usize) -> Option<u16> {
        self.array(offset).map(u16::from_le_bytes)
    }

    /// A big-endian 24-bit unsigned integer at `offset`.
    pub fn get_u24_be(&self, offset: usize) -> Option<u32> {
        let [a, b, c] = self.array(offset)?;
        Some(u32::from_be_bytes([0, a, b, c]))
    }

    /// A little-endian 24-bit unsigned integer at `offset`.
    pub fn get_u24_le(&self, offset: usize) -> Option<u32> {
        let [a, b, c] = self.array(offset)?;
        Some(u32::from_le_bytes([a, b, c, 0]))
    }

    /// A big-endian `u32` at `offset`.
    pub fn get_u32_be(&self, offset: usize) -> Option<u32> {
        self.array(offset).map(u32::from_be_bytes)
    }

    /// A little-endian `u32` at `offset`.
    pub fn get_u32_le(&self, offset: usize) -> Option<u32> {
        self.array(offset).map(u32::from_le_bytes)
    }

    /// A big-endian `u64` at `offset`.
    pub fn get_u64_be(&self, offset: usize) -> Option<u64> {
        self.array(offset).map(u64::from_be_bytes)
    }

    /// A little-endian `u64` at `offset`.
    pub fn get_u64_le(&self, offset: usize) -> Option<u64> {
        self.array(offset).map(u64::from_le_bytes)
    }

    /// The signed byte at `offset`.
    pub fn get_i8(&self, offset: usize) -> Option<i8> {
        self.array(offset).map(i8::from_be_bytes)
    }

    /// A big-endian `i16` at `offset`.
    pub fn get_i16_be(&self, offset: usize) -> Option<i16> {
        self.array(offset).map(i16::from_be_bytes)
    }

    /// A little-endian `i16` at `offset`.
    pub fn get_i16_le(&self, offset: usize) -> Option<i16> {
        self.array(offset).map(i16::from_le_bytes)
    }

    /// A big-endian `i32` at `offset`.
    pub fn get_i32_be(&self, offset: usize) -> Option<i32> {
        self.array(offset).map(i32::from_be_bytes)
    }

    /// A little-endian `i32` at `offset`.
    pub fn get_i32_le(&self, offset: usize) -> Option<i32> {
        self.array(offset).map(i32::from_le_bytes)
    }

    /// A big-endian `i64` at `offset`.
    pub fn get_i64_be(&self, offset: usize) -> Option<i64> {
        self.array(offset).map(i64::from_be_bytes)
    }

    /// A little-endian `i64` at `offset`.
    pub fn get_i64_le(&self, offset: usize) -> Option<i64> {
        self.array(offset).map(i64::from_le_bytes)
    }

    /// The source port of the packet's transport, `0` when it has none.
    pub fn src_port(&self) -> u32 {
        // SAFETY: `pinfo` is the callback's live packet info.
        self.pinfo
            .map_or(0, |pinfo| unsafe { pinfo.as_ref().srcport })
    }

    /// The destination port of the packet's transport, `0` when it has none.
    pub fn dst_port(&self) -> u32 {
        // SAFETY: `pinfo` is the callback's live packet info.
        self.pinfo
            .map_or(0, |pinfo| unsafe { pinfo.as_ref().destport })
    }

    /// The packet's frame number, counted from 1.
    pub fn frame_number(&self) -> u32 {
        // SAFETY: `pinfo` is the callback's live packet info.
        self.pinfo.map_or(0, |pinfo| unsafe { pinfo.as_ref().num })
    }

    /// Replaces the Info column's text. Text after an interior NUL is dropped.
    pub fn set_info(&mut self, text: &str) {
        self.column(sys::COL_INFO as c_int, text, false);
    }

    /// Appends to the Info column's text. Text after an interior NUL is dropped.
    pub fn append_info(&mut self, text: &str) {
        self.column(sys::COL_INFO as c_int, text, true);
    }

    fn column(&mut self, column: c_int, text: &str, append: bool) {
        let Some(mut pinfo) = self.pinfo else {
            return;
        };
        let text = text.split('\0').next().unwrap_or_default();
        let Ok(text) = CString::new(text) else {
            return;
        };
        // SAFETY: `pinfo` is the callback's live packet info; Wireshark
        // copies the text before returning.
        unsafe {
            let cinfo = pinfo.as_mut().cinfo;
            if cinfo.is_null() {
                return;
            }
            if append {
                sys::col_append_str(cinfo, column, text.as_ptr());
            } else {
                sys::col_add_str(cinfo, column, text.as_ptr());
            }
        }
    }

    /// Whether the protocol runs as a post-dissector for this packet: after
    /// all other dissection, over the whole frame. The runtime then leaves
    /// the Protocol column alone and appends the Info text.
    pub fn is_postdissector(&self) -> bool {
        self.post
    }

    /// Whether this is the first time Wireshark dissects this packet.
    ///
    /// Wireshark dissects packets again (when one is selected, filtered or
    /// a capture is reloaded); state that follows the conversation, such as
    /// a request awaiting its response, is updated on the first pass only.
    pub fn is_first_pass(&self) -> bool {
        self.pinfo.is_none_or(|pinfo| {
            // SAFETY: `pinfo` and its frame data belong to the running callback.
            unsafe {
                let frame = pinfo.as_ref().fd;
                frame.is_null() || frame_flags(&*frame).visited() == 0
            }
        })
    }

    /// Runs `f` on this conversation's `T`, created with `T::default()` the
    /// first time; `None` when the packet belongs to no conversation.
    ///
    /// A conversation is Wireshark's: the packets between one pair of
    /// addresses and ports. Values are kept per protocol and per type, and
    /// dropped when Wireshark opens another capture.
    pub fn with_conversation<T: Default + Send + 'static, R>(
        &mut self,
        f: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        let pinfo = self.pinfo?;
        // SAFETY: `pinfo` belongs to the running callback.
        let conversation =
            NonNull::new(unsafe { sys::find_or_create_conversation(pinfo.as_ptr()) })?;
        // SAFETY: Wireshark returned a live conversation.
        let key = (
            unsafe { conversation.as_ref().conv_index },
            TypeId::of::<T>(),
        );
        let lock = || {
            self.protocol
                .conversations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        };
        // Taken out while `f` runs, so `f` may use the packet freely.
        let mut value = lock()
            .remove(&key)
            .and_then(|value| value.downcast::<T>().ok())
            .unwrap_or_default();
        let result = f(&mut value);
        lock().insert(key, value);
        Some(result)
    }

    /// Publishes `value` to the protocol's tap, named like its
    /// [`FILTER_NAME`](crate::Dissector::FILTER_NAME), for the plugin's
    /// [`Tap`](crate::Tap)s to read with
    /// [`TapPacket::data`](crate::TapPacket::data).
    pub fn tap<T: Any + Send>(&mut self, value: T) {
        let Some(pinfo) = self.pinfo else {
            return;
        };
        let frame = self.frame_number();
        let mut tapped = self
            .protocol
            .tapped
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if tapped.0 != frame {
            // Listeners consumed the previous frame's values when its
            // dissection ended.
            *tapped = (frame, Vec::new());
        }
        let value: Box<Box<dyn Any + Send>> = Box::new(Box::new(value));
        let data = core::ptr::from_ref::<Box<dyn Any + Send>>(&value).cast::<core::ffi::c_void>();
        tapped.1.push(value);
        // SAFETY: the value stays boxed in `tapped` until the next frame,
        // after the listeners have read it.
        unsafe { sys::tap_queue_packet(self.protocol.tap, pinfo.as_ptr(), data) };
    }

    /// Reports the expert finding `name` (registered in
    /// [`Dissector::EXPERTS`](crate::Dissector::EXPERTS)) with its summary.
    ///
    /// # Errors
    ///
    /// [`PacketFieldError::UnknownField`] when the protocol registers no
    /// such finding.
    pub fn add_expert(&mut self, name: &str) -> Result<(), PacketFieldError> {
        self.expert_with(name, None)
    }

    /// Reports the expert finding `name` with `text` instead of its summary.
    /// Text after an interior NUL is dropped.
    ///
    /// # Errors
    ///
    /// As [`add_expert`](Self::add_expert).
    pub fn add_expert_text(&mut self, name: &str, text: &str) -> Result<(), PacketFieldError> {
        self.expert_with(name, Some(text))
    }

    fn expert_with(&mut self, name: &str, text: Option<&str>) -> Result<(), PacketFieldError> {
        let field = self.protocol.expert(name)?.field;
        let Some(pinfo) = self.pinfo else {
            return Ok(());
        };
        let item = self
            .tree()
            .ok()
            .and(self.item)
            .map_or(core::ptr::null_mut(), NonNull::as_ptr);
        // SAFETY: `pinfo` and `item` belong to the running callback, and
        // `field` is the registered entry's storage, live for the process.
        unsafe {
            match text {
                None => {
                    sys::expert_add_info(pinfo.as_ptr(), item, field.as_ptr());
                }
                Some(text) => {
                    let text = CString::new(text.split('\0').next().unwrap_or_default())
                        .unwrap_or_default();
                    sys::expert_add_info_format(
                        pinfo.as_ptr(),
                        item,
                        field.as_ptr(),
                        c"%s".as_ptr(),
                        text.as_ptr(),
                    );
                }
            }
        }
        Ok(())
    }

    /// Whether Wireshark asked for a protocol tree for this packet. Tree
    /// insertions return [`PacketFieldError::NoTree`] when it did not.
    pub fn has_tree(&self) -> bool {
        self.parent.is_some()
    }

    /// The protocol's subtree, created with its tree item the first time.
    fn tree(&mut self) -> Result<NonNull<sys::proto_tree>, PacketFieldError> {
        if let Some(tree) = self.tree {
            return Ok(tree);
        }
        let parent = self.parent.ok_or(PacketFieldError::NoTree)?;
        // SAFETY: `parent` and `tvb` belong to the running callback, and
        // `proto`/`ett` were registered for this protocol.
        let (item, tree) = unsafe {
            let item = sys::proto_tree_add_item(
                parent.as_ptr(),
                self.protocol.proto,
                self.tvb.as_ptr(),
                0,
                -1,
                sys::ENC_NA,
            );
            let tree = sys::proto_item_add_subtree(item, self.protocol.ett);
            (NonNull::new(item), NonNull::new(tree))
        };
        self.item = item;
        self.tree = tree;
        tree.ok_or(PacketFieldError::NoTree)
    }

    /// Marks the packet as this protocol's: its Protocol column, and its
    /// tree item covering `size` bytes.
    pub(crate) fn accept(&mut self, size: usize) {
        if !self.post {
            self.column(
                sys::COL_PROTOCOL as c_int,
                self.protocol.short_name.to_str().unwrap_or_default(),
                false,
            );
        }
        if self.tree().is_ok()
            && let Some(item) = self.item
            && let Ok(size) = c_int::try_from(size)
        {
            // SAFETY: `item` was created during this callback.
            unsafe { sys::proto_item_set_len(item.as_ptr(), size) };
        }
    }

    /// Adds the registered field `field` over `length` bytes at `offset`,
    /// decoded by Wireshark from the field's type and `encoding`.
    ///
    /// `field` is the field's abbreviation, with or without the protocol's
    /// `<filter>.` prefix.
    ///
    /// # Errors
    ///
    /// [`PacketFieldError::UnknownField`], [`PacketFieldError::OutOfBounds`]
    /// or [`PacketFieldError::NoTree`].
    pub fn add_item(
        &mut self,
        field: &str,
        offset: usize,
        length: usize,
        encoding: Encoding,
    ) -> Result<(), PacketFieldError> {
        let registered = self.protocol.field(field)?;
        let id = registered.id;
        if !length_fits(registered.kind, length) {
            return Err(PacketFieldError::WrongLength);
        }
        let (offset, length) = self.range(offset, length)?;
        let tree = self.tree()?;
        // SAFETY: the field is registered, the range is captured, and the
        // tree and buffer belong to the running callback.
        unsafe {
            sys::proto_tree_add_item(
                tree.as_ptr(),
                id,
                self.tvb.as_ptr(),
                offset,
                length,
                encoding.0,
            );
        }
        Ok(())
    }

    /// Adds an unsigned integer field registered as `U8` to `U32` with
    /// `value`, over its width at `offset`.
    ///
    /// # Errors
    ///
    /// [`PacketFieldError::UnsupportedFieldType`] for another field type,
    /// [`PacketFieldError::ValueOutOfRange`] when `value` exceeds the width,
    /// and the errors of [`add_item`](Self::add_item).
    pub fn add_uint(
        &mut self,
        field: &str,
        offset: usize,
        value: u32,
    ) -> Result<(), PacketFieldError> {
        let (id, width) = self.integer_field(field, FieldType::is_unsigned)?;
        if width == 8 {
            return Err(PacketFieldError::UnsupportedFieldType);
        }
        if width < 4 && value >> (width * 8) != 0 {
            return Err(PacketFieldError::ValueOutOfRange);
        }
        let (offset, width) = self.range(offset, width)?;
        let tree = self.tree()?;
        // SAFETY: as in `add_item`.
        unsafe {
            sys::proto_tree_add_uint(tree.as_ptr(), id, self.tvb.as_ptr(), offset, width, value)
        };
        Ok(())
    }

    /// Adds a signed integer field registered as `I8` to `I32`.
    ///
    /// # Errors
    ///
    /// As [`add_uint`](Self::add_uint).
    pub fn add_int(
        &mut self,
        field: &str,
        offset: usize,
        value: i32,
    ) -> Result<(), PacketFieldError> {
        let (id, width) = self.integer_field(field, FieldType::is_signed)?;
        if width == 8 {
            return Err(PacketFieldError::UnsupportedFieldType);
        }
        if width < 4 {
            let bits = width * 8;
            let (min, max) = (-(1i32 << (bits - 1)), (1i32 << (bits - 1)) - 1);
            if !(min..=max).contains(&value) {
                return Err(PacketFieldError::ValueOutOfRange);
            }
        }
        let (offset, width) = self.range(offset, width)?;
        let tree = self.tree()?;
        // SAFETY: as in `add_item`.
        unsafe {
            sys::proto_tree_add_int(tree.as_ptr(), id, self.tvb.as_ptr(), offset, width, value)
        };
        Ok(())
    }

    /// Adds a field registered as `U64`.
    ///
    /// # Errors
    ///
    /// As [`add_uint`](Self::add_uint).
    pub fn add_uint64(
        &mut self,
        field: &str,
        offset: usize,
        value: u64,
    ) -> Result<(), PacketFieldError> {
        let (id, width) = self.integer_field(field, FieldType::is_unsigned)?;
        if width != 8 {
            return Err(PacketFieldError::UnsupportedFieldType);
        }
        let (offset, width) = self.range(offset, width)?;
        let tree = self.tree()?;
        // SAFETY: as in `add_item`.
        unsafe {
            sys::proto_tree_add_uint64(tree.as_ptr(), id, self.tvb.as_ptr(), offset, width, value)
        };
        Ok(())
    }

    /// Adds a field registered as `I64`.
    ///
    /// # Errors
    ///
    /// As [`add_uint`](Self::add_uint).
    pub fn add_int64(
        &mut self,
        field: &str,
        offset: usize,
        value: i64,
    ) -> Result<(), PacketFieldError> {
        let (id, width) = self.integer_field(field, FieldType::is_signed)?;
        if width != 8 {
            return Err(PacketFieldError::UnsupportedFieldType);
        }
        let (offset, width) = self.range(offset, width)?;
        let tree = self.tree()?;
        // SAFETY: as in `add_item`.
        unsafe {
            sys::proto_tree_add_int64(tree.as_ptr(), id, self.tvb.as_ptr(), offset, width, value)
        };
        Ok(())
    }

    /// Adds every field of a decoded header; see [`Header::add_to`].
    ///
    /// # Errors
    ///
    /// The first error an insertion returns.
    pub fn add_header<H: Header>(&mut self, header: &H) -> Result<(), PacketFieldError> {
        header.add_to(self)
    }

    fn integer_field(
        &self,
        field: &str,
        signedness: fn(FieldType) -> bool,
    ) -> Result<(c_int, usize), PacketFieldError> {
        let field = self.protocol.field(field)?;
        match field.kind.width() {
            Some(width) if signedness(field.kind) => Ok((field.id, width)),
            _ => Err(PacketFieldError::UnsupportedFieldType),
        }
    }

    fn range(&self, offset: usize, length: usize) -> Result<(c_int, c_int), PacketFieldError> {
        let end = offset
            .checked_add(length)
            .ok_or(PacketFieldError::OutOfBounds)?;
        if end > self.captured_len() {
            return Err(PacketFieldError::OutOfBounds);
        }
        let offset = c_int::try_from(offset).map_err(|_| PacketFieldError::OutOfBounds)?;
        let length = c_int::try_from(length).map_err(|_| PacketFieldError::OutOfBounds)?;
        Ok((offset, length))
    }
}

/// Whether Wireshark takes `length` bytes for a field of `kind`; it throws
/// on one it does not.
fn length_fits(kind: FieldType, length: usize) -> bool {
    match kind {
        FieldType::Ipv4 => length == 4,
        FieldType::Ipv6 => length == 16,
        FieldType::Ether => length == 6,
        FieldType::Bool => (1..=8).contains(&length),
        kind => kind
            .width()
            .is_none_or(|width| (1..=width).contains(&length)),
    }
}

/// How Wireshark decodes a field's bytes, its `ENC_*` flags.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Encoding(u32);

impl Encoding {
    /// Big-endian (network order) integers.
    pub const BIG_ENDIAN: Self = Self(sys::ENC_BIG_ENDIAN);
    /// Little-endian integers.
    pub const LITTLE_ENDIAN: Self = Self(sys::ENC_LITTLE_ENDIAN);
    /// No encoding: byte arrays, addresses and labels.
    pub const NA: Self = Self(sys::ENC_NA);
    /// ASCII text.
    pub const ASCII: Self = Self(sys::ENC_ASCII);
    /// UTF-8 text.
    pub const UTF_8: Self = Self(sys::ENC_UTF_8);

    /// Raw `ENC_*` flags, combined with `|` in C.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw `ENC_*` flags.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for Encoding {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A field could not be added to the protocol tree.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketFieldError {
    /// Wireshark did not ask for a tree for this packet.
    NoTree,
    /// The protocol registers no field by that name.
    UnknownField,
    /// The field's registered type does not fit the operation.
    UnsupportedFieldType,
    /// The range is outside the captured bytes.
    OutOfBounds,
    /// The value does not fit the field's width.
    ValueOutOfRange,
    /// The length does not fit the field's type (an integer wider than its
    /// width or empty, an address not of its size).
    WrongLength,
}

impl fmt::Display for PacketFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoTree => "wireshark did not ask for a protocol tree",
            Self::UnknownField => "the protocol registers no such field",
            Self::UnsupportedFieldType => "the field's type does not fit the operation",
            Self::OutOfBounds => "the range is outside the captured packet",
            Self::ValueOutOfRange => "the value does not fit the field's width",
            Self::WrongLength => "the length does not fit the field's type",
        })
    }
}

impl core::error::Error for PacketFieldError {}

/// `frame` with its bitfields where the binding's accessors read them.
///
/// bindgen packs `frame_data`'s `unsigned int` bitfields right after the
/// narrower field before them, as GCC does; MSVC starts them at the next
/// `unsigned int` boundary, so on MSVC targets the unit is copied from there.
#[cfg(target_env = "msvc")]
fn frame_flags(frame: &sys::frame_data) -> sys::frame_data {
    let packed = core::mem::offset_of!(sys::frame_data, _bitfield_1);
    let msvc = packed.next_multiple_of(core::mem::align_of::<core::ffi::c_uint>());
    // SAFETY: a plain C struct, copied whole; the unit's bytes lie inside it
    // (the next field is 8-aligned in both layouts).
    unsafe {
        let mut copy = core::ptr::read(frame);
        core::ptr::copy_nonoverlapping(
            core::ptr::from_ref(frame).cast::<u8>().add(msvc),
            core::ptr::from_mut(&mut copy._bitfield_1).cast::<u8>(),
            core::mem::size_of_val(&copy._bitfield_1),
        );
        copy
    }
}

/// `frame`: the binding's layout is the compiler's.
#[cfg(not(target_env = "msvc"))]
fn frame_flags(frame: &sys::frame_data) -> &sys::frame_data {
    frame
}
