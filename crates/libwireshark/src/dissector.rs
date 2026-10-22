use crate::bindings;
use crate::utils::get_static_cstring;
use std::collections::HashMap;
use std::ffi::CString;
use std::marker::PhantomData;
use std::ptr::NonNull;

/// A packet buffer and its optional dissection context, valid only for one
/// Wireshark dissector callback.
pub struct PacketView<'packet> {
    tvb: NonNull<bindings::tvbuff_t>,
    pinfo: Option<NonNull<bindings::packet_info>>,
    tree: Option<NonNull<bindings::proto_tree>>,
    field_ids: HashMap<&'static str, (i32, i32)>,
    _callback: PhantomData<&'packet mut ()>,
    _not_send: PhantomData<*mut ()>,
}

impl<'packet> PacketView<'packet> {
    /// Creates a callback-scoped view from Wireshark-owned pointers.
    ///
    /// # Safety
    /// `tvb` and any non-null context pointers must remain valid for the
    /// returned view's lifetime, as guaranteed by the dissector callback API.
    pub(crate) unsafe fn from_raw(
        tvb: *mut bindings::tvbuff_t,
        pinfo: *mut bindings::packet_info,
        tree: *mut bindings::proto_tree,
        field_ids: HashMap<&'static str, (i32, i32)>,
    ) -> Option<Self> {
        Some(Self {
            tvb: NonNull::new(tvb)?,
            pinfo: NonNull::new(pinfo),
            tree: NonNull::new(tree),
            field_ids,
            _callback: PhantomData,
            _not_send: PhantomData,
        })
    }

    /// Returns the number of bytes captured for this packet buffer.
    pub fn captured_len(&self) -> usize {
        // SAFETY: `tvb` is non-null and remains valid for the PacketView callback lifetime.
        unsafe { bindings::tvb_captured_length(self.tvb.as_ptr()) as usize }
    }

    /// Returns the packet buffer's reported length.
    pub fn reported_len(&self) -> usize {
        // SAFETY: `tvb` is non-null and remains valid for the PacketView callback lifetime.
        unsafe { bindings::tvb_reported_length(self.tvb.as_ptr()) as usize }
    }

    /// Reads one captured byte, returning `None` when the offset is out of
    /// bounds or cannot be represented by the native API.
    pub fn get_u8(&self, offset: usize) -> Option<u8> {
        self.read_unsigned(offset, 1, false)
            .map(|value| value as u8)
    }

    /// Reads a captured 16-bit unsigned integer in network byte order.
    pub fn get_u16_be(&self, offset: usize) -> Option<u16> {
        self.read_unsigned(offset, 2, false)
            .map(|value| value as u16)
    }

    /// Reads a captured 16-bit unsigned integer in little-endian byte order.
    pub fn get_u16_le(&self, offset: usize) -> Option<u16> {
        self.read_unsigned(offset, 2, true)
            .map(|value| value as u16)
    }

    /// Reads a captured 24-bit unsigned integer in network byte order.
    pub fn get_u24_be(&self, offset: usize) -> Option<u32> {
        self.read_unsigned(offset, 3, false)
            .map(|value| value as u32)
    }

    /// Reads a captured 24-bit unsigned integer in little-endian byte order.
    pub fn get_u24_le(&self, offset: usize) -> Option<u32> {
        self.read_unsigned(offset, 3, true)
            .map(|value| value as u32)
    }

    /// Reads a captured 32-bit unsigned integer in network byte order.
    pub fn get_u32_be(&self, offset: usize) -> Option<u32> {
        self.read_unsigned(offset, 4, false)
            .map(|value| value as u32)
    }

    /// Reads a captured 32-bit unsigned integer in little-endian byte order.
    pub fn get_u32_le(&self, offset: usize) -> Option<u32> {
        self.read_unsigned(offset, 4, true)
            .map(|value| value as u32)
    }

    /// Reads a captured 64-bit unsigned integer in network byte order.
    pub fn get_u64_be(&self, offset: usize) -> Option<u64> {
        self.read_unsigned(offset, 8, false)
    }

    /// Reads a captured 64-bit unsigned integer in little-endian byte order.
    pub fn get_u64_le(&self, offset: usize) -> Option<u64> {
        self.read_unsigned(offset, 8, true)
    }

    /// Reads a captured signed byte.
    pub fn get_i8(&self, offset: usize) -> Option<i8> {
        self.read_signed(offset, 1, false).map(|value| value as i8)
    }

    /// Reads a captured 16-bit signed integer in network byte order.
    pub fn get_i16_be(&self, offset: usize) -> Option<i16> {
        self.read_signed(offset, 2, false).map(|value| value as i16)
    }

    /// Reads a captured 16-bit signed integer in little-endian byte order.
    pub fn get_i16_le(&self, offset: usize) -> Option<i16> {
        self.read_signed(offset, 2, true).map(|value| value as i16)
    }

    /// Reads a captured 24-bit signed integer in network byte order.
    pub fn get_i24_be(&self, offset: usize) -> Option<i32> {
        self.read_signed(offset, 3, false).map(|value| value as i32)
    }

    /// Reads a captured 24-bit signed integer in little-endian byte order.
    pub fn get_i24_le(&self, offset: usize) -> Option<i32> {
        self.read_signed(offset, 3, true).map(|value| value as i32)
    }

    /// Reads a captured 32-bit signed integer in network byte order.
    pub fn get_i32_be(&self, offset: usize) -> Option<i32> {
        self.read_signed(offset, 4, false).map(|value| value as i32)
    }

    /// Reads a captured 32-bit signed integer in little-endian byte order.
    pub fn get_i32_le(&self, offset: usize) -> Option<i32> {
        self.read_signed(offset, 4, true).map(|value| value as i32)
    }

    /// Reads a captured 64-bit signed integer in network byte order.
    pub fn get_i64_be(&self, offset: usize) -> Option<i64> {
        self.read_signed(offset, 8, false)
    }

    /// Reads a captured 64-bit signed integer in little-endian byte order.
    pub fn get_i64_le(&self, offset: usize) -> Option<i64> {
        self.read_signed(offset, 8, true)
    }

    fn read_unsigned(&self, offset: usize, width: usize, little_endian: bool) -> Option<u64> {
        let end = offset.checked_add(width)?;
        if !(1..=8).contains(&width) || end > self.captured_len() {
            return None;
        }
        let native_offset = i32::try_from(offset).ok()?;
        let mut value = 0u64;
        for index in 0..width {
            let byte_offset = native_offset.checked_add(i32::try_from(index).ok()?)?;
            // SAFETY: The full byte range was checked against captured length and the native API offset range.
            let byte = unsafe { bindings::tvb_get_uint8(self.tvb.as_ptr(), byte_offset) };
            if little_endian {
                value |= u64::from(byte) << (index * 8);
            } else {
                value = (value << 8) | u64::from(byte);
            }
        }
        Some(value)
    }

    fn read_signed(&self, offset: usize, width: usize, little_endian: bool) -> Option<i64> {
        let value = self.read_unsigned(offset, width, little_endian)?;
        let bits = width * 8;
        Some(if bits == 64 {
            value as i64
        } else {
            ((value << (64 - bits)) as i64) >> (64 - bits)
        })
    }

    /// Appends text to the packet's Info column when column information is
    /// available. The C API copies the string during this call.
    pub fn add_info(&mut self, text: &str) -> Result<(), std::ffi::NulError> {
        let Some(mut pinfo) = self.pinfo else {
            return Ok(());
        };
        let c_text = CString::new(text)?;
        // SAFETY: `pinfo` is callback-scoped, and Wireshark copies this valid C string during the call.
        unsafe {
            let pinfo = pinfo.as_mut();
            if !pinfo.cinfo.is_null() {
                bindings::col_add_str(pinfo.cinfo, bindings::COL_INFO, c_text.as_ptr());
            }
        }
        Ok(())
    }

    /// Returns whether Wireshark provided a protocol tree for this callback.
    pub fn has_tree(&self) -> bool {
        self.tree.is_some()
    }

    /// Adds a registered field to the protocol tree using Wireshark's field decoder.
    ///
    /// `encoding` accepts Wireshark `ENC_*` flags from `bindings`. The field's
    /// registered type determines how Wireshark interprets the selected bytes.
    pub fn add_item(
        &mut self,
        field: &str,
        offset: usize,
        length: usize,
        encoding: u32,
    ) -> Result<(), PacketFieldError> {
        let (field_id, _) = self.field(field)?;
        let (tree, offset, length) = self.checked_range(offset, length)?;
        // SAFETY: The registered field and captured range were checked; all native pointers are callback-scoped.
        unsafe {
            bindings::proto_tree_add_item(
                tree.as_ptr(),
                field_id,
                self.tvb.as_ptr(),
                offset,
                length,
                encoding,
            );
        }
        Ok(())
    }

    /// Adds an unsigned integer field registered by this protocol.
    ///
    /// The value is checked against the captured packet range before the
    /// Wireshark tree API is called. Width must match an FT_UINT8, FT_UINT16,
    /// FT_UINT24, or FT_UINT32 field registration.
    pub fn add_uint(
        &mut self,
        field: &str,
        offset: usize,
        width: usize,
        value: u32,
    ) -> Result<(), PacketFieldError> {
        let (field_id, field_type) = self.field(field)?;
        let expected_width = match field_type {
            value if value == bindings::ftenum_FT_UINT8 => 1,
            value if value == bindings::ftenum_FT_UINT16 => 2,
            value if value == bindings::ftenum_FT_UINT24 => 3,
            value if value == bindings::ftenum_FT_UINT32 => 4,
            _ => return Err(PacketFieldError::UnsupportedFieldType),
        };
        if width != expected_width {
            return Err(PacketFieldError::WidthMismatch);
        }
        if u64::from(value) > Self::unsigned_max(width) {
            return Err(PacketFieldError::ValueOutOfRange);
        }
        let (tree, offset, width) = self.checked_range(offset, width)?;
        // SAFETY: The checked field ID and byte range belong to this callback's protocol and tvbuff.
        unsafe {
            bindings::proto_tree_add_uint(
                tree.as_ptr(),
                field_id,
                self.tvb.as_ptr(),
                offset,
                width,
                value,
            );
        }
        Ok(())
    }

    /// Adds a signed integer field registered as FT_INT8, FT_INT16, FT_INT24, or FT_INT32.
    ///
    /// The field type determines the required width. The value and captured
    /// packet range are validated before the Wireshark tree API is called.
    pub fn add_int(
        &mut self,
        field: &str,
        offset: usize,
        width: usize,
        value: i32,
    ) -> Result<(), PacketFieldError> {
        let (field_id, field_type) = self.field(field)?;
        let expected_width = match field_type {
            value if value == bindings::ftenum_FT_INT8 => 1,
            value if value == bindings::ftenum_FT_INT16 => 2,
            value if value == bindings::ftenum_FT_INT24 => 3,
            value if value == bindings::ftenum_FT_INT32 => 4,
            _ => return Err(PacketFieldError::UnsupportedFieldType),
        };
        if width != expected_width {
            return Err(PacketFieldError::WidthMismatch);
        }
        let (minimum, maximum) = Self::signed_range(width);
        if i64::from(value) < minimum || i64::from(value) > maximum {
            return Err(PacketFieldError::ValueOutOfRange);
        }
        let (tree, offset, width) = self.checked_range(offset, width)?;
        // SAFETY: The field type, identifier, and captured byte range were checked above.
        unsafe {
            bindings::proto_tree_add_int(
                tree.as_ptr(),
                field_id,
                self.tvb.as_ptr(),
                offset,
                width,
                value,
            );
        }
        Ok(())
    }

    /// Adds a 64-bit unsigned field registered as FT_UINT64.
    pub fn add_uint64(
        &mut self,
        field: &str,
        offset: usize,
        value: u64,
    ) -> Result<(), PacketFieldError> {
        let (field_id, field_type) = self.field(field)?;
        if field_type != bindings::ftenum_FT_UINT64 {
            return Err(PacketFieldError::UnsupportedFieldType);
        }
        let (tree, offset, width) = self.checked_range(offset, 8)?;
        // SAFETY: The field is FT_UINT64 and the full eight-byte captured range was checked.
        unsafe {
            bindings::proto_tree_add_uint64(
                tree.as_ptr(),
                field_id,
                self.tvb.as_ptr(),
                offset,
                width,
                value,
            );
        }
        Ok(())
    }

    /// Adds a 64-bit signed field registered as FT_INT64.
    pub fn add_int64(
        &mut self,
        field: &str,
        offset: usize,
        value: i64,
    ) -> Result<(), PacketFieldError> {
        let (field_id, field_type) = self.field(field)?;
        if field_type != bindings::ftenum_FT_INT64 {
            return Err(PacketFieldError::UnsupportedFieldType);
        }
        let (tree, offset, width) = self.checked_range(offset, 8)?;
        // SAFETY: The field is FT_INT64 and the full eight-byte captured range was checked.
        unsafe {
            bindings::proto_tree_add_int64(
                tree.as_ptr(),
                field_id,
                self.tvb.as_ptr(),
                offset,
                width,
                value,
            );
        }
        Ok(())
    }

    /// Applies a decoded header struct to the protocol tree.
    pub fn add_header<H: crate::header::Header>(
        &mut self,
        header: &H,
    ) -> Result<(), PacketFieldError> {
        header.add_to(self)
    }

    fn field(&self, field: &str) -> Result<(i32, i32), PacketFieldError> {
        self.field_ids
            .get(field)
            .copied()
            .filter(|(id, _)| *id >= 0)
            .ok_or(PacketFieldError::UnknownField)
    }

    fn checked_range(
        &self,
        offset: usize,
        width: usize,
    ) -> Result<(NonNull<bindings::proto_tree>, i32, i32), PacketFieldError> {
        let tree = self.tree.ok_or(PacketFieldError::NoTree)?;
        let end = offset
            .checked_add(width)
            .ok_or(PacketFieldError::OutOfBounds)?;
        if end > self.captured_len() {
            return Err(PacketFieldError::OutOfBounds);
        }
        let offset = i32::try_from(offset).map_err(|_| PacketFieldError::OutOfBounds)?;
        let width = i32::try_from(width).map_err(|_| PacketFieldError::OutOfBounds)?;
        i32::try_from(end).map_err(|_| PacketFieldError::OutOfBounds)?;
        Ok((tree, offset, width))
    }

    fn unsigned_max(width: usize) -> u64 {
        if width == 8 {
            u64::MAX
        } else {
            (1u64 << (width * 8)) - 1
        }
    }

    fn signed_range(width: usize) -> (i64, i64) {
        let bits = width * 8;
        (-(1i64 << (bits - 1)), (1i64 << (bits - 1)) - 1)
    }
}

/// A checked failure when adding a packet field to the protocol tree.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketFieldError {
    /// Wireshark did not provide a protocol tree for the callback.
    NoTree,
    /// The field abbreviation is not registered by this protocol.
    UnknownField,
    /// The registered field type does not match the requested integer operation.
    UnsupportedFieldType,
    /// The supplied width does not match the registered field type.
    WidthMismatch,
    /// The field width or packet range is invalid.
    OutOfBounds,
    /// The supplied integer cannot be represented by the registered field width.
    ValueOutOfRange,
}

impl std::fmt::Display for PacketFieldError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NoTree => "Wireshark did not provide a protocol tree",
            Self::UnknownField => "the protocol field is not registered",
            Self::UnsupportedFieldType => {
                "the registered field type does not match the integer operation"
            }
            Self::WidthMismatch => "the field width does not match its registered type",
            Self::OutOfBounds => "the field range is outside the captured packet",
            Self::ValueOutOfRange => "the integer does not fit the registered field width",
        })
    }
}

impl std::error::Error for PacketFieldError {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DissectorAdd {
    Uint(&'static str, u32, bool),
}

/// A successfully decoded packet and the data the runtime should publish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DissectResult<H> {
    /// Decoded header values to add to the protocol tree.
    pub header: H,
    /// Number of packet bytes consumed by this dissector.
    pub size: usize,
    /// Optional text to append to Wireshark's Info column.
    pub info: Option<String>,
}

impl<H> DissectResult<H> {
    /// Creates a successful dissection result without Info-column text.
    pub fn new(header: H, size: usize) -> Self {
        Self {
            header,
            size,
            info: None,
        }
    }

    /// Sets the Info-column text published by the runtime.
    pub fn with_info(mut self, info: impl Into<String>) -> Self {
        self.info = Some(info.into());
        self
    }
}

impl DissectorAdd {
    /// Attaches this mapping to a native dissector handle.
    ///
    /// # Safety
    /// `dissector` must be a live handle created by Wireshark for the current
    /// protocol registration.
    pub unsafe fn register(&self, dissector: *mut bindings::dissector_handle) {
        // SAFETY: The caller guarantees a live handle; names are static NUL-terminated strings.
        match self {
            DissectorAdd::Uint(name, val, with_pref) => unsafe {
                if *with_pref {
                    bindings::dissector_add_uint_with_preference(
                        get_static_cstring(name),
                        *val,
                        dissector,
                    );
                } else {
                    bindings::dissector_add_uint(get_static_cstring(name), *val, dissector);
                }
            },
        }
    }

    /// Removes this mapping from a live dissector table.
    ///
    /// # Safety
    /// `dissector` must be a live handle previously registered with this mapping.
    pub unsafe fn unregister(&self, dissector: *mut bindings::dissector_handle) {
        match self {
            DissectorAdd::Uint(name, value, _) => {
                // SAFETY: The caller guarantees this mapping is currently registered.
                unsafe {
                    bindings::dissector_delete_uint(get_static_cstring(name), *value, dissector)
                };
            }
        }
    }
}
