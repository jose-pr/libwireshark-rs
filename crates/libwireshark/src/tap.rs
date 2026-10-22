//! Tap listeners: statistics over packets, run by `tshark -z <name>`.

use crate::sys;
use alloc::string::String;
use core::any::Any;
use core::ffi::{CStr, c_char};
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::time::Duration;

/// A statistic over the packets of one tap, offered as `tshark -z NAME` or
/// `tshark -z NAME,FILTER`. A plugin lists its taps with
/// [`plugin!`](crate::plugin).
///
/// ```no_run
/// use libwireshark::{Tap, TapPacket};
///
/// #[derive(Default)]
/// struct UdpBytes(u64);
///
/// impl Tap for UdpBytes {
///     const NAME: &'static str = "udpbytes";
///     const TAP: &'static str = "udp";
///
///     fn packet(&mut self, packet: &TapPacket<'_>) {
///         self.0 += u64::from(packet.len());
///     }
///
///     fn draw(&self) -> String {
///         format!("UDP bytes: {}\n", self.0)
///     }
/// }
///
/// libwireshark::plugin!(dissectors = [], taps = [UdpBytes]);
/// ```
pub trait Tap: Default + Send + 'static {
    /// The `-z` name.
    const NAME: &'static str;
    /// The tap listened to: one of Wireshark's (`"frame"`, `"udp"`, `"tcp"`,
    /// `"ip"`, ...) or the `FILTER_NAME` of a protocol in the same plugin,
    /// which publishes values with [`PacketView::tap`](crate::PacketView::tap).
    const TAP: &'static str;

    /// Counts one packet the tap reported and the filter, if any, matched.
    fn packet(&mut self, packet: &TapPacket<'_>);

    /// The statistic's report, which tshark prints when the capture ends.
    fn draw(&self) -> String;

    /// Starts over, as when Wireshark reloads the capture. The default
    /// returns to `Self::default()`.
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// One packet a tap reported: its frame, addresses, and the value a
/// protocol of the same plugin published.
pub struct TapPacket<'packet> {
    pinfo: NonNull<sys::packet_info>,
    data: Option<&'packet (dyn Any + Send)>,
    _callback: PhantomData<&'packet sys::packet_info>,
}

impl core::fmt::Debug for TapPacket<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TapPacket")
            .field("frame_number", &self.frame_number())
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl<'packet> TapPacket<'packet> {
    /// # Safety
    ///
    /// `pinfo` is the running tap callback's packet info, valid until it
    /// returns.
    pub(crate) unsafe fn from_raw(
        pinfo: NonNull<sys::packet_info>,
        data: Option<&'packet (dyn Any + Send)>,
    ) -> Self {
        Self {
            pinfo,
            data,
            _callback: PhantomData,
        }
    }

    fn info(&self) -> &sys::packet_info {
        // SAFETY: `pinfo` is valid for `'packet` (see `from_raw`).
        unsafe { self.pinfo.as_ref() }
    }

    /// The packet's frame number, counted from 1.
    pub fn frame_number(&self) -> u32 {
        self.info().num
    }

    /// The frame's length on the wire.
    pub fn len(&self) -> u32 {
        let frame = self.info().fd;
        // SAFETY: the frame data belongs to the packet being tapped.
        unsafe { frame.as_ref() }.map_or(0, |frame| frame.pkt_len)
    }

    /// Whether the frame is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// When the packet was captured, since the Unix epoch.
    pub fn time(&self) -> Duration {
        let stamp = self.info().abs_ts;
        let secs = u64::try_from(stamp.secs).unwrap_or(0);
        let nanos = u32::try_from(stamp.nsecs).unwrap_or(0);
        Duration::new(secs, nanos)
    }

    /// The transport source port; 0 when there is none.
    pub fn src_port(&self) -> u32 {
        self.info().srcport
    }

    /// The transport destination port; 0 when there is none.
    pub fn dst_port(&self) -> u32 {
        self.info().destport
    }

    /// The packet's source address as Wireshark shows it.
    pub fn source(&self) -> String {
        address_text(&self.info().src)
    }

    /// The packet's destination address as Wireshark shows it.
    pub fn destination(&self) -> String {
        address_text(&self.info().dst)
    }

    /// The value a protocol of this plugin published with
    /// [`PacketView::tap`](crate::PacketView::tap), when it is a `T`.
    /// `None` on Wireshark's own taps.
    pub fn data<T: 'static>(&self) -> Option<&'packet T> {
        let data: &'packet (dyn Any + Send) = self.data?;
        data.downcast_ref()
    }
}

fn address_text(address: &sys::address) -> String {
    let mut buffer = [0 as c_char; 256];
    // SAFETY: the buffer's length is passed; Wireshark NUL-terminates within it.
    unsafe {
        sys::address_to_str_buf(address, buffer.as_mut_ptr(), buffer.len() as _);
        CStr::from_ptr(buffer.as_ptr())
    }
    .to_string_lossy()
    .into_owned()
}
