//! The packet a provider's `dissect` is lent: a [`PacketView`] behind the
//! `wireshark_packet` kind.

use guatiao::Status;
use guatiao::library::ProviderError;
use libwireshark::{Encoding, PacketFieldError, PacketView};
use libwireshark_api::Packet;
use std::thread::ThreadId;

/// A [`PacketView`] lent to a provider for one `dissect` call.
pub(crate) struct Lent<'call, 'packet> {
    view: &'call mut PacketView<'packet>,
    /// The dissecting thread: the only one the view may be used from.
    thread: ThreadId,
}

// SAFETY: the view is reached only through `view()`, which answers on the
// thread that lent it, the one dissecting; a slot called from any other
// thread does nothing.
unsafe impl Send for Lent<'_, '_> {}

impl<'call, 'packet> Lent<'call, 'packet> {
    pub(crate) fn new(view: &'call mut PacketView<'packet>) -> Self {
        Self {
            view,
            thread: std::thread::current().id(),
        }
    }

    fn view(&mut self) -> Result<&mut PacketView<'packet>, ProviderError> {
        if std::thread::current().id() == self.thread {
            Ok(self.view)
        } else {
            Err(ProviderError::new(
                Status::GUATIAO_ERR_UNSUPPORTED,
                "the packet is used only from the thread that lent it",
            ))
        }
    }

    fn view_ref(&self) -> Option<&PacketView<'packet>> {
        (std::thread::current().id() == self.thread).then_some(&*self.view)
    }
}

/// A field that cannot be added is an error, except when Wireshark asked
/// for no tree: then there is nothing to add to, and the packet stands.
fn added(result: Result<(), PacketFieldError>) -> Result<(), ProviderError> {
    match result {
        Ok(()) | Err(PacketFieldError::NoTree) => Ok(()),
        Err(error) => Err(refused(error)),
    }
}

fn refused(error: PacketFieldError) -> ProviderError {
    ProviderError::new(Status::GUATIAO_ERR_BAD_VALUE, &error.to_string())
}

fn offset(value: i64) -> Result<usize, ProviderError> {
    usize::try_from(value).map_err(|_| refused(PacketFieldError::OutOfBounds))
}

impl Packet for Lent<'_, '_> {
    fn add_item(
        &mut self,
        field: &str,
        start: i64,
        length: i64,
        little_endian: bool,
    ) -> Result<(), ProviderError> {
        let encoding = if little_endian {
            Encoding::LITTLE_ENDIAN
        } else {
            Encoding::BIG_ENDIAN
        };
        let (start, length) = (offset(start)?, offset(length)?);
        added(self.view()?.add_item(field, start, length, encoding))
    }

    fn add_uint(&mut self, field: &str, start: i64, value: u64) -> Result<(), ProviderError> {
        let start = offset(start)?;
        let view = self.view()?;
        // A field of up to 32 bits takes a u32; a wider one refuses it.
        if let Ok(narrow) = u32::try_from(value) {
            match view.add_uint(field, start, narrow) {
                Err(PacketFieldError::UnsupportedFieldType) => {}
                result => return added(result),
            }
        }
        added(view.add_uint64(field, start, value))
    }

    fn add_int(&mut self, field: &str, start: i64, value: i64) -> Result<(), ProviderError> {
        let start = offset(start)?;
        let view = self.view()?;
        // As in `add_uint`.
        if let Ok(narrow) = i32::try_from(value) {
            match view.add_int(field, start, narrow) {
                Err(PacketFieldError::UnsupportedFieldType) => {}
                result => return added(result),
            }
        }
        added(view.add_int64(field, start, value))
    }

    fn set_info(&mut self, text: &str) {
        if let Ok(view) = self.view() {
            view.set_info(text);
        }
    }

    fn append_info(&mut self, text: &str) {
        if let Ok(view) = self.view() {
            view.append_info(text);
        }
    }

    fn add_expert(&mut self, name: &str, text: &str) -> Result<(), ProviderError> {
        let view = self.view()?;
        added(if text.is_empty() {
            view.add_expert(name)
        } else {
            view.add_expert_text(name, text)
        })
    }

    fn is_first_pass(&self) -> bool {
        self.view_ref().is_some_and(PacketView::is_first_pass)
    }

    fn is_postdissector(&self) -> bool {
        self.view_ref().is_some_and(PacketView::is_postdissector)
    }

    fn frame_number(&self) -> i64 {
        self.view_ref().map_or(0, |view| view.frame_number().into())
    }

    fn src_port(&self) -> i64 {
        self.view_ref().map_or(0, |view| view.src_port().into())
    }

    fn dst_port(&self) -> i64 {
        self.view_ref().map_or(0, |view| view.dst_port().into())
    }
}
