//! A protocol as the type-erased table the runtime calls: a [`Dissector`]
//! known at compile time, or a [`DynamicDissector`] described at run time.

use crate::dissector::{Binding, Dissector};
use crate::dynamic::{DynamicDissector, ProtocolSpec};
use crate::expert::Expert;
use crate::header::{FieldInfo, Header};
use crate::packet::PacketView;
use crate::prefs::{Declaration, PreferenceMap, Preferences};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::marker::PhantomData;

/// A protocol's typed preferences, erased so one runtime serves every protocol.
pub(crate) type Erased = dyn Any + Send + Sync;

/// What the runtime asks of a protocol once it is registered.
pub(crate) trait Implementation: Send + Sync {
    fn declarations(&self) -> Vec<Declaration>;
    fn fields(&self) -> &'static [FieldInfo];
    /// The fixed header length of messages framed over TCP, if framed.
    fn framing_header(&self) -> Option<usize>;
    fn message_len(&self, header: &[u8]) -> Option<usize>;
    fn load(&self, values: &PreferenceMap) -> Option<Arc<Erased>>;
    fn dissect_on(&self, state: &Erased) -> Vec<Binding>;
    fn dissect(&self, state: &Erased, packet: &mut PacketView<'_>) -> Option<usize>;
}

/// One protocol of a plugin: its names, and the table of what it does.
pub struct Protocol {
    pub(crate) name: &'static str,
    pub(crate) short_name: &'static str,
    pub(crate) filter_name: &'static str,
    pub(crate) experts: &'static [Expert],
    pub(crate) imp: &'static dyn Implementation,
}

impl core::fmt::Debug for Protocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Protocol")
            .field("name", &self.name)
            .field("short_name", &self.short_name)
            .field("filter_name", &self.filter_name)
            .finish_non_exhaustive()
    }
}

impl Protocol {
    /// The protocol `D` describes; what `plugin!(dissectors = [..])` builds.
    #[doc(hidden)]
    pub const fn of<D: Dissector>() -> Self {
        Self {
            name: D::NAME,
            short_name: D::SHORT_NAME,
            filter_name: D::FILTER_NAME,
            experts: D::EXPERTS,
            imp: const { &Typed::<D>(PhantomData) },
        }
    }

    /// The protocol `spec` describes, dissected by `dissector`. Both live
    /// for the process, as everything Wireshark registers does.
    pub fn dynamic(spec: ProtocolSpec, dissector: impl DynamicDissector) -> Self {
        let ProtocolSpec {
            name,
            short_name,
            filter_name,
            fields,
            experts,
            preferences,
        } = spec;
        Self {
            name,
            short_name,
            filter_name,
            experts: experts.leak(),
            imp: Box::leak(Box::new(Described {
                fields: fields.leak(),
                preferences,
                dissector,
            })),
        }
    }
}

/// A [`Dissector`]'s functions, monomorphised.
struct Typed<D>(PhantomData<fn() -> D>);

impl<D: Dissector> Implementation for Typed<D> {
    fn declarations(&self) -> Vec<Declaration> {
        <D::Preferences as Preferences>::declarations()
    }

    fn fields(&self) -> &'static [FieldInfo] {
        <D::Header as Header>::fields()
    }

    fn framing_header(&self) -> Option<usize> {
        D::tcp_framing().map(|framing| framing.header_len())
    }

    fn message_len(&self, header: &[u8]) -> Option<usize> {
        D::tcp_framing()?.message_len(header)
    }

    fn load(&self, values: &PreferenceMap) -> Option<Arc<Erased>> {
        let preferences = D::Preferences::from_values(values).ok()?;
        Some(Arc::new(preferences))
    }

    fn dissect_on(&self, state: &Erased) -> Vec<Binding> {
        state
            .downcast_ref::<D::Preferences>()
            .map(D::dissect_on)
            .unwrap_or_default()
    }

    fn dissect(&self, state: &Erased, packet: &mut PacketView<'_>) -> Option<usize> {
        let preferences = state.downcast_ref::<D::Preferences>()?;
        let result = D::dissect(preferences, packet)?;
        packet.accept(result.size);
        // A field that cannot be added (no tree, a short capture) leaves the
        // rest of the dissection standing, as Wireshark's own dissectors do.
        let _ = packet.add_header(&result.header);
        if let Some(info) = &result.info {
            if packet.is_postdissector() {
                packet.append_info(info);
            } else {
                packet.set_info(info);
            }
        }
        Some(result.size)
    }
}

/// A [`DynamicDissector`] and the fields it was registered with.
struct Described<T> {
    fields: &'static [FieldInfo],
    preferences: Vec<Declaration>,
    dissector: T,
}

impl<T: DynamicDissector> Implementation for Described<T> {
    fn declarations(&self) -> Vec<Declaration> {
        self.preferences.clone()
    }

    fn fields(&self) -> &'static [FieldInfo] {
        self.fields
    }

    fn framing_header(&self) -> Option<usize> {
        self.dissector.tcp_header_len()
    }

    fn message_len(&self, header: &[u8]) -> Option<usize> {
        self.dissector.message_len(header)
    }

    fn load(&self, values: &PreferenceMap) -> Option<Arc<Erased>> {
        let preferences = self.dissector.preferences(values)?;
        Some(Arc::new(preferences))
    }

    fn dissect_on(&self, state: &Erased) -> Vec<Binding> {
        state
            .downcast_ref::<T::Preferences>()
            .map(|preferences| self.dissector.dissect_on(preferences))
            .unwrap_or_default()
    }

    fn dissect(&self, state: &Erased, packet: &mut PacketView<'_>) -> Option<usize> {
        let preferences = state.downcast_ref::<T::Preferences>()?;
        let size = self.dissector.dissect(preferences, packet)?;
        packet.accept(size);
        Some(size)
    }
}
