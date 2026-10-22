//! A [`Dissector`] as the type-erased table of functions the runtime calls.

use crate::dissector::{Binding, Dissector, TcpFraming};
use crate::expert::Expert;
use crate::header::{FieldInfo, Header};
use crate::packet::PacketView;
use crate::prefs::{Declaration, PreferenceMap, Preferences};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

/// A protocol's typed preferences, erased so one runtime serves every protocol.
pub(crate) type Erased = dyn Any + Send + Sync;

/// One protocol of a plugin, as the type-erased functions of its [`Dissector`].
#[derive(Debug)]
pub struct Protocol {
    pub(crate) name: &'static str,
    pub(crate) short_name: &'static str,
    pub(crate) filter_name: &'static str,
    pub(crate) experts: &'static [Expert],
    pub(crate) declarations: fn() -> Vec<Declaration>,
    pub(crate) fields: fn() -> &'static [FieldInfo],
    pub(crate) framing: fn() -> Option<TcpFraming>,
    pub(crate) load: fn(&PreferenceMap) -> Option<Arc<Erased>>,
    pub(crate) dissect_on: fn(&Erased) -> Vec<Binding>,
    pub(crate) dissect: fn(&Erased, &mut PacketView<'_>) -> Option<usize>,
}

impl Protocol {
    /// The protocol `D` describes.
    pub const fn of<D: Dissector>() -> Self {
        Self {
            name: D::NAME,
            short_name: D::SHORT_NAME,
            filter_name: D::FILTER_NAME,
            experts: D::EXPERTS,
            declarations: <D::Preferences as Preferences>::declarations,
            fields: <D::Header as Header>::fields,
            framing: D::tcp_framing,
            load: load::<D>,
            dissect_on: dissect_on::<D>,
            dissect: dissect::<D>,
        }
    }
}

fn load<D: Dissector>(values: &PreferenceMap) -> Option<Arc<Erased>> {
    let preferences = D::Preferences::from_values(values).ok()?;
    Some(Arc::new(preferences))
}

fn dissect_on<D: Dissector>(preferences: &Erased) -> Vec<Binding> {
    preferences
        .downcast_ref::<D::Preferences>()
        .map(D::dissect_on)
        .unwrap_or_default()
}

fn dissect<D: Dissector>(preferences: &Erased, packet: &mut PacketView<'_>) -> Option<usize> {
    let preferences = preferences.downcast_ref::<D::Preferences>()?;
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
