//! The C callbacks of what a plugin registers at run time. Wireshark calls
//! a display-filter function, a file format's open routine and a codec's
//! init with no data pointer, so each run-time registration takes a slot:
//! a callback monomorphised for the plugin and the slot's index, which
//! finds what was registered there.

use super::PluginStatic;
use super::codecs;
#[cfg(file_type_plugins)]
use super::file_types;
use super::filters;

/// How many run-time registrations of each kind a plugin holds; more are
/// skipped and reported.
pub(crate) const COUNT: usize = 32;

/// `[callback::<P, 0>, ..., callback::<P, 31>]` as `ty`.
macro_rules! each_slot {
    ($callback:ident::<$plugin:ident> as $ty:ty) => {
        each_slot!(@ $callback $plugin $ty [
            0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
            16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        ])
    };
    (@ $callback:ident $plugin:ident $ty:ty [$($index:literal)*]) => {
        [$($callback::<$plugin, $index> as $ty),*]
    };
}

/// A plugin's slot callbacks, one array per data-less callback type.
#[derive(Debug)]
pub struct Slots {
    pub(crate) filters: [filters::Function; COUNT],
    #[cfg(file_type_plugins)]
    pub(crate) file_types: [file_types::Open; COUNT],
    pub(crate) codecs: codecs::InitSlots,
}

impl Slots {
    /// The slots of the plugin `P` names.
    pub const fn of<P: PluginStatic>() -> Self {
        use codecs::{init_slot as codec, legacy_init_slot as legacy_codec};
        #[cfg(file_type_plugins)]
        use file_types::open_slot as open;
        use filters::slot as filter;
        Self {
            filters: each_slot!(filter::<P> as filters::Function),
            #[cfg(file_type_plugins)]
            file_types: each_slot!(open::<P> as file_types::Open),
            codecs: codecs::InitSlots {
                context: each_slot!(codec::<P> as codecs::ContextInit),
                legacy: each_slot!(legacy_codec::<P> as codecs::LegacyInit),
            },
        }
    }
}
