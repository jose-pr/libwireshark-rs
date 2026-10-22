//! The C callbacks of what a plugin registers at run time. Wireshark calls
//! a display-filter function with no data pointer, so each run-time
//! registration takes a slot: a callback monomorphised for the plugin and
//! the slot's index, which finds what was registered there.

use super::PluginStatic;
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
}

impl Slots {
    /// The slots of the plugin `P` names.
    pub const fn of<P: PluginStatic>() -> Self {
        use filters::slot as filter;
        Self {
            filters: each_slot!(filter::<P> as filters::Function),
        }
    }
}
