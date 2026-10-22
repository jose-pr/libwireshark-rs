/// Makes this library a Wireshark plugin holding the listed dissectors and taps.
///
/// Write it once, in the root of a `cdylib` crate. It exports the symbols
/// Wireshark's loader reads (`plugin_version`, `plugin_want_major`,
/// `plugin_want_minor`, `plugin_describe`, `plugin_register`) and keeps the
/// plugin's registration state.
///
/// The plugin version is the crate's `CARGO_PKG_VERSION` unless given:
///
/// ```ignore (needs a cdylib crate whose dissectors are defined)
/// libwireshark::plugin!(FooDissector);
/// libwireshark::plugin!(FooDissector, BarDissector);
/// libwireshark::plugin!(dissectors = [FooDissector], taps = [FooStats]);
/// libwireshark::plugin!(dissectors = [FooDissector], filters = [FooFunction]);
/// libwireshark::plugin!(dissectors = [FooDissector], taps = [FooStats], filters = [FooFunction]);
/// libwireshark::plugin!(version = "1.2.0", dissectors = [FooDissector, BarDissector]);
/// ```
///
/// A plugin is built for one Wireshark release line (major.minor), the one
/// `libwireshark-sys` was built against; Wireshark refuses it under another.
#[macro_export]
macro_rules! plugin {
    (
        version = $version:expr,
        dissectors = [$($dissector:ty),* $(,)?]
        $(, taps = [$($tap:ty),* $(,)?])?
        $(, filters = [$($filter:ty),* $(,)?])? $(,)?
    ) => {
        const _: () = {
            struct ThisPlugin;

            impl $crate::__private::PluginStatic for ThisPlugin {
                fn plugin() -> &'static $crate::__private::Plugin {
                    &PLUGIN
                }
            }

            static PLUGIN: $crate::__private::Plugin = $crate::__private::Plugin::new(
                &[$($crate::__private::Protocol::of::<$dissector>()),*],
                &[$($($crate::__private::TapSpec::of::<$tap>()),*)?],
                &[$($($crate::__private::FilterSpec::of::<$filter, ThisPlugin>()),*)?],
            );
            const TAPS: usize = {
                let taps: &[&str] = &[$($(::core::stringify!($tap)),*)?];
                taps.len()
            };
            const FILTERS: usize = {
                let filters: &[&str] = &[$($(::core::stringify!($filter)),*)?];
                filters.len()
            };

            extern "C" fn register_protoinfo() {
                PLUGIN.register_protoinfo($crate::__private::Callbacks {
                    apply: apply_preferences,
                    heuristic,
                    cleanup,
                });
            }

            extern "C" fn register_handoff() {
                PLUGIN.register_handoff();
            }

            extern "C" fn apply_preferences() {
                PLUGIN.apply_preferences();
            }

            extern "C" fn cleanup() {
                PLUGIN.cleanup();
            }

            extern "C" fn heuristic(
                tvb: *mut $crate::sys::tvbuff_t,
                pinfo: *mut $crate::sys::packet_info,
                tree: *mut $crate::sys::proto_tree,
                _data: *mut ::core::ffi::c_void,
            ) -> $crate::__private::HeuristicResult {
                // SAFETY: Wireshark calls this as a heuristic dissector, with
                // the packet's buffer, info and tree.
                let accepted = unsafe { PLUGIN.heuristic(tvb, pinfo, tree) };
                $crate::__private::heuristic_result(accepted)
            }

            extern "C" fn register_taps() {
                PLUGIN.register_taps();
            }

            static PROTO_PLUGIN: $crate::sys::proto_plugin =
                $crate::__private::proto_plugin(register_protoinfo, register_handoff);

            static TAP_PLUGIN: $crate::sys::tap_plugin = $crate::__private::tap_plugin(register_taps);

            extern "C" fn register_filters() {
                PLUGIN.register_filters();
            }

            extern "C" fn deregister_filters() {
                PLUGIN.deregister_filters();
            }

            static DFILTER_PLUGIN: $crate::__private::DfilterPlugin =
                $crate::__private::dfilter_plugin(register_filters, deregister_filters);

            const VERSION: &str = $version;

            #[unsafe(no_mangle)]
            #[used]
            #[allow(non_upper_case_globals)]
            static plugin_version: [u8; VERSION.len() + 1] =
                $crate::__private::nul_terminated::<{ VERSION.len() + 1 }>(VERSION);

            #[unsafe(no_mangle)]
            #[used]
            #[allow(non_upper_case_globals)]
            static plugin_want_major: ::core::ffi::c_int = $crate::__private::WANT_MAJOR;

            #[unsafe(no_mangle)]
            #[used]
            #[allow(non_upper_case_globals)]
            static plugin_want_minor: ::core::ffi::c_int = $crate::__private::WANT_MINOR;

            #[unsafe(no_mangle)]
            extern "C" fn plugin_describe() -> u32 {
                $crate::__private::describe(TAPS, FILTERS)
            }

            #[unsafe(no_mangle)]
            extern "C" fn plugin_register() {
                $crate::__private::register(
                    &PROTO_PLUGIN,
                    &TAP_PLUGIN,
                    &DFILTER_PLUGIN,
                    [TAPS > 0, FILTERS > 0],
                );
            }
        };
    };
    (
        dissectors = [$($dissector:ty),* $(,)?]
        $(, taps = [$($tap:ty),* $(,)?])?
        $(, filters = [$($filter:ty),* $(,)?])? $(,)?
    ) => {
        $crate::plugin!(
            version = ::core::env!("CARGO_PKG_VERSION"),
            dissectors = [$($dissector),*]
            $(, taps = [$($tap),*])?
            $(, filters = [$($filter),*])?
        );
    };
    ($($dissector:ty),+ $(,)?) => {
        $crate::plugin!(
            version = ::core::env!("CARGO_PKG_VERSION"),
            dissectors = [$($dissector),+]
        );
    };
}
