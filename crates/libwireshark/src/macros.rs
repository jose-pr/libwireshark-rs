/// Makes this library a Wireshark plugin holding the listed dissectors.
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
/// libwireshark::plugin!(version = "1.2.0", dissectors = [FooDissector, BarDissector]);
/// ```
///
/// A plugin is built for one Wireshark release line (major.minor), the one
/// `libwireshark-sys` was built against; Wireshark refuses it under another.
#[macro_export]
macro_rules! plugin {
    ($($dissector:ty),+ $(,)?) => {
        $crate::plugin!(
            version = ::core::env!("CARGO_PKG_VERSION"),
            dissectors = [$($dissector),+]
        );
    };
    (version = $version:expr, dissectors = [$($dissector:ty),+ $(,)?] $(,)?) => {
        const _: () = {
            static PLUGIN: $crate::__private::Plugin = $crate::__private::Plugin::new(&[
                $($crate::__private::Protocol::of::<$dissector>()),+
            ]);

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

            static PROTO_PLUGIN: $crate::sys::proto_plugin =
                $crate::__private::proto_plugin(register_protoinfo, register_handoff);

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
                $crate::__private::DESCRIBE_DISSECTOR
            }

            #[unsafe(no_mangle)]
            extern "C" fn plugin_register() {
                $crate::__private::register(&PROTO_PLUGIN);
            }
        };
    };
}
