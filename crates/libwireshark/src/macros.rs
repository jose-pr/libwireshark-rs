/// Makes this library a Wireshark plugin holding the listed protocols, taps,
/// display-filter functions, file formats or codecs.
///
/// Write it once, in the root of a `cdylib` crate. It exports the symbols
/// Wireshark's loader reads (`plugin_version`, `plugin_want_major`,
/// `plugin_want_minor`, `plugin_describe`, `plugin_register`) and keeps the
/// plugin's registration state.
///
/// Each key takes a list of types and may be left out; the plugin version is
/// the crate's `CARGO_PKG_VERSION` unless given:
///
/// ```ignore (needs a cdylib crate whose types are defined)
/// libwireshark::plugin!(FooDissector);
/// libwireshark::plugin!(FooDissector, BarDissector);
/// libwireshark::plugin!(dissectors = [FooDissector], taps = [FooStats]);
/// libwireshark::plugin!(dissectors = [FooDissector], filters = [FooFunction]);
/// libwireshark::plugin!(file_types = [FooCapture], dissectors = [FooDissector]);
/// libwireshark::plugin!(codecs = [FooCodec]);
/// libwireshark::plugin!(version = "1.2.0", dissectors = [FooDissector, BarDissector]);
/// ```
///
/// | Key | Types implement | Installed under `<plugins>/<major>.<minor>/` |
/// | --- | --- | --- |
/// | `dissectors` | [`Dissector`](crate::Dissector) | `epan/` |
/// | `taps` | [`Tap`](crate::Tap) | `epan/` |
/// | `filters` | [`FilterFunction`](crate::FilterFunction) | `epan/` |
/// | `file_types` | [`FileType`](crate::FileType) | `wiretap/`, for the whole library |
/// | `codecs` | [`Codec`](crate::Codec) | `codecs/`, alone in their library |
///
/// Wireshark loads the `wiretap/` libraries before it registers protocols,
/// so a library with file formats can hold anything but codecs; it loads
/// `codecs/` libraries after, so a library with codecs holds only codecs,
/// which a compile-time check enforces.
///
/// A plugin is built for one Wireshark release line (major.minor), the one
/// `libwireshark-sys` was built against; Wireshark refuses it under another.
#[macro_export]
macro_rules! plugin {
    (@parse { $version:tt $dissectors:tt $taps:tt $filters:tt $file_types:tt $codecs:tt }) => {
        $crate::plugin!(@expand
            version = $version,
            dissectors = $dissectors,
            taps = $taps,
            filters = $filters,
            file_types = $file_types,
            codecs = $codecs
        );
    };
    (@parse { $_v:tt $d:tt $t:tt $f:tt $ft:tt $c:tt } version = $value:tt $(, $($rest:tt)*)?) => {
        $crate::plugin!(@parse { ($value) $d $t $f $ft $c } $($($rest)*)?);
    };
    (@parse { $v:tt $_d:tt $t:tt $f:tt $ft:tt $c:tt } dissectors = $value:tt $(, $($rest:tt)*)?) => {
        $crate::plugin!(@parse { $v $value $t $f $ft $c } $($($rest)*)?);
    };
    (@parse { $v:tt $d:tt $_t:tt $f:tt $ft:tt $c:tt } taps = $value:tt $(, $($rest:tt)*)?) => {
        $crate::plugin!(@parse { $v $d $value $f $ft $c } $($($rest)*)?);
    };
    (@parse { $v:tt $d:tt $t:tt $_f:tt $ft:tt $c:tt } filters = $value:tt $(, $($rest:tt)*)?) => {
        $crate::plugin!(@parse { $v $d $t $value $ft $c } $($($rest)*)?);
    };
    (@parse { $v:tt $d:tt $t:tt $f:tt $_ft:tt $c:tt } file_types = $value:tt $(, $($rest:tt)*)?) => {
        $crate::plugin!(@parse { $v $d $t $f $value $c } $($($rest)*)?);
    };
    (@parse { $v:tt $d:tt $t:tt $f:tt $ft:tt $_c:tt } codecs = $value:tt $(, $($rest:tt)*)?) => {
        $crate::plugin!(@parse { $v $d $t $f $ft $value } $($($rest)*)?);
    };
    (@parse { $($state:tt)* } $key:ident = $($rest:tt)*) => {
        ::core::compile_error!(::core::concat!(
            "plugin!: unknown key `", ::core::stringify!($key),
            "`; expected version, dissectors, taps, filters, file_types or codecs"
        ));
    };
    (@expand
        version = $version:expr,
        dissectors = [$($dissector:ty),* $(,)?],
        taps = [$($tap:ty),* $(,)?],
        filters = [$($filter:ty),* $(,)?],
        file_types = [$($file_type:ty),* $(,)?],
        codecs = [$($codec:ty),* $(,)?]
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
                &[$($crate::__private::TapSpec::of::<$tap>()),*],
                &[$($crate::__private::FilterSpec::of::<$filter, ThisPlugin>()),*],
                &[$($crate::__private::FileTypeSpec::of::<$file_type, ThisPlugin>()),*],
                &[$($crate::__private::CodecSpec::of::<$codec>()),*],
            );

            const _: () = {
                let codecs: &[&str] = &[$(::core::stringify!($codec)),*];
                let others: &[&str] = &[
                    $(::core::stringify!($dissector),)*
                    $(::core::stringify!($tap),)*
                    $(::core::stringify!($filter),)*
                    $(::core::stringify!($file_type),)*
                ];
                ::core::assert!(
                    codecs.is_empty() || others.is_empty(),
                    "a plugin with codecs holds nothing else: Wireshark loads it after registering protocols"
                );
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

            extern "C" fn register_filters() {
                PLUGIN.register_filters();
            }

            extern "C" fn deregister_filters() {
                PLUGIN.deregister_filters();
            }

            extern "C" fn register_file_types() {
                PLUGIN.register_file_types();
            }

            extern "C" fn register_codecs() {
                PLUGIN.register_codecs();
            }

            static TABLES: $crate::__private::Tables =
                $crate::__private::Tables::new($crate::__private::Entries {
                    register_protoinfo,
                    register_handoff,
                    register_taps,
                    register_filters,
                    deregister_filters,
                    register_file_types,
                    register_codecs,
                });

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
                PLUGIN.describe()
            }

            #[unsafe(no_mangle)]
            extern "C" fn plugin_register() {
                PLUGIN.register(&TABLES);
            }
        };
    };
    ($($key:ident = $value:tt),+ $(,)?) => {
        $crate::plugin!(@parse {
            (::core::env!("CARGO_PKG_VERSION")) [] [] [] [] []
        } $($key = $value),+);
    };
    ($($dissector:ty),+ $(,)?) => {
        $crate::plugin!(dissectors = [$($dissector),+]);
    };
}
