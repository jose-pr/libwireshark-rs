# Plugins in other languages

`libwireshark-bridge` is one Wireshark plugin that loads plugins written in
any language [guatiao](https://github.com/Boriken-Dev/guatiao) supports.
Rust, C and Python have typed helpers and examples here; Node.js, Go, Julia,
R, MATLAB/Octave, Fortran and C++ reach the same kinds through guatiao's own
bindings, from the C header `libwireshark_api.h` or the kind descriptions. A provider implements the kinds of
`libwireshark-api` and links no Wireshark, so **one provider build serves
every Wireshark release line**; only the bridge is built per line.

| Kind | What it is | Typed helper (Rust, Python) |
| --- | --- | --- |
| `wireshark_dissector` | a protocol: description, `dissect_on`, `dissect` | `ProtocolDissector` |
| `wireshark_tap` | a `-z` statistic, one listener per invocation | `Tap` |
| `wireshark_filter_function` | `name(field)` in a display filter (4.4 on) | `FilterFunction` |
| `wireshark_file_type` | a capture format, read through a lent source (4.6 on) | `FileType` |
| `wireshark_codec` | an RTP audio codec, one decoder per stream | `Codec` |

## Installing

1. Build `libwireshark-bridge` for your Wireshark release line and copy it
   into `<plugins>/<major>.<minor>/epan/`, like any plugin.
2. Put providers in a `bridge` directory of a plugin directory (personal
   or global), or in a directory named by `LIBWIRESHARK_BRIDGE_PATH`.

A provider is a library declaring one of the kinds (a Rust `cdylib`
calling `guatiao::providers!`, or a C shared library filling the tables of
`libwireshark_api.h`), or a Python module with its `*.guatiao-py.toml`
manifest beside the guatiao-py bridge library. Problems are written to
stderr as `libwireshark-bridge: ...`; `LIBWIRESHARK_BRIDGE_LOG` set to
anything reports what loaded as well.

## A protocol, three ways

The header and the preferences are declared, not parsed: the bridge decodes
the header for each packet and adds its fields once the provider accepts,
registers the preferences, and asks `dissect_on` where to bind each time
they change.

=== "Rust"

    ```rust
    #[derive(Schema, FromValue)]
    #[map(crate = ::libwireshark_api::guatiao)]
    pub struct RsfooHeader {
        /// The protocol version.
        #[schema(title = "Version")]
        pub version: u8,
        /// The message's length.
        #[schema(title = "Length")]
        pub length: u16,
    }

    impl ProtocolDissector for Rsfoo {
        const NAME: &'static str = "Rust FOO Protocol";
        const SHORT_NAME: &'static str = "RSFOO";
        const FILTER_NAME: &'static str = "rsfoo";
        type Header = RsfooHeader;
        type Preferences = RsfooPreferences;
        // dissect_on and dissect receive the typed header and preferences
    }

    libwireshark_api::dissector!(Rsfoo);
    guatiao::providers!(Rsfoo);
    ```

=== "Python"

    ```python
    class PyfooHeader(Header):
        version: Annotated[U8, Meta(name="Version")]
        "The protocol version"

        length: Annotated[U16, Meta(name="Length")]


    class Pyfoo(provide.Provider, ProtocolDissector):
        NAME = "Python FOO Protocol"
        SHORT_NAME = "PYFOO"
        FILTER_NAME = "pyfoo"
        HEADER = PyfooHeader
        PREFERENCES = PyfooPreferences

        def dissect_on(self, preferences: PyfooPreferences) -> List[Binding]:
            return [Table.udp_port(preferences.port)]
    ```

=== "C"

    ```c
    static guatiao_entry DESCRIPTION[] = {
        GUATIAO_ENTRY_LIT("name", GUATIAO_VALUE_STRING_LIT("C FOO Protocol")),
        GUATIAO_ENTRY_LIT("short_name", GUATIAO_VALUE_STRING_LIT("CFOO")),
        GUATIAO_ENTRY_LIT("filter_name", GUATIAO_VALUE_STRING_LIT("cfoo")),
        GUATIAO_ENTRY_LIT("header", GUATIAO_VALUE_LIST_LIT(HEADER)),
    };
    ```

The complete providers, with a tap, a filter function, a format and a codec
beside each protocol, are in [Examples](examples.md).

## Reference

- The kinds and their models: the `libwireshark-api` crate
  ([Rust reference](https://jose-pr.github.io/libwireshark-rs/rust/libwireshark_api/index.html)).
- The C tables: [`libwireshark_api.h`](https://github.com/jose-pr/libwireshark-rs/blob/master/crates/libwireshark-api/include/libwireshark_api.h).
- Python: [the `libwireshark` package](python.md).
