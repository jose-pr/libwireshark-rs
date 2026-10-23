# Examples

Every example is in the repository's
[`examples/`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples)
directory, and the test suite builds each one and loads it in the real
tshark (and sharkd, for codecs), so they stay working.

## Plugins in Rust

| Example | Shows | Installed in | Try |
| --- | --- | --- | --- |
| [`basic-dissector`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/basic-dissector) | one protocol, FOO over UDP: header fields, named values, a port preference | `epan/` | `tshark -Y foo -o foo.port:111` |
| [`multi-protocol`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/multi-protocol) | two protocols in one library, BAR over TCP and BAZ over UDP | `epan/` | `tshark -Y "bar or baz"` |
| [`stream-protocol`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/stream-protocol) | LPM messages reassembled from TCP with conversation state and expert findings; HBEAT found by heuristics; FSIZE, a post-dissector; the `lpmstats` and `udpbytes` taps; the `port_class` and `digits` filter functions | `epan/` | `tshark -q -z lpmstats` |
| [`capture-file`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/capture-file) | RSCAP, a capture format (4.6 on) | `wiretap/` | `tshark -r capture.rscap` |
| [`audio-codec`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/audio-codec) | L8, an RTP audio codec | `codecs/` | play the stream in Wireshark's RTP player |
| [`runtime-protocol`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/runtime-protocol) | everything registered at run time: RFOO (a protocol described when the plugin loads), the `rtap` tap, the `rdouble` filter function, the RRCAP format and the RL8 codec | `epan/` | `tshark -q -z rtap` |

Build them all with `cargo build --release`; each library lands in
`target/release/`.

## Plugins in other languages

[`examples/guatiao`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/guatiao)
holds the same protocol three times, each a twin of FOO, written as a
guatiao provider and loaded by the `libwireshark-guatiao` plugin:

| Provider | Language | Protocol | Also provides |
| --- | --- | --- | --- |
| [`rust-provider`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/guatiao/rust-provider) | Rust: a `ProtocolDissector` with header and preference structs | RSFOO, UDP 113 | `-z rstap`, `rs_double()`, the RSGCAP format, the RSL8 codec |
| [`c-provider`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/guatiao/c-provider) | C: `cfoo.c`, the tables of `libwireshark_api.h` and literal trees | CFOO, UDP 114 | `-z ctap`, `c_double()` |
| [`python-provider`](https://github.com/jose-pr/libwireshark-rs/tree/master/examples/guatiao/python-provider) | Python: `pyfoo.py`, typed `Header`, `Preferences` and `Expert` classes | PYFOO, UDP 115 | `-z pytap`, `py_double()`, the PYGCAP format, the PYL8 codec |

Install `libwireshark-guatiao` as an `epan/` plugin and the providers in a
`guatiao` directory of a plugin directory, or in a directory named by
`LIBWIRESHARK_GUATIAO_PATH`; see [Plugins in other languages](other-languages.md).

## Wireshark hosted in a program

The host's tests are its examples: the
[Rust test](https://github.com/jose-pr/libwireshark-rs/blob/master/crates/libwireshark/tests/host.rs)
dissects frames and reads a capture through a display filter with
`basic-dissector` and `multi-protocol` loaded, and the
[Python test](https://github.com/jose-pr/libwireshark-rs/blob/master/bindings/python/tests/test_host.py)
does the same from Python, with the guatiao plugin serving the Rust
provider. See [Hosting Wireshark](hosting.md).
