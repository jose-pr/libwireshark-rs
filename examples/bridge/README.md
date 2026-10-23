# Providers for libwireshark-bridge

The same protocol three times, each a twin of FOO (a version byte, a flags
byte, a big-endian length), each written in another language and loaded
by the `libwireshark-bridge` plugin, with the other kinds of plugin
beside it:

| Directory | Language | Protocol | Port |
| --- | --- | --- | --- |
| `rust-provider/` | Rust: a `ProtocolDissector` with header and preference structs, in a `cdylib` | RSFOO | UDP 113 |
| `c-provider/` | C: `cfoo.c`, the tables of `libwireshark_api.h` and literal trees | CFOO | UDP 114 |
| `python-provider/` | Python: `pyfoo.py`, a `ProtocolDissector` with `Header` and `Preferences` classes, and its `pyfoo.guatiao-py.toml` manifest | PYFOO | UDP 115 |

Each declares its header (version, flags in hex, length) for the bridge to
decode and add, names version 7, and reports an expert finding for any
other version; a packet shorter than the header is declined. The Rust and
Python ones declare their port as a preference and bind in `dissect_on`
(`-o rsfoo.port:..`), and keep a count per conversation; the C one binds a
fixed port and shows the frame number.

Beside its protocol, each provides a tap listener counting frames
(`-z rstap`, `-z ctap`, `-z pytap`) and a display-filter function doubling
an integer field (`rs_double`, `c_double`, `py_double`); the Rust and
Python ones also a capture format (RSGCAP and PYGCAP: an 8-byte magic,
then records of a nanosecond time, two lengths and the bytes; Wireshark
4.6 on) and an RTP codec decoding unsigned 8-bit samples (`RSL8`,
`PYL8`).

Install a provider in a `bridge` directory of Wireshark's plugin
directory, or in a directory named by `LIBWIRESHARK_BRIDGE_PATH` (see the
host's README). The Python one also needs the guatiao-py bridge library in
the same directory. `crates/libwireshark-bridge/tests/tshark.rs` builds,
installs and runs all three.
