# Providers for libwireshark-guatiao

The same protocol three times, each a twin of FOO (a version byte, a flags
byte, a big-endian length), each written in another language and loaded
by the `libwireshark-guatiao` host plugin:

| Directory | Language | Protocol | Port |
| --- | --- | --- | --- |
| `rust-provider/` | Rust: a `ProtocolDissector` with header and preference structs, in a `cdylib` | RSFOO | UDP 113 |
| `c-provider/` | C: `cfoo.c`, the tables of `libwireshark_api.h` and literal trees | CFOO | UDP 114 |
| `python-provider/` | Python: `pyfoo.py`, a `ProtocolDissector` with `Header` and `Preferences` classes, and its `pyfoo.guatiao-py.toml` manifest | PYFOO | UDP 115 |

Each declares its header (version, flags in hex, length) for the host to
decode and add, names version 7, and reports an expert finding for any
other version; a packet shorter than the header is declined. The Rust and
Python ones declare their port as a preference and bind in `dissect_on`
(`-o rsfoo.port:..`), and keep a count per conversation; the C one binds a
fixed port and shows the frame number.

Install a provider in a `guatiao` directory of Wireshark's plugin
directory, or in a directory named by `LIBWIRESHARK_GUATIAO_PATH` (see the
host's README). The Python one also needs the guatiao-py bridge library in
the same directory. `crates/libwireshark-guatiao/tests/tshark.rs` builds,
installs and runs all three.
