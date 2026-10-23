# libwireshark

**Wireshark plugins in Rust, plugins in any language through one host
plugin, and Wireshark itself hosted in your program.** A protocol is a Rust
type implementing `Dissector`, its fields and preferences are plain structs,
and a plugin is one `plugin!` line: no Wireshark SDK, no C, no `unsafe`.
The same model reaches C, Python and every other language
[guatiao](https://github.com/Boriken-Dev/guatiao) supports (Node.js, Go,
Julia, R, MATLAB/Octave, Fortran, C++) through one plugin, the bridge, and
the other way round a program in any of them can dissect frames and read
captures with Wireshark and the plugins you load.

Every Wireshark release line from 3.0 to 4.6 is supported, on Windows,
Linux, macOS and FreeBSD, x86_64 and aarch64. A plugin is built for one
line, as Wireshark requires.

## Three ways in

| You want to | Use | Start here |
| --- | --- | --- |
| Write a dissector, tap, display-filter function, capture format or codec in Rust | the `libwireshark` crate | [Plugins in Rust](plugins.md) |
| Write one in Python, C or any other language guatiao supports, built once for every release line | the `libwireshark-bridge` plugin and the `libwireshark-api` kinds | [Plugins in other languages](other-languages.md), [Python](python.md) |
| Dissect frames or read captures with Wireshark from a program | `libwireshark::host`, or `libwireshark.Host` in Python | [Hosting Wireshark](hosting.md) |

Each comes with runnable examples, which the test suite loads in the real
tshark and sharkd: see [Examples](examples.md).

## Installation

Rust, for a plugin (a `cdylib`) or a program hosting Wireshark:

```console
cargo add libwireshark --features derive
cargo add libwireshark --features host
```

Install Clang (for bindgen) and the Wireshark release you build for. On
Windows, `llvm-readobj` and `llvm-dlltool` (LLVM) build the import library
the Wireshark installer leaves out.

Python, for dissectors written in Python or Wireshark hosted in Python:

```console
pip install libwireshark
```

| Feature (Rust) | Adds |
| --- | --- |
| `derive` | `#[derive(Header)]` and `#[derive(Preferences)]` |
| `host` | `libwireshark::host`: Wireshark's dissection engine in a program |

## 30-second tour

A protocol on UDP port 111, with two fields Wireshark can filter on:

```rust
use libwireshark::{Binding, DissectResult, Dissector, Header, NoPreferences, PacketView};

#[derive(Header)]
struct FooHeader {
    #[header(name = "Version")]
    version: u8,
    #[header(name = "Length")]
    length: u16,
}

struct Foo;

impl Dissector for Foo {
    type Preferences = NoPreferences;
    type Header = FooHeader;
    const NAME: &'static str = "FOO Protocol";
    const SHORT_NAME: &'static str = "FOO";
    const FILTER_NAME: &'static str = "foo";

    fn dissect_on(_: &NoPreferences) -> Vec<Binding> {
        vec![Binding::udp_port(111)]
    }

    fn dissect(_: &NoPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<FooHeader>> {
        let header = FooHeader::decode(packet.bytes())?;
        let info = format!("FOO version {}", header.version);
        Some(DissectResult::new(header, FooHeader::SIZE).with_info(info))
    }
}

libwireshark::plugin!(Foo);
```

`cargo build --release`, copy the library into
`<plugins>/<major>.<minor>/epan/`, and `tshark -Y foo` filters on it.

The same protocol dissected from Python, by Wireshark hosted in the
process:

```python
from libwireshark import Host

with Host(plugins=["foo.dll"]) as wireshark:
    frame = wireshark.dissect(data)
    print(frame["foo.version"], frame.columns["Info"])
```

## Learn more

- [Plugins in Rust](plugins.md): every kind of plugin, and where each is installed.
- [Examples](examples.md): what each example shows, and how to run it.
- [Plugins in other languages](other-languages.md) and [Python](python.md).
- [Hosting Wireshark](hosting.md).
- API reference: [Rust](https://jose-pr.github.io/libwireshark-rs/rust/libwireshark/index.html),
  [Python](api/python.md), and the
  [C header](https://github.com/jose-pr/libwireshark-rs/blob/master/crates/libwireshark-api/include/libwireshark_api.h).
- [Architecture](architecture.md) and [FFI safety](ffi-safety.md): the internals.
- [Changelog](changelog.md).

## License

MPL-2.0, as guatiao, for everything that does not link or embed Wireshark
(`libwireshark-api`, `libwireshark-derive`, `cargo-wireshark`, the Python
package, the bridge's example providers); GPL-2.0-or-later, as Wireshark,
for `libwireshark-sys`, `libwireshark`, `libwireshark-bridge` and the example
plugins. A provider for the bridge links no Wireshark and may use any license.
