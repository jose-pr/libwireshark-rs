# libwireshark

[![Version](https://img.shields.io/crates/v/libwireshark.svg)](https://crates.io/crates/libwireshark)
[![Rust version](https://img.shields.io/crates/msrv/libwireshark.svg)](https://crates.io/crates/libwireshark)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE)
[![Docs](https://img.shields.io/docsrs/libwireshark)](https://docs.rs/libwireshark)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/libwireshark-rs/test.yaml)](https://github.com/jose-pr/libwireshark-rs/actions/workflows/test.yaml)

Write Wireshark dissector plugins in Rust. **A protocol is a type
implementing `Dissector`, its fields and preferences are plain structs, and a
plugin is one `plugin!` line**; no `unsafe`, no C, no Wireshark build. See
the [API documentation](https://docs.rs/libwireshark).

## Features

- `Dissector`: a protocol's names, the dissector tables it is attached to
  (recomputed whenever preferences change), and the function that decodes
  one packet.
- `PacketView`: the captured bytes as a `&[u8]`, endian-aware integer reads,
  the Info column, and checked insertion of registered fields.
- `#[derive(Header)]`: display-filter fields from a struct of integers,
  added to the protocol tree for you, plus a generated `decode(&[u8])`.
- `#[derive(Preferences)]`: protocol preferences from a struct; the dissector
  receives the current values as that struct.
- `plugin!`: exports what Wireshark's loader reads, for one or more
  protocols.
- The runtime sets the Protocol column and adds the protocol's own tree item,
  so `-Y <protocol>` filters work.

## Installation

```console
cargo add libwireshark --features derive
```

| Feature | Adds | Default |
| --- | --- | --- |
| `derive` | `#[derive(Header)]` and `#[derive(Preferences)]` | no |

The plugin crate is a `cdylib`:

```toml
[lib]
crate-type = ["cdylib"]
```

Building needs Clang (for bindgen) and the Wireshark release the plugin is
for: its runtime library, or a development SDK. On Windows, `llvm-readobj`
and `llvm-dlltool` make the import library Wireshark does not ship.
`libwireshark-sys` describes how the installation is found.

## Quick start

A protocol on a fixed port, with no fields or preferences:

```rust,no_run
use libwireshark::{Binding, DissectResult, Dissector, NoHeader, NoPreferences, PacketView};

struct Echo;

impl Dissector for Echo {
    type Preferences = NoPreferences;
    type Header = NoHeader;
    const NAME: &'static str = "Echo Protocol";
    const SHORT_NAME: &'static str = "ECHO";
    const FILTER_NAME: &'static str = "echo";

    fn dissect_on(_: &NoPreferences) -> Vec<Binding> {
        vec![Binding::udp_port(7)]
    }

    fn dissect(_: &NoPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<NoHeader>> {
        let length = packet.captured_len();
        Some(DissectResult::new(NoHeader, length).with_info(format!("echo, {length} bytes")))
    }
}

libwireshark::plugin!(Echo);
```

Fields and a configurable port, with the `derive` feature:

```rust,ignore (needs the derive feature)
use libwireshark::{Binding, DissectResult, Dissector, Header, PacketView, Preferences};

#[derive(Preferences)]
struct FooPreferences {
    #[preference(title = "UDP port", description = "UDP port FOO is decoded on")]
    port: u16,
}

impl Default for FooPreferences {
    fn default() -> Self {
        Self { port: 111 }
    }
}

/// Filter on `foo.version` and `foo.length`.
#[derive(Header)]
struct FooHeader {
    #[header(name = "Version", display = "hex")]
    version: u8,
    #[header(name = "Length")]
    length: u16,
}

struct Foo;

impl Dissector for Foo {
    type Preferences = FooPreferences;
    type Header = FooHeader;
    const NAME: &'static str = "FOO Protocol";
    const SHORT_NAME: &'static str = "FOO";
    const FILTER_NAME: &'static str = "foo";

    fn dissect_on(preferences: &FooPreferences) -> Vec<Binding> {
        vec![Binding::udp_port(preferences.port)]
    }

    fn dissect(_: &FooPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<FooHeader>> {
        let header = FooHeader::decode(packet.bytes())?;
        let info = format!("FOO version {}", header.version);
        Some(DissectResult::new(header, FooHeader::SIZE).with_info(info))
    }
}

libwireshark::plugin!(Foo);
```

Build it with `cargo build --release` and copy the library into Wireshark's
personal plugin directory for its release line, `<dir>/<major>.<minor>/epan/`.
**Help › About Wireshark › Folders** shows the directory: on Windows it is
`%APPDATA%\Wireshark\plugins`, elsewhere `~/.local/lib/wireshark/plugins`.
On macOS the directory is `<major>-<minor>`, and the copy must be named
`<name>.so`: Wireshark loads only `.so` files there, and Cargo builds a
`.dylib`.

## API overview

| Item | Purpose |
| --- | --- |
| `Dissector`, `DissectResult`, `Binding` | a protocol, an accepted packet, a dissector-table entry |
| `PacketView`, `Encoding`, `PacketFieldError` | one packet during dissection |
| `Header`, `FieldInfo`, `FieldType`, `Base`, `NoHeader` | registered fields |
| `prefs` (`Preferences`, `PreferenceValue`, `Declaration`, `Value`) | protocol preferences |
| `plugin!` | the plugin's exported entry points |
| `sys` | the raw `libwireshark-sys` bindings |

## Compatibility

A plugin is built for one Wireshark release line (major.minor) and loads
only in that line; build once per line you support. The bindings cover
3.0 to 4.6 on Windows, Linux, macOS and FreeBSD, x86_64 and aarch64.

## Development

From the repository root (the build reads the header bundles from the
`headers` branch by itself):

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p libwireshark --all-features --test tshark -- --ignored
```

The last command loads the example plugins in the installed tshark.

### Releasing

Bump `workspace.package.version`, move the changelog's Unreleased section
under the new version, and push a `v<version>` tag; the release workflow
publishes the crates in dependency order.

## License

GPL-2.0-or-later, as Wireshark; see
[LICENSE](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE).
