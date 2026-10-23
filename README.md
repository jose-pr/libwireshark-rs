# libwireshark-rs

[![Version](https://img.shields.io/crates/v/libwireshark.svg)](https://crates.io/crates/libwireshark)
[![Rust version](https://img.shields.io/crates/msrv/libwireshark.svg)](https://crates.io/crates/libwireshark)
[![PyPI](https://img.shields.io/pypi/v/libwireshark.svg?label=pypi)](https://pypi.org/project/libwireshark/)
[![Python versions](https://img.shields.io/pypi/pyversions/libwireshark.svg)](https://pypi.org/project/libwireshark/)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE)
[![Docs](https://img.shields.io/docsrs/libwireshark)](https://docs.rs/libwireshark)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/libwireshark-rs/test.yaml)](https://github.com/jose-pr/libwireshark-rs/actions/workflows/test.yaml)

Wireshark dissector plugins in Rust. **A protocol is a type implementing
`Dissector`, its fields and preferences are derived from plain structs, and
a plugin is one `plugin!` line**, built with Cargo against an installed
Wireshark, with no Wireshark SDK, C code or `unsafe`. See
[`libwireshark`](https://docs.rs/libwireshark).

## Features

| Crate | What it is |
| --- | --- |
| [`libwireshark`](crates/libwireshark) | the plugin API: `Dissector`, `PacketView`, `plugin!`, the `derive` feature, and the `host` feature: Wireshark hosted in a program |
| [`libwireshark-derive`](crates/libwireshark-derive) | `#[derive(Header)]` and `#[derive(Preferences)]`, used through `libwireshark` |
| [`libwireshark-sys`](crates/libwireshark-sys) | raw bindings, generated from bundled headers for Wireshark 3.0 to 4.6 |
| [`cargo-wireshark`](crates/cargo-wireshark) | `cargo wireshark doctor`, and generating, fetching and publishing the header bundles |
| [`libwireshark-guatiao`](crates/libwireshark-guatiao) | one plugin that loads dissectors written in Rust, C or Python as [guatiao](https://github.com/Boriken-Dev/guatiao) providers |
| [`libwireshark-api`](crates/libwireshark-api) | what those providers implement: the kinds, a C header, and the Rust helpers (typed headers, preferences and expert findings) |
| [`bindings/python`](bindings/python) | the `libwireshark` Python package: dissectors as typed classes, for the guatiao host |

The [examples](examples) are plugins: `basic-dissector` (one protocol with
fields and a port preference), `multi-protocol` (two protocols in one
library) and `stream-protocol` (TCP reassembly, conversation state, named
values and expert findings; a heuristic dissector; a post-dissector; two
`tshark -z` statistics; two display-filter functions), `capture-file` (a
capture file format Wireshark opens), `audio-codec` (an RTP audio
decoder) and `runtime-protocol` (a protocol described when the plugin
loads).

## Installation

```console
cargo add libwireshark --features derive
```

Make the crate a `cdylib`, and install Clang (bindgen) and the Wireshark
release you build for. On Windows, `llvm-readobj` and `llvm-dlltool` (LLVM)
build the import library the Wireshark installer leaves out.

## Quick start

```rust,no_run
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

`cargo build --release`, then copy the library into
`<plugins>/<major>.<minor>/epan/` (Help › About Wireshark › Folders shows
the personal plugin directory; on macOS use `<major>-<minor>/epan/` and name
the library `*.so`, the only suffix Wireshark loads there). `tshark -Y foo` then filters on it.

## API overview

See the crates' READMEs and, for agents, the `AGENTS.md` beside each crate's
`Cargo.toml`: [libwireshark](crates/libwireshark/AGENTS.md),
[libwireshark-sys](crates/libwireshark-sys/AGENTS.md),
[libwireshark-derive](crates/libwireshark-derive/AGENTS.md),
[cargo-wireshark](crates/cargo-wireshark/AGENTS.md).
[Architecture](docs/architecture.md) and [FFI safety](docs/ffi-safety.md)
describe the internals.

## Compatibility

Wireshark loads a plugin only in the release line (major.minor) it was built
for; build one library per line. Bindings exist for every stable line from
3.0 to 4.6 on Windows, Linux, macOS and FreeBSD, x86_64 and aarch64. CI
loads the examples in tshark on Linux, macOS and Windows and type-checks the
runtime against every line.

## Development

The header bundles live on the `headers` branch; a checkout's build reads
them from there. To copy them into `crates/libwireshark-sys/headers`, or to
regenerate them:

```console
cargo run -p cargo-wireshark -- wireshark headers fetch
cargo run -p cargo-wireshark -- wireshark headers generate
cargo run -p cargo-wireshark -- wireshark headers publish
git push origin headers
```

Checks, as CI runs them:

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p libwireshark --all-features --test tshark -- --ignored
```

The last one loads the examples in the installed tshark
(`LIBWIRESHARK_TEST_TSHARK` names it when it is not on `PATH`).

### Releasing

Bump `workspace.package.version`, give the changelog's Unreleased section
that version, and push `v<version>`; the release workflow checks the
packages, creates the GitHub release and publishes the crates in dependency
order. The test workflow runs on demand or for a `ci-*` tag.

## License

GPL-2.0-or-later, as Wireshark; see [LICENSE](LICENSE).
