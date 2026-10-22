# libwireshark-derive

[![Version](https://img.shields.io/crates/v/libwireshark-derive.svg)](https://crates.io/crates/libwireshark-derive)
[![Rust version](https://img.shields.io/crates/msrv/libwireshark-derive.svg)](https://crates.io/crates/libwireshark-derive)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE)
[![Docs](https://img.shields.io/docsrs/libwireshark-derive)](https://docs.rs/libwireshark-derive)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/libwireshark-rs/test.yaml)](https://github.com/jose-pr/libwireshark-rs/actions/workflows/test.yaml)

The derive macros of [`libwireshark`](https://crates.io/crates/libwireshark).
**Do not depend on this crate directly**: enable `libwireshark`'s `derive`
feature, which re-exports `Header` and `Preferences` from its root.

## Features

- `#[derive(Header)]`: registered display-filter fields from a struct of
  integers, their insertion into the protocol tree, and `decode(&[u8])`.
- `#[derive(Preferences)]`: protocol preferences from a struct.

## Installation

```console
cargo add libwireshark --features derive
```

## Quick start

See [`libwireshark`'s documentation](https://docs.rs/libwireshark), which
documents both derives and their attributes.

## Development

```console
cargo test -p libwireshark-derive
```

## License

GPL-2.0-or-later; see
[LICENSE](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE).
