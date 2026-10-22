# cargo-wireshark

[![Version](https://img.shields.io/crates/v/cargo-wireshark.svg)](https://crates.io/crates/cargo-wireshark)
[![Rust version](https://img.shields.io/crates/msrv/cargo-wireshark.svg)](https://crates.io/crates/cargo-wireshark)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE)
[![Docs](https://img.shields.io/docsrs/cargo-wireshark)](https://docs.rs/cargo-wireshark)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/libwireshark-rs/test.yaml)](https://github.com/jose-pr/libwireshark-rs/actions/workflows/test.yaml)

A Cargo subcommand for Wireshark plugin development: **it finds the installed
Wireshark, and generates, fetches or publishes the header bundles
`libwireshark-sys` builds its bindings from**, straight from Wireshark's
source tags, without configuring or building Wireshark.

## Features

- `cargo wireshark doctor` / `version`: the Wireshark runtime, SDK or
  source tree installed, and its version.
- `cargo wireshark headers generate`: bundles for every stable release line
  from 3.0, or for one source tree; GLib/Gcrypt headers come from the system,
  given directories, or Wireshark's own SHA-256-verified dependency archives.
- `cargo wireshark headers fetch` / `publish`: copy the bundles from, or
  commit them to, the repository's `headers` branch.
- `cargo wireshark configure` / `bindings`: CMake configuration and bindgen
  over a Wireshark source tree, for SDK work.

## Installation

```console
cargo install cargo-wireshark
```

Needs `git` for `headers`, Clang/libclang for `bindings`, and CMake for
`configure`.

## Quick start

```console
cargo wireshark doctor
cargo wireshark headers fetch
```

## Command line

```console
cargo wireshark headers generate --version 4.6
cargo wireshark headers generate --target-os linux --arch aarch64 \
    --dependency-include-dir /usr/include/glib-2.0 \
    --dependency-include-dir /usr/lib64/glib-2.0/include \
    --dependency-include-dir /usr/include
cargo wireshark headers generate --source-dir ../wireshark --output-dir bundles
cargo wireshark headers publish -m "chore: regenerate header bundles"
```

`generate` writes `wireshark-<major>-<minor>.h`, the same for every target,
and `deps-<os>-<arch>.h` for the target named. Paths default to this
repository's layout (`wireshark-src`, `crates/libwireshark-sys/headers`).
Exit status: 0 success, 1 failure, 2 invalid arguments.

## API overview

The binary is a thin front over the library (`cargo_wireshark`):
`generate_public_header`, `generate_release_lines`, `fetch_bundles`,
`publish_bundles`, `export_report`, `Sdk::discover`, `Runtime::discover`,
`SourceTree`. The library reads no settings from the environment; the
binary maps each `WIRESHARK_*` variable to a flag.

## Development

```console
cargo test -p cargo-wireshark
```

## License

GPL-2.0-or-later; see
[LICENSE](https://github.com/jose-pr/libwireshark-rs/blob/master/LICENSE).
