# libwireshark-rs

`libwireshark-rs` is a Rust workspace for developing native Wireshark dissector plugins. It provides raw Wireshark bindings, a Rust registration layer, a Cargo development command, and plugin examples.

Versioned public-header bundles are stored in `crates/libwireshark-sys/headers/` as `<major>-<minor>-<os>-<arch>.h`. Each bundle embeds Wireshark's source-declared headers, GLib/Gcrypt headers, and generated configuration declarations in one file. The sys crate generates Rust bindings from the bundle matching the installed runtime's Wireshark version and Rust target OS and architecture. A development SDK is optional; the build can use the Wireshark runtime DLL/shared library directly.

## Features

- Raw EPAN and Wireshark C bindings, including the plugin registration interface.
- Rust helpers for protocol registration, fields, preferences, dissector handles, and table attachment.
- `Dissector`, `Preferences`, and `Header` traits for mapping Rust protocol descriptions to Wireshark registration descriptors.
- Optional derives for typed preference structs and display-filter header fields, plus the plugin entry-point attribute.
- Optional SDK discovery through pkg-config or explicit include and library directories, with runtime-only DLL/shared-library discovery as a fallback.
- `cargo wireshark doctor`, `version`, `headers`, `configure`, and `bindings` development commands.
- Basic, TCP, UDP, and dual-transport plugin examples under `examples/`.

## Installation

Install the Wireshark runtime matching the plugin's major/minor target before building a plugin. The checked-in header bundle supplies C declarations, so a Wireshark development SDK is not required.

Set `WIRESHARK_DIR` or `WIRESHARK_DLL` when Wireshark is installed outside the standard location. The build detects the major/minor version from the adjacent TShark executable; set `WIRESHARK_VERSION` if that is not available. An installed SDK remains supported and is preferred when pkg-config or explicit include/library paths identify one.

```toml
[dependencies]
libwireshark = { path = "crates/libwireshark", features = ["macros"] }
libwireshark-sys = { path = "crates/libwireshark-sys" }
```

Add `WIRESHARK_BINDGEN_HEADER` to use an explicit umbrella instead of the version-selected one. Bindgen requires Clang/libclang. On Windows, if the runtime install does not include an import library, the build creates one from the DLL export table using `llvm-readobj` and `llvm-dlltool`.

## Quick start

Start with the [basic dissector example](examples/basic-dissector/src/lib.rs). It registers a UDP dissector and displays the first payload byte as its version. Build examples against an installed Wireshark runtime with:

```console
cargo build -p basic-dissector
```

The workspace also includes `tcp-dissector`, `udp-dissector`, and
`multi-protocol` examples. `FooPlugin` in the latter registers two protocols
from one plugin library, each with its own dissector and TCP or UDP port table.
A single protocol can also attach its dissector to multiple tables.

## Command line

Build the independent development command and check Wireshark runtime discovery:

```console
cargo run -p cargo-wireshark -- doctor
cargo run -p cargo-wireshark -- version
```

When the binary is on `PATH`, Cargo exposes the same commands as `cargo wireshark doctor`, `version`, `headers`, `configure`, and `bindings`. The doctor reports runtime, SDK, and source installations separately. Set `WIRESHARK_TSHARK` or `WIRESHARK_SOURCE_DIR` for nonstandard locations.

Generate umbrellas for stable release lines from the cloned `wireshark-src` repository, or generate one for a selected source checkout:

```powershell
crates\libwireshark-sys\scripts\generate-version-headers.ps1
```

```console
cargo wireshark headers --source-dir path/to/wireshark-source --arch aarch64
```

The command can compare all source-declared public EPAN headers with a Wireshark DLL and optionally write an export-filtered umbrella:

```console
cargo wireshark headers --source-dir path/to/wireshark-source --arch aarch64
cargo wireshark headers --source-dir path/to/wireshark-source --dll path/to/libwireshark.dll --filtered-output .wireshark/generated/libwireshark-exported.h
```

Header generation resolves GLib and Gcrypt development headers from supplied/system paths or downloads Wireshark-declared, SHA-256-verified development archives, then embeds their transitive includes. Older source releases without a suitable archive declaration use the current Wireshark dependency manifest. Generation reads source declarations and does not configure or build Wireshark with CMake. The DLL comparison uses `llvm-readobj` and reports lexical export/header matches; it does not prove ABI compatibility. Bindgen requires Clang/libclang, and a matching Wireshark runtime library is still required to link a plugin.

## API overview

| Package | Purpose |
| --- | --- |
| `libwireshark-sys` | Raw bindings, native discovery, and linking. |
| `libwireshark` | Protocol registration and callback-scoped packet and field helpers. See the [runtime API guide](crates/libwireshark/README.md). |
| `libwireshark-macros` | Optional procedural macro package. |
| `cargo-wireshark` | Runtime/SDK discovery, header generation, and Rust binding generation. |

See [architecture](docs/architecture.md), [compatibility](docs/compatibility.md), and [FFI safety](docs/ffi-safety.md) for details.

## Development

```console
cargo metadata --format-version 1 --no-deps
cargo fmt --all --check
cargo build -p cargo-wireshark
```

Building the complete workspace requires the matching Wireshark runtime. See [development setup](docs/development.md).
