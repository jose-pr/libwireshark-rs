# Development

## Requirements

Install Rust 1.89 or newer and a Wireshark runtime that matches the plugin's major/minor target. The checked-in public-header bundle supplies the C declarations, including GLib/Gcrypt headers and Wireshark configuration declarations. A Wireshark development SDK is optional. Bindgen requires Clang/libclang; on Windows, generating an import library from a DLL requires `llvm-readobj` and `llvm-dlltool` when the installation does not provide one.

## Versioned public headers

`crates/libwireshark-sys/scripts/generate-version-headers.ps1` clones Wireshark into `wireshark-src` when needed, checks out stable release-line tags in temporary Git worktrees, and writes `crates/libwireshark-sys/headers/<major>-<minor>-<os>-<arch>.h` for stable release lines starting at Wireshark 3. The OS defaults to the host and can be set with `-TargetOS` (`windows`, `linux`, or `macos`); the architecture defaults to the host and can be set with `-Architecture`, for example `aarch64` or `x86_64`. The script uses Wireshark's public-header lists and does not configure or build Wireshark with CMake. It leaves the source checkout's current revision and working tree unchanged.

When generating a Linux bundle on a non-Linux host, provide GLib/Gcrypt development header roots for the requested Linux architecture through `WIRESHARK_DEPENDENCY_INCLUDE_DIRS`; native Linux generation uses the system's development headers. The generated bundle embeds these headers and does not require them from plugin consumers.

The generator resolves GLib and Gcrypt development headers from supplied or system include paths. When either is missing, it reads Wireshark's source artifact manifest, downloads the architecture-matched development archive, verifies its SHA-256 checksum, and expands its transitive includes into the generated umbrella. For older source trees without an artifact manifest or matching target archive, it consults the current Wireshark manifest. The dependency archives are cached under the system temporary directory. Generated bundles are self-contained C header files; compiling Rust bindings from them does not need Wireshark source or development headers.

To generate one header from a local source tree:

```console
cargo run -p cargo-wireshark -- wireshark headers --source-dir path/to/wireshark-source --arch aarch64
```

Pass `--dependency-include-dir` one or more times to provide dependency headers explicitly. Pass `--dll` to compare source declarations with a DLL's exported names. `--filtered-output` writes an umbrella containing candidate headers that mention exported names; the comparison is lexical and does not establish that a symbol is part of the public plugin ABI.

## Runtime discovery and generated bindings

`libwireshark-sys` first accepts a matching development SDK discovered through pkg-config or explicit include/library paths. When no SDK is found, it searches for `libwireshark.dll`, `libwireshark.so`, or `libwireshark.dylib` through `WIRESHARK_DLL`, `WIRESHARK_DIR`, and standard installation paths. It detects the version from adjacent TShark or `WIRESHARK_VERSION`, selects `headers/<major>-<minor>-<os>-<arch>.h`, and generates bindings for the Rust target. On Windows, it creates an import library from the runtime DLL export table when a matching import library is absent.

Set `WIRESHARK_BINDGEN_HEADER` to select another umbrella. `WIRESHARK_BINDGEN_TARGET` can override the Clang target triple. The sys crate does not build Wireshark or require its SDK in runtime-only mode. It still needs the matching native Wireshark runtime and its normal runtime dependencies when building/loading a plugin. The preferences layer dynamically loads the GLib runtime for GLib-owned strings, so it does not link against GLib development import libraries.

`cargo wireshark doctor` reports SDK, source, and runtime discovery. `cargo wireshark headers` creates public-header umbrellas. `cargo wireshark bindings` is an SDK-oriented command for explicit binding generation. `cargo wireshark configure` optionally runs Wireshark's CMake configuration to produce generated headers for SDK workflows.

## Build and validate

```console
cargo fmt --all --check
cargo test --workspace
cargo build -p basic-dissector
```

Load the resulting shared library in the corresponding Wireshark/TShark installation and dissect a capture to verify registration and packet handling.
