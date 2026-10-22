# Compatibility policy

## Wireshark ABI

Wireshark's native plugin ABI is compatible across micro (patch) releases on a best-effort basis. A plugin must be rebuilt for every major or minor Wireshark version. The loader checks `plugin_want_major` and `plugin_want_minor`; a plugin built against a different major/minor pair is rejected.

The build selects the checked-in `<major>-<minor>-<os>-<arch>.h` bundle for the detected Wireshark version and Cargo target OS and architecture. `WIRESHARK_BINDGEN_HEADER` explicitly overrides the selected bundle. A missing versioned bundle is an error; the build has no fallback binding snapshot. Bundles contain target-specific dependency headers and should be regenerated when adding a target.

## Native platforms

- **Linux:** runtime-only builds use `libwireshark.so` and the normal runtime dependency closure installed by the distribution. SDK/pkg-config discovery remains supported.
- **macOS:** runtime-only builds use `libwireshark.dylib` from the Wireshark installation and its normal runtime dependency closure. SDK discovery remains supported where development files are available.
- **Windows:** runtime-only builds use `libwireshark.dll`. If its import library is absent, `llvm-readobj` and `llvm-dlltool` create one from the DLL export table. The runtime installation must include its dependent DLLs and match the Rust target architecture and ABI.

All targets need Clang/libclang for bindgen. Runtime-only mode needs no Wireshark headers, generated SDK headers, or Wireshark build system. The generated bundles supply the C declarations, while the installed runtime supplies the native implementation.

## Rust compatibility

The runtime, macro, CLI, sys, and example crates use Rust 2024. All workspace crates declare Rust 1.89 as their MSRV.

## Compatibility testing

CI should exercise the supported Wireshark major/minor pairs independently because each plugin binary is ABI-specific. Cross-compiling a plugin against one version does not establish compatibility with another. Runtime loading under the target Wireshark/TShark version is required for a release claim.
