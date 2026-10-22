# `libwireshark-sys` — API header

Header-file-style reference for the `libwireshark-sys` crate: every public item with
its signature, contract and gotchas, so the crate can be used without
reading its source. It ships inside the package and is self-contained.
Development documentation lives with the source at
<https://github.com/jose-pr/libwireshark-rs>.

No features. MSRV 1.89. Build dependencies: `bindgen` (needs libclang) and
`pkg-config`. `links = "wireshark"`.

## Items

bindgen output for the EPAN public headers of one Wireshark release line,
at the crate root: `extern "C"` functions (all `unsafe`), `#[repr(C)]`
structs, enum constants as `<enum>_<VARIANT>` (`ftenum_FT_UINT8`,
`field_display_e_BASE_HEX`), `#define`s as constants (`ENC_BIG_ENDIAN`,
`COL_INFO`, `VERSION_MAJOR`, `VERSION_MINOR`). No layout tests are
generated. Names and signatures differ between release lines (a boolean
preference slot is `*mut gboolean` before 4.0 and `*mut bool` after).

## Bundles

`headers/wireshark-<major>-<minor>.h` (3.0 to 4.6, target-independent) and
`headers/deps-<os>-<arch>.h` (GLib and Gcrypt for windows, linux, macos,
freebsd × x86_64, aarch64). The build includes deps, then wireshark.
Lookup order for each file: `WIRESHARK_BUNDLE_DIR`, the crate's `headers/`,
the `headers` branch of the git checkout the crate is in (fetched from
`origin` once unless `CARGO_NET_OFFLINE` is set). A missing bundle fails the
build with the commands that produce it.

## Environment variables

| Variable | Effect |
| --- | --- |
| `WIRESHARK_DIR` | installation or SDK root |
| `WIRESHARK_DLL` | the runtime library itself |
| `WIRESHARK_INCLUDE_DIR`, `WIRESHARK_LIB_DIR`, `WIRESHARK_GENERATED_INCLUDE_DIR`, `WIRESHARK_SOURCE_DIR` | an SDK's parts |
| `WIRESHARK_VERSION` | release line (`4.6` or `4.6.9`) when it cannot be detected |
| `WIRESHARK_TSHARK` | tshark to ask for the version |
| `WIRESHARK_NO_LINK` | any value: generate bindings, link nothing |
| `WIRESHARK_BUNDLE_DIR` | directory searched first for bundles |
| `WIRESHARK_BINDGEN_HEADER` | one C header to bind instead of the bundles |
| `WIRESHARK_BINDGEN_TARGET` | clang `--target` for bindgen |
| `DOCS_RS` | set by docs.rs: release line 4.6, linux x86_64, no link |

The `WIRESHARK_*` names follow the `<LIB>_DIR` convention of `-sys` crates.

The build reports the release line to the build scripts of crates that
depend on this one directly: `DEP_WIRESHARK_VERSION=<major>.<minor>`.

## Gotchas

- An SDK takes precedence over a runtime when both are found.
- A runtime without tshark next to it needs `WIRESHARK_VERSION`.
- Cross-compiling needs the target's C headers (libc) for bindgen.
- On Windows the generated import library is checked against the target
  architecture; an x64 Wireshark cannot link an aarch64 plugin.
- bindgen lays out C bitfields as GCC does; on `*-windows-msvc` a bitfield
  unit that follows a narrower field sits at a different offset than its
  accessors read (`_frame_data`'s flags, for one); `libwireshark` reads
  those from where MSVC puts them.
