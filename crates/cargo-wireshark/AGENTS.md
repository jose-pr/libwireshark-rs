# `cargo-wireshark` — API header

Header-file-style reference for the `cargo-wireshark` crate: every public item with
its signature, contract and gotchas, so the crate can be used without
reading its source. It ships inside the package and is self-contained.
Development documentation lives with the source at
<https://github.com/jose-pr/libwireshark-rs>.

No features. MSRV 1.89. Depends on `clap`, `bindgen` (libclang at run time
for `bindings`), `ureq` (rustls), `sha2`, `zip`, `sevenz-rust2`,
`lzma-rust2`, `tar`. No `unsafe`. Runs `git`, `cmake`, `llvm-readobj`,
`tshark` and `pkg-config` as subprocesses with argument vectors.

## Command line

Invoked as `cargo wireshark <command>` or `cargo-wireshark <command>`.

| Command | Does |
| --- | --- |
| `doctor` | reports the SDK, runtime (tshark) and source tree found; 1 when no SDK |
| `version` | prints the installed version |
| `headers generate [--version M.m]... [--target-os OS] [--arch ARCH] [--repository DIR] [--output-dir DIR] [--dependency-include-dir DIR]...` | bundles for each stable release line (`vX.Y.0`, even Y, from 3.0), from temporary worktrees of a Wireshark clone (cloned when absent) |
| `headers generate --source-dir DIR [--dll DLL [--filtered-output FILE] [--report-output FILE]]` | bundles from one source tree; with `--dll`, a report of DLL exports against source declarations |
| `headers fetch [--remote origin] [--output-dir DIR]` | copies the bundles from `<remote>/headers` |
| `headers publish [-m MESSAGE] [--output-dir DIR]` | commits the bundles to the local `headers` branch (orphan when new); does not push |
| `configure --source-dir DIR [--build-dir DIR] [--cmake-arg ARG]...` | runs Wireshark's CMake configure to produce `config.h` |
| `bindings --header H --source-dir DIR --generated-include-dir DIR [--output F]` | runs bindgen over a source tree |

Defaults: `--repository wireshark-src`, `--output-dir
crates/libwireshark-sys/headers` (relative to the working directory),
`--target-os`/`--arch` the host's. Exit status 0 success, 1 failure, 2
invalid arguments. Results on stdout, one-line errors on stderr prefixed
`cargo-wireshark:`.

## Library (`cargo_wireshark`)

```rust
pub fn generate_public_header(config: &PublicHeaderConfig) -> Result<GeneratedPublicHeader, GenerateError>;
pub fn generate_release_lines(config: &ReleaseBundlesConfig) -> Result<Vec<ReleaseLine>, GenerateError>;
pub fn release_lines(repository: &Path) -> Result<Vec<ReleaseLine>, GenerateError>;
pub fn fetch_bundles(checkout: &Path, remote: &str, output_dir: &Path) -> Result<usize, GenerateError>;
pub fn publish_bundles(checkout: &Path, output_dir: &Path, message: &str) -> Result<bool, GenerateError>;
pub fn generate_headers(config: &HeaderConfig) -> Result<GeneratedHeaders, GenerateError>;   // CMake
pub fn generate_bindings(config: &BindingsConfig) -> Result<PathBuf, GenerateError>;         // bindgen
pub fn wireshark_bundle_name(major: &str, minor: &str) -> String;   // "wireshark-4-6.h"
pub fn dependency_bundle_name(target_os: &str, architecture: &str) -> String; // "deps-linux-x86_64.h"
pub const BUNDLE_BRANCH: &str = "headers";
pub const WIRESHARK_REMOTE: &str = "https://github.com/wireshark/wireshark.git";
impl Sdk { pub fn discover(config: &SdkConfig) -> Result<Sdk, Error>; }
impl Runtime { pub fn discover() -> Option<Runtime>; pub fn from_executable(PathBuf) -> Option<Runtime>; }
impl SourceTree { pub fn inspect(root: PathBuf) -> Option<SourceTree>; }
```

`PublicHeaderConfig` has public fields `source_dir`, `architecture`,
`target_os`, `dependency_include_dirs`, `output_dir`, `dll`,
`filtered_output`, `llvm_readobj`. `ReleaseBundlesConfig::new(repository,
output_dir, target_os, architecture)`, then set `versions` and
`dependency_include_dirs`.

A release-line bundle holds Wireshark's declared public headers (`epan`,
`epan/dfilter`, `epan/ftypes`, plus `packet-tcp.h` and `packet-udp.h` from
`epan/dissectors`) with `epan/packet.h` first, their transitive includes,
and generated `config.h`/`ws_version.h` defines. A dependency bundle holds
everything reachable from `glib.h`, `gmodule.h` and `gcrypt.h`. Each
embedded file is marked `/* Begin <path below its include root> */`.

## Errors

`GenerateError` (`#[non_exhaustive]`): `InvalidSource`,
`InvalidPublicHeaderList`, `MissingPublicHeader`, `SourceHeaderRead`,
`DependencyHeaders`, `ExportInspection`, `CmakeUnavailable`, `CmakeFailed`,
`MissingGeneratedHeaders`, `InvalidHeader`, `BindgenFailed`, `WriteFailed`,
`Git`. `Error` (SDK discovery): `#[non_exhaustive]`.

## Environment variables

`WIRESHARK_DIR`, `WIRESHARK_SOURCE_DIR`, `WIRESHARK_INCLUDE_DIR`,
`WIRESHARK_GENERATED_INCLUDE_DIR`, `WIRESHARK_LIB_DIR`, `WIRESHARK_VERSION`
(discovery); `WIRESHARK_TSHARK` (tshark to query); `WIRESHARK_BUILD_DIR`,
`WIRESHARK_CMAKE` (`configure`); `WIRESHARK_BINDGEN_TARGET` (`bindings`);
`WIRESHARK_DEPENDENCY_INCLUDE_DIRS` (extra GLib/Gcrypt roots, a path list).

## Gotchas

- Without GLib/Gcrypt headers for the target, Windows and macOS archives are
  downloaded from dev-libs.wireshark.org and cached under the temporary
  directory; Linux and FreeBSD need `--dependency-include-dir`.
- A source tag without an archive declaration for the target uses the
  manifest on Wireshark's master branch.
