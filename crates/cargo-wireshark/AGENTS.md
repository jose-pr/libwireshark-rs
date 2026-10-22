# `cargo-wireshark` — API header

Header-file-style reference for the `cargo-wireshark` crate: every public item with
its signature, contract and gotchas, so the crate can be used without
reading its source. It ships inside the package and is self-contained.
Development documentation lives with the source at
<https://github.com/jose-pr/libwireshark-rs>.

No features. MSRV 1.89. Depends on `clap`, `bindgen` (libclang at run time
for `bindings`), `ureq` (rustls), `sha2`, `zip`, `sevenz-rust2`,
`lzma-rust2`, `tar`. No `unsafe`. Runs `git`, `cmake`, `llvm-readobj`,
`tshark` and `pkg-config` as subprocesses with argument vectors. The library
reads no environment variable except `PATH` and `ProgramFiles` to find tshark;
the binary reads the ones below.

## Command line

Invoked as `cargo wireshark <command>` or `cargo-wireshark <command>`.

| Command | Does |
| --- | --- |
| `doctor [discovery flags]` | reports the runtime (tshark), SDK and source tree found; fails when there is neither runtime nor SDK |
| `version [discovery flags]` | prints the version of the SDK, else the runtime, else the source tree |
| `headers generate [--version M.m]... [--target-os OS] [--arch ARCH] [--repository DIR] [--output-dir DIR] [--dependency-include-dir DIR]... [--cache-dir DIR]` | bundles for each stable release line (`vX.Y.0`, even Y, from 3.0), from temporary worktrees of a Wireshark clone (cloned when absent) |
| `headers generate --source-dir DIR [--dll DLL [--filtered-output FILE] [--report-output FILE]]` | bundles from one source tree; with `--dll`, a Markdown report of DLL exports against source declarations |
| `headers fetch [--remote origin] [--output-dir DIR]` | copies the bundles from `<remote>/headers` |
| `headers publish [-m MESSAGE] [--output-dir DIR]` | commits the bundles to the local `headers` branch (orphan when new); does not push |
| `configure --source-dir DIR [--build-dir DIR] [--cmake CMAKE] [--cmake-arg ARG]...` | runs Wireshark's CMake configure to produce `config.h` |
| `bindings --source-dir DIR --generated-include-dir DIR --header H [--output F] [--target T] [--clang-arg A]...` | runs bindgen over a source tree |

Discovery flags: `--dir`, `--include-dir`, `--generated-include-dir`,
`--lib-dir`, `--wireshark-version`, `--tshark`, `--source-dir`.

Defaults: `--repository wireshark-src`, `--output-dir
crates/libwireshark-sys/headers` (relative to the working directory),
`--target-os`/`--arch` the host's, `--cache-dir` the user cache directory
(`%LOCALAPPDATA%\cargo-wireshark`, `~/Library/Caches/cargo-wireshark`,
`$XDG_CACHE_HOME/cargo-wireshark` or `~/.cache/cargo-wireshark`). Exit
status 0 success, 1 failure, 2 invalid arguments. Results on stdout, one-line
errors on stderr prefixed `cargo-wireshark:`.

## Library (`cargo_wireshark`)

```rust
pub fn generate_public_header(config: &PublicHeaderConfig) -> Result<GeneratedPublicHeader, GenerateError>;
pub fn generate_release_lines(config: &ReleaseBundlesConfig) -> Result<Vec<ReleaseLine>, GenerateError>;
pub fn release_lines(repository: &Path) -> Result<Vec<ReleaseLine>, GenerateError>;
pub fn fetch_bundles(checkout: &Path, remote: &str, output_dir: &Path) -> Result<usize, GenerateError>;
pub fn publish_bundles(checkout: &Path, output_dir: &Path, message: &str) -> Result<bool, GenerateError>;
pub fn generate_headers(config: &HeaderConfig) -> Result<GeneratedHeaders, GenerateError>;   // CMake
pub fn generate_bindings(config: &BindingsConfig) -> Result<PathBuf, GenerateError>;         // bindgen
pub fn export_report(header: &GeneratedPublicHeader) -> Option<String>;                       // None without a DLL
pub fn write_export_report(path: &Path, header: &GeneratedPublicHeader) -> std::io::Result<()>;
pub fn wireshark_bundle_name(major: &str, minor: &str) -> String;   // "wireshark-4-6.h"
pub fn dependency_bundle_name(target_os: &str, architecture: &str) -> String; // "deps-linux-x86_64.h"
pub const BUNDLE_BRANCH: &str = "headers";
pub const WIRESHARK_REMOTE: &str = "https://github.com/wireshark/wireshark.git";
impl Sdk { pub fn discover(config: &SdkConfig) -> Result<Sdk, Error>; }
impl Runtime { pub fn discover(tshark: Option<&Path>) -> Option<Runtime>; pub fn from_executable(PathBuf) -> Option<Runtime>; }
impl SourceTree { pub fn inspect(root: PathBuf) -> Option<SourceTree>; }
impl PublicHeaderConfig { pub fn new(source_dir, output_dir, target_os, architecture, cache_dir) -> Self; }
impl ReleaseBundlesConfig { pub fn new(repository, output_dir, target_os, architecture, cache_dir) -> Self; }
impl ExportComparison { pub fn unmatched_exports(&self) -> usize; }
```

`PublicHeaderConfig` (`#[non_exhaustive]`) also has public `dependency_include_dirs`,
`dll`, `filtered_output`, `llvm_readobj`; `ReleaseBundlesConfig` has
`versions` and `dependency_include_dirs`. `GeneratedPublicHeader` holds
`version`, `wireshark_header`, `dependency_header`, `header_count` and
`comparison: Option<ExportComparison>` (`export_count`, `matched_exports`,
`missing_public_headers`, `declarations_missing_from_dll`,
`no_header_matches`, `filtered`). Export matching is by name in header
text, not a declaration or ABI check.

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
`Git`. `Error` (SDK discovery, `#[non_exhaustive]`): `NotFound`,
`InvalidPaths`, `InvalidVersion`.

## Environment variables

Each backs the flag named in parentheses; a flag given wins.

| Variable | Flag |
| --- | --- |
| `WIRESHARK_DIR` | `--dir` |
| `WIRESHARK_INCLUDE_DIR` | `--include-dir` |
| `WIRESHARK_GENERATED_INCLUDE_DIR` | `--generated-include-dir` |
| `WIRESHARK_LIB_DIR` | `--lib-dir` |
| `WIRESHARK_VERSION` | `--wireshark-version` |
| `WIRESHARK_TSHARK` | `--tshark` |
| `WIRESHARK_SOURCE_DIR` | `--source-dir` (discovery, `configure`, `bindings`) |
| `WIRESHARK_DEPENDENCY_INCLUDE_DIRS` | `--dependency-include-dir` (a path list) |
| `CARGO_WIRESHARK_CACHE_DIR` | `--cache-dir` |
| `WIRESHARK_BUILD_DIR` | `configure --build-dir` |
| `WIRESHARK_CMAKE` | `configure --cmake` |
| `WIRESHARK_BINDGEN_TARGET` | `bindings --target` |

## Gotchas

- Without GLib/Gcrypt headers for the target, Windows and macOS archives are
  downloaded from dev-libs.wireshark.org, checked against Wireshark's
  SHA-256, and kept extracted under the cache directory; Linux and FreeBSD
  need `--dependency-include-dir`.
- Extraction refuses entries whose path leaves the destination, skips links,
  and stops past 1 GiB.
- A source tag without an archive declaration for the target uses the
  manifest on Wireshark's master branch.
