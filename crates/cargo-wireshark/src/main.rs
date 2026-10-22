//! `cargo wireshark`: argument parsing and output over the `cargo_wireshark` library.

#![forbid(unsafe_code)]

use cargo_wireshark::{
    BUNDLE_BRANCH, BindingsConfig, GenerateError, GeneratedPublicHeader, HeaderConfig,
    PublicHeaderConfig, ReleaseBundlesConfig, Runtime, Sdk, SdkConfig, SourceTree, fetch_bundles,
    generate_bindings, generate_headers, generate_public_header, generate_release_lines,
    publish_bundles, write_export_report,
};
use clap::{Args, Parser, Subcommand};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Separator of a path list in an environment variable.
const PATH_LIST: char = if cfg!(windows) { ';' } else { ':' };

/// Where libwireshark-sys looks for bundles, relative to the repository root.
const DEFAULT_BUNDLE_DIR: &str = "crates/libwireshark-sys/headers";

/// Wireshark plugin development tools.
///
/// Exit status: 0 success, 1 the operation failed, 2 invalid arguments.
#[derive(Debug, Parser)]
#[command(name = "cargo-wireshark")]
struct Cli {
    #[command(subcommand)]
    command: WiresharkCommand,
}

#[derive(Debug, Subcommand)]
enum WiresharkCommand {
    /// Report the Wireshark runtime, SDK and source tree found; fails when there is neither runtime nor SDK.
    Doctor(DiscoveryArgs),
    /// Print the installed Wireshark version.
    Version(DiscoveryArgs),
    /// Generate, fetch or publish the header bundles libwireshark-sys reads.
    #[command(subcommand)]
    Headers(HeadersCommand),
    /// Configure Wireshark's CMake project to produce generated configuration headers.
    Configure(ConfigureArgs),
    /// Generate Rust FFI bindings from a Wireshark header tree.
    Bindings(BindingsArgs),
}

/// Where to look for Wireshark; each flag also reads its environment variable.
#[derive(Debug, Args)]
struct DiscoveryArgs {
    /// Wireshark installation or SDK root.
    #[arg(long, env = "WIRESHARK_DIR")]
    dir: Option<PathBuf>,
    /// Directory holding the SDK's headers (`epan/packet.h`).
    #[arg(long, env = "WIRESHARK_INCLUDE_DIR")]
    include_dir: Option<PathBuf>,
    /// Directory holding the SDK's generated `config.h`.
    #[arg(long, env = "WIRESHARK_GENERATED_INCLUDE_DIR")]
    generated_include_dir: Option<PathBuf>,
    /// Directory holding the Wireshark link library.
    #[arg(long, env = "WIRESHARK_LIB_DIR")]
    lib_dir: Option<PathBuf>,
    /// Version of an SDK that carries no pkg-config metadata.
    #[arg(long = "wireshark-version", env = "WIRESHARK_VERSION")]
    version: Option<String>,
    /// tshark to query; default `tshark` on PATH, then the Windows install location.
    #[arg(long, env = "WIRESHARK_TSHARK")]
    tshark: Option<PathBuf>,
    /// Wireshark source tree to report on.
    #[arg(long, env = "WIRESHARK_SOURCE_DIR")]
    source_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum HeadersCommand {
    /// Generate bundles from Wireshark's stable release tags (vX.Y.0, even Y, from 3.0),
    /// or from one source tree with --source-dir.
    Generate(Box<GenerateArgs>),
    /// Copy the bundles from the `headers` branch into the bundle directory.
    Fetch(FetchArgs),
    /// Commit the bundle directory to the local `headers` branch (does not push).
    Publish(PublishArgs),
}

#[derive(Debug, Args)]
struct GenerateArgs {
    /// One Wireshark source tree to generate from, instead of the release tags.
    #[arg(long, conflicts_with_all = ["repository", "versions"])]
    source_dir: Option<PathBuf>,
    /// Wireshark clone; created from the upstream repository when absent.
    #[arg(long, default_value = "wireshark-src")]
    repository: PathBuf,
    /// Bundle directory.
    #[arg(long, default_value = DEFAULT_BUNDLE_DIR)]
    output_dir: PathBuf,
    /// Rust target operating system; defaults to the host's.
    #[arg(long, default_value_t = std::env::consts::OS.to_owned())]
    target_os: String,
    /// Rust target architecture; defaults to the host's.
    #[arg(long, default_value_t = std::env::consts::ARCH.to_owned())]
    arch: String,
    /// Only this release line, such as 4.6; may be repeated.
    #[arg(long = "version", value_name = "MAJOR.MINOR")]
    versions: Vec<String>,
    /// GLib/Gcrypt include directory for the target; may be repeated, or a path list in the variable.
    #[arg(
        long = "dependency-include-dir",
        env = "WIRESHARK_DEPENDENCY_INCLUDE_DIRS",
        value_delimiter = PATH_LIST
    )]
    dependency_include_dirs: Vec<PathBuf>,
    /// Where downloaded dependency archives are kept; default the user cache directory.
    #[arg(long, env = "CARGO_WIRESHARK_CACHE_DIR")]
    cache_dir: Option<PathBuf>,
    /// Wireshark DLL whose exports are compared with the source declarations.
    #[arg(long, requires = "source_dir")]
    dll: Option<PathBuf>,
    /// Also write a release-line bundle limited to headers mentioning DLL exports.
    #[arg(long, requires = "dll")]
    filtered_output: Option<PathBuf>,
    /// Where the export comparison report goes.
    #[arg(
        long,
        requires = "dll",
        default_value = "libwireshark-export-comparison.md"
    )]
    report_output: PathBuf,
    /// LLVM object reader used to read DLL exports.
    #[arg(long, default_value = "llvm-readobj")]
    llvm_readobj: OsString,
}

#[derive(Debug, Args)]
struct FetchArgs {
    /// Remote holding the `headers` branch.
    #[arg(long, default_value = "origin")]
    remote: String,
    /// Bundle directory.
    #[arg(long, default_value = DEFAULT_BUNDLE_DIR)]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct PublishArgs {
    /// Bundle directory.
    #[arg(long, default_value = DEFAULT_BUNDLE_DIR)]
    output_dir: PathBuf,
    /// Commit message.
    #[arg(short, long, default_value = "chore: regenerate header bundles")]
    message: String,
}

#[derive(Debug, Args)]
struct ConfigureArgs {
    /// Wireshark source root.
    #[arg(long, env = "WIRESHARK_SOURCE_DIR")]
    source_dir: PathBuf,
    /// CMake build directory; defaults to build-rust-plugin-sdk under the source root.
    #[arg(long, env = "WIRESHARK_BUILD_DIR")]
    build_dir: Option<PathBuf>,
    /// CMake executable name or path.
    #[arg(long, env = "WIRESHARK_CMAKE", default_value = "cmake")]
    cmake: OsString,
    /// Extra CMake configuration argument; may be repeated.
    #[arg(long = "cmake-arg", value_name = "ARG")]
    cmake_args: Vec<OsString>,
}

#[derive(Debug, Args)]
struct BindingsArgs {
    /// Wireshark source root.
    #[arg(long, env = "WIRESHARK_SOURCE_DIR")]
    source_dir: PathBuf,
    /// CMake build directory containing config.h.
    #[arg(long, env = "WIRESHARK_GENERATED_INCLUDE_DIR")]
    generated_include_dir: PathBuf,
    /// C header passed to bindgen.
    #[arg(long)]
    header: PathBuf,
    /// Output Rust file.
    #[arg(long, default_value = "bindings.rs")]
    output: PathBuf,
    /// clang target triple.
    #[arg(long, env = "WIRESHARK_BINDGEN_TARGET")]
    target: Option<String>,
    /// Additional clang argument; may be repeated.
    #[arg(long = "clang-arg", value_name = "ARG")]
    clang_args: Vec<OsString>,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(cargo_args());
    let result = match cli.command {
        WiresharkCommand::Doctor(args) => doctor(args),
        WiresharkCommand::Version(args) => version(args),
        WiresharkCommand::Headers(command) => headers(command),
        WiresharkCommand::Configure(args) => configure(args),
        WiresharkCommand::Bindings(args) => bindings(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cargo-wireshark: {error}");
            ExitCode::FAILURE
        }
    }
}

/// What discovery found, from the flags of `doctor` and `version`.
struct Found {
    sdk: Result<Sdk, cargo_wireshark::Error>,
    runtime: Option<Runtime>,
    source: Option<SourceTree>,
}

fn discover(args: DiscoveryArgs) -> Found {
    let mut config = SdkConfig::default();
    config.root = args.dir;
    config.include_dir = args.include_dir;
    config.generated_include_dir = args.generated_include_dir;
    config.lib_dir = args.lib_dir;
    config.version = args.version;
    Found {
        sdk: Sdk::discover(&config),
        runtime: Runtime::discover(args.tshark.as_deref()),
        source: args.source_dir.and_then(SourceTree::inspect),
    }
}

fn doctor(args: DiscoveryArgs) -> Result<(), String> {
    let found = discover(args);
    if let Some(runtime) = &found.runtime {
        println!(
            "Wireshark {} runtime: {}",
            runtime.version,
            runtime.executable.display()
        );
    }
    match &found.sdk {
        Ok(sdk) => println!(
            "Wireshark {} SDK: {}",
            sdk.version.as_deref().unwrap_or("unknown"),
            sdk.include_dir.display()
        ),
        Err(error) => println!("No SDK ({error}); plugins build against the runtime."),
    }
    if let Some(source) = &found.source {
        println!(
            "Wireshark {} source: {}",
            source.version.as_deref().unwrap_or("unknown"),
            source.root.display()
        );
    }
    if found.runtime.is_none() && found.sdk.is_err() {
        return Err(
            "no Wireshark runtime or SDK was found; install Wireshark or pass --dir or --tshark"
                .to_owned(),
        );
    }
    Ok(())
}

fn version(args: DiscoveryArgs) -> Result<(), String> {
    let found = discover(args);
    let version = found
        .sdk
        .ok()
        .and_then(|sdk| sdk.version)
        .or_else(|| found.runtime.map(|runtime| runtime.version))
        .or_else(|| found.source.and_then(|source| source.version))
        .ok_or("no Wireshark SDK, tshark or source tree with a version was found")?;
    println!("{version}");
    Ok(())
}

fn headers(command: HeadersCommand) -> Result<(), String> {
    match command {
        HeadersCommand::Generate(args) if args.source_dir.is_some() => source_headers(*args),
        HeadersCommand::Generate(args) => {
            let mut config = ReleaseBundlesConfig::new(
                args.repository,
                args.output_dir,
                args.target_os,
                args.arch,
                args.cache_dir.unwrap_or_else(default_cache_dir),
            );
            config.versions = args.versions;
            config.dependency_include_dirs = args.dependency_include_dirs;
            for line in generate_release_lines(&config).map_err(text)? {
                println!(
                    "Generated Wireshark {}.{} from {}.",
                    line.major, line.minor, line.tag
                );
            }
            Ok(())
        }
        HeadersCommand::Fetch(args) => {
            let count =
                fetch_bundles(Path::new("."), &args.remote, &args.output_dir).map_err(text)?;
            println!(
                "Copied {count} bundles from {}/{BUNDLE_BRANCH} into {}.",
                args.remote,
                args.output_dir.display()
            );
            Ok(())
        }
        HeadersCommand::Publish(args) => {
            if publish_bundles(Path::new("."), &args.output_dir, &args.message).map_err(text)? {
                println!(
                    "Committed the bundles to {BUNDLE_BRANCH}; push with `git push origin {BUNDLE_BRANCH}`."
                );
            } else {
                println!(
                    "{BUNDLE_BRANCH} already matches {}.",
                    args.output_dir.display()
                );
            }
            Ok(())
        }
    }
}

fn source_headers(args: GenerateArgs) -> Result<(), String> {
    let mut config = PublicHeaderConfig::new(
        args.source_dir.expect("called with --source-dir"),
        args.output_dir,
        args.target_os,
        args.arch,
        args.cache_dir.unwrap_or_else(default_cache_dir),
    );
    config.dependency_include_dirs = args.dependency_include_dirs;
    config.dll = args.dll;
    config.filtered_output = args.filtered_output;
    config.llvm_readobj = args.llvm_readobj;
    let header = generate_public_header(&config).map_err(text)?;
    println!(
        "Generated Wireshark {} headers ({} public headers) at {} and {}.",
        header.version.as_deref().unwrap_or("unknown-version"),
        header.header_count,
        header.wireshark_header.display(),
        header.dependency_header.display()
    );
    if header.comparison.is_some() {
        write_export_report(&args.report_output, &header).map_err(|error| error.to_string())?;
        print_comparison(&header, &args.report_output);
    }
    Ok(())
}

fn print_comparison(header: &GeneratedPublicHeader, report: &Path) {
    let Some(comparison) = &header.comparison else {
        return;
    };
    if let Some((filtered, count)) = &comparison.filtered {
        println!(
            "Generated an export-filtered bundle of {count} public headers at {}.",
            filtered.display()
        );
    }
    println!(
        "Compared {} DLL exports: {} matched in public headers, {} not. Report: {}.",
        comparison.export_count,
        comparison.matched_exports,
        comparison.unmatched_exports(),
        report.display()
    );
}

fn configure(args: ConfigureArgs) -> Result<(), String> {
    let headers = generate_headers(&HeaderConfig {
        source_dir: args.source_dir,
        build_dir: args.build_dir,
        cmake: args.cmake,
        cmake_args: args.cmake_args,
    })
    .map_err(text)?;
    println!(
        "Generated Wireshark {} configuration headers in {}.",
        headers.version.as_deref().unwrap_or("unknown-version"),
        headers.build_dir.display()
    );
    Ok(())
}

fn bindings(args: BindingsArgs) -> Result<(), String> {
    let output = generate_bindings(&BindingsConfig {
        source_dir: args.source_dir,
        generated_include_dir: args.generated_include_dir,
        header: args.header,
        output: args.output,
        target: args.target,
        clang_args: args.clang_args,
    })
    .map_err(text)?;
    println!("Generated Rust bindings at {}.", output.display());
    Ok(())
}

fn text(error: GenerateError) -> String {
    error.to_string()
}

/// The user's cache directory for cargo-wireshark: `%LOCALAPPDATA%` on
/// Windows, `~/Library/Caches` on macOS, `$XDG_CACHE_HOME` or `~/.cache`
/// elsewhere; the temporary directory when none is known.
fn default_cache_dir() -> PathBuf {
    let var = |name| {
        std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        var("LOCALAPPDATA")
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|home| home.join("Library/Caches"))
    } else {
        var("XDG_CACHE_HOME").or_else(|| var("HOME").map(|home| home.join(".cache")))
    };
    base.unwrap_or_else(std::env::temp_dir)
        .join("cargo-wireshark")
}

/// The arguments without the `wireshark` that `cargo wireshark` inserts.
fn cargo_args() -> Vec<OsString> {
    let mut args = std::env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| OsString::from("cargo-wireshark"));
    let mut values: Vec<_> = args.collect();
    if values.first().and_then(|value| value.to_str()) == Some("wireshark") {
        values.remove(0);
    }
    let mut result = Vec::with_capacity(values.len() + 1);
    result.push(program);
    result.extend(values);
    result
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{CommandFactory, Parser};

    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn a_dll_comparison_needs_a_source_tree() {
        let error =
            Cli::try_parse_from(["cargo-wireshark", "headers", "generate", "--dll", "x.dll"])
                .unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn one_source_tree_excludes_release_line_selection() {
        let error = Cli::try_parse_from([
            "cargo-wireshark",
            "headers",
            "generate",
            "--source-dir",
            "ws",
            "--version",
            "4.6",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
