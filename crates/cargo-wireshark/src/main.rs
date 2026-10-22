extern crate alloc;

use cargo_wireshark::{
    BUNDLE_BRANCH, BindingsConfig, HeaderConfig, PublicHeaderConfig, ReleaseBundlesConfig, Runtime,
    Sdk, SdkConfig, SourceTree, fetch_bundles, generate_bindings, generate_headers,
    generate_public_header, generate_release_lines, publish_bundles,
};
use clap::{Args, Parser, Subcommand};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "cargo-wireshark",
    about = "Wireshark plugin development tools",
    after_help = "Environment: WIRESHARK_VERSION, WIRESHARK_DIR, WIRESHARK_SOURCE_DIR, WIRESHARK_INCLUDE_DIR, WIRESHARK_GENERATED_INCLUDE_DIR, WIRESHARK_BUILD_DIR, WIRESHARK_LIB_DIR, WIRESHARK_TSHARK, WIRESHARK_CMAKE, WIRESHARK_BINDGEN_TARGET, WIRESHARK_DEPENDENCY_INCLUDE_DIRS"
)]
struct Cli {
    #[command(subcommand)]
    command: WiresharkCommand,
}

#[derive(Debug, Subcommand)]
enum WiresharkCommand {
    /// Check that the installed Wireshark development SDK can be discovered.
    Doctor,
    /// Print the installed Wireshark version.
    Version,
    /// Generate, fetch or publish the header bundles libwireshark-sys reads.
    #[command(subcommand)]
    Headers(HeadersCommand),
    /// Configure Wireshark's CMake project to produce generated configuration headers.
    Configure(ConfigureArgs),
    /// Generate Rust FFI bindings from a Wireshark header tree.
    #[command(alias = "generate-bindings")]
    Bindings(BindingsArgs),
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
    /// GLib/Gcrypt include directory for the target; may be repeated.
    #[arg(long = "dependency-include-dir")]
    dependency_include_dirs: Vec<PathBuf>,
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

/// Where libwireshark-sys looks for bundles, relative to the repository root.
const DEFAULT_BUNDLE_DIR: &str = "crates/libwireshark-sys/headers";

#[derive(Debug, Args)]
struct ConfigureArgs {
    /// Wireshark source root; defaults to WIRESHARK_SOURCE_DIR or WIRESHARK_DIR.
    #[arg(long, env = "WIRESHARK_SOURCE_DIR")]
    source_dir: Option<PathBuf>,
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
    /// Wireshark source root; defaults to WIRESHARK_SOURCE_DIR or WIRESHARK_DIR.
    #[arg(long, env = "WIRESHARK_SOURCE_DIR")]
    source_dir: Option<PathBuf>,
    /// CMake build directory containing config.h.
    #[arg(long, env = "WIRESHARK_GENERATED_INCLUDE_DIR")]
    generated_include_dir: Option<PathBuf>,
    /// C header passed to bindgen.
    #[arg(long)]
    header: PathBuf,
    /// Output Rust file; defaults to .wireshark/generated/bindings.rs.
    #[arg(long, default_value = ".wireshark/generated/bindings.rs")]
    output: PathBuf,
    /// clang target triple; defaults to WIRESHARK_BINDGEN_TARGET when set.
    #[arg(long, env = "WIRESHARK_BINDGEN_TARGET")]
    target: Option<String>,
    /// Additional clang argument; may be repeated for dependency include paths or defines.
    #[arg(long = "clang-arg", value_name = "ARG")]
    clang_args: Vec<OsString>,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(cargo_args());
    match cli.command {
        WiresharkCommand::Doctor => diagnostics(false),
        WiresharkCommand::Version => diagnostics(true),
        WiresharkCommand::Headers(command) => run_headers(command),
        WiresharkCommand::Configure(args) => run_configure(args),
        WiresharkCommand::Bindings(args) => run_bindings(args),
    }
}

fn run_headers(command: HeadersCommand) -> ExitCode {
    let result = match command {
        HeadersCommand::Generate(args) if args.source_dir.is_some() => {
            return run_source_headers(args);
        }
        HeadersCommand::Generate(args) => {
            let mut config = ReleaseBundlesConfig::new(
                args.repository,
                args.output_dir.clone(),
                args.target_os,
                args.arch,
            );
            config.versions = args.versions;
            config.dependency_include_dirs = args.dependency_include_dirs;
            generate_release_lines(&config).map(|lines| {
                for line in lines {
                    println!("Generated Wireshark {}.{} from {}.", line.major, line.minor, line.tag);
                }
            })
        }
        HeadersCommand::Fetch(args) => {
            fetch_bundles(Path::new("."), &args.remote, &args.output_dir).map(|count| {
                println!("Copied {count} bundles from {}/{BUNDLE_BRANCH} into {}.", args.remote, args.output_dir.display());
            })
        }
        HeadersCommand::Publish(args) => {
            publish_bundles(Path::new("."), &args.output_dir, &args.message).map(|committed| {
                if committed {
                    println!("Committed the bundles to {BUNDLE_BRANCH}; push with `git push origin {BUNDLE_BRANCH}`.");
                } else {
                    println!("{BUNDLE_BRANCH} already matches {}.", args.output_dir.display());
                }
            })
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cargo-wireshark: {error}");
            ExitCode::FAILURE
        }
    }
}

fn diagnostics(version_only: bool) -> ExitCode {
    let mut config = SdkConfig::default();
    config.root = std::env::var_os("WIRESHARK_DIR")
        .or_else(|| std::env::var_os("WIRESHARK_SOURCE_DIR"))
        .map(Into::into);
    config.include_dir = std::env::var_os("WIRESHARK_INCLUDE_DIR").map(Into::into);
    config.generated_include_dir =
        std::env::var_os("WIRESHARK_GENERATED_INCLUDE_DIR").map(Into::into);
    config.lib_dir = std::env::var_os("WIRESHARK_LIB_DIR").map(Into::into);
    config.version = std::env::var("WIRESHARK_VERSION").ok();
    let runtime = Runtime::discover();
    let source = source_dir_from_env().and_then(SourceTree::inspect);
    match Sdk::discover(&config) {
        Ok(sdk) if version_only => print_version(
            sdk.version
                .or_else(|| runtime.as_ref().map(|r| r.version.clone()))
                .or_else(|| source.as_ref().and_then(|s| s.version.clone())),
            "the selected SDK and TShark executable have no version metadata",
        ),
        Ok(sdk) => {
            println!(
                "Wireshark {} SDK detected.",
                sdk.version.as_deref().unwrap_or("unknown")
            );
            ExitCode::SUCCESS
        }
        Err(error) if version_only => {
            let version = runtime
                .as_ref()
                .map(|runtime| runtime.version.clone())
                .or_else(|| source.as_ref().and_then(|source| source.version.clone()));
            print_version(
                version,
                &format!(
                    "{error}; no version metadata was found in an SDK, TShark executable, or source tree"
                ),
            )
        }
        Err(error) => {
            if let Some(runtime) = runtime {
                println!(
                    "Wireshark {} runtime detected at {}.",
                    runtime.version,
                    runtime.executable.display()
                );
            }
            if let Some(source) = source {
                println!(
                    "Wireshark {} source detected at {}.",
                    source.version.as_deref().unwrap_or("unknown"),
                    source.root.display()
                );
                println!(
                    "The source headers need generated configuration headers and native link libraries to build a plugin."
                );
            }
            eprintln!(
                "cargo-wireshark: {error}; install the matching Wireshark development SDK or set WIRESHARK_SOURCE_DIR, WIRESHARK_INCLUDE_DIR, WIRESHARK_GENERATED_INCLUDE_DIR, and WIRESHARK_LIB_DIR"
            );
            ExitCode::FAILURE
        }
    }
}

fn run_source_headers(args: Box<GenerateArgs>) -> ExitCode {
    let source_dir = args.source_dir.expect("called with --source-dir");
    let config = PublicHeaderConfig {
        source_dir,
        architecture: args.arch,
        target_os: args.target_os,
        dependency_include_dirs: args.dependency_include_dirs,
        output_dir: args.output_dir,
        dll: args.dll,
        filtered_output: args.filtered_output,
        llvm_readobj: args.llvm_readobj,
    };
    match generate_public_header(&config) {
        Ok(header) => {
            let report_output = header.export_count.is_some().then_some(args.report_output);
            if let Some(report_path) = &report_output
                && let Err(error) = write_export_report(report_path, &header)
            {
                eprintln!("cargo-wireshark: {error}");
                return ExitCode::FAILURE;
            }
            println!(
                "Generated Wireshark {} headers ({} public headers) at {} and {}.",
                header.version.as_deref().unwrap_or("unknown-version"),
                header.header_count,
                header.wireshark_header.display(),
                header.dependency_header.display()
            );
            if let Some(filtered) = &header.filtered_output {
                println!(
                    "Generated export-filtered umbrella at {}.",
                    filtered.display()
                );
                println!(
                    "Filtered public headers: {}.",
                    header.filtered_header_count.unwrap_or_default()
                );
            }
            if let Some(export_count) = header.export_count {
                println!("Compared {export_count} DLL exports against source headers.");
                if let Some(report_path) = report_output {
                    println!(
                        "Wrote export comparison report to {}.",
                        report_path.display()
                    );
                }
                println!(
                    "DLL exports matched in public headers: {}.",
                    header.matched_exports
                );
                println!(
                    "DLL exports not matched in public headers: {}.",
                    header.unmatched_exports
                );
                for (symbol, files) in header.missing_public_headers {
                    println!("Export {symbol} is declared outside the public header lists:");
                    for file in files {
                        println!("  {}", file.display());
                    }
                }
                for (symbol, files) in &header.declarations_missing_from_dll {
                    println!("Public WS_DLL_PUBLIC declaration {symbol} is absent from the DLL:");
                    for file in files {
                        println!("  {}", file.display());
                    }
                }
                for symbol in header.no_header_matches {
                    println!("Export {symbol} has no matching header in the source tree.");
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cargo-wireshark: {error}");
            ExitCode::FAILURE
        }
    }
}

fn write_export_report(
    path: &std::path::Path,
    header: &cargo_wireshark::GeneratedPublicHeader,
) -> std::io::Result<()> {
    let mut report = format!(
        "# Wireshark {} DLL export/header comparison\n\n- Source public headers: {}\n- DLL exports inspected: {}\n- Exports mentioned in source public headers: {}\n- Exports not matched in public headers: {}\n\n",
        header.version.as_deref().unwrap_or("unknown version"),
        header.header_count,
        header.export_count.unwrap_or_default(),
        header.matched_exports,
        header.unmatched_exports,
    );
    let mut non_public_headers = alloc::collections::BTreeMap::<PathBuf, Vec<&str>>::new();
    for (symbol, files) in &header.missing_public_headers {
        for file in files {
            non_public_headers
                .entry(file.clone())
                .or_default()
                .push(symbol);
        }
    }
    report.push_str("## Candidate headers missing from the public-header import\n\n");
    if non_public_headers.is_empty() {
        report.push_str("None.\n\n");
    } else {
        for (file, symbols) in &non_public_headers {
            report.push_str(&format!(
                "- `{}` ({} exports): ",
                file.display().to_string().replace('\\', "/"),
                symbols.len(),
            ));
            report.push_str(
                &symbols
                    .iter()
                    .map(|symbol| format!("`{symbol}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            report.push('\n');
        }
        report.push('\n');
    }
    report.push_str("## Exports found only outside the public header lists\n\n");
    if header.missing_public_headers.is_empty() {
        report.push_str("None.\n\n");
    } else {
        for (symbol, files) in &header.missing_public_headers {
            report.push_str(&format!("- `{symbol}`: "));
            report.push_str(
                &files
                    .iter()
                    .map(|file| file.display().to_string().replace('\\', "/"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            report.push('\n');
        }
        report.push('\n');
    }
    report.push_str("## Public WS_DLL_PUBLIC declarations absent from the DLL\n\n");
    if header.declarations_missing_from_dll.is_empty() {
        report.push_str("None.\n\n");
    } else {
        for (symbol, files) in &header.declarations_missing_from_dll {
            report.push_str(&format!("- `{symbol}`: "));
            report.push_str(
                &files
                    .iter()
                    .map(|file| file.display().to_string().replace('\\', "/"))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            report.push('\n');
        }
        report.push('\n');
    }
    report.push_str("## Exports with no header-name match in the source tree\n\n");
    if header.no_header_matches.is_empty() {
        report.push_str("None.\n\n");
    } else {
        for symbol in &header.no_header_matches {
            report.push_str(&format!("- `{symbol}`\n"));
        }
        report.push('\n');
    }
    if let Some(filtered_path) = &header.filtered_output {
        report.push_str(&format!(
            "Export-filtered umbrella: `{}` ({} public headers).\n",
            filtered_path.display(),
            header.filtered_header_count.unwrap_or_default(),
        ));
    }
    report.push_str(
        "\nName matching searches C header text and is not a C declaration or ABI validation.\n",
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, report)
}

fn run_configure(args: ConfigureArgs) -> ExitCode {
    let Some(source_dir) = args.source_dir.or_else(source_dir_from_env) else {
        eprintln!(
            "cargo-wireshark: set --source-dir or WIRESHARK_SOURCE_DIR to a Wireshark source checkout"
        );
        return ExitCode::FAILURE;
    };
    let config = HeaderConfig {
        source_dir,
        build_dir: args.build_dir,
        cmake: args.cmake,
        cmake_args: args.cmake_args,
    };
    match generate_headers(&config) {
        Ok(headers) => {
            println!(
                "Generated Wireshark {} configuration headers in {}.",
                headers.version.as_deref().unwrap_or("unknown-version"),
                headers.build_dir.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cargo-wireshark: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_bindings(args: BindingsArgs) -> ExitCode {
    let Some(source_dir) = args.source_dir.or_else(source_dir_from_env) else {
        eprintln!(
            "cargo-wireshark: set --source-dir or WIRESHARK_SOURCE_DIR to a Wireshark source checkout"
        );
        return ExitCode::FAILURE;
    };
    let Some(generated_include_dir) = args
        .generated_include_dir
        .or_else(|| std::env::var_os("WIRESHARK_BUILD_DIR").map(PathBuf::from))
    else {
        eprintln!(
            "cargo-wireshark: set --generated-include-dir to a configured CMake build directory, or set WIRESHARK_GENERATED_INCLUDE_DIR"
        );
        return ExitCode::FAILURE;
    };
    let header = args.header;
    let config = BindingsConfig {
        source_dir,
        generated_include_dir,
        header,
        output: args.output,
        target: args.target,
        clang_args: args.clang_args,
    };
    match generate_bindings(&config) {
        Ok(output) => {
            println!("Generated Rust bindings at {}.", output.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cargo-wireshark: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_version(version: Option<String>, error: &str) -> ExitCode {
    match version {
        Some(version) => {
            println!("{version}");
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("cargo-wireshark: {error}");
            ExitCode::FAILURE
        }
    }
}

fn source_dir_from_env() -> Option<PathBuf> {
    std::env::var_os("WIRESHARK_SOURCE_DIR")
        .or_else(|| std::env::var_os("WIRESHARK_DIR"))
        .map(PathBuf::from)
}

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
    use clap::CommandFactory;

    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }
}
