use cargo_wireshark::{
    BindingsConfig, HeaderConfig, PublicHeaderConfig, Runtime, Sdk, SdkConfig, SourceTree,
    generate_bindings, generate_headers, generate_public_header,
};
use clap::{Args, Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "cargo-wireshark",
    about = "Wireshark plugin development tools",
    after_help = "Environment: WIRESHARK_VERSION, WIRESHARK_DIR, WIRESHARK_SOURCE_DIR, WIRESHARK_INCLUDE_DIR, WIRESHARK_GENERATED_INCLUDE_DIR, WIRESHARK_BUILD_DIR, WIRESHARK_LIB_DIR, WIRESHARK_TSHARK, WIRESHARK_CMAKE, WIRESHARK_BINDGEN_TARGET, WIRESHARK_BINDGEN_HEADER"
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
    /// Generate a single header containing Wireshark's source-declared public headers.
    #[command(aliases = ["header", "generate-header", "generate-headers"])]
    Headers(HeaderArgs),
    /// Configure Wireshark's CMake project to produce generated configuration headers.
    Configure(ConfigureArgs),
    /// Generate Rust FFI bindings from a Wireshark header tree.
    #[command(alias = "generate-bindings")]
    Bindings(BindingsArgs),
}

#[derive(Debug, Args)]
struct HeaderArgs {
    /// Wireshark source root; defaults to WIRESHARK_SOURCE_DIR or WIRESHARK_DIR.
    #[arg(long, env = "WIRESHARK_SOURCE_DIR")]
    source_dir: Option<PathBuf>,
    /// Output path; defaults to the versioned header for --target-os and --arch.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Rust target architecture suffix; defaults to the host architecture.
    #[arg(long, default_value_t = std::env::consts::ARCH.to_owned())]
    arch: String,
    /// Rust target operating system; defaults to the host operating system.
    #[arg(long, default_value_t = std::env::consts::OS.to_owned())]
    target_os: String,
    /// Additional GLib/Gcrypt include directory; may be repeated.
    #[arg(long = "dependency-include-dir", action = clap::ArgAction::Append)]
    dependency_include_dirs: Vec<PathBuf>,
    /// Optional Wireshark DLL to compare against source declarations.
    #[arg(long)]
    dll: Option<PathBuf>,
    /// Output a smaller generated header containing only public headers mentioning DLL exports.
    #[arg(long, requires = "dll")]
    filtered_output: Option<PathBuf>,
    /// Optional comparison report path; defaults under .wireshark/generated when --dll is used.
    #[arg(long, requires = "dll")]
    report_output: Option<PathBuf>,
    /// LLVM object reader executable used for DLL export inspection.
    #[arg(long, default_value = "llvm-readobj")]
    llvm_readobj: OsString,
}

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
    /// C header passed to bindgen; defaults to the checked-in header for the source version.
    #[arg(long)]
    header: Option<PathBuf>,
    /// Output Rust file; defaults to .wireshark/generated/bindings.rs.
    #[arg(long, default_value = ".wireshark/generated/bindings.rs")]
    output: PathBuf,
    /// clang target triple; defaults to WIRESHARK_BINDGEN_TARGET when set.
    #[arg(long, env = "WIRESHARK_BINDGEN_TARGET")]
    target: Option<String>,
    /// Rust target architecture used to select the versioned header; defaults to --target or host.
    #[arg(long)]
    arch: Option<String>,
    /// Rust target operating system used to select the versioned header; defaults to --target or host.
    #[arg(long)]
    target_os: Option<String>,
    /// Additional clang argument; may be repeated for dependency include paths or defines.
    #[arg(long = "clang-arg", value_name = "ARG")]
    clang_args: Vec<OsString>,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(cargo_args());
    match cli.command {
        WiresharkCommand::Doctor => diagnostics(false),
        WiresharkCommand::Version => diagnostics(true),
        WiresharkCommand::Headers(args) => run_headers(args),
        WiresharkCommand::Configure(args) => run_configure(args),
        WiresharkCommand::Bindings(args) => run_bindings(args),
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

fn run_headers(args: HeaderArgs) -> ExitCode {
    let Some(source_dir) = args.source_dir.or_else(source_dir_from_env) else {
        eprintln!(
            "cargo-wireshark: set --source-dir or WIRESHARK_SOURCE_DIR to a Wireshark source checkout"
        );
        return ExitCode::FAILURE;
    };
    let Some(output) = args.output.or_else(|| {
        SourceTree::inspect(source_dir.clone())
            .and_then(|tree| tree.version)
            .as_deref()
            .and_then(|version| version_header_path(version, &args.target_os, &args.arch))
    }) else {
        eprintln!(
            "cargo-wireshark: could not determine a valid versioned output path; pass --output"
        );
        return ExitCode::FAILURE;
    };
    let config = PublicHeaderConfig {
        source_dir,
        architecture: args.arch,
        target_os: args.target_os,
        dependency_include_dirs: args.dependency_include_dirs,
        output,
        dll: args.dll,
        filtered_output: args.filtered_output,
        llvm_readobj: args.llvm_readobj,
    };
    match generate_public_header(&config) {
        Ok(header) => {
            let report_output = if header.export_count.is_some() {
                Some(args.report_output.unwrap_or_else(|| {
                    PathBuf::from(".wireshark/generated/libwireshark-export-comparison.md")
                }))
            } else {
                None
            };
            if let Some(report_path) = &report_output
                && let Err(error) = write_export_report(report_path, &header)
            {
                eprintln!("cargo-wireshark: {error}");
                return ExitCode::FAILURE;
            }
            println!(
                "Generated a public-header umbrella for Wireshark {} ({} headers) at {}.",
                header.version.as_deref().unwrap_or("unknown-version"),
                header.header_count,
                header.output.display()
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
    let mut non_public_headers = std::collections::BTreeMap::<PathBuf, Vec<&str>>::new();
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
    let header = match args.header {
        Some(header) => header,
        None => {
            let Some(version) =
                SourceTree::inspect(source_dir.clone()).and_then(|tree| tree.version)
            else {
                eprintln!(
                    "cargo-wireshark: could not determine the source tree version; pass --header explicitly"
                );
                return ExitCode::FAILURE;
            };
            let architecture = args
                .arch
                .as_deref()
                .or_else(|| {
                    args.target
                        .as_deref()
                        .and_then(|target| target.split('-').next())
                })
                .unwrap_or(std::env::consts::ARCH);
            let target_os = args
                .target_os
                .as_deref()
                .or_else(|| args.target.as_deref().and_then(target_os_from_triple))
                .unwrap_or(std::env::consts::OS);
            let Some(header) = version_header_path(&version, target_os, architecture) else {
                eprintln!(
                    "cargo-wireshark: invalid source version {version}; pass --header explicitly"
                );
                return ExitCode::FAILURE;
            };
            if !header.is_file() {
                eprintln!(
                    "cargo-wireshark: no checked-in public-header umbrella for {version}: {}; generate it with scripts/generate-version-headers.ps1 or pass --header",
                    header.display()
                );
                return ExitCode::FAILURE;
            }
            header
        }
    };
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

fn version_header_path(version: &str, target_os: &str, architecture: &str) -> Option<PathBuf> {
    let mut parts = version.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    if !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
        || !matches!(target_os, "windows" | "linux" | "macos")
        || architecture.is_empty()
        || !architecture
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return None;
    }
    Some(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../libwireshark-sys/headers")
            .join(format!("{major}-{minor}-{target_os}-{architecture}.h")),
    )
}

fn target_os_from_triple(target: &str) -> Option<&'static str> {
    if target.contains("windows") {
        Some("windows")
    } else if target.contains("linux") {
        Some("linux")
    } else if target.contains("apple-darwin") {
        Some("macos")
    } else {
        None
    }
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
    use super::version_header_path;

    #[test]
    fn versioned_header_path_contains_version_os_and_target_architecture() {
        let path = version_header_path("4.6.9", "windows", "aarch64").expect("valid header path");
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("4-6-windows-aarch64.h")
        );
    }

    #[test]
    fn versioned_header_path_rejects_path_components_in_architecture() {
        assert!(version_header_path("4.6.9", "windows", "../x86_64").is_none());
    }

    #[test]
    fn operating_system_and_architecture_select_distinct_bundles() {
        let windows = version_header_path("4.6.9", "windows", "x86_64").unwrap();
        let linux = version_header_path("4.6.9", "linux", "x86_64").unwrap();
        assert_ne!(windows, linux);
        assert_eq!(windows.file_name().unwrap(), "4-6-windows-x86_64.h");
        assert_eq!(linux.file_name().unwrap(), "4-6-linux-x86_64.h");
    }

    #[test]
    fn target_triples_select_supported_operating_systems() {
        assert_eq!(
            super::target_os_from_triple("x86_64-unknown-linux-gnu"),
            Some("linux")
        );
        assert_eq!(
            super::target_os_from_triple("x86_64-pc-windows-msvc"),
            Some("windows")
        );
        assert_eq!(
            super::target_os_from_triple("aarch64-apple-darwin"),
            Some("macos")
        );
    }
}
