use core::fmt;
use sha2::Digest;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Paths and an optional version supplied to Wireshark SDK discovery.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SdkConfig {
    /// Root directory of a Wireshark development installation.
    pub root: Option<PathBuf>,
    /// Directory containing the installed Wireshark headers.
    pub include_dir: Option<PathBuf>,
    /// Directory containing the Wireshark link library.
    pub lib_dir: Option<PathBuf>,
    /// Directory containing generated Wireshark configuration headers.
    pub generated_include_dir: Option<PathBuf>,
    /// Version of an installation whose SDK has no pkg-config metadata.
    pub version: Option<String>,
}

/// A Wireshark runtime installation, which can inspect captures but cannot by itself build plugins.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Runtime {
    /// Runtime version reported by TShark.
    pub version: String,
    /// TShark executable used to query the runtime.
    pub executable: PathBuf,
}

/// A Wireshark source checkout, which may lack generated headers and built native libraries.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SourceTree {
    /// Version declared by the source checkout when available.
    pub version: Option<String>,
    /// Source root containing `epan/packet.h`.
    pub root: PathBuf,
}

/// An installed Wireshark development SDK.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Sdk {
    /// SDK version, or `None` when explicit paths do not carry version metadata.
    pub version: Option<String>,
    /// Header directory containing `epan/packet.h`.
    pub include_dir: PathBuf,
    /// Directory containing generated headers such as `config.h`, when separate.
    pub generated_include_dir: Option<PathBuf>,
    /// Native library directory.
    pub lib_dir: PathBuf,
}

/// An error while locating a Wireshark development SDK.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The `wireshark` pkg-config module could not be resolved and explicit paths were incomplete.
    NotFound,
    /// The selected SDK paths do not contain the required headers or library directory.
    InvalidPaths,
    /// `pkg-config` returned a version that was not valid UTF-8.
    InvalidVersion,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("Wireshark development files were not found"),
            Self::InvalidPaths => f.write_str("Wireshark SDK paths are incomplete or invalid"),
            Self::InvalidVersion => f.write_str("pkg-config returned an invalid Wireshark version"),
        }
    }
}

impl std::error::Error for Error {}

/// Inputs for configuring Wireshark's generated C headers.
#[derive(Clone, Debug)]
pub struct HeaderConfig {
    /// Wireshark source root.
    pub source_dir: PathBuf,
    /// CMake build directory; defaults to `build-rust-plugin-sdk` under the source root.
    pub build_dir: Option<PathBuf>,
    /// CMake executable name or path.
    pub cmake: OsString,
    /// Extra CMake arguments, passed after `-S` and `-B`.
    pub cmake_args: Vec<OsString>,
}

/// Inputs for generating a wrapper over Wireshark's source-declared public headers.
#[derive(Clone, Debug)]
pub struct PublicHeaderConfig {
    /// Wireshark source root.
    pub source_dir: PathBuf,
    /// Rust target architecture used to select target-matched dependency headers.
    pub architecture: String,
    /// Rust target operating system used to select target-matched dependency headers.
    pub target_os: String,
    /// Directories containing available GLib and Gcrypt development headers.
    pub dependency_include_dirs: Vec<PathBuf>,
    /// Destination for the generated C umbrella header.
    pub output: PathBuf,
    /// Optional Wireshark DLL whose exports should be compared with declarations.
    pub dll: Option<PathBuf>,
    /// Optional destination for an umbrella limited to headers mentioning exported symbols.
    pub filtered_output: Option<PathBuf>,
    /// LLVM object reader used to inspect PE exports.
    pub llvm_readobj: OsString,
}

/// Result of collecting and optionally comparing source-declared public headers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GeneratedPublicHeader {
    /// Wireshark source version, when available.
    pub version: Option<String>,
    /// Generated umbrella over all public headers.
    pub output: PathBuf,
    /// Number of source-declared public headers included.
    pub header_count: usize,
    /// Generated optional umbrella containing only headers with exported symbol declarations.
    pub filtered_output: Option<PathBuf>,
    /// Number of headers in the optional export-filtered umbrella.
    pub filtered_header_count: Option<usize>,
    /// Number of DLL exports inspected, or `None` when no DLL was supplied.
    pub export_count: Option<usize>,
    /// Number of named DLL exports found in public header text.
    pub matched_exports: usize,
    /// Number of named DLL exports with no match in public header text.
    pub unmatched_exports: usize,
    /// Exported names mentioned by headers outside Wireshark's declared public-header lists,
    /// with the source files that mention each name.
    pub missing_public_headers: Vec<(String, Vec<PathBuf>)>,
    /// Public `WS_DLL_PUBLIC` function declarations that are absent from the selected DLL.
    pub declarations_missing_from_dll: Vec<(String, Vec<PathBuf>)>,
    /// Exported names not mentioned by any C header in the source tree.
    pub no_header_matches: Vec<String>,
}

/// Generated header locations produced by CMake configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GeneratedHeaders {
    /// Wireshark version declared by the source tree.
    pub version: Option<String>,
    /// CMake build directory containing generated headers.
    pub build_dir: PathBuf,
    /// Generated Wireshark configuration header.
    pub config_header: PathBuf,
    /// Generated Wireshark version header.
    pub version_header: PathBuf,
}

/// Inputs for generating Rust FFI bindings from Wireshark headers.
#[derive(Clone, Debug)]
pub struct BindingsConfig {
    /// Wireshark source root.
    pub source_dir: PathBuf,
    /// CMake build directory containing `config.h`.
    pub generated_include_dir: PathBuf,
    /// C umbrella header passed to bindgen.
    pub header: PathBuf,
    /// Destination for generated Rust bindings.
    pub output: PathBuf,
    /// Optional clang target triple.
    pub target: Option<String>,
    /// Additional arguments passed to clang, such as dependency include paths.
    pub clang_args: Vec<OsString>,
}

/// A header or binding generation operation failed.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GenerateError {
    /// The supplied path does not contain a Wireshark source tree.
    InvalidSource,
    /// A source CMake file does not declare the requested public-header list.
    InvalidPublicHeaderList(PathBuf),
    /// A header named by Wireshark's public-header list is absent from the source tree.
    MissingPublicHeader(PathBuf),
    /// A local header referenced by a public header could not be read.
    SourceHeaderRead(PathBuf),
    /// Required GLib or Gcrypt development headers could not be found or fetched.
    DependencyHeaders(String),
    /// DLL exports could not be inspected.
    ExportInspection(String),
    /// CMake could not be started.
    CmakeUnavailable(String),
    /// CMake configuration failed.
    CmakeFailed(String),
    /// CMake did not produce the expected headers.
    MissingGeneratedHeaders(PathBuf),
    /// The umbrella header is missing or unreadable.
    InvalidHeader(PathBuf),
    /// Bindgen could not parse the supplied Wireshark headers.
    BindgenFailed(String),
    /// Generated bindings could not be written.
    WriteFailed(String),
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource => f.write_str("the source path is not a Wireshark checkout containing epan/packet.h and CMakeLists.txt"),
            Self::InvalidPublicHeaderList(path) => write!(f, "could not read a public-header list from {}", path.display()),
            Self::MissingPublicHeader(path) => write!(f, "a source-declared public header is missing: {}", path.display()),
            Self::SourceHeaderRead(path) => write!(f, "could not read source header {}", path.display()),
            Self::DependencyHeaders(error) => write!(f, "could not resolve GLib/Gcrypt headers: {error}"),
            Self::ExportInspection(error) => write!(f, "could not inspect DLL exports: {error}"),
            Self::CmakeUnavailable(error) => write!(f, "could not start CMake: {error}"),
            Self::CmakeFailed(error) => write!(f, "Wireshark CMake configuration failed: {error}"),
            Self::MissingGeneratedHeaders(path) => write!(f, "generated config.h and ws_version.h were not found in {}", path.display()),
            Self::InvalidHeader(path) => write!(f, "bindgen input header is missing: {}", path.display()),
            Self::BindgenFailed(error) => write!(f, "bindgen failed: {error}"),
            Self::WriteFailed(error) => write!(f, "could not write generated bindings: {error}"),
        }
    }
}

impl std::error::Error for GenerateError {}

/// Generates an umbrella header from Wireshark's own public-header lists without running CMake.
///
/// If `dll` and `filtered_output` are both supplied, also writes an umbrella containing only
/// headers whose source text declares a name exported by that DLL. Export matching is a name
/// comparison only; it cannot validate or infer C signatures or ABI layouts.
pub fn generate_public_header(
    config: &PublicHeaderConfig,
) -> Result<GeneratedPublicHeader, GenerateError> {
    let source =
        SourceTree::inspect(config.source_dir.clone()).ok_or(GenerateError::InvalidSource)?;
    let header_lists = [
        (
            source.root.join("epan/CMakeLists.txt"),
            "LIBWIRESHARK_PUBLIC_HEADERS",
            "epan",
        ),
        (
            source.root.join("epan/dfilter/CMakeLists.txt"),
            "DFILTER_PUBLIC_HEADERS",
            "epan/dfilter",
        ),
        (
            source.root.join("epan/ftypes/CMakeLists.txt"),
            "FTYPE_PUBLIC_HEADERS",
            "epan/ftypes",
        ),
        (
            source.root.join("epan/dissectors/CMakeLists.txt"),
            "DISSECTOR_PUBLIC_HEADERS",
            "epan/dissectors",
        ),
    ];
    let mut headers = Vec::new();
    let modern_lists_present = header_lists.iter().all(|(cmake_file, variable, _)| {
        std::fs::read_to_string(cmake_file)
            .is_ok_and(|contents| contents.contains(&format!("set({variable}")))
    });
    if modern_lists_present {
        for (cmake_file, variable, directory) in header_lists {
            for name in cmake_header_list(&cmake_file, variable)? {
                let relative = PathBuf::from(directory).join(name);
                let path = source.root.join(&relative);
                if !path.is_file() {
                    return Err(GenerateError::MissingPublicHeader(path));
                }
                headers.push((relative, path));
            }
        }
    } else {
        headers = debian_public_headers(&source.root)?;
    }
    // Keep Wireshark's declared order. Some dissector headers intentionally
    // rely on shared typedefs declared by earlier entries without including
    // their owning header directly.
    let mut seen_headers = std::collections::HashSet::new();
    headers.retain(|(relative, _)| seen_headers.insert(relative.clone()));

    let dependency_roots = dependency_header_roots(
        &source.root,
        &config.target_os,
        &config.architecture,
        &config.dependency_include_dirs,
    )?;
    write_umbrella(
        &source.root,
        &config.output,
        &headers
            .iter()
            .map(|(relative, _)| relative)
            .collect::<Vec<_>>(),
        &dependency_roots,
        source.version.as_deref(),
    )?;

    let (
        filtered_output,
        filtered_header_count,
        export_count,
        matched_exports,
        unmatched_exports,
        missing_public_headers,
        declarations_missing_from_dll,
        no_header_matches,
    ) = match (&config.dll, &config.filtered_output) {
        (Some(dll), filtered_output) => {
            let exports = inspect_pe_exports(&config.llvm_readobj, dll)?;
            let all_header_matches = find_export_header_mentions(&source.root, &exports)?;
            let export_set: std::collections::HashSet<&str> =
                exports.iter().map(String::as_str).collect();
            let mut public_declarations: std::collections::HashMap<String, Vec<PathBuf>> =
                std::collections::HashMap::new();
            for (relative, path) in &headers {
                let Ok(contents) = std::fs::read_to_string(path) else {
                    continue;
                };
                for symbol in public_function_declarations(&contents) {
                    if !export_set.contains(symbol.as_str()) {
                        public_declarations
                            .entry(symbol)
                            .or_default()
                            .push(relative.clone());
                    }
                }
            }
            for files in public_declarations.values_mut() {
                files.sort();
                files.dedup();
            }
            let public_paths: std::collections::HashSet<PathBuf> =
                std::collections::HashSet::from_iter(headers.iter().map(|(_, path)| path.clone()));
            let public_symbols: std::collections::HashSet<String> =
                std::collections::HashSet::from_iter(
                    all_header_matches
                        .iter()
                        .filter(|(_, files)| files.iter().any(|file| public_paths.contains(file)))
                        .map(|(symbol, _)| symbol.clone()),
                );
            let filtered = headers
                .iter()
                .filter_map(|(relative, path)| {
                    let has_export = public_symbols.iter().any(|symbol| {
                        all_header_matches
                            .get(symbol)
                            .is_some_and(|files| files.contains(path))
                    });
                    has_export.then_some(relative)
                })
                .collect::<Vec<_>>();
            let filtered_count = filtered.len();
            if let Some(filtered_output) = filtered_output {
                write_umbrella(
                    &source.root,
                    filtered_output,
                    &filtered,
                    &dependency_roots,
                    source.version.as_deref(),
                )?;
            }
            let missing_public_headers = all_header_matches
                .iter()
                .filter(|(symbol, _)| !public_symbols.contains(*symbol))
                .map(|(symbol, files)| {
                    let candidates = files
                        .iter()
                        .filter(|file| !public_paths.contains(*file))
                        .cloned()
                        .collect();
                    (symbol.clone(), candidates)
                })
                .filter(|(_, files): &(String, Vec<PathBuf>)| !files.is_empty())
                .collect::<Vec<_>>();
            let no_header_matches = exports
                .iter()
                .filter(|symbol| !all_header_matches.contains_key(*symbol))
                .cloned()
                .collect::<Vec<_>>();
            let matched_count = public_symbols.len();
            (
                filtered_output.clone(),
                filtered_output.as_ref().map(|_| filtered_count),
                Some(exports.len()),
                matched_count,
                exports.len().saturating_sub(matched_count),
                missing_public_headers,
                public_declarations.into_iter().collect(),
                no_header_matches,
            )
        }
        (None, None) => (None, None, None, 0, 0, Vec::new(), Vec::new(), Vec::new()),
        (None, Some(_)) => {
            return Err(GenerateError::ExportInspection(
                "--filtered-output requires --dll".to_owned(),
            ));
        }
    };

    Ok(GeneratedPublicHeader {
        version: source.version,
        output: config.output.clone(),
        header_count: headers.len(),
        filtered_output,
        filtered_header_count,
        export_count,
        matched_exports,
        unmatched_exports,
        missing_public_headers,
        declarations_missing_from_dll,
        no_header_matches,
    })
}

fn find_export_header_mentions(
    source_root: &Path,
    exports: &[String],
) -> Result<std::collections::HashMap<String, Vec<PathBuf>>, GenerateError> {
    let export_set: std::collections::HashSet<&str> =
        std::collections::HashSet::from_iter(exports.iter().map(String::as_str));
    let mut matches: std::collections::HashMap<String, Vec<PathBuf>> =
        std::collections::HashMap::new();
    let mut headers = Vec::new();
    let mut pending = vec![source_root.to_owned()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| GenerateError::ExportInspection(error.to_string()))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| GenerateError::ExportInspection(error.to_string()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| GenerateError::ExportInspection(error.to_string()))?;
            if file_type.is_dir() {
                let name = entry.file_name();
                if name != ".git"
                    && name != "build"
                    && !name.to_string_lossy().starts_with("build-")
                {
                    pending.push(path);
                }
            } else if file_type.is_file()
                && path.extension().is_some_and(|extension| extension == "h")
            {
                headers.push(path);
            }
        }
    }
    for path in &headers {
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(_) => continue,
        };
        let mut token = String::new();
        let mut found = std::collections::HashSet::new();
        for character in contents.chars().chain(std::iter::once(' ')) {
            if character.is_ascii_alphanumeric() || character == '_' {
                token.push(character);
            } else if !token.is_empty() {
                if export_set.contains(token.as_str()) {
                    found.insert(token.clone());
                }
                token.clear();
            }
        }
        for symbol in found {
            matches.entry(symbol).or_default().push(path.clone());
        }
    }
    for paths in matches.values_mut() {
        paths.sort();
    }
    Ok(matches)
}

fn public_function_declarations(source: &str) -> std::collections::HashSet<String> {
    let source = strip_c_comments(source);
    let source = source
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let mut functions = std::collections::HashSet::new();
    for statement in source.split(';') {
        if !statement.contains("WS_DLL_PUBLIC")
            || statement.contains("typedef")
            || statement.contains(['{', '}'])
        {
            continue;
        }
        let tokens = c_tokens(statement);
        let Some(marker) = tokens.iter().position(|token| token == "WS_DLL_PUBLIC") else {
            continue;
        };
        for index in marker + 1..tokens.len() {
            if tokens[index] != "(" || index == 0 {
                continue;
            }
            if tokens.get(index + 1).is_some_and(|token| token == "*") {
                continue;
            }
            let candidate = &tokens[index - 1];
            if !is_c_identifier(candidate) || candidate.chars().all(|c| !c.is_ascii_lowercase()) {
                continue;
            }
            functions.insert(candidate.clone());
            break;
        }
    }
    functions
}

fn c_tokens(source: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut identifier = String::new();
    for character in source.chars().chain(std::iter::once(' ')) {
        if character.is_ascii_alphanumeric() || character == '_' {
            identifier.push(character);
        } else {
            if !identifier.is_empty() {
                tokens.push(std::mem::take(&mut identifier));
            }
            if !character.is_whitespace() {
                tokens.push(character.to_string());
            }
        }
    }
    tokens
}

fn is_c_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn strip_c_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            while let Some(character) = characters.next() {
                if character == '*' && characters.peek() == Some(&'/') {
                    characters.next();
                    break;
                }
                if character == '\n' {
                    output.push('\n');
                }
            }
        } else if character == '/' && characters.peek() == Some(&'/') {
            characters.next();
            for character in characters.by_ref() {
                if character == '\n' {
                    output.push('\n');
                    break;
                }
            }
        } else {
            output.push(character);
        }
    }
    output
}

fn cmake_header_list(cmake_file: &Path, variable: &str) -> Result<Vec<String>, GenerateError> {
    let source = std::fs::read_to_string(cmake_file)
        .map_err(|_| GenerateError::InvalidPublicHeaderList(cmake_file.to_owned()))?;
    let start = source
        .find(&format!("set({variable}"))
        .ok_or_else(|| GenerateError::InvalidPublicHeaderList(cmake_file.to_owned()))?;
    let body = &source[start..];
    let body = body
        .split_once('\n')
        .map(|(_, body)| body)
        .ok_or_else(|| GenerateError::InvalidPublicHeaderList(cmake_file.to_owned()))?;
    let mut headers = Vec::new();
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or_default();
        if line.trim() == ")" {
            return Ok(headers);
        }
        for value in line.split_whitespace() {
            if value.ends_with(".h") && !value.contains(['$', '{', '}']) {
                headers.push(value.to_owned());
            }
        }
    }
    Err(GenerateError::InvalidPublicHeaderList(
        cmake_file.to_owned(),
    ))
}

fn debian_public_headers(source_root: &Path) -> Result<Vec<(PathBuf, PathBuf)>, GenerateError> {
    let manifest = source_root.join("debian/wireshark-dev.header-files");
    let source = std::fs::read_to_string(&manifest)
        .map_err(|_| GenerateError::InvalidPublicHeaderList(manifest.clone()))?;
    let mut headers = Vec::new();
    for pattern in source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if pattern == "config.h" {
            continue;
        }
        if let Some(directory) = pattern.strip_suffix("/*.h") {
            let parent = source_root.join(directory);
            let entries = std::fs::read_dir(&parent)
                .map_err(|_| GenerateError::InvalidPublicHeaderList(manifest.clone()))?;
            for entry in entries {
                let entry =
                    entry.map_err(|_| GenerateError::InvalidPublicHeaderList(manifest.clone()))?;
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|extension| extension == "h") {
                    let relative = path
                        .strip_prefix(source_root)
                        .map_err(|_| GenerateError::InvalidPublicHeaderList(manifest.clone()))?
                        .to_owned();
                    headers.push((relative, path));
                }
            }
            continue;
        }
        let relative = PathBuf::from(pattern);
        let direct = source_root.join(&relative);
        let resolved = if direct.is_file() {
            Some(direct)
        } else if relative.components().count() == 1 {
            [
                source_root.join("epan").join(&relative),
                source_root.join("wsutil").join(&relative),
            ]
            .into_iter()
            .find(|path| path.is_file())
        } else {
            None
        };
        if let Some(path) = resolved {
            let relative = path
                .strip_prefix(source_root)
                .map_err(|_| GenerateError::InvalidPublicHeaderList(manifest.clone()))?
                .to_owned();
            headers.push((relative, path));
        }
    }
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    headers.dedup_by(|left, right| left.0 == right.0);
    if headers.is_empty() {
        return Err(GenerateError::InvalidPublicHeaderList(manifest));
    }
    Ok(headers)
}

fn write_umbrella(
    source_root: &Path,
    output: &Path,
    headers: &[&PathBuf],
    dependency_roots: &[PathBuf],
    version: Option<&str>,
) -> Result<(), GenerateError> {
    let source_root =
        std::fs::canonicalize(source_root).map_err(|_| GenerateError::InvalidSource)?;
    let (major, minor, patch) = version_components(version);
    let mut contents = format!(
        r#"/* Generated by embedding Wireshark public headers and dependency headers. */
#ifndef LIBWIRESHARK_RS_GENERATED_PUBLIC_H
#define LIBWIRESHARK_RS_GENERATED_PUBLIC_H
#define __GLIB_H_INSIDE__
#define __GLIB_GOBJECT_H_INSIDE__
#define __GIO_GIO_H_INSIDE__
/* Wireshark has X-macro headers that are included with caller-provided
 * expansions from implementation files. In an API umbrella they contribute
 * no declarations, so define their expansion hooks as empty. */
#define DEF_COND_ACE_TOKEN(VAL, VAR, STR)
#define DEF_COND_ACE_TOKEN_WITH_DATA(VAL, VAR, STR)
/* Some public dissector declarations use this opaque type before the header
 * that owns its forward declaration appears in Wireshark's public list. */
typedef struct _dcerpc_info dcerpc_info;
#ifndef __CONFIG_H__
#define __CONFIG_H__
#define PACKAGE "wireshark"
#define VERSION "{}"
#define VERSION_MAJOR {major}
#define VERSION_MINOR {minor}
#define VERSION_MICRO {patch}
#define HAVE_PLUGINS 1
#define HAVE_LIBGCRYPT 1
#define PCRE2_CODE_UNIT_WIDTH 8
#if defined(_WIN32)
#define YY_NO_UNISTD_H
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#endif
#endif
#ifndef __WS_VERSION_H__
#define __WS_VERSION_H__
#define WIRESHARK_VERSION_MAJOR {major}
#define WIRESHARK_VERSION_MINOR {minor}
#define WIRESHARK_VERSION_MICRO {patch}
#endif
"#,
        version.unwrap_or("0.0.0")
    );
    let mut include_stack = Vec::new();
    let mut included = std::collections::HashSet::new();
    let mut ordered_headers = Vec::new();
    for header in headers {
        collect_source_headers(
            &source_root,
            &source_root.join(header),
            dependency_roots,
            &mut include_stack,
            &mut included,
            &mut ordered_headers,
        )?;
    }
    for header in ordered_headers {
        let source = std::fs::read_to_string(&header)
            .map_err(|_| GenerateError::SourceHeaderRead(header.clone()))?;
        contents.push_str(&format!(
            "\n/* Begin {} */\n",
            header
                .strip_prefix(&source_root)
                .unwrap_or(&header)
                .to_string_lossy()
                .replace('\\', "/")
        ));
        for line in source.lines() {
            if c_include_target(line).is_some_and(|name| {
                name == "config.h"
                    || name == "ws_version.h"
                    || resolve_embedded_include(&source_root, dependency_roots, &header, name)
                        .is_some()
            }) {
                continue;
            }
            contents.push_str(line);
            contents.push('\n');
        }
        contents.push_str("/* End embedded header */\n");
    }
    contents.push_str("#endif /* LIBWIRESHARK_RS_GENERATED_PUBLIC_H */\n");
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| GenerateError::WriteFailed(error.to_string()))?;
    }
    std::fs::write(output, contents).map_err(|error| GenerateError::WriteFailed(error.to_string()))
}

fn collect_source_headers(
    source_root: &Path,
    header: &Path,
    dependency_roots: &[PathBuf],
    include_stack: &mut Vec<PathBuf>,
    included: &mut std::collections::HashSet<PathBuf>,
    ordered_headers: &mut Vec<PathBuf>,
) -> Result<(), GenerateError> {
    let canonical = std::fs::canonicalize(header)
        .map_err(|_| GenerateError::SourceHeaderRead(header.to_owned()))?;
    if include_stack.contains(&canonical) || included.contains(&canonical) {
        return Ok(());
    }
    let source = std::fs::read_to_string(&canonical)
        .map_err(|_| GenerateError::SourceHeaderRead(canonical.clone()))?;
    include_stack.push(canonical.clone());
    for line in source.lines() {
        if let Some(include) = c_include_target(line)
            && let Some(path) =
                resolve_embedded_include(source_root, dependency_roots, &canonical, include)
        {
            collect_source_headers(
                source_root,
                &path,
                dependency_roots,
                include_stack,
                included,
                ordered_headers,
            )?;
        }
    }
    include_stack.pop();
    included.insert(canonical.clone());
    ordered_headers.push(canonical);
    Ok(())
}

fn resolve_embedded_include(
    source_root: &Path,
    dependency_roots: &[PathBuf],
    including: &Path,
    name: &str,
) -> Option<PathBuf> {
    resolve_source_include(source_root, including, name).or_else(|| {
        let name = Path::new(name);
        dependency_roots.iter().find_map(|root| {
            [root.join(name), including.parent()?.join(name)]
                .into_iter()
                .find(|path| path.is_file())
                .and_then(|path| std::fs::canonicalize(path).ok())
        })
    })
}

fn version_components(version: Option<&str>) -> (&str, &str, &str) {
    let mut parts = version.unwrap_or("0.0.0").split('.');
    (
        parts.next().unwrap_or("0"),
        parts.next().unwrap_or("0"),
        parts.next().unwrap_or("0"),
    )
}

fn c_include_target(line: &str) -> Option<&str> {
    let directive = line.trim().strip_prefix('#')?.trim_start();
    let target = directive.strip_prefix("include")?.trim_start();
    if let Some(target) = target.strip_prefix('"') {
        target.split_once('"').map(|(name, _)| name)
    } else if let Some(target) = target.strip_prefix('<') {
        target.split_once('>').map(|(name, _)| name)
    } else {
        None
    }
}

fn resolve_source_include(source_root: &Path, including: &Path, name: &str) -> Option<PathBuf> {
    let root = source_root;
    let name = Path::new(name);
    let candidates = [
        including.parent()?.join(name),
        root.join(name),
        root.join("include").join(name),
    ];
    candidates.into_iter().find_map(|candidate| {
        let path = std::fs::canonicalize(candidate).ok()?;
        (path.starts_with(root) && path.is_file()).then_some(path)
    })
}

fn dependency_header_roots(
    source_root: &Path,
    target_os: &str,
    architecture: &str,
    configured: &[PathBuf],
) -> Result<Vec<PathBuf>, GenerateError> {
    let mut roots = configured.to_vec();
    if let Some(paths) = std::env::var_os("WIRESHARK_DEPENDENCY_INCLUDE_DIRS") {
        roots.extend(std::env::split_paths(&paths));
    }
    roots.extend(system_dependency_include_dirs(target_os, architecture));
    roots.retain(|path| path.is_dir());
    let mut normalized = Vec::new();
    for root in &roots {
        for name in ["glib.h", "glibconfig.h", "gcrypt.h", "gpg-error.h"] {
            if let Some(header_root) = find_nested_header(std::slice::from_ref(root), name) {
                normalized.push(header_root);
            }
        }
    }
    roots = normalized;
    roots.sort();
    roots.dedup();

    let need_glib = find_nested_header(&roots, "glib.h").is_none()
        || find_nested_header(&roots, "glibconfig.h").is_none();
    let need_gcrypt = find_nested_header(&roots, "gcrypt.h").is_none()
        || find_nested_header(&roots, "gpg-error.h").is_none();
    if !need_glib && !need_gcrypt {
        return Ok(roots);
    }

    let fetch = source_root.join("cmake/modules/FetchArtifacts.cmake");
    let manifest = std::fs::read_to_string(&fetch).ok();
    let current_manifest = || {
        let url = "https://raw.githubusercontent.com/wireshark/wireshark/master/cmake/modules/FetchArtifacts.cmake";
        ureq::get(url)
            .call()
            .and_then(|response| response.into_body().read_to_string())
            .map_err(|error| {
                GenerateError::DependencyHeaders(format!(
                    "{} has no usable dependency archive declaration and the current Wireshark dependency manifest could not be downloaded ({error}); provide GLib and Gcrypt include paths",
                    fetch.display()
                ))
            })
    };
    let cache = std::env::temp_dir().join("cargo-wireshark-artifacts");
    for (package, missing) in [("glib", need_glib), ("libgcrypt", need_gcrypt)] {
        if !missing {
            continue;
        }
        let artifact = manifest
            .as_deref()
            .and_then(|manifest| dependency_artifact(manifest, package, architecture, target_os))
            .or_else(|| {
                // Older source releases may not declare archives for newer
                // target architectures. Their headers remain compatible with
                // the current architecture-matched development bundle.
                current_manifest().ok().and_then(|manifest| {
                    dependency_artifact(&manifest, package, architecture, target_os)
                })
            });
        let (archive_path, checksum, base_url) = artifact.ok_or_else(|| {
            GenerateError::DependencyHeaders(format!(
                "Wireshark does not declare a {package} development archive for {} on {}; provide its include directory with --dependency-include-dir",
                architecture,
                target_os
            ))
        })?;
        let archive_name = Path::new(&archive_path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                GenerateError::DependencyHeaders("invalid dependency archive name".to_owned())
            })?;
        let archive = cache.join(&checksum).join(archive_name);
        let extraction = archive.with_extension("headers");
        let extraction_complete = extraction.join(".cargo-wireshark-extracted");
        if !extraction_complete.is_file() {
            if let Some(parent) = archive.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
            }
            if extraction.exists() {
                std::fs::remove_dir_all(&extraction)
                    .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
            }
            let url = format!("{base_url}/{archive_path}");
            let response = ureq::get(&url).call().map_err(|error| {
                GenerateError::DependencyHeaders(format!("download {url}: {error}"))
            })?;
            let bytes = response
                .into_body()
                .into_with_config()
                .limit(512 * 1024 * 1024)
                .read_to_vec()
                .map_err(|error| {
                    GenerateError::DependencyHeaders(format!("read {url}: {error}"))
                })?;
            let actual = format!("{:x}", sha2::Sha256::digest(&bytes));
            if actual != checksum {
                return Err(GenerateError::DependencyHeaders(format!(
                    "SHA-256 mismatch for {archive_name}: expected {checksum}, received {actual}"
                )));
            }
            std::fs::write(&archive, bytes)
                .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
            extract_dependency_archive(&archive, &extraction)?;
            std::fs::write(&extraction_complete, b"ok")
                .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
        }
        let names = if package == "glib" {
            ["glib.h", "glibconfig.h"]
        } else {
            ["gcrypt.h", "gpg-error.h"]
        };
        for header_name in names {
            let root = find_nested_header(std::slice::from_ref(&extraction), header_name)
                .ok_or_else(|| {
                    GenerateError::DependencyHeaders(format!(
                        "{archive_name} was extracted but did not contain {header_name}"
                    ))
                })?;
            roots.push(root);
        }
    }

    if find_nested_header(&roots, "glib.h").is_none()
        || find_nested_header(&roots, "glibconfig.h").is_none()
        || find_nested_header(&roots, "gcrypt.h").is_none()
        || find_nested_header(&roots, "gpg-error.h").is_none()
    {
        return Err(GenerateError::DependencyHeaders(
            "the selected development packages do not provide glib.h, gcrypt.h, and gpg-error.h"
                .to_owned(),
        ));
    }
    Ok(roots)
}

fn system_dependency_include_dirs(target_os: &str, architecture: &str) -> Vec<PathBuf> {
    let candidates = match target_os {
        "windows" => vec![
            if architecture == "x86_64" {
                PathBuf::from(r"C:\msys64\mingw64\include\glib-2.0")
            } else {
                PathBuf::from(r"C:\msys64\clangarm64\include\glib-2.0")
            },
            if architecture == "x86_64" {
                PathBuf::from(r"C:\msys64\mingw64\lib\glib-2.0\include")
            } else {
                PathBuf::from(r"C:\msys64\clangarm64\lib\glib-2.0\include")
            },
            if architecture == "x86_64" {
                PathBuf::from(r"C:\msys64\mingw64\include")
            } else {
                PathBuf::from(r"C:\msys64\clangarm64\include")
            },
        ],
        "macos" => vec![
            PathBuf::from("/opt/homebrew/opt/glib/include/glib-2.0"),
            PathBuf::from("/opt/homebrew/opt/glib/lib/glib-2.0/include"),
            PathBuf::from("/opt/homebrew/include"),
            PathBuf::from("/usr/local/opt/glib/include/glib-2.0"),
            PathBuf::from("/usr/local/opt/glib/lib/glib-2.0/include"),
            PathBuf::from("/usr/local/include"),
        ],
        "linux" if architecture == "x86_64" => vec![
            PathBuf::from("/usr/include/glib-2.0"),
            PathBuf::from("/usr/lib/x86_64-linux-gnu/glib-2.0/include"),
            PathBuf::from("/usr/include"),
        ],
        "linux" => vec![
            PathBuf::from("/usr/include/glib-2.0"),
            PathBuf::from("/usr/lib/aarch64-linux-gnu/glib-2.0/include"),
            PathBuf::from("/usr/lib/arm-linux-gnueabihf/glib-2.0/include"),
            PathBuf::from("/usr/include"),
        ],
        _ => Vec::new(),
    };
    candidates
}

fn find_nested_header(roots: &[PathBuf], filename: &str) -> Option<PathBuf> {
    let mut pending = roots.to_vec();
    while let Some(directory) = pending.pop() {
        let direct = directory.join(filename);
        if direct.is_file() {
            return Some(directory);
        }
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.file_name().is_some_and(|name| name == filename) {
                return path.parent().map(Path::to_owned);
            }
            if path.is_dir() {
                pending.push(path);
            }
        }
    }
    None
}

fn dependency_artifact(
    manifest: &str,
    package: &str,
    architecture: &str,
    operating_system: &str,
) -> Option<(String, String, &'static str)> {
    let architecture_token = match (operating_system, architecture) {
        ("windows", "aarch64") => "arm64",
        ("windows", "x86_64") => "x64",
        ("macos", _) => "universal",
        _ => return None,
    };
    let package_token = if package == "glib" {
        "glib-bundle-"
    } else {
        "libgcrypt-bundle-"
    };
    manifest.lines().find_map(|line| {
        let body = line
            .trim()
            .strip_prefix("add_artifact(")?
            .strip_suffix(')')?;
        let mut parts = body.split_whitespace();
        let path = parts.next()?;
        let checksum = parts.next()?;
        (path.starts_with(&format!("{package}/"))
            && path.contains(package_token)
            && path.contains(architecture_token))
        .then(|| {
            let base_url = if operating_system == "macos" {
                "https://dev-libs.wireshark.org/macos/packages"
            } else {
                "https://dev-libs.wireshark.org/windows/packages"
            };
            (path.to_owned(), checksum.to_owned(), base_url)
        })
    })
}

fn extract_dependency_archive(archive: &Path, destination: &Path) -> Result<(), GenerateError> {
    std::fs::create_dir_all(destination)
        .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
    match archive.extension().and_then(|extension| extension.to_str()) {
        Some("7z") => sevenz_rust2::decompress_file(archive, destination)
            .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?,
        Some("zip") => {
            let file = std::fs::File::open(archive)
                .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
            let mut archive = zip::ZipArchive::new(file)
                .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
            for index in 0..archive.len() {
                let mut entry = archive
                    .by_index(index)
                    .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
                let relative = entry.enclosed_name().ok_or_else(|| {
                    GenerateError::DependencyHeaders(format!(
                        "unsafe path in dependency ZIP: {}",
                        entry.name()
                    ))
                })?;
                let output = destination.join(relative);
                if entry.is_dir() {
                    std::fs::create_dir_all(&output)
                        .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
                } else {
                    if let Some(parent) = output.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
                    }
                    let mut file = std::fs::File::create(&output)
                        .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
                    std::io::copy(&mut entry, &mut file)
                        .map_err(|error| GenerateError::DependencyHeaders(error.to_string()))?;
                }
            }
        }
        Some("xz") => {
            let output = Command::new("tar")
                .arg("-xJf")
                .arg(archive)
                .arg("-C")
                .arg(destination)
                .output()
                .map_err(|error| {
                    GenerateError::DependencyHeaders(format!("could not start tar: {error}"))
                })?;
            if !output.status.success() {
                return Err(GenerateError::DependencyHeaders(
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                ));
            }
        }
        Some(extension) => {
            return Err(GenerateError::DependencyHeaders(format!(
                "unsupported dependency archive format: .{extension}"
            )));
        }
        None => {
            return Err(GenerateError::DependencyHeaders(
                "dependency archive has no extension".to_owned(),
            ));
        }
    }
    Ok(())
}

fn inspect_pe_exports(reader: &OsString, dll: &Path) -> Result<Vec<String>, GenerateError> {
    let output = Command::new(reader)
        .arg("--coff-exports")
        .arg(dll)
        .output()
        .map_err(|error| GenerateError::ExportInspection(error.to_string()))?;
    if !output.status.success() {
        return Err(GenerateError::ExportInspection(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut exports = Vec::new();
    for line in text.lines() {
        let Some((label, value)) = line.trim().split_once(':') else {
            continue;
        };
        if label == "Name" {
            let name = value.trim();
            if !name.is_empty() {
                exports.push(name.to_owned());
            }
        }
    }
    if exports.is_empty() {
        return Err(GenerateError::ExportInspection(
            "the DLL has no named exports".to_owned(),
        ));
    }
    exports.sort();
    exports.dedup();
    Ok(exports)
}

/// Runs Wireshark's CMake configure step to create build-specific C headers.
///
/// # Arguments
///
/// `config` supplies the source root, optional build directory, CMake executable, and extra CMake arguments.
///
/// # Returns
///
/// The build directory and paths to the generated configuration and version headers.
///
/// # Errors
///
/// Returns an error if the source tree is invalid, CMake cannot run or configure, or the expected headers are absent.
pub fn generate_headers(config: &HeaderConfig) -> Result<GeneratedHeaders, GenerateError> {
    let source =
        SourceTree::inspect(config.source_dir.clone()).ok_or(GenerateError::InvalidSource)?;
    if !source.root.join("CMakeLists.txt").is_file() {
        return Err(GenerateError::InvalidSource);
    }
    let build_dir = config
        .build_dir
        .clone()
        .unwrap_or_else(|| source.root.join("build-rust-plugin-sdk"));
    let status = Command::new(&config.cmake)
        .arg("-S")
        .arg(&source.root)
        .arg("-B")
        .arg(&build_dir)
        .args(&config.cmake_args)
        .status()
        .map_err(|error| GenerateError::CmakeUnavailable(error.to_string()))?;
    if !status.success() {
        return Err(GenerateError::CmakeFailed(status.to_string()));
    }

    let config_header = build_dir.join("config.h");
    let version_header = build_dir.join("ws_version.h");
    if !config_header.is_file() || !version_header.is_file() {
        return Err(GenerateError::MissingGeneratedHeaders(build_dir));
    }
    Ok(GeneratedHeaders {
        version: source.version,
        build_dir,
        config_header,
        version_header,
    })
}

/// Generates Rust bindings from the selected source and configured header trees.
///
/// # Arguments
///
/// `config` supplies the Wireshark source root, generated include directory, C umbrella header, output path, and clang arguments.
///
/// # Returns
///
/// The path written with the generated Rust declarations.
///
/// # Errors
///
/// Returns an error if an input is missing, bindgen cannot parse the headers, or the output cannot be written.
pub fn generate_bindings(config: &BindingsConfig) -> Result<PathBuf, GenerateError> {
    if !config.header.is_file() {
        return Err(GenerateError::InvalidHeader(config.header.clone()));
    }
    if !config.generated_include_dir.join("config.h").is_file()
        || !config.generated_include_dir.join("ws_version.h").is_file()
    {
        return Err(GenerateError::MissingGeneratedHeaders(
            config.generated_include_dir.clone(),
        ));
    }
    let source =
        SourceTree::inspect(config.source_dir.clone()).ok_or(GenerateError::InvalidSource)?;
    let mut builder = bindgen::Builder::default()
        .header(config.header.to_string_lossy())
        .layout_tests(false)
        .blocklist_item("_.*");
    if let Some(target) = &config.target {
        builder = builder.clang_arg(format!("--target={target}"));
    }
    for include_dir in [
        source.root.clone(),
        source.root.join("include"),
        config.generated_include_dir.clone(),
    ] {
        builder = builder.clang_arg(format!("-I{}", include_dir.display()));
    }
    for arg in &config.clang_args {
        builder = builder.clang_arg(arg.to_string_lossy().into_owned());
    }
    let bindings = builder
        .generate()
        .map_err(|error| GenerateError::BindgenFailed(error.to_string()))?;
    if let Some(parent) = config.output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| GenerateError::WriteFailed(error.to_string()))?;
    }
    bindings
        .write_to_file(&config.output)
        .map_err(|error| GenerateError::WriteFailed(error.to_string()))?;
    Ok(config.output.clone())
}

impl Sdk {
    /// Finds the installed SDK described by `config`.
    pub fn discover(config: &SdkConfig) -> Result<Self, Error> {
        if config.root.is_some()
            || config.include_dir.is_some()
            || config.lib_dir.is_some()
            || config.generated_include_dir.is_some()
        {
            let include_dir = config
                .include_dir
                .clone()
                .filter(|path| path.join("epan/packet.h").is_file())
                .or_else(|| config.root.as_deref().and_then(find_include_dir))
                .ok_or(Error::NotFound)?;
            let lib_dir = config
                .lib_dir
                .clone()
                .or_else(|| config.root.as_deref().and_then(find_library_dir))
                .ok_or(Error::NotFound)?;
            return Self::from_paths(
                config.version.clone(),
                include_dir,
                lib_dir,
                config.generated_include_dir.clone(),
            );
        }

        if let Ok(output) = Command::new("pkg-config")
            .args(["--modversion", "wireshark"])
            .output()
            && output.status.success()
        {
            let version = String::from_utf8(output.stdout)
                .map_err(|_| Error::InvalidVersion)?
                .trim()
                .to_owned();
            let libdir = Command::new("pkg-config")
                .args(["--variable=libdir", "wireshark"])
                .output();
            let Ok(libdir) = libdir else {
                return Err(Error::InvalidPaths);
            };
            let mut include_paths = library_include_paths().unwrap_or_default();
            if include_paths.is_empty()
                && let Ok(output) = Command::new("pkg-config")
                    .args(["--variable=includedir", "wireshark"])
                    .output()
                && output.status.success()
            {
                include_paths.push(
                    String::from_utf8(output.stdout)
                        .map_err(|_| Error::InvalidPaths)?
                        .trim()
                        .into(),
                );
            }
            let include_dir = include_paths
                .iter()
                .find(|path| path.join("epan/packet.h").is_file())
                .cloned()
                .ok_or(Error::InvalidPaths)?;
            let generated_include_dir = include_paths
                .iter()
                .find(|path| path.join("config.h").is_file())
                .filter(|path| path.as_path() != include_dir.as_path())
                .cloned();
            let lib_dir = String::from_utf8(libdir.stdout)
                .map_err(|_| Error::InvalidPaths)?
                .trim()
                .into();
            return Self::from_paths(Some(version), include_dir, lib_dir, generated_include_dir);
        }

        Err(Error::NotFound)
    }

    fn from_paths(
        version: Option<String>,
        include_dir: PathBuf,
        lib_dir: PathBuf,
        generated_include_dir: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let config_header_exists = include_dir.join("config.h").is_file()
            || generated_include_dir
                .as_ref()
                .is_some_and(|path| path.join("config.h").is_file());
        if !include_dir.join("epan/packet.h").is_file()
            || !config_header_exists
            || !has_link_library(&lib_dir)
        {
            return Err(Error::InvalidPaths);
        }
        Ok(Self {
            version,
            include_dir,
            generated_include_dir,
            lib_dir,
        })
    }
}

fn library_include_paths() -> Option<Vec<PathBuf>> {
    let output = Command::new("pkg-config")
        .args(["--cflags-only-I", "wireshark"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let output = String::from_utf8(output.stdout).ok()?;
    Some(
        output
            .split_whitespace()
            .filter_map(|flag| flag.strip_prefix("-I"))
            .map(PathBuf::from)
            .collect(),
    )
}

impl Runtime {
    /// Finds TShark on `PATH`, or queries the executable configured in `WIRESHARK_TSHARK`.
    pub fn discover() -> Option<Self> {
        let executable = std::env::var_os("WIRESHARK_TSHARK")
            .map(PathBuf::from)
            .or_else(|| find_executable("tshark"))
            .or_else(default_windows_tshark)?;
        Self::from_executable(executable)
    }

    /// Queries a specific TShark executable.
    pub fn from_executable(executable: PathBuf) -> Option<Self> {
        let output = Command::new(&executable).arg("--version").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let version_output = String::from_utf8(output.stdout).ok()?;
        let version = version_output
            .lines()
            .find_map(|line| line.split_whitespace().find(|word| is_version(word)))?;
        Some(Self {
            version: version.to_owned(),
            executable,
        })
    }
}

impl SourceTree {
    /// Inspects a source root for Wireshark headers and its declared version.
    pub fn inspect(root: PathBuf) -> Option<Self> {
        if !root.join("epan/packet.h").is_file() {
            return None;
        }
        let version = std::fs::read_to_string(root.join("CMakeLists.txt"))
            .ok()
            .and_then(|cmake| cmake_version(&cmake))
            .or_else(|| {
                std::fs::read_to_string(root.join("configure.ac"))
                    .ok()
                    .and_then(|configure| autotools_version(&configure))
            });
        Some(Self { version, root })
    }
}

fn cmake_version(contents: &str) -> Option<String> {
    let value = |name: &str| {
        let prefix = format!("set({name} ");
        contents.lines().find_map(|line| {
            line.trim()
                .strip_prefix(&prefix)
                .and_then(|value| value.split_whitespace().next())
                .map(|value| value.trim_end_matches(')').to_owned())
        })
    };
    Some(format!(
        "{}.{}.{}",
        value("PROJECT_MAJOR_VERSION")?,
        value("PROJECT_MINOR_VERSION")?,
        value("PROJECT_PATCH_VERSION")?
    ))
}

fn autotools_version(contents: &str) -> Option<String> {
    let value = |name: &str| {
        let prefix = format!("m4_define([version_{name}], [");
        contents.lines().find_map(|line| {
            line.trim()
                .strip_prefix(&prefix)
                .and_then(|value| value.split_once(']'))
                .map(|(value, _)| value.to_owned())
        })
    };
    Some(format!(
        "{}.{}.{}",
        value("major")?,
        value("minor")?,
        value("micro")?
    ))
}

fn is_version(word: &str) -> bool {
    let mut parts = word.split('.');
    parts
        .next()
        .is_some_and(|part| part.chars().all(|c| c.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|part| part.chars().all(|c| c.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|part| part.chars().all(|c| c.is_ascii_digit()))
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let extension = if cfg!(windows) { ".exe" } else { "" };
    let executable_name = format!("{name}{extension}");
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|path| path.join(&executable_name))
        .find(|path| path.is_file())
}

fn default_windows_tshark() -> Option<PathBuf> {
    if !cfg!(windows) {
        return None;
    }
    let program_files = std::env::var_os("ProgramFiles")?;
    let executable = PathBuf::from(program_files)
        .join("Wireshark")
        .join("tshark.exe");
    executable.is_file().then_some(executable)
}

fn find_include_dir(root: &Path) -> Option<PathBuf> {
    [
        root.join("include/wireshark"),
        root.join("include"),
        root.to_owned(),
    ]
    .into_iter()
    .find(|path| path.join("epan/packet.h").is_file())
}

fn find_library_dir(root: &Path) -> Option<PathBuf> {
    [root.join("lib"), root.join("lib64"), root.to_owned()]
        .into_iter()
        .find(|path| {
            [
                "wireshark.lib",
                "libwireshark.lib",
                "libwireshark.so",
                "libwireshark.dylib",
                "wireshark.dll.a",
            ]
            .iter()
            .any(|file| path.join(file).is_file())
        })
}

fn has_link_library(path: &Path) -> bool {
    [
        "wireshark.lib",
        "libwireshark.lib",
        "libwireshark.so",
        "libwireshark.dylib",
        "wireshark.dll.a",
    ]
    .iter()
    .any(|file| path.join(file).is_file())
}

#[cfg(test)]
mod tests {
    use super::{PublicHeaderConfig, SourceTree, generate_public_header};
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after UNIX_EPOCH")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("cargo-wireshark-test-{nonce}"));
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("test file has parent"))
                .expect("create test file parent");
            fs::write(path, contents).expect("write test file");
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn builds_public_umbrella_from_source_lists_without_cmake() {
        let scratch = Scratch::new();
        scratch.write(
            "CMakeLists.txt",
            "set(PROJECT_MAJOR_VERSION 4)\nset(PROJECT_MINOR_VERSION 6)\nset(PROJECT_PATCH_VERSION 9)\n",
        );
        scratch.write(
            "epan/packet.h",
            "#include \"nested.h\"\n#include <glib.h>\n#include <gcrypt.h>\n/* packet API */\n",
        );
        scratch.write("epan/nested.h", "typedef int nested_type;\n");
        scratch.write("deps/glib-2.0/glib.h", "#include <glib/gtypes.h>\n");
        scratch.write(
            "deps/glib-2.0/glib/gtypes.h",
            "typedef unsigned long gsize;\n",
        );
        scratch.write(
            "deps/glib-2.0/glibconfig.h",
            "#define GLIB_SIZEOF_VOID_P 8\n",
        );
        scratch.write(
            "deps/gcrypt.h",
            "#include <gpg-error.h>\ntypedef int gcry_error_t;\n",
        );
        scratch.write("deps/gpg-error.h", "typedef unsigned int gpg_error_t;\n");
        scratch.write(
            "epan/CMakeLists.txt",
            "set(LIBWIRESHARK_PUBLIC_HEADERS\n packet.h\n)\n",
        );
        scratch.write(
            "epan/dfilter/CMakeLists.txt",
            "set(DFILTER_PUBLIC_HEADERS\n dfilter.h\n)\n",
        );
        scratch.write("epan/dfilter/dfilter.h", "/* filter API */\n");
        scratch.write(
            "epan/ftypes/CMakeLists.txt",
            "set(FTYPE_PUBLIC_HEADERS\n ftypes.h\n)\n",
        );
        scratch.write("epan/ftypes/ftypes.h", "/* field API */\n");
        scratch.write(
            "epan/dissectors/CMakeLists.txt",
            "set(DISSECTOR_PUBLIC_HEADERS\n proto.h\n)\n",
        );
        scratch.write("epan/dissectors/proto.h", "/* dissector API */\n");
        let output = scratch.0.join("generated/libwireshark.h");

        let generated = generate_public_header(&PublicHeaderConfig {
            source_dir: scratch.0.clone(),
            architecture: "aarch64".to_owned(),
            target_os: "windows".to_owned(),
            dependency_include_dirs: vec![scratch.0.join("deps")],
            output: output.clone(),
            dll: None,
            filtered_output: None,
            llvm_readobj: OsString::from("llvm-readobj"),
        })
        .expect("generate public umbrella");

        assert_eq!(generated.version.as_deref(), Some("4.6.9"));
        assert_eq!(generated.header_count, 4);
        let umbrella = fs::read_to_string(output).expect("read generated umbrella");
        assert!(umbrella.contains("#define VERSION \"4.6.9\""));
        assert!(umbrella.contains("#define WIRESHARK_VERSION_MAJOR 4"));
        assert!(!umbrella.contains("#include \"config.h\""));
        assert!(umbrella.contains("/* packet API */"));
        assert!(umbrella.contains("typedef int nested_type;"));
        assert!(umbrella.contains("typedef unsigned long gsize;"));
        assert!(umbrella.contains("typedef unsigned int gpg_error_t;"));
        assert!(!umbrella.contains("#include <glib.h>"));
        assert!(!umbrella.contains("#include <gcrypt.h>"));
        assert!(umbrella.contains("/* dissector API */"));
        assert!(!umbrella.contains("#include \"epan/packet.h\""));
    }

    #[test]
    fn inspects_autotools_source_versions() {
        let scratch = Scratch::new();
        scratch.write("epan/packet.h", "");
        scratch.write(
            "configure.ac",
            "m4_define([version_major], [4])\nm4_define([version_minor], [6])\nm4_define([version_micro], [9])\n",
        );
        assert_eq!(
            SourceTree::inspect(scratch.0.clone()).and_then(|tree| tree.version),
            Some("4.6.9".to_owned())
        );
    }
}
