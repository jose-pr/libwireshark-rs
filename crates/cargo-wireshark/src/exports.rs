//! Comparing a Wireshark DLL's exports with the source declarations.

use crate::error::GenerateError;
use crate::public::GeneratedPublicHeader;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A Wireshark DLL's exports set against the source tree's headers. Matching
/// is by name in header text; it does not check signatures or ABI layouts.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ExportComparison {
    /// Named exports inspected.
    pub export_count: usize,
    /// Exports mentioned in a declared public header.
    pub matched_exports: usize,
    /// Exports mentioned only outside the declared public headers, with the
    /// headers that mention them.
    pub missing_public_headers: Vec<(String, Vec<PathBuf>)>,
    /// `WS_DLL_PUBLIC` declarations in public headers that the DLL lacks.
    pub declarations_missing_from_dll: Vec<(String, Vec<PathBuf>)>,
    /// Exports no header in the source tree mentions.
    pub no_header_matches: Vec<String>,
    /// The export-filtered bundle written, and how many headers it holds.
    pub filtered: Option<(PathBuf, usize)>,
    public_symbols: HashSet<String>,
    mentions: HashMap<String, Vec<PathBuf>>,
}

impl ExportComparison {
    /// Exports not mentioned in a declared public header.
    pub fn unmatched_exports(&self) -> usize {
        self.export_count.saturating_sub(self.matched_exports)
    }

    /// Compares `exports` with `headers` (relative, absolute) under `source_root`.
    pub(crate) fn of(
        source_root: &Path,
        headers: &[(PathBuf, PathBuf)],
        exports: &[String],
    ) -> Result<Self, GenerateError> {
        let mentions = find_export_header_mentions(source_root, exports)?;
        let export_set: HashSet<&str> = exports.iter().map(String::as_str).collect();
        let mut missing_from_dll: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for (relative, path) in headers {
            let Ok(contents) = std::fs::read_to_string(path) else {
                continue;
            };
            for symbol in public_function_declarations(&contents) {
                if !export_set.contains(symbol.as_str()) {
                    missing_from_dll
                        .entry(symbol)
                        .or_default()
                        .push(relative.clone());
                }
            }
        }
        for files in missing_from_dll.values_mut() {
            files.sort();
            files.dedup();
        }
        let public_paths: HashSet<&PathBuf> = headers.iter().map(|(_, path)| path).collect();
        let public_symbols: HashSet<String> = mentions
            .iter()
            .filter(|(_, files)| files.iter().any(|file| public_paths.contains(file)))
            .map(|(symbol, _)| symbol.clone())
            .collect();
        let mut missing_public_headers = mentions
            .iter()
            .filter(|(symbol, _)| !public_symbols.contains(*symbol))
            .map(|(symbol, files)| {
                let outside = files
                    .iter()
                    .filter(|file| !public_paths.contains(file))
                    .cloned()
                    .collect::<Vec<_>>();
                (symbol.clone(), outside)
            })
            .filter(|(_, files)| !files.is_empty())
            .collect::<Vec<_>>();
        missing_public_headers.sort();
        let no_header_matches = exports
            .iter()
            .filter(|symbol| !mentions.contains_key(*symbol))
            .cloned()
            .collect();
        let mut declarations_missing_from_dll = missing_from_dll.into_iter().collect::<Vec<_>>();
        declarations_missing_from_dll.sort();
        Ok(Self {
            export_count: exports.len(),
            matched_exports: public_symbols.len(),
            missing_public_headers,
            declarations_missing_from_dll,
            no_header_matches,
            filtered: None,
            public_symbols,
            mentions,
        })
    }

    /// The public headers that mention an export, for the filtered bundle.
    pub(crate) fn filtered_headers<'a>(
        &self,
        headers: &'a [(PathBuf, PathBuf)],
    ) -> Vec<&'a PathBuf> {
        headers
            .iter()
            .filter(|(_, path)| {
                self.public_symbols.iter().any(|symbol| {
                    self.mentions
                        .get(symbol)
                        .is_some_and(|files| files.contains(path))
                })
            })
            .map(|(relative, _)| relative)
            .collect()
    }
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
        for character in contents.chars().chain(core::iter::once(' ')) {
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

pub(crate) fn c_tokens(source: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut identifier = String::new();
    for character in source.chars().chain(core::iter::once(' ')) {
        if character.is_ascii_alphanumeric() || character == '_' {
            identifier.push(character);
        } else {
            if !identifier.is_empty() {
                tokens.push(core::mem::take(&mut identifier));
            }
            if !character.is_whitespace() {
                tokens.push(character.to_string());
            }
        }
    }
    tokens
}

pub(crate) fn is_c_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

pub(crate) fn strip_c_comments(source: &str) -> String {
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

pub(crate) fn inspect_pe_exports(
    reader: &OsString,
    dll: &Path,
) -> Result<Vec<String>, GenerateError> {
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

/// The DLL export comparison of `header` as a Markdown report: counts,
/// candidate headers outside the public lists, declarations the DLL lacks,
/// and exports no header names. `None` when no DLL was compared.
pub fn export_report(header: &GeneratedPublicHeader) -> Option<String> {
    let comparison = header.comparison.as_ref()?;
    let paths = |files: &[PathBuf]| {
        files
            .iter()
            .map(|file| format!("`{}`", file.display().to_string().replace('\\', "/")))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut report = format!(
        "# Wireshark {} DLL export/header comparison\n\n- Source public headers: {}\n- DLL exports inspected: {}\n- Exports mentioned in source public headers: {}\n- Exports not matched in public headers: {}\n\n",
        header.version.as_deref().unwrap_or("unknown version"),
        header.header_count,
        comparison.export_count,
        comparison.matched_exports,
        comparison.unmatched_exports(),
    );
    let mut by_header = alloc::collections::BTreeMap::<&PathBuf, Vec<&str>>::new();
    for (symbol, files) in &comparison.missing_public_headers {
        for file in files {
            by_header.entry(file).or_default().push(symbol);
        }
    }
    report.push_str("## Candidate headers missing from the public-header lists\n\n");
    for (file, symbols) in &by_header {
        let names = symbols
            .iter()
            .map(|symbol| format!("`{symbol}`"))
            .collect::<Vec<_>>();
        report.push_str(&format!(
            "- {} ({} exports): {}\n",
            paths(core::slice::from_ref(*file)),
            symbols.len(),
            names.join(", ")
        ));
    }
    if by_header.is_empty() {
        report.push_str("None.\n");
    }
    report.push_str("\n## Public WS_DLL_PUBLIC declarations absent from the DLL\n\n");
    for (symbol, files) in &comparison.declarations_missing_from_dll {
        report.push_str(&format!("- `{symbol}`: {}\n", paths(files)));
    }
    if comparison.declarations_missing_from_dll.is_empty() {
        report.push_str("None.\n");
    }
    report.push_str("\n## Exports no header in the source tree names\n\n");
    for symbol in &comparison.no_header_matches {
        report.push_str(&format!("- `{symbol}`\n"));
    }
    if comparison.no_header_matches.is_empty() {
        report.push_str("None.\n");
    }
    if let Some((path, count)) = &comparison.filtered {
        report.push_str(&format!(
            "\nExport-filtered bundle: {} ({count} public headers).\n",
            paths(core::slice::from_ref(path))
        ));
    }
    report.push_str(
        "\nMatching searches C header text by name; it does not check declarations or the ABI.\n",
    );
    Some(report)
}

/// Writes [`export_report`] to `path`, beside it first and then renamed
/// over it, so a failed write leaves no partial report.
///
/// # Errors
///
/// The I/O error of creating the directory, writing or renaming.
pub fn write_export_report(path: &Path, header: &GeneratedPublicHeader) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let Some(report) = export_report(header) else {
        return Ok(());
    };
    let partial = path.with_extension("md.partial");
    std::fs::write(&partial, report)?;
    std::fs::rename(partial, path)
}
