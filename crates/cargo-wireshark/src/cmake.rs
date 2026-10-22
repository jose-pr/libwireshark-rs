//! Wireshark's CMake configure step, for SDK workflows.

use crate::discovery::SourceTree;
use crate::error::GenerateError;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

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
