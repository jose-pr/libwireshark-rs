//! The errors of discovery and generation.

use core::fmt;
use std::path::PathBuf;

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

impl core::error::Error for Error {}

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
    /// A git command failed.
    Git(String),
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
            Self::WriteFailed(error) => write!(f, "could not write generated output: {error}"),
            Self::Git(error) => write!(f, "git failed: {error}"),
        }
    }
}

impl core::error::Error for GenerateError {}
