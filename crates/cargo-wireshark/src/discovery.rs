//! Finding an installed Wireshark: an SDK, a runtime (tshark), a source tree.

use crate::error::Error;
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

pub(crate) fn library_include_paths() -> Option<Vec<PathBuf>> {
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
    /// Queries `tshark` when given, else `tshark` on `PATH`, else the
    /// default Windows install location.
    pub fn discover(tshark: Option<&Path>) -> Option<Self> {
        let executable = tshark
            .map(Path::to_owned)
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

pub(crate) fn cmake_version(contents: &str) -> Option<String> {
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

pub(crate) fn autotools_version(contents: &str) -> Option<String> {
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

pub(crate) fn is_version(word: &str) -> bool {
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

pub(crate) fn find_executable(name: &str) -> Option<PathBuf> {
    let extension = if cfg!(windows) { ".exe" } else { "" };
    let executable_name = format!("{name}{extension}");
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|path| path.join(&executable_name))
        .find(|path| path.is_file())
}

pub(crate) fn default_windows_tshark() -> Option<PathBuf> {
    if !cfg!(windows) {
        return None;
    }
    let program_files = std::env::var_os("ProgramFiles")?;
    let executable = PathBuf::from(program_files)
        .join("Wireshark")
        .join("tshark.exe");
    executable.is_file().then_some(executable)
}

pub(crate) fn find_include_dir(root: &Path) -> Option<PathBuf> {
    [
        root.join("include/wireshark"),
        root.join("include"),
        root.to_owned(),
    ]
    .into_iter()
    .find(|path| path.join("epan/packet.h").is_file())
}

pub(crate) fn find_library_dir(root: &Path) -> Option<PathBuf> {
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

pub(crate) fn has_link_library(path: &Path) -> bool {
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
