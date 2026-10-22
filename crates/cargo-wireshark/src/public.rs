//! Collecting Wireshark's declared public headers into bundles.

use crate::bundle;
use crate::deps::dependency_header_roots;
use crate::discovery::SourceTree;
use crate::error::GenerateError;
use crate::exports::{ExportComparison, inspect_pe_exports};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Inputs for generating a wrapper over Wireshark's source-declared public headers.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PublicHeaderConfig {
    /// Wireshark source root.
    pub source_dir: PathBuf,
    /// Rust target architecture used to select target-matched dependency headers.
    pub architecture: String,
    /// Rust target operating system used to select target-matched dependency headers.
    pub target_os: String,
    /// Directories containing available GLib and Gcrypt development headers.
    pub dependency_include_dirs: Vec<PathBuf>,
    /// Directory receiving `wireshark-<major>-<minor>.h` and `deps-<os>-<arch>.h`.
    pub output_dir: PathBuf,
    /// Optional Wireshark DLL whose exports should be compared with declarations.
    pub dll: Option<PathBuf>,
    /// Optional destination for an umbrella limited to headers mentioning exported symbols.
    pub filtered_output: Option<PathBuf>,
    /// LLVM object reader used to inspect PE exports.
    pub llvm_readobj: OsString,
    /// Where downloaded dependency archives are kept, extracted.
    pub cache_dir: PathBuf,
}

impl PublicHeaderConfig {
    /// Bundles for `target_os`/`architecture` from `source_dir` into
    /// `output_dir`, with dependency archives cached under `cache_dir`. No
    /// extra include directories, no DLL comparison, `llvm-readobj` from `PATH`.
    pub fn new(
        source_dir: PathBuf,
        output_dir: PathBuf,
        target_os: String,
        architecture: String,
        cache_dir: PathBuf,
    ) -> Self {
        Self {
            source_dir,
            architecture,
            target_os,
            dependency_include_dirs: Vec::new(),
            output_dir,
            dll: None,
            filtered_output: None,
            llvm_readobj: OsString::from("llvm-readobj"),
            cache_dir,
        }
    }
}

/// Result of collecting and optionally comparing source-declared public headers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GeneratedPublicHeader {
    /// Wireshark source version, when available.
    pub version: Option<String>,
    /// Generated release-line bundle, the same for every target.
    pub wireshark_header: PathBuf,
    /// Generated GLib/Gcrypt bundle for the selected target.
    pub dependency_header: PathBuf,
    /// Number of source-declared public headers included.
    pub header_count: usize,
    /// The DLL export comparison, when a DLL was given.
    pub comparison: Option<ExportComparison>,
}

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
    headers.retain(|(relative, _)| {
        !relative.starts_with("epan/dissectors")
            || relative
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| bundle::DISSECTOR_HEADERS.contains(&name))
    });
    // Before 4.6, several public headers use packet types without including
    // their headers; emitting these first declares them for the rest.
    for first in bundle::LEADING_HEADERS.iter().rev() {
        if let Some(index) = headers
            .iter()
            .position(|(relative, _)| relative == Path::new(first))
        {
            let header = headers.remove(index);
            headers.insert(0, header);
        }
    }

    let dependency_roots = dependency_header_roots(
        &source.root,
        &config.target_os,
        &config.architecture,
        &config.dependency_include_dirs,
        &config.cache_dir,
    )?;
    let (major, minor, _) = version_components(source.version.as_deref());
    let wireshark_header = config
        .output_dir
        .join(bundle::wireshark_bundle_name(major, minor));
    let dependency_header = config.output_dir.join(bundle::dependency_bundle_name(
        &config.target_os,
        &config.architecture,
    ));
    let required = bundle::write_wireshark_bundle(
        &source.root,
        &wireshark_header,
        &headers
            .iter()
            .map(|(relative, _)| relative)
            .collect::<Vec<_>>(),
        &dependency_roots,
        source.version.as_deref(),
    )?;
    bundle::write_dependency_bundle(
        &dependency_header,
        &dependency_roots,
        &required,
        &config.target_os,
        &config.architecture,
    )?;

    let comparison = match (&config.dll, &config.filtered_output) {
        (Some(dll), filtered_output) => {
            let exports = inspect_pe_exports(&config.llvm_readobj, dll)?;
            let mut comparison = ExportComparison::of(&source.root, &headers, &exports)?;
            if let Some(output) = filtered_output {
                let filtered = comparison.filtered_headers(&headers);
                bundle::write_wireshark_bundle(
                    &source.root,
                    output,
                    &filtered,
                    &dependency_roots,
                    source.version.as_deref(),
                )?;
                comparison.filtered = Some((output.clone(), filtered.len()));
            }
            Some(comparison)
        }
        (None, None) => None,
        (None, Some(_)) => {
            return Err(GenerateError::ExportInspection(
                "--filtered-output requires --dll".to_owned(),
            ));
        }
    };

    Ok(GeneratedPublicHeader {
        version: source.version,
        wireshark_header,
        dependency_header,
        header_count: headers.len(),
        comparison,
    })
}

pub(crate) fn cmake_header_list(
    cmake_file: &Path,
    variable: &str,
) -> Result<Vec<String>, GenerateError> {
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

pub(crate) fn debian_public_headers(
    source_root: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>, GenerateError> {
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

pub(crate) fn version_components(version: Option<&str>) -> (&str, &str, &str) {
    let mut parts = version.unwrap_or("0.0.0").split('.');
    (
        parts.next().unwrap_or("0"),
        parts.next().unwrap_or("0"),
        parts.next().unwrap_or("0"),
    )
}

pub(crate) fn c_include_target(line: &str) -> Option<&str> {
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

pub(crate) fn resolve_source_include(
    source_root: &Path,
    including: &Path,
    name: &str,
) -> Option<PathBuf> {
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

#[cfg(test)]
mod tests {
    use super::{PublicHeaderConfig, generate_public_header};
    use crate::discovery::SourceTree;
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
        let output_dir = scratch.0.join("generated");

        let generated = generate_public_header(&PublicHeaderConfig {
            source_dir: scratch.0.clone(),
            architecture: "aarch64".to_owned(),
            target_os: "windows".to_owned(),
            dependency_include_dirs: vec![scratch.0.join("deps")],
            output_dir: output_dir.clone(),
            dll: None,
            filtered_output: None,
            llvm_readobj: OsString::from("llvm-readobj"),
            cache_dir: scratch.0.join("cache"),
        })
        .expect("generate public umbrella");

        assert_eq!(generated.version.as_deref(), Some("4.6.9"));
        assert_eq!(generated.header_count, 3);
        assert_eq!(
            generated.wireshark_header,
            output_dir.join("wireshark-4-6.h")
        );
        assert_eq!(
            generated.dependency_header,
            output_dir.join("deps-windows-aarch64.h")
        );
        let umbrella = fs::read_to_string(&generated.wireshark_header).expect("read bundle");
        let deps = fs::read_to_string(&generated.dependency_header).expect("read deps");
        assert!(umbrella.contains("#define VERSION \"4.6.9\""));
        assert!(umbrella.contains("#define WIRESHARK_VERSION_MAJOR 4"));
        assert!(!umbrella.contains("#include \"config.h\""));
        assert!(umbrella.contains("/* packet API */"));
        assert!(umbrella.contains("typedef int nested_type;"));
        assert!(
            !umbrella.contains("gsize"),
            "dependencies stay out of the release-line bundle"
        );
        assert!(deps.contains("typedef unsigned long gsize;"));
        assert!(deps.contains("typedef unsigned int gpg_error_t;"));
        assert!(!deps.contains("#include <glib/gtypes.h>"));
        assert!(!umbrella.contains("#include <glib.h>"));
        assert!(!umbrella.contains("#include <gcrypt.h>"));
        assert!(
            !umbrella.contains("/* dissector API */"),
            "unlisted dissector headers are dropped"
        );
        assert!(!umbrella.contains("#include \"epan/packet.h\""));
        let root = fs::canonicalize(&scratch.0).expect("canonical scratch");
        let root = root.to_string_lossy().replace('\\', "/");
        for marker in umbrella
            .lines()
            .chain(deps.lines())
            .filter(|line| line.starts_with("/* Begin "))
        {
            assert!(
                !marker.contains(':') && !marker.contains(&*root),
                "{marker} names the build machine"
            );
        }
        assert!(deps.contains("/* Begin glib.h */"));
        assert!(deps.contains("/* Begin glib/gtypes.h */"));
        assert!(umbrella.contains("/* Begin epan/packet.h */"));
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
