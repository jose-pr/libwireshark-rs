//! GLib and Gcrypt development headers: given, system, or downloaded.

use crate::error::GenerateError;
use sha2::Digest;
use std::path::{Path, PathBuf};

pub(crate) fn dependency_header_roots(
    source_root: &Path,
    target_os: &str,
    architecture: &str,
    configured: &[PathBuf],
    cache: &Path,
) -> Result<Vec<PathBuf>, GenerateError> {
    let mut roots = configured.to_vec();
    roots.extend(system_dependency_include_dirs(target_os, architecture));
    roots.retain(|path| path.is_dir());
    let mut normalized = Vec::new();
    for root in &roots {
        for name in ["glib.h", "glibconfig.h", "gcrypt.h", "gpg-error.h"] {
            if let Some(header_root) = find_nested_header(core::slice::from_ref(root), name) {
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
        if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(GenerateError::DependencyHeaders(format!(
                "the {package} archive declaration has no SHA-256 checksum"
            )));
        }
        let extraction =
            cached_extraction(cache, &checksum, archive_name, base_url, &archive_path)?;
        let names = if package == "glib" {
            ["glib.h", "glibconfig.h"]
        } else {
            ["gcrypt.h", "gpg-error.h"]
        };
        for header_name in names {
            let root = find_nested_header(core::slice::from_ref(&extraction), header_name)
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

pub(crate) fn system_dependency_include_dirs(target_os: &str, architecture: &str) -> Vec<PathBuf> {
    match target_os {
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
    }
}

pub(crate) fn find_nested_header(roots: &[PathBuf], filename: &str) -> Option<PathBuf> {
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

pub(crate) fn dependency_artifact(
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

/// Extracts `archive` (`.7z`, `.zip` or `.tar.xz`) into `destination`.
///
/// Every entry's path must stay below `destination`, and the archive may
/// write at most [`EXTRACTED_LIMIT`] bytes. Links and other special entries
/// are skipped: headers never need them, and a skipped link points nowhere.
pub(crate) fn extract_dependency_archive(
    archive: &Path,
    destination: &Path,
) -> Result<(), GenerateError> {
    let failed =
        |error: &dyn core::fmt::Display| GenerateError::DependencyHeaders(error.to_string());
    std::fs::create_dir_all(destination).map_err(|error| failed(&error))?;
    let mut sink = Sink {
        destination,
        written: 0,
    };
    match archive.extension().and_then(|extension| extension.to_str()) {
        Some("7z") => sevenz_rust2::decompress_file_with_extract_fn(
            archive,
            destination,
            |entry, reader, _| {
                sink.entry(entry.name(), entry.is_directory(), reader)
                    .map(|()| true)
                    .map_err(|error| sevenz_rust2::Error::Other(error.to_string().into()))
            },
        )
        .map_err(|error| failed(&error))?,
        Some("zip") => {
            let file = std::fs::File::open(archive).map_err(|error| failed(&error))?;
            let mut zip = zip::ZipArchive::new(file).map_err(|error| failed(&error))?;
            for index in 0..zip.len() {
                let mut entry = zip.by_index(index).map_err(|error| failed(&error))?;
                if entry.is_symlink() {
                    continue;
                }
                let name = entry.name().to_owned();
                let directory = entry.is_dir();
                sink.entry(&name, directory, &mut entry)?;
            }
        }
        Some("xz") => {
            let file = std::fs::File::open(archive).map_err(|error| failed(&error))?;
            let decoder = lzma_rust2::XzReader::new(std::io::BufReader::new(file), true);
            let mut tar = tar::Archive::new(decoder);
            for entry in tar.entries().map_err(|error| failed(&error))? {
                let mut entry = entry.map_err(|error| failed(&error))?;
                let name = entry
                    .path()
                    .map_err(|error| failed(&error))?
                    .to_string_lossy()
                    .into_owned();
                let kind = entry.header().entry_type();
                if !(kind.is_file() || kind.is_dir()) {
                    continue;
                }
                sink.entry(&name, kind.is_dir(), &mut entry)?;
            }
        }
        Some(extension) => {
            return Err(failed(&format!(
                "unsupported dependency archive format: .{extension}"
            )));
        }
        None => return Err(failed(&"dependency archive has no extension")),
    }
    Ok(())
}

/// The most an extracted dependency archive may write; Wireshark's are
/// tens of megabytes.
pub(crate) const EXTRACTED_LIMIT: u64 = 1 << 30;

/// Writes archive entries below one directory, counting what it writes.
struct Sink<'a> {
    destination: &'a Path,
    written: u64,
}

impl Sink<'_> {
    fn entry(
        &mut self,
        name: &str,
        directory: bool,
        reader: &mut dyn std::io::Read,
    ) -> Result<(), GenerateError> {
        let failed =
            |error: &dyn core::fmt::Display| GenerateError::DependencyHeaders(error.to_string());
        let relative = enclosed(name)
            .ok_or_else(|| failed(&format!("path outside the archive in {name:?}")))?;
        if relative.as_os_str().is_empty() && !directory {
            return Err(failed(&"a file entry without a name"));
        }
        let output = self.destination.join(relative);
        if directory {
            return std::fs::create_dir_all(&output).map_err(|error| failed(&error));
        }
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).map_err(|error| failed(&error))?;
        }
        let mut file = std::fs::File::create(&output).map_err(|error| failed(&error))?;
        let budget = EXTRACTED_LIMIT - self.written;
        let copied = std::io::copy(&mut std::io::Read::take(reader, budget + 1), &mut file)
            .map_err(|error| failed(&error))?;
        if copied > budget {
            return Err(failed(&format!(
                "dependency archive expands past {EXTRACTED_LIMIT} bytes"
            )));
        }
        self.written += copied;
        Ok(())
    }
}

/// `name` as a relative path of normal components (empty for the archive's
/// root), or `None` when it is absolute or climbs out with `..`.
pub(crate) fn enclosed(name: &str) -> Option<PathBuf> {
    use std::path::Component;
    let mut path = PathBuf::new();
    for component in Path::new(&name.replace('\\', "/")).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(path)
}

/// The extracted archive `<cache>/<checksum>/headers`, downloaded, verified
/// and extracted on first use. Extraction goes to a sibling directory that
/// is renamed into place, so an interrupted run leaves nothing that looks
/// complete.
fn cached_extraction(
    cache: &Path,
    checksum: &str,
    archive_name: &str,
    base_url: &str,
    archive_path: &str,
) -> Result<PathBuf, GenerateError> {
    let io = |error: std::io::Error| GenerateError::DependencyHeaders(error.to_string());
    let entry = cache.join(checksum);
    let extraction = entry.join("headers");
    if extraction.is_dir() {
        return Ok(extraction);
    }
    std::fs::create_dir_all(&entry).map_err(io)?;
    let url = format!("{base_url}/{archive_path}");
    let response = ureq::get(&url)
        .call()
        .map_err(|error| GenerateError::DependencyHeaders(format!("download {url}: {error}")))?;
    let bytes = response
        .into_body()
        .into_with_config()
        .limit(512 * 1024 * 1024)
        .read_to_vec()
        .map_err(|error| GenerateError::DependencyHeaders(format!("read {url}: {error}")))?;
    let actual = format!("{:x}", sha2::Sha256::digest(&bytes));
    if actual != checksum {
        return Err(GenerateError::DependencyHeaders(format!(
            "SHA-256 mismatch for {archive_name}: expected {checksum}, received {actual}"
        )));
    }
    let id = std::process::id();
    let archive = entry.join(format!("{id}-{archive_name}"));
    let partial = entry.join(format!("headers.partial-{id}"));
    std::fs::write(&archive, bytes).map_err(io)?;
    let extracted = extract_dependency_archive(&archive, &partial);
    let _ = std::fs::remove_file(&archive);
    if let Err(error) = extracted.and_then(|()| std::fs::rename(&partial, &extraction).map_err(io))
    {
        let _ = std::fs::remove_dir_all(&partial);
        // Another run may have finished the same extraction first.
        if !extraction.is_dir() {
            return Err(error);
        }
    }
    Ok(extraction)
}

#[cfg(test)]
mod tests {
    use super::{enclosed, extract_dependency_archive};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "cargo-wireshark-extract-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create the scratch directory");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn assert_refused(scratch: &Scratch, archive: &Path) {
        let destination = scratch.0.join("out");
        let error = extract_dependency_archive(archive, &destination)
            .expect_err("a climbing entry is refused");
        assert!(error.to_string().contains("outside"), "{error}");
        assert!(
            !scratch.0.join("evil.h").exists(),
            "nothing lands outside the destination"
        );
    }

    #[test]
    fn entry_paths_must_stay_below_the_destination() {
        assert_eq!(
            enclosed("include/glib.h"),
            Some(PathBuf::from("include/glib.h"))
        );
        assert_eq!(
            enclosed("./include//glib.h"),
            Some(PathBuf::from("include/glib.h"))
        );
        assert_eq!(enclosed("../evil.h"), None);
        assert_eq!(enclosed("include/../../evil.h"), None);
        assert_eq!(enclosed("/etc/passwd"), None);
        assert_eq!(enclosed("..\\evil.h"), None);
        assert_eq!(enclosed("./"), Some(PathBuf::new()));
    }

    #[test]
    fn a_zip_entry_climbing_out_is_refused() {
        let scratch = Scratch::new("zip");
        let archive = scratch.0.join("deps.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
        zip.start_file("../evil.h", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"evil").unwrap();
        zip.finish().unwrap();
        assert_refused(&scratch, &archive);
    }

    #[test]
    fn a_tar_xz_entry_climbing_out_is_refused() {
        let scratch = Scratch::new("tar");
        let archive = scratch.0.join("deps.tar.xz");
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.as_old_mut().name[..9].copy_from_slice(b"../evil.h");
        header.set_size(4);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        tar.append(&header, &b"evil"[..]).unwrap();
        let tar = tar.into_inner().unwrap();
        let mut xz = lzma_rust2::XzWriter::new(
            std::fs::File::create(&archive).unwrap(),
            lzma_rust2::XzOptions::default(),
        )
        .unwrap();
        xz.write_all(&tar).unwrap();
        xz.finish().unwrap();
        assert_refused(&scratch, &archive);
    }

    #[test]
    fn a_7z_entry_climbing_out_is_refused() {
        let scratch = Scratch::new("7z");
        let archive = scratch.0.join("deps.7z");
        let mut writer = sevenz_rust2::ArchiveWriter::create(&archive).unwrap();
        let entry = sevenz_rust2::ArchiveEntry::new_file("../evil.h");
        writer
            .push_archive_entry(entry, Some(&b"evil"[..]))
            .unwrap();
        writer.finish().unwrap();
        assert_refused(&scratch, &archive);
    }

    #[test]
    fn a_well_formed_archive_extracts() {
        let scratch = Scratch::new("good");
        let archive = scratch.0.join("deps.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
        zip.start_file("include/glib.h", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"#define G 1\n").unwrap();
        zip.finish().unwrap();
        let destination = scratch.0.join("out");
        extract_dependency_archive(&archive, &destination).expect("extract");
        assert_eq!(
            std::fs::read_to_string(destination.join("include/glib.h")).unwrap(),
            "#define G 1\n"
        );
    }
}
