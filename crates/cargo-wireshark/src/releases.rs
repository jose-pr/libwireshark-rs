//! Header bundles for every stable Wireshark release line, and the
//! repository branch that stores them.

use crate::{GenerateError, PublicHeaderConfig, generate_public_header};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The branch holding the generated bundles.
pub const BUNDLE_BRANCH: &str = "headers";

/// Wireshark's upstream repository, cloned when no checkout is given.
pub const WIRESHARK_REMOTE: &str = "https://github.com/wireshark/wireshark.git";

/// A stable release line and the tag it starts at.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct ReleaseLine {
    /// Major version.
    pub major: u32,
    /// Minor version, always even.
    pub minor: u32,
    /// The `vX.Y.0` tag.
    pub tag: String,
}

/// Inputs for [`generate_release_lines`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ReleaseBundlesConfig {
    /// Wireshark clone; created from [`WIRESHARK_REMOTE`] when absent.
    pub repository: PathBuf,
    /// Directory receiving the bundles.
    pub output_dir: PathBuf,
    /// Rust target operating system.
    pub target_os: String,
    /// Rust target architecture.
    pub architecture: String,
    /// Release lines to generate (`"4.6"`); empty for all from 3.0.
    pub versions: Vec<String>,
    /// GLib/Gcrypt include roots for the target.
    pub dependency_include_dirs: Vec<PathBuf>,
}

impl ReleaseBundlesConfig {
    /// Generates every release line for one target from `repository` into `output_dir`.
    pub fn new(
        repository: PathBuf,
        output_dir: PathBuf,
        target_os: String,
        architecture: String,
    ) -> Self {
        Self {
            repository,
            output_dir,
            target_os,
            architecture,
            versions: Vec::new(),
            dependency_include_dirs: Vec::new(),
        }
    }
}

/// Stable release lines from 3.0 in `repository`: `vX.Y.0` tags with an even minor.
///
/// # Errors
///
/// [`GenerateError::Git`] when the tags cannot be listed.
pub fn release_lines(repository: &Path) -> Result<Vec<ReleaseLine>, GenerateError> {
    let tags = git(Some(repository), ["tag", "--list", "v*"])?;
    let mut lines = tags
        .lines()
        .filter_map(|tag| {
            let (major, rest) = tag.strip_prefix('v')?.split_once('.')?;
            let (minor, patch) = rest.split_once('.')?;
            let (major, minor) = (major.parse().ok()?, minor.parse().ok()?);
            (patch == "0" && major >= 3 && minor % 2 == 0).then(|| ReleaseLine {
                major,
                minor,
                tag: tag.to_owned(),
            })
        })
        .collect::<Vec<_>>();
    lines.sort();
    Ok(lines)
}

/// Generates the bundles of each selected release line, oldest first, from a
/// temporary worktree of its tag. Returns the lines generated.
///
/// The dependency bundle is the same for every line; the newest one wins.
///
/// # Errors
///
/// [`GenerateError::Git`] for a clone, fetch or worktree failure, and any
/// error of [`generate_public_header`].
pub fn generate_release_lines(
    config: &ReleaseBundlesConfig,
) -> Result<Vec<ReleaseLine>, GenerateError> {
    let repository = &config.repository;
    if !repository.join(".git").exists() {
        git(
            None,
            [
                OsStr::new("clone"),
                OsStr::new("--filter=blob:none"),
                OsStr::new("--no-checkout"),
                OsStr::new(WIRESHARK_REMOTE),
                repository.as_os_str(),
            ],
        )?;
    }
    git(
        Some(repository),
        ["fetch", "--quiet", "--filter=blob:none", "--tags", "origin"],
    )?;
    let mut lines = release_lines(repository)?;
    if !config.versions.is_empty() {
        lines.retain(|line| {
            config
                .versions
                .contains(&format!("{}.{}", line.major, line.minor))
        });
    }
    if lines.is_empty() {
        return Err(GenerateError::Git(
            "no matching Wireshark release lines".to_owned(),
        ));
    }
    let scratch =
        std::env::temp_dir().join(format!("cargo-wireshark-worktrees-{}", std::process::id()));
    for line in &lines {
        let worktree = scratch.join(&line.tag);
        git(
            Some(repository),
            [
                OsStr::new("worktree"),
                OsStr::new("add"),
                OsStr::new("--quiet"),
                OsStr::new("--detach"),
                worktree.as_os_str(),
                OsStr::new(&line.tag),
            ],
        )?;
        let generated = generate_public_header(&PublicHeaderConfig {
            source_dir: worktree.clone(),
            architecture: config.architecture.clone(),
            target_os: config.target_os.clone(),
            dependency_include_dirs: config.dependency_include_dirs.clone(),
            output_dir: config.output_dir.clone(),
            dll: None,
            filtered_output: None,
            llvm_readobj: "llvm-readobj".into(),
        });
        git(
            Some(repository),
            [
                OsStr::new("worktree"),
                OsStr::new("remove"),
                OsStr::new("--force"),
                worktree.as_os_str(),
            ],
        )?;
        generated?;
    }
    let _ = std::fs::remove_dir(&scratch);
    Ok(lines)
}

/// Copies every bundle on `remote`'s [`BUNDLE_BRANCH`] into `output_dir`,
/// for the checkout containing `checkout`. Returns how many were copied.
///
/// # Errors
///
/// [`GenerateError::Git`] when the branch cannot be fetched or read, and
/// [`GenerateError::WriteFailed`] when a bundle cannot be written.
pub fn fetch_bundles(
    checkout: &Path,
    remote: &str,
    output_dir: &Path,
) -> Result<usize, GenerateError> {
    let reference = format!("{remote}/{BUNDLE_BRANCH}");
    git(
        Some(checkout),
        [
            "fetch",
            "--quiet",
            remote,
            &format!("{BUNDLE_BRANCH}:refs/remotes/{reference}"),
        ],
    )?;
    let names = git(Some(checkout), ["ls-tree", "--name-only", &reference])?;
    std::fs::create_dir_all(output_dir)
        .map_err(|error| GenerateError::WriteFailed(error.to_string()))?;
    let mut copied = 0;
    for name in names.lines().filter(|name| is_bundle_name(name)) {
        let output = Command::new("git")
            .arg("-C")
            .arg(checkout)
            .args(["show", &format!("{reference}:{name}")])
            .output()
            .map_err(|error| GenerateError::Git(error.to_string()))?;
        if !output.status.success() {
            return Err(GenerateError::Git(format!(
                "could not read {name} from {reference}"
            )));
        }
        std::fs::write(output_dir.join(name), output.stdout)
            .map_err(|error| GenerateError::WriteFailed(error.to_string()))?;
        copied += 1;
    }
    Ok(copied)
}

/// Commits the bundles in `output_dir` to the local [`BUNDLE_BRANCH`] of the
/// checkout containing `checkout`, creating it as an orphan branch when
/// absent. Returns `false` when the branch already matched. Does not push.
///
/// # Errors
///
/// [`GenerateError::Git`] for a worktree or commit failure, and
/// [`GenerateError::WriteFailed`] when no bundle is found or one cannot be copied.
pub fn publish_bundles(
    checkout: &Path,
    output_dir: &Path,
    message: &str,
) -> Result<bool, GenerateError> {
    let write_error = |error: std::io::Error| GenerateError::WriteFailed(error.to_string());
    let mut bundles = std::fs::read_dir(output_dir)
        .map_err(write_error)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(is_bundle_name)
        })
        .collect::<Vec<_>>();
    bundles.sort();
    if bundles.is_empty() {
        return Err(GenerateError::WriteFailed(format!(
            "no bundles in {}",
            output_dir.display()
        )));
    }
    let worktree = std::env::temp_dir().join(format!(
        "cargo-wireshark-{BUNDLE_BRANCH}-{}",
        std::process::id()
    ));
    let exists = git(
        Some(checkout),
        ["rev-parse", "--verify", "--quiet", BUNDLE_BRANCH],
    )
    .is_ok();
    let mut add = vec![
        OsStr::new("worktree"),
        OsStr::new("add"),
        OsStr::new("--quiet"),
    ];
    if exists {
        add.extend([worktree.as_os_str(), OsStr::new(BUNDLE_BRANCH)]);
    } else {
        add.extend([
            OsStr::new("--orphan"),
            OsStr::new("-b"),
            OsStr::new(BUNDLE_BRANCH),
            worktree.as_os_str(),
        ]);
    }
    git(Some(checkout), add)?;
    let committed = (|| {
        for bundle in &bundles {
            let name = bundle.file_name().expect("bundles have file names");
            std::fs::copy(bundle, worktree.join(name)).map_err(write_error)?;
        }
        std::fs::write(worktree.join("README.md"), BRANCH_README).map_err(write_error)?;
        std::fs::write(worktree.join(".gitattributes"), "* text=auto eol=lf\n")
            .map_err(write_error)?;
        git(Some(&worktree), ["add", "--all", "."])?;
        if git(Some(&worktree), ["status", "--porcelain"])?
            .trim()
            .is_empty()
        {
            return Ok(false);
        }
        git(Some(&worktree), ["commit", "--quiet", "-m", message])?;
        Ok(true)
    })();
    git(
        Some(checkout),
        [
            OsStr::new("worktree"),
            OsStr::new("remove"),
            OsStr::new("--force"),
            worktree.as_os_str(),
        ],
    )?;
    committed
}

const BRANCH_README: &str = "# Wireshark header bundles

Generated by `cargo wireshark bundles generate` and read by `libwireshark-sys`.
`wireshark-<major>-<minor>.h` holds one release line's public headers and is
the same for every target; `deps-<os>-<arch>.h` holds the GLib and Gcrypt
headers for one target. A build includes the deps bundle first.
";

fn is_bundle_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".h") else {
        return false;
    };
    let word = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    };
    match stem.split('-').collect::<Vec<_>>()[..] {
        ["wireshark", major, minor] => [major, minor]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())),
        ["deps", os, arch] => word(os) && word(arch),
        _ => false,
    }
}

fn git<I, S>(directory: Option<&Path>, args: I) -> Result<String, GenerateError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new("git");
    if let Some(directory) = directory {
        command.arg("-C").arg(directory);
    }
    let output = command
        .args(args)
        .output()
        .map_err(|error| GenerateError::Git(format!("could not run git: {error}")))?;
    if !output.status.success() {
        return Err(GenerateError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::is_bundle_name;

    #[test]
    fn only_bundle_file_names_are_copied() {
        assert!(is_bundle_name("wireshark-4-6.h"));
        assert!(is_bundle_name("deps-windows-x86_64.h"));
        assert!(!is_bundle_name("README.md"));
        assert!(!is_bundle_name("deps-../x.h"));
        assert!(!is_bundle_name("wireshark-4-x.h"));
    }
}
