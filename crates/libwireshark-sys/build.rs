//! Generates bindings from the header bundles for the detected Wireshark
//! release line and links the matching SDK or runtime library.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const ENVIRONMENT: &[&str] = &[
    "WIRESHARK_DIR",
    "WIRESHARK_INCLUDE_DIR",
    "WIRESHARK_GENERATED_INCLUDE_DIR",
    "WIRESHARK_LIB_DIR",
    "WIRESHARK_DLL",
    "WIRESHARK_VERSION",
    "WIRESHARK_SOURCE_DIR",
    "WIRESHARK_TSHARK",
    "WIRESHARK_BINDGEN_HEADER",
    "WIRESHARK_BINDGEN_TARGET",
    "WIRESHARK_BUNDLE_DIR",
    "WIRESHARK_NO_LINK",
    "DOCS_RS",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_LIBDIR",
];

/// Release line documented on docs.rs, where no Wireshark is installed.
const DOCS_RS_VERSION: &str = "4.6";

fn main() {
    for name in ENVIRONMENT {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let architecture = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo sets CARGO_CFG_TARGET_ARCH");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo sets CARGO_CFG_TARGET_OS");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));

    let no_link = env::var_os("DOCS_RS").is_some() || env::var_os("WIRESHARK_NO_LINK").is_some();
    let (installation, runtime) = if no_link {
        (None, None)
    } else {
        let installation = discover_installation();
        let runtime = installation.is_none().then(discover_runtime).flatten();
        (installation, runtime)
    };
    let version = if env::var_os("DOCS_RS").is_some() {
        DOCS_RS_VERSION.to_owned()
    } else {
        installation
            .as_ref()
            .and_then(|value| value.version.clone())
            .or_else(|| runtime.as_ref().and_then(|value| value.version.clone()))
            .or_else(|| env::var("WIRESHARK_VERSION").ok())
            .or_else(version_from_source)
            .or_else(version_from_tshark)
            .unwrap_or_else(|| {
                panic!(
                    "Wireshark was not found, so its version is unknown. Install the Wireshark runtime, \
                     set WIRESHARK_DLL or WIRESHARK_DIR to it, or set WIRESHARK_VERSION (with \
                     WIRESHARK_NO_LINK=1 to build without linking)"
                )
            })
    };
    if installation.is_none() && runtime.is_none() && !no_link {
        panic!(
            "Wireshark {version} was not found to link against. Set WIRESHARK_DLL to \
             libwireshark.dll/.so/.dylib or WIRESHARK_DIR to the installation, or set \
             WIRESHARK_NO_LINK=1 to generate bindings without linking"
        );
    }
    let (major, minor) = version_pair(&version).unwrap_or_else(|| {
        panic!("invalid Wireshark version '{version}'; expected major.minor[.patch]")
    });
    // `DEP_WIRESHARK_VERSION` for dependents' build scripts.
    println!("cargo:version={major}.{minor}");

    let header = match env::var_os("WIRESHARK_BINDGEN_HEADER") {
        Some(header) => {
            let header = PathBuf::from(header);
            println!("cargo:rerun-if-changed={}", header.display());
            header
        }
        None => {
            let (os, arch) = if env::var_os("DOCS_RS").is_some() {
                ("linux", "x86_64")
            } else {
                (target_os.as_str(), architecture.as_str())
            };
            umbrella(&output, major, minor, os, arch)
        }
    };
    if let Some(installation) = installation {
        generate_bindings(&header, &installation.include_dirs, &output);
    } else {
        if let Some(runtime) = runtime {
            link_runtime(&runtime.library, &output, &architecture);
        }
        generate_bindings(&header, &[], &output);
    }
}

/// Writes the umbrella bindgen reads: the target's dependency bundle, then
/// the release line's Wireshark bundle.
fn umbrella(
    output: &Path,
    major: &str,
    minor: &str,
    target_os: &str,
    architecture: &str,
) -> PathBuf {
    let names = [
        format!("deps-{target_os}-{architecture}.h"),
        format!("wireshark-{major}-{minor}.h"),
    ];
    let paths = names.each_ref().map(|name| bundle(output, name));
    let umbrella = output.join("libwireshark-umbrella.h");
    let contents = paths
        .iter()
        .map(|path| {
            format!(
                "#include \"{}\"\n",
                path.display().to_string().replace('\\', "/")
            )
        })
        .collect::<String>();
    std::fs::write(&umbrella, contents).expect("write the bindgen umbrella into OUT_DIR");
    umbrella
}

/// Finds one bundle: `WIRESHARK_BUNDLE_DIR`, then the crate's `headers/`
/// (where a packaged crate has them), then the repository's `headers` branch.
fn bundle(output: &Path, name: &str) -> PathBuf {
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let directories = env::var_os("WIRESHARK_BUNDLE_DIR")
        .map(PathBuf::from)
        .into_iter()
        .chain([manifest.join("headers")]);
    for directory in directories {
        let path = directory.join(name);
        if path.is_file() {
            println!("cargo:rerun-if-changed={}", path.display());
            return path;
        }
    }
    if let Some(path) = bundle_from_branch(&manifest, output, name) {
        return path;
    }
    panic!(
        "no header bundle {name}. In a checkout, run `cargo wireshark headers fetch`; to build \
         one from Wireshark source, run `cargo wireshark headers generate --source-dir \
         <wireshark> --output-dir <dir>` and set WIRESHARK_BUNDLE_DIR=<dir>"
    );
}

/// Reads a bundle from the `headers` branch of the checkout this crate sits
/// in, fetching the branch once when it is absent and Cargo is not offline.
fn bundle_from_branch(manifest: &Path, output: &Path, name: &str) -> Option<PathBuf> {
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(manifest)
            .args(args)
            .output()
            .ok()
            .filter(|result| result.status.success())
    };
    git(&["rev-parse", "--git-dir"])?;
    let show = |reference: &str| git(&["show", &format!("{reference}:{name}")]);
    let contents = show("origin/headers")
        .or_else(|| show("headers"))
        .or_else(|| {
            if env::var_os("CARGO_NET_OFFLINE").is_some() {
                return None;
            }
            git(&[
                "fetch",
                "--quiet",
                "origin",
                "headers:refs/remotes/origin/headers",
            ])?;
            show("origin/headers")
        })?;
    let directory = output.join("headers");
    std::fs::create_dir_all(&directory).ok()?;
    let path = directory.join(name);
    std::fs::write(&path, contents.stdout).ok()?;
    Some(path)
}

struct RuntimeInstallation {
    library: PathBuf,
    version: Option<String>,
}

fn discover_runtime() -> Option<RuntimeInstallation> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os("WIRESHARK_DLL") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(root) = env::var_os("WIRESHARK_DIR").map(PathBuf::from) {
        candidates.extend([
            root.join("libwireshark.dll"),
            root.join("libwireshark.so"),
            root.join("libwireshark.dylib"),
            root.join("lib/libwireshark.so"),
            root.join("lib/libwireshark.dylib"),
        ]);
    }
    if let Some(program_files) = env::var_os("ProgramFiles") {
        candidates.push(PathBuf::from(program_files).join("Wireshark/libwireshark.dll"));
    }
    candidates.extend([
        PathBuf::from(r"C:\Program Files\Wireshark\libwireshark.dll"),
        PathBuf::from("/usr/lib/libwireshark.so"),
        PathBuf::from("/usr/lib/x86_64-linux-gnu/libwireshark.so"),
        PathBuf::from("/usr/lib/aarch64-linux-gnu/libwireshark.so"),
        PathBuf::from("/usr/lib64/libwireshark.so"),
        PathBuf::from("/usr/local/lib/libwireshark.so"),
        PathBuf::from("/opt/homebrew/lib/libwireshark.dylib"),
        PathBuf::from("/Applications/Wireshark.app/Contents/Frameworks/libwireshark.dylib"),
    ]);
    let library = candidates.into_iter().find(|path| path.is_file())?;
    let version = env::var("WIRESHARK_VERSION")
        .ok()
        .or_else(|| version_from_tshark_near(&library));
    Some(RuntimeInstallation { library, version })
}

fn version_from_tshark_near(library: &Path) -> Option<String> {
    let parent = library.parent()?;
    [
        parent.join("tshark.exe"),
        parent.join("tshark"),
        parent.join("../bin/tshark"),
        parent.join("../MacOS/tshark"),
    ]
    .into_iter()
    .find_map(|candidate| version_from_executable(&candidate))
}

fn version_from_executable(candidate: &Path) -> Option<String> {
    let output = Command::new(candidate).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find(|token| token.as_bytes().first().is_some_and(u8::is_ascii_digit))
        .map(|value| value.trim_start_matches('v').to_owned())
}

fn link_runtime(library: &Path, output_dir: &Path, architecture: &str) {
    if library
        .extension()
        .is_some_and(|extension| extension == "dll")
    {
        let import_library = [
            library.with_extension("lib"),
            library.with_file_name("wireshark.lib"),
        ]
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| create_import_library(library, output_dir, architecture));
        let search_dir = import_library
            .parent()
            .expect("import library has a parent");
        println!("cargo:rustc-link-search=native={}", search_dir.display());
        let link_name = import_library
            .file_stem()
            .expect("import library has a file name")
            .to_string_lossy();
        println!("cargo:rustc-link-lib=dylib={link_name}");
    } else {
        let search_dir = library.parent().expect("runtime library has a parent");
        println!("cargo:rustc-link-search=native={}", search_dir.display());
        println!("cargo:rustc-link-lib=dylib=wireshark");
    }
    println!("cargo:rerun-if-changed={}", library.display());
}

/// Builds `wireshark.lib` from the DLL's export table; Wireshark's Windows
/// installer ships the DLL without an import library.
fn create_import_library(library: &Path, output_dir: &Path, architecture: &str) -> PathBuf {
    let inspection = Command::new("llvm-readobj")
        .arg("--coff-exports")
        .arg(library)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "could not run llvm-readobj on {}: {error}",
                library.display()
            )
        });
    if !inspection.status.success() {
        panic!(
            "llvm-readobj failed for {}: {}",
            library.display(),
            String::from_utf8_lossy(&inspection.stderr)
        );
    }
    let text = String::from_utf8_lossy(&inspection.stdout);
    let dll_arch = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("Arch:").map(str::trim));
    let (expected, machine) = match architecture {
        "aarch64" => ("aarch64", "arm64"),
        "x86_64" => ("x86_64", "i386:x86-64"),
        "x86" => ("i386", "i386"),
        other => panic!("cannot create a Wireshark import library for target architecture {other}"),
    };
    if dll_arch != Some(expected) {
        panic!(
            "Wireshark DLL architecture {dll_arch:?} does not match Rust target architecture {architecture}"
        );
    }
    let exports = parse_exports(&text);
    if exports.is_empty() {
        panic!(
            "no named exports found in Wireshark DLL {}",
            library.display()
        );
    }
    let output_library = output_dir.join("wireshark.lib");
    let definition = output_library.with_extension("def");
    let mut contents = format!(
        "LIBRARY {}\nEXPORTS\n",
        library.file_name().unwrap_or_default().to_string_lossy()
    );
    for (ordinal, name) in exports {
        contents.push_str(&format!("{name} @{ordinal}\n"));
    }
    std::fs::write(&definition, contents).expect("write the Wireshark DLL export definition");
    let result = Command::new("llvm-dlltool")
        .args(["-m", machine, "-D"])
        .arg(library.file_name().expect("DLL has a file name"))
        .arg("-d")
        .arg(&definition)
        .arg("-l")
        .arg(&output_library)
        .output()
        .unwrap_or_else(|error| panic!("could not run llvm-dlltool: {error}"));
    if !result.status.success() || !output_library.is_file() {
        panic!(
            "llvm-dlltool failed to create {}: {}",
            output_library.display(),
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    output_library
}

fn parse_exports(output: &str) -> Vec<(u32, String)> {
    let mut exports = Vec::new();
    let mut ordinal = None;
    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Ordinal:") {
            ordinal = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("Name:")
            && let (Some(ordinal), name) = (ordinal.take(), value.trim())
            && !name.is_empty()
            && !name.chars().any(char::is_whitespace)
        {
            exports.push((ordinal, name.to_owned()));
        }
    }
    exports
}

struct Installation {
    include_dirs: Vec<PathBuf>,
    version: Option<String>,
}

fn discover_installation() -> Option<Installation> {
    let explicit_paths = [
        "WIRESHARK_DIR",
        "WIRESHARK_SOURCE_DIR",
        "WIRESHARK_INCLUDE_DIR",
        "WIRESHARK_GENERATED_INCLUDE_DIR",
        "WIRESHARK_LIB_DIR",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some());
    if explicit_paths {
        return discover_explicit_installation();
    }
    let library = pkg_config::Config::new()
        .cargo_metadata(true)
        .probe("wireshark")
        .ok()?;
    Some(Installation {
        include_dirs: library.include_paths,
        version: Some(library.version),
    })
}

fn discover_explicit_installation() -> Option<Installation> {
    let root = env::var_os("WIRESHARK_DIR")
        .or_else(|| env::var_os("WIRESHARK_SOURCE_DIR"))
        .map(PathBuf::from);
    let include = env::var_os("WIRESHARK_INCLUDE_DIR")
        .map(PathBuf::from)
        .filter(|path| path.join("epan/packet.h").is_file())
        .or_else(|| root.as_deref().and_then(find_include_dir))?;
    let library = env::var_os("WIRESHARK_LIB_DIR")
        .map(PathBuf::from)
        .filter(|path| link_library_name(path).is_some())
        .or_else(|| root.as_deref().and_then(find_library_dir))?;
    let generated = env::var_os("WIRESHARK_GENERATED_INCLUDE_DIR").map(PathBuf::from);
    if !include.join("config.h").is_file()
        && !generated
            .as_ref()
            .is_some_and(|path| path.join("config.h").is_file())
    {
        return None;
    }
    println!("cargo:rustc-link-search=native={}", library.display());
    let link_name = link_library_name(&library).expect("library directory holds a link library");
    println!("cargo:rustc-link-lib=dylib={link_name}");

    let mut include_dirs = vec![include];
    if let Some(root) = root
        .as_deref()
        .filter(|path| path.join("epan/packet.h").is_file())
    {
        let source_include = root.join("include");
        if source_include.is_dir() {
            include_dirs.push(source_include);
        }
    }
    include_dirs.extend(generated);
    Some(Installation {
        include_dirs,
        version: env::var("WIRESHARK_VERSION").ok(),
    })
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
        .find(|path| link_library_name(path).is_some())
}

/// The `-l` name of the Wireshark link library in `path`, if it holds one.
fn link_library_name(path: &Path) -> Option<&'static str> {
    [
        ("wireshark.lib", "wireshark"),
        ("libwireshark.lib", "libwireshark"),
        ("libwireshark.so", "wireshark"),
        ("libwireshark.dylib", "wireshark"),
        ("wireshark.dll.a", "wireshark"),
    ]
    .into_iter()
    .find(|(file, _)| path.join(file).is_file())
    .map(|(_, name)| name)
}

fn version_pair(version: &str) -> Option<(&str, &str)> {
    let mut parts = version.trim().split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    (digits(major) && digits(minor)).then_some((major, minor))
}

fn version_from_source() -> Option<String> {
    let root = env::var_os("WIRESHARK_SOURCE_DIR")
        .or_else(|| env::var_os("WIRESHARK_DIR"))
        .map(PathBuf::from)?;
    if let Ok(source) = std::fs::read_to_string(root.join("CMakeLists.txt"))
        && let (Some(major), Some(minor)) = (
            cmake_version_component(&source, "MAJOR"),
            cmake_version_component(&source, "MINOR"),
        )
    {
        return Some(format!("{major}.{minor}"));
    }
    let configure = std::fs::read_to_string(root.join("configure.ac")).ok()?;
    let major = autotools_version_component(&configure, "major")?;
    let minor = autotools_version_component(&configure, "minor")?;
    Some(format!("{major}.{minor}"))
}

fn cmake_version_component(source: &str, component: &str) -> Option<String> {
    let marker = format!("set(PROJECT_{component}_VERSION");
    source.lines().find_map(|line| {
        let (_, right) = line.split_once(&marker)?;
        let value = right.split(')').next()?.trim();
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| value.to_owned())
    })
}

fn autotools_version_component(source: &str, component: &str) -> Option<String> {
    let marker = format!("m4_define([version_{component}], [");
    source.lines().find_map(|line| {
        let (_, value) = line.split_once(&marker)?;
        let value = value.split_once(']')?.0;
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| value.to_owned())
    })
}

fn version_from_tshark() -> Option<String> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os("WIRESHARK_TSHARK") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("WIRESHARK_LIB_DIR").map(PathBuf::from) {
        candidates.push(path.join("tshark.exe"));
        candidates.push(path.join("tshark"));
        if path
            .file_name()
            .is_some_and(|name| name == "lib" || name == "lib64")
            && let Some(parent) = path.parent()
        {
            candidates.push(parent.join("bin/tshark"));
            candidates.push(parent.join("tshark.exe"));
        }
    }
    if let Some(path) = env::var_os("WIRESHARK_DIR").map(PathBuf::from) {
        candidates.push(path.join("tshark.exe"));
        candidates.push(path.join("bin/tshark"));
    }
    candidates.push(PathBuf::from("tshark"));
    candidates.push(PathBuf::from("tshark.exe"));
    candidates
        .into_iter()
        .find_map(|candidate| version_from_executable(&candidate))
}

fn generate_bindings(header: &Path, include_dirs: &[PathBuf], output: &Path) {
    let mut builder = bindgen::Builder::default()
        .header(header.to_string_lossy().into_owned())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .layout_tests(false)
        .allowlist_recursively(true);
    if let Ok(target) = env::var("WIRESHARK_BINDGEN_TARGET") {
        builder = builder.clang_arg(format!("--target={target}"));
    } else if env::var_os("DOCS_RS").is_some() {
        builder = builder.clang_arg("--target=x86_64-unknown-linux-gnu");
    } else if let Ok(target) = env::var("TARGET") {
        builder = builder.clang_arg(format!("--target={target}"));
    }
    for include_dir in include_dirs {
        builder = builder.clang_arg(format!("-I{}", include_dir.display()));
    }
    builder
        .generate()
        .unwrap_or_else(|error| {
            panic!(
                "bindgen could not parse the Wireshark header bundle {} with libclang: {error}",
                header.display()
            )
        })
        .write_to_file(output.join("bindings.rs"))
        .expect("write the generated Wireshark bindings");
}
