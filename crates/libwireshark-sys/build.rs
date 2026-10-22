use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    for name in [
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
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let architecture = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("Cargo sets CARGO_CFG_TARGET_ARCH for build scripts");
    let target_os =
        env::var("CARGO_CFG_TARGET_OS").expect("Cargo sets CARGO_CFG_TARGET_OS for build scripts");
    let installation = discover_installation();
    let runtime = installation.is_none().then(discover_runtime).flatten();
    if installation.is_none() && runtime.is_none() {
        panic!(
            "Wireshark runtime was not found. Set WIRESHARK_DLL to libwireshark.dll/.so or WIRESHARK_DIR to the runtime installation. The selected header bundle supplies C declarations; a Wireshark SDK is not required."
        );
    }

    let version = installation
        .as_ref()
        .and_then(|value| value.version.clone())
        .or_else(|| runtime.as_ref().and_then(|value| value.version.clone()))
        .or_else(|| version_from_source())
        .or_else(version_from_tshark)
        .unwrap_or_else(|| {
            panic!(
                "Wireshark was found but its major/minor version could not be determined; set WIRESHARK_VERSION or WIRESHARK_TSHARK"
            )
        });
    let (major, minor) = version_pair(&version).unwrap_or_else(|| {
        panic!("invalid Wireshark version '{version}'; expected major.minor[.patch]")
    });

    let header = binding_header(major, minor, &target_os, &architecture);
    if !header.is_file() {
        panic!(
            "no public-header umbrella is checked in for Wireshark {major}.{minor} on {target_os}-{architecture} (looked for {}); generate it with scripts/generate-version-headers.ps1 -TargetOS {target_os} -Architecture {architecture} or set WIRESHARK_BINDGEN_HEADER",
            header.display()
        );
    }
    println!("cargo:rerun-if-changed={}", header.display());
    if let Some(installation) = installation {
        generate_bindings(&header, &installation.include_dirs);
    } else if let Some(runtime) = runtime {
        let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
        link_runtime(&runtime.library, &output, &architecture);
        generate_bindings(&header, &[]);
    }
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
        parent.join("../bin/tshark.exe"),
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
        let import_library = import_library_for(
            library,
            output_dir,
            architecture,
            "wireshark.lib",
            &[
                library.with_extension("lib"),
                library.with_file_name("wireshark.lib"),
            ],
        );
        emit_import_library(&import_library);
    } else {
        let search_dir = library.parent().expect("runtime library has parent");
        println!("cargo:rustc-link-search=native={}", search_dir.display());
        println!("cargo:rustc-link-lib=dylib=wireshark");
    }
    println!("cargo:rerun-if-changed={}", library.display());
}

fn import_library_for(
    library: &Path,
    output_dir: &Path,
    architecture: &str,
    output_name: &str,
    candidates: &[PathBuf],
) -> PathBuf {
    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| create_import_library(library, output_dir, architecture, output_name))
}

fn emit_import_library(import_library: &Path) {
    let search_dir = import_library.parent().expect("import library has parent");
    println!("cargo:rustc-link-search=native={}", search_dir.display());
    let link_name = import_library
        .file_stem()
        .expect("import library has a filename")
        .to_string_lossy();
    println!("cargo:rustc-link-lib=dylib={link_name}");
}

fn create_import_library(
    library: &Path,
    output_dir: &Path,
    architecture: &str,
    output_name: &str,
) -> PathBuf {
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
        "x86_64" => ("x86_64", "x64"),
        "x86" => ("i386", "i386"),
        other => panic!("cannot create a Wireshark import library for target architecture {other}"),
    };
    if dll_arch != Some(expected) {
        panic!(
            "Wireshark DLL architecture {:?} does not match Rust target architecture {architecture}",
            dll_arch
        );
    }
    let exports = parse_exports(&text);
    if exports.is_empty() {
        panic!(
            "no named exports found in Wireshark DLL {}",
            library.display()
        );
    }
    let output_library = output_dir.join(output_name);
    let definition = output_library.with_extension("def");
    let mut contents = format!(
        "LIBRARY {}\nEXPORTS\n",
        library.file_name().unwrap_or_default().to_string_lossy()
    );
    for (ordinal, name) in exports {
        contents.push_str(&format!("{name} @{ordinal}\n"));
    }
    std::fs::write(&definition, contents).expect("write Wireshark DLL export definition");
    let status = Command::new("llvm-dlltool")
        .args(["-m", machine, "-D"])
        .arg(library.file_name().expect("DLL has a filename"))
        .arg("-d")
        .arg(&definition)
        .arg("-l")
        .arg(&output_library)
        .status()
        .unwrap_or_else(|error| panic!("could not run llvm-dlltool: {error}"));
    if !status.success() || !output_library.is_file() {
        panic!("llvm-dlltool failed to create {}", output_library.display());
    }
    output_library
}

fn parse_exports(output: &str) -> Vec<(u32, String)> {
    let mut exports = Vec::new();
    let mut ordinal = None;
    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Ordinal:") {
            ordinal = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("Name:") {
            if let (Some(ordinal), name) = (ordinal.take(), value.trim())
                && !name.is_empty()
                && !name.chars().any(char::is_whitespace)
            {
                exports.push((ordinal, name.to_owned()));
            }
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
        .filter(|path| has_link_library(path))
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
    let link_name = if library.join("wireshark.lib").is_file() {
        "wireshark"
    } else if library.join("libwireshark.lib").is_file() {
        "libwireshark"
    } else if library.join("libwireshark.so").is_file() {
        "wireshark"
    } else if library.join("libwireshark.dylib").is_file() {
        "wireshark"
    } else {
        "wireshark"
    };
    println!("cargo:rustc-link-lib=dylib={link_name}");

    let mut include_dirs = vec![include.clone()];
    if let Some(root) = root
        .as_deref()
        .filter(|path| path.join("epan/packet.h").is_file())
    {
        let source_include = root.join("include");
        if source_include.is_dir() {
            include_dirs.push(source_include);
        }
    }
    if let Some(generated) = generated {
        include_dirs.push(generated);
    }

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
        .find(|path| has_link_library(path))
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

fn binding_header(major: &str, minor: &str, target_os: &str, architecture: &str) -> PathBuf {
    if let Some(header) = env::var_os("WIRESHARK_BINDGEN_HEADER") {
        let header = PathBuf::from(header);
        return if header.is_absolute() {
            header
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(header)
        };
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("headers")
        .join(format!("{major}-{minor}-{target_os}-{architecture}.h"))
}

fn version_pair(version: &str) -> Option<(&str, &str)> {
    let mut parts = version.trim().split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((major, minor))
}

fn version_from_source() -> Option<String> {
    let root = env::var_os("WIRESHARK_SOURCE_DIR")
        .or_else(|| env::var_os("WIRESHARK_DIR"))
        .map(PathBuf::from)?;
    let source = std::fs::read_to_string(root.join("CMakeLists.txt")).ok();
    if let Some(source) = source {
        let major = cmake_version_component(&source, "MAJOR");
        let minor = cmake_version_component(&source, "MINOR");
        if let (Some(major), Some(minor)) = (major, minor) {
            return Some(format!("{major}.{minor}"));
        }
    }
    let configure = std::fs::read_to_string(root.join("configure.ac")).ok()?;
    let major = autotools_version_component(&configure, "major")?;
    let minor = autotools_version_component(&configure, "minor")?;
    Some(format!("{major}.{minor}"))
}

fn cmake_version_component(source: &str, component: &str) -> Option<String> {
    let marker = format!("set(PROJECT_{component}_VERSION");
    source.lines().find_map(|line| {
        let (left, right) = line.split_once(&marker)?;
        let _ = left;
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
        {
            if let Some(parent) = path.parent() {
                candidates.push(parent.join("bin/tshark"));
                candidates.push(parent.join("tshark.exe"));
            }
        }
    }
    if let Some(path) = env::var_os("WIRESHARK_DIR").map(PathBuf::from) {
        candidates.push(path.join("tshark.exe"));
        candidates.push(path.join("bin/tshark"));
    }
    candidates.push(PathBuf::from("tshark"));
    candidates.push(PathBuf::from("tshark.exe"));

    candidates.into_iter().find_map(|candidate| {
        let output = Command::new(candidate).arg("--version").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        text.split_whitespace()
            .find(|token| token.as_bytes().first().is_some_and(u8::is_ascii_digit))
            .map(|value| value.trim_start_matches('v').to_owned())
    })
}

fn generate_bindings(header: &Path, include_dirs: &[PathBuf]) {
    let mut builder = bindgen::Builder::default()
        .header(header.to_string_lossy().into_owned())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .layout_tests(false)
        .allowlist_recursively(true);
    if let Ok(target) = env::var("WIRESHARK_BINDGEN_TARGET") {
        builder = builder.clang_arg(format!("--target={target}"));
    } else if let Ok(target) = env::var("TARGET") {
        builder = builder.clang_arg(format!("--target={target}"));
    }
    for include_dir in include_dirs {
        builder = builder.clang_arg(format!("-I{}", include_dir.display()));
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    builder
        .generate()
        .unwrap_or_else(|error| {
            panic!(
                "failed to generate bindings from the self-contained Wireshark public-header bundle at {} with libclang: {error}",
                header.display()
            )
        })
        .write_to_file(output.join("bindings.rs"))
        .expect("failed to write generated Wireshark bindings");
}
