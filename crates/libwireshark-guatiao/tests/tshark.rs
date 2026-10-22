//! The host plugin, loaded by the real tshark, dissecting through providers
//! written in Rust, C and Python.
//!
//! Ignored by default, like libwireshark's tshark tests. The C provider
//! needs a C compiler (`CC`, else clang, cc or gcc); the Python provider a
//! guatiao checkout at the pinned revision with its Python bridge built
//! (`LIBWIRESHARK_TEST_GUATIAO`; `LIBWIRESHARK_TEST_GUATIAO_BRIDGE` names
//! the bridge's file when it is built elsewhere), and on Windows the
//! directory holding `python3.dll` on `PATH`. A missing one is a printed
//! skip, and a failure when `LIBWIRESHARK_TEST_REQUIRE_ALL` is set.

#[path = "../../libwireshark/tests/harness/mod.rs"]
mod harness;

use harness::{Profile, Segment, frame, plugin};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The packets each provider gets: version 7, an unknown version 9, and
/// one too short for the header.
fn frames(port: u16) -> Vec<Vec<u8>> {
    vec![
        frame(&Segment::Udp(port, &[7, 1, 2, 3])),
        frame(&Segment::Udp(port, &[9, 1, 0, 4])),
        frame(&Segment::Udp(port, &[7, 1])),
    ]
}

/// What [`rows`] answers for a provider whose Info line counts with
/// `count`: the header, a named value, an expert finding, and the short
/// packet declined.
fn expected(short: &str, count: &str) -> [String; 2] {
    [
        format!("{short}\t7\t0x01\t515\t{short} version 7, {count} 1\t"),
        format!("{short}\t9\t0x01\t4\t{short} version 9, {count} 2\tUnknown version"),
    ]
}

/// The Protocol column of each packet with the port preference moved away.
fn moved(profile: &Profile, filter: &str) -> Vec<String> {
    let preference = format!("{filter}.port:999");
    profile.fields(&["-o", &preference], &["_ws.col.Protocol"])
}

/// A profile with the host in `epan/`, the capture of [`frames`], and
/// `providers/` as the host's search path.
fn profile(test: &str, port: u16) -> (Profile, PathBuf) {
    let profile = Profile::new(test, &[("libwireshark_guatiao", "epan")], &frames(port));
    let providers = profile.root().join("providers");
    std::fs::create_dir_all(&providers).expect("create the providers directory");
    let path = providers
        .to_str()
        .expect("a UTF-8 temporary path")
        .to_owned();
    (
        profile.with_env("LIBWIRESHARK_GUATIAO_PATH", &path),
        providers,
    )
}

/// `filter`'s Protocol column, version, length, Info and expert message
/// for each packet.
fn rows(profile: &Profile, filter: &str) -> Vec<String> {
    let fields = [
        "_ws.col.Protocol".to_owned(),
        format!("{filter}.version"),
        format!("{filter}.flags"),
        format!("{filter}.length"),
        "_ws.col.Info".to_owned(),
        "_ws.expert.message".to_owned(),
    ];
    let fields = fields.iter().map(String::as_str).collect::<Vec<_>>();
    profile.fields(&["-Y", filter], &fields)
}

fn skip(what: &str, why: &str) {
    assert!(
        std::env::var_os("LIBWIRESHARK_TEST_REQUIRE_ALL").is_none(),
        "{what}: {why}"
    );
    println!("skipped {what}: {why}");
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn the_host_loads_as_a_dissector_plugin() {
    let (profile, _) = profile("guatiao-load", 113);
    let plugins = profile.run(&["-G", "plugins"]);
    let line = plugins
        .lines()
        .find(|line| line.contains("libwireshark_guatiao"))
        .unwrap_or_else(|| panic!("the host is not loaded:\n{plugins}"));
    assert!(line.contains("dissector"), "{line}");
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn a_provider_written_in_rust_dissects_through_the_host() {
    let (profile, providers) = profile("guatiao-rust", 113);
    let library = plugin("guatiao_rust_provider");
    std::fs::copy(
        &library,
        providers.join(library.file_name().expect("a file")),
    )
    .expect("install the provider");
    assert_eq!(rows(&profile, "rsfoo"), expected("RSFOO", "packet"));
    assert_eq!(
        moved(&profile, "rsfoo"),
        ["UDP"; 3],
        "dissect_on follows the port"
    );
}

fn compiler() -> Option<PathBuf> {
    let named = std::env::var_os("CC").map(PathBuf::from);
    named
        .into_iter()
        .chain(["clang", "cc", "gcc"].map(PathBuf::from))
        .find(|cc| Command::new(cc).arg("--version").output().is_ok())
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn a_provider_written_in_c_dissects_through_the_host() {
    let Some(cc) = compiler() else {
        return skip("the C provider", "no C compiler (CC, clang, cc, gcc)");
    };
    let Some(include) = option_env!("GUATIAO_INCLUDE_DIR") else {
        return skip("the C provider", "guatiao reported no include directory");
    };
    let (profile, providers) = profile("guatiao-c", 114);
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let library = providers.join(format!(
        "{}cfoo{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let compile = Command::new(&cc)
        .args(["-shared", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .args(if cfg!(windows) {
            &[][..]
        } else {
            &["-fPIC"][..]
        })
        .arg("-I")
        .arg(include)
        .arg("-I")
        .arg(manifest.join("../libwireshark-api/include"))
        .arg("-o")
        .arg(&library)
        .arg(manifest.join("../../examples/guatiao/c-provider/cfoo.c"))
        .output()
        .expect("the compiler answered --version");
    assert!(
        compile.status.success(),
        "cfoo.c did not compile: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert_eq!(rows(&profile, "cfoo"), expected("CFOO", "frame"));
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn a_provider_written_in_python_dissects_through_the_host() {
    let Some(checkout) = std::env::var_os("LIBWIRESHARK_TEST_GUATIAO").map(PathBuf::from) else {
        return skip(
            "the Python provider",
            "LIBWIRESHARK_TEST_GUATIAO names no guatiao checkout with its Python bridge built",
        );
    };
    let bridge = std::env::var_os("LIBWIRESHARK_TEST_GUATIAO_BRIDGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            checkout
                .join("crates/guatiao-py/target/debug")
                .join(format!(
                    "{}guatiao_py{}",
                    std::env::consts::DLL_PREFIX,
                    std::env::consts::DLL_SUFFIX
                ))
        });
    if !bridge.is_file() {
        return skip(
            "the Python provider",
            &format!("{} is not built", bridge.display()),
        );
    }
    let (profile, providers) = profile("guatiao-python", 115);
    std::fs::copy(&bridge, providers.join(bridge.file_name().expect("a file")))
        .expect("install the bridge");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for file in ["pyfoo.py", "pyfoo.guatiao-py.toml"] {
        std::fs::copy(
            manifest
                .join("../../examples/guatiao/python-provider")
                .join(file),
            providers.join(file),
        )
        .expect("install the module");
    }
    let python_path = std::env::join_paths([
        checkout.join("bindings/python/src"),
        manifest.join("../libwireshark-api/python"),
    ])
    .expect("paths without the separator");
    let profile = profile.with_env("PYTHONPATH", python_path.to_str().expect("a UTF-8 path"));
    assert_eq!(rows(&profile, "pyfoo"), expected("PYFOO", "packet"));
    assert_eq!(
        moved(&profile, "pyfoo"),
        ["UDP"; 3],
        "dissect_on follows the port"
    );
}
