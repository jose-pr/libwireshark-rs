//! Enables what exists only from some Wireshark release line on, from the
//! line `libwireshark-sys` was built for.

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_WIRESHARK_VERSION");
    println!("cargo:rustc-check-cfg=cfg(file_type_plugins)");
    for line in ["3_2", "3_6", "4_0", "4_2", "4_4", "4_6"] {
        println!("cargo:rustc-check-cfg=cfg(wireshark_{line})");
    }
    let version = std::env::var("DEP_WIRESHARK_VERSION")
        .expect("libwireshark-sys reports the release line it was built for");
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0));
    let line = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    // A file reader's `struct wtap`, and records that carry their own data.
    if line >= (4, 6) {
        println!("cargo:rustc-cfg=file_type_plugins");
    }
    // `wireshark_M_m`: built for release line M.m or later, where the
    // program side of EPAN (`host`) changed shape.
    for (at, name) in [
        ((3, 2), "3_2"),
        ((3, 6), "3_6"),
        ((4, 0), "4_0"),
        ((4, 2), "4_2"),
        ((4, 4), "4_4"),
        ((4, 6), "4_6"),
    ] {
        if line >= at {
            println!("cargo:rustc-cfg=wireshark_{name}");
        }
    }
    // The engine's test links libwireshark but runs only when asked: on MSVC
    // it loads on first call, so the test binaries start without Wireshark
    // on `PATH`.
    if std::env::var_os("CARGO_FEATURE_HOST").is_some()
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg-tests=/DELAYLOAD:libwireshark.dll");
        println!("cargo:rustc-link-arg-tests=delayimp.lib");
        // The other tests import nothing from libwireshark: the linker says
        // the delay-load is unused (LNK4199), which is expected.
        println!("cargo:rustc-link-arg-tests=/IGNORE:4199");
    }
}
