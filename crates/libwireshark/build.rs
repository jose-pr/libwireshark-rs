//! Enables what exists only from some Wireshark release line on, from the
//! line `libwireshark-sys` was built for.

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_WIRESHARK_VERSION");
    println!("cargo:rustc-check-cfg=cfg(file_type_plugins)");
    println!("cargo:rustc-check-cfg=cfg(host)");
    let version = std::env::var("DEP_WIRESHARK_VERSION")
        .expect("libwireshark-sys reports the release line it was built for");
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0));
    let line = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    // A file reader's `struct wtap`, and records that carry their own data.
    // ... and the program side of EPAN that `host` embeds.
    if line >= (4, 6) {
        println!("cargo:rustc-cfg=file_type_plugins");
        println!("cargo:rustc-cfg=host");
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
