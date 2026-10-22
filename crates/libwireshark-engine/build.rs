//! The engine embeds the host-side API of one release line: 4.6 on, where
//! a record carries its own data.

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_WIRESHARK_VERSION");
    println!("cargo:rustc-check-cfg=cfg(engine)");
    let version = std::env::var("DEP_WIRESHARK_VERSION")
        .expect("libwireshark-sys reports the release line it was built for");
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0));
    let line = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    if line >= (4, 6) {
        println!("cargo:rustc-cfg=engine");
    }
    // The tests run only when asked, but link libwireshark: on MSVC it loads
    // on first call, so a test binary starts without Wireshark on `PATH`.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-tests=/DELAYLOAD:libwireshark.dll");
        println!("cargo:rustc-link-arg-tests=delayimp.lib");
    }
}
