//! Enables what exists only from some Wireshark release line on, from the
//! line `libwireshark-sys` was built for.

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_WIRESHARK_VERSION");
    println!("cargo:rustc-check-cfg=cfg(file_type_plugins)");
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
}
