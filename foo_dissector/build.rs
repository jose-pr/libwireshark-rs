fn main() {
    println!("cargo:rustc-link-lib=wireshark-src/build/libwireshark");
    println!("cargo:rerun-if-changed=src/wireshark.h");
}
