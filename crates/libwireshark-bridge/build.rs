//! Hands the tests the directory of `guatiao.h`, which a C provider is
//! compiled against.

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_GUATIAO_INCLUDE");
    if let Ok(dir) = std::env::var("DEP_GUATIAO_INCLUDE") {
        println!("cargo::rustc-env=GUATIAO_INCLUDE_DIR={dir}");
    }
}
