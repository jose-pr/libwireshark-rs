//! Renders `include/libwireshark_api.h`, the kind tables as C structs, when
//! the `c-header` feature is on. The tables are `#[guatiao::kind]` output,
//! so cbindgen expands the crate first: that needs `RUSTC_BOOTSTRAP=1` and a
//! target directory of its own, set here around the render only. guatiao's
//! types keep the names `guatiao.h` gives them through the rename table it
//! ships beside that header (`DEP_GUATIAO_INCLUDE`).
//!
//! Refresh the committed copy with
//! `GUATIAO_WRITE_HEADER=1 cargo build -p libwireshark-api --features c-header`.

fn main() {
    println!("cargo::rerun-if-changed=src");
    println!("cargo::rerun-if-changed=cbindgen.toml");
    println!("cargo::rerun-if-env-changed=GUATIAO_WRITE_HEADER");
    #[cfg(feature = "c-header")]
    render();
}

#[cfg(feature = "c-header")]
fn render() {
    use std::path::PathBuf;

    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo"));
    // SAFETY: the build script is single-threaded here; the variables are
    // read by the cargo that cbindgen spawns to expand the crate.
    unsafe {
        std::env::set_var("RUSTC_BOOTSTRAP", "1");
        std::env::set_var("CARGO_EXPAND_TARGET_DIR", out_dir.join("expand"));
    }
    let mut config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml"))
        .expect("cbindgen.toml is beside this script");
    let include = PathBuf::from(std::env::var("DEP_GUATIAO_INCLUDE").expect("guatiao links"));
    let renames = include.join("kind_rename.toml");
    println!("cargo::rerun-if-changed={}", renames.display());
    let guatiao_names =
        cbindgen::Config::from_file(&renames).expect("guatiao ships its rename table");
    config.export.rename.extend(guatiao_names.export.rename);
    let generated = match cbindgen::generate_with_config(&crate_dir, config) {
        Ok(generated) => generated,
        Err(error) => {
            println!("cargo::warning=cbindgen could not render the kind header: {error}");
            return;
        }
    };
    let rendered = out_dir.join("libwireshark_api.h");
    generated.write_to_file(&rendered);
    println!(
        "cargo::rustc-env=LIBWIRESHARK_API_GENERATED_HEADER={}",
        rendered.display()
    );
    if std::env::var_os("GUATIAO_WRITE_HEADER").is_some() {
        generated.write_to_file(crate_dir.join("include").join("libwireshark_api.h"));
    }
}
