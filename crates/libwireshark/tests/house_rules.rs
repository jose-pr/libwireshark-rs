//! Rules the source keeps, checked so they stay kept.

use std::path::Path;

fn sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = std::fs::read_dir(&root)
        .expect("read src")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (
                name,
                std::fs::read_to_string(&path).expect("read a source file"),
            )
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn files_containing(needle: impl Fn(&str) -> bool) -> Vec<String> {
    sources()
        .into_iter()
        .filter(|(_, text)| {
            text.lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .any(&needle)
        })
        .map(|(name, _)| name)
        .collect()
}

#[test]
fn unsafe_code_stays_in_the_ffi_modules() {
    // lib.rs names `unsafe_code` in its lint attributes; macros.rs writes
    // `#[unsafe(no_mangle)]` into the plugin crate.
    assert_eq!(
        files_containing(|line| line.contains("unsafe")),
        ["lib.rs", "macros.rs", "packet.rs", "plugin.rs"]
    );
}

#[test]
fn the_library_keeps_no_process_global_state() {
    // macros.rs declares the plugin's statics inside the plugin crate.
    let statics = files_containing(|line| {
        let line = line.trim_start();
        line.starts_with("static ")
            || line.starts_with("pub static ")
            || line.contains("OnceLock")
            || line.contains("LazyLock")
            || line.contains("thread_local!")
    });
    assert_eq!(statics, ["macros.rs"]);
}
