//! Rules the source keeps, checked so they stay kept.

use std::path::Path;

/// Every `.rs` file under `src/`, as (`/`-separated relative path, text).
fn sources() -> Vec<(String, String)> {
    fn walk(root: &Path, directory: &Path, files: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(directory).expect("read a source directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(root, &path, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((
                    relative,
                    std::fs::read_to_string(&path).expect("read a source file"),
                ));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &root, &mut files);
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
    // `#[unsafe(no_mangle)]` and one `unsafe` call into the plugin crate.
    assert_eq!(
        files_containing(|line| line.contains("unsafe")),
        [
            "lib.rs",
            "macros.rs",
            "packet.rs",
            "plugin/callbacks.rs",
            "plugin/mod.rs",
            "plugin/preferences.rs",
            "plugin/runtime.rs",
        ]
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

#[test]
fn sources_hold_no_control_bytes() {
    // A NUL byte inside a string literal compiles, and reads as a space.
    for (name, text) in sources() {
        assert!(
            !text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t'),
            "{name} holds a control character"
        );
    }
}
