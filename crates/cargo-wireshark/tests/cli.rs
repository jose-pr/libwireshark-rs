//! The built binary's exit statuses: 0 success, 1 failure, 2 invalid arguments.

use std::process::{Command, Output};

fn cargo_wireshark(args: &[&str], directory: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargo-wireshark"))
        .args(args)
        .current_dir(directory)
        .output()
        .expect("run cargo-wireshark")
}

fn scratch(name: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("cargo-wireshark-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create a scratch directory");
    path
}

#[test]
fn help_succeeds_and_names_every_command() {
    let output = cargo_wireshark(&["--help"], &std::env::temp_dir());
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8_lossy(&output.stdout);
    for command in ["doctor", "version", "headers", "configure", "bindings"] {
        assert!(help.contains(command), "--help lists {command}");
    }
}

#[test]
fn cargo_inserts_the_subcommand_name_and_it_is_accepted() {
    let output = cargo_wireshark(&["wireshark", "headers", "--help"], &std::env::temp_dir());
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn invalid_arguments_exit_with_status_2() {
    let output = cargo_wireshark(
        &["headers", "generate", "--dll", "x.dll"],
        &std::env::temp_dir(),
    );
    assert_eq!(output.status.code(), Some(2));
    let output = cargo_wireshark(&["no-such-command"], &std::env::temp_dir());
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn a_failed_operation_exits_with_status_1_and_one_error_line() {
    let directory = scratch("fetch");
    let output = cargo_wireshark(
        &["headers", "fetch", "--remote", "no-such-remote"],
        &directory,
    );
    let _ = std::fs::remove_dir_all(&directory);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("cargo-wireshark: "), "{stderr}");
    assert!(
        output.stdout.is_empty(),
        "results go to stdout only on success"
    );
}

#[test]
fn publishing_an_empty_bundle_directory_fails() {
    let directory = scratch("publish");
    std::fs::create_dir_all(directory.join("bundles")).unwrap();
    let output = cargo_wireshark(
        &["headers", "publish", "--output-dir", "bundles"],
        &directory,
    );
    let _ = std::fs::remove_dir_all(&directory);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no bundles"));
}
