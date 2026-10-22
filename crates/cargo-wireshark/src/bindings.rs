//! bindgen over a Wireshark source tree, for SDK workflows.

use crate::discovery::SourceTree;
use crate::error::GenerateError;
use std::ffi::OsString;
use std::path::PathBuf;

/// Inputs for generating Rust FFI bindings from Wireshark headers.
#[derive(Clone, Debug)]
pub struct BindingsConfig {
    /// Wireshark source root.
    pub source_dir: PathBuf,
    /// CMake build directory containing `config.h`.
    pub generated_include_dir: PathBuf,
    /// C umbrella header passed to bindgen.
    pub header: PathBuf,
    /// Destination for generated Rust bindings.
    pub output: PathBuf,
    /// Optional clang target triple.
    pub target: Option<String>,
    /// Additional arguments passed to clang, such as dependency include paths.
    pub clang_args: Vec<OsString>,
}

/// Generates Rust bindings from the selected source and configured header trees.
///
/// # Arguments
///
/// `config` supplies the Wireshark source root, generated include directory, C umbrella header, output path, and clang arguments.
///
/// # Returns
///
/// The path written with the generated Rust declarations.
///
/// # Errors
///
/// Returns an error if an input is missing, bindgen cannot parse the headers, or the output cannot be written.
pub fn generate_bindings(config: &BindingsConfig) -> Result<PathBuf, GenerateError> {
    if !config.header.is_file() {
        return Err(GenerateError::InvalidHeader(config.header.clone()));
    }
    if !config.generated_include_dir.join("config.h").is_file()
        || !config.generated_include_dir.join("ws_version.h").is_file()
    {
        return Err(GenerateError::MissingGeneratedHeaders(
            config.generated_include_dir.clone(),
        ));
    }
    let source =
        SourceTree::inspect(config.source_dir.clone()).ok_or(GenerateError::InvalidSource)?;
    let mut builder = bindgen::Builder::default()
        .header(config.header.to_string_lossy())
        .layout_tests(false)
        .blocklist_item("_.*");
    if let Some(target) = &config.target {
        builder = builder.clang_arg(format!("--target={target}"));
    }
    for include_dir in [
        source.root.clone(),
        source.root.join("include"),
        config.generated_include_dir.clone(),
    ] {
        builder = builder.clang_arg(format!("-I{}", include_dir.display()));
    }
    for arg in &config.clang_args {
        builder = builder.clang_arg(arg.to_string_lossy().into_owned());
    }
    let bindings = builder
        .generate()
        .map_err(|error| GenerateError::BindgenFailed(error.to_string()))?;
    if let Some(parent) = config.output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| GenerateError::WriteFailed(error.to_string()))?;
    }
    bindings
        .write_to_file(&config.output)
        .map_err(|error| GenerateError::WriteFailed(error.to_string()))?;
    Ok(config.output.clone())
}
