#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

extern crate alloc;

mod bindings;
mod bundle;
mod cmake;
mod deps;
mod discovery;
mod error;
mod exports;
mod public;
mod releases;

pub use bindings::{BindingsConfig, generate_bindings};
pub use bundle::{dependency_bundle_name, wireshark_bundle_name};
pub use cmake::{GeneratedHeaders, HeaderConfig, generate_headers};
pub use discovery::{Runtime, Sdk, SdkConfig, SourceTree};
pub use error::{Error, GenerateError};
pub use exports::{ExportComparison, export_report, write_export_report};
pub use public::{GeneratedPublicHeader, PublicHeaderConfig, generate_public_header};
pub use releases::{
    BUNDLE_BRANCH, ReleaseBundlesConfig, ReleaseLine, WIRESHARK_REMOTE, fetch_bundles,
    generate_release_lines, publish_bundles, release_lines,
};
