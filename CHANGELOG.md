# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Workspace crates for raw bindings, the Rust runtime, macros, and `cargo-wireshark`.
- Documentation for architecture, Wireshark compatibility, development setup, and FFI safety.
- `cargo wireshark doctor` and `cargo wireshark version` commands.
- `cargo wireshark headers` for no-CMake public-header aggregation and DLL export comparison, plus `cargo wireshark bindings` for Rust FFI output.
- Optional `#[wireshark_plugin]` entry-point macro and ARM64-aware Windows DLL import-library helper.
- `#[wireshark_plugin]` resolves renamed `libwireshark` dependencies and rejects unsupported attribute arguments.
- Callback-scoped `PacketView` access for bounded byte reads, registered unsigned fields, and Info-column text.
- Big- and little-endian signed and unsigned integer reads, plus checked signed and 64-bit field insertion.
- Checked generic `PacketView::add_item` insertion for registered Wireshark field types.
- Basic, TCP, UDP, and dual-transport example plugins.

### Changed

- Wireshark development headers and libraries are discovered from pkg-config or explicit SDK paths; public-header aggregation reads source lists directly, while CMake configuration is an explicit optional command.
- The fallback bindings are restricted to Wireshark 3.2.4 on `x86_64-pc-windows-msvc`; other targets and versions use bindgen.
- Plugin registration storage and preference strings have retained owners, and Rust panics are contained at C callback boundaries.
- SDK discovery accepts separate source, generated-header, and native-library paths and reports runtime/source installations independently.
