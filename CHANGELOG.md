# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

First release of the crates under these names.

### Added

- `libwireshark`: the `Dissector` trait, `PacketView` with the captured bytes
  as a slice, integer reads, columns and checked field insertion, `Binding`
  for dissector-table entries, typed `prefs`, and `plugin!` exporting a
  plugin of one or more protocols.
- `#[derive(Header)]` (registered fields plus `SIZE` and `decode(&[u8])`)
  and `#[derive(Preferences)]`, behind `libwireshark`'s `derive` feature.
- `libwireshark-sys`: bindings for Wireshark 3.0 to 4.6, generated from
  bundled headers for Windows, Linux, macOS and FreeBSD on x86_64 and
  aarch64; links the runtime without an SDK, or an SDK when one is found;
  `WIRESHARK_NO_LINK` for builds without Wireshark.
- `cargo-wireshark`: `doctor`, `version`, `headers generate|fetch|publish`,
  `configure` and `bindings`.
- Accepted packets set the Protocol column and add the protocol's tree item,
  so protocol display filters match; plugins report themselves as
  dissectors.
- Heuristic dissectors and post-dissectors (`Binding::heuristic`,
  `Binding::postdissector`), TCP message reassembly (`TcpFraming`),
  per-conversation state (`PacketView::with_conversation`), expert info
  (`Dissector::EXPERTS`, `PacketView::add_expert`), named values
  (`FieldInfo::with_values`, `#[header(values = ...)]`) and `bool`,
  byte-array, MAC and IP address fields in `#[derive(Header)]`.
- Tap listeners (`Tap`, `TapPacket`) offered as `tshark -z <name>[,<filter>]`,
  over Wireshark's taps or values a protocol publishes with
  `PacketView::tap`.
- Display-filter functions (`FilterFunction`, `FieldValue`) for Wireshark
  4.4 and later, returning a number or text.
- Capture file formats (`FileType`, `CaptureFile`, `Record`,
  `Encapsulation`) for Wireshark 4.6 and later, and audio codecs (`Codec`)
  for the RTP player; `Binding::encapsulation`.
- `plugin!` takes its lists in any order, each optional, and adds
  `file_types`, `codecs` and `dynamic`.
- Protocols described at run time (`dynamic::{Protocol, ProtocolSpec,
  DynamicDissector}`), and taps, display-filter functions, capture formats
  and codecs registered at run time (`dynamic::Registrations`); a plugin
  in `epan/` provides run-time formats and codecs to the programs that
  dissect (tshark, sharkd, Wireshark).
- `libwireshark-api` and `libwireshark-guatiao`: Wireshark dissectors
  written in any language guatiao reaches (Rust, C, Python), each declaring
  its header and preferences as typed structs and binding in `dissect_on`;
  one host plugin loads them all. Examples in `examples/guatiao`.
- The guatiao kinds `wireshark_tap`, `wireshark_filter_function`,
  `wireshark_file_type` and `wireshark_codec`, served by the same host, with
  Python helper classes (`Tap`, `FilterFunction`, `FileType`, `Codec`) and
  example providers in Rust, C and Python.
- `libwireshark::host` (feature `host`): Wireshark's dissection engine
  hosted in a program, on every release line (3.0 to 4.6): dissect frames and read
  capture files (with a display filter) using Wireshark's dissectors and
  the plugins it is given, into the protocol tree and the packet list's
  columns. `libwireshark-guatiao` serves it as the `wireshark_host` kind
  (`libwireshark-api::host`), which the Python package's `Host` drives.
- `PacketView::add_item` refuses a length its field's type does not take
  (`PacketFieldError::WrongLength`) instead of letting Wireshark throw; a
  TCP framing length that cannot be read hands the rest of the segment to
  `dissect`; a binding to a table not keyed by integers is skipped.
- `libwireshark-sys` reports its release line to dependents' build scripts
  as `DEP_WIRESHARK_VERSION`.
- A protocol whose names Wireshark already has is skipped instead of
  aborting Wireshark.
- Three example plugins, and tests that load them in tshark.

[Unreleased]: https://github.com/jose-pr/libwireshark-rs/commits/master
