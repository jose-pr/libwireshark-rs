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
- A protocol whose names Wireshark already has is skipped instead of
  aborting Wireshark.
- Three example plugins, and tests that load them in tshark.

[Unreleased]: https://github.com/jose-pr/libwireshark-rs/commits/master
