# `libwireshark-bridge` — API header

A Wireshark plugin (a `cdylib`; the `rlib` exists only for its tests) that
loads guatiao providers of the `wireshark_dissector` kind
(`libwireshark-api`) and registers each as a protocol, through
`libwireshark`'s run-time protocols. No Rust API. Built per Wireshark
release line like any `libwireshark` plugin; installed in `epan/`.

## When Wireshark loads it

1. Search path: `LIBWIRESHARK_BRIDGE_PATH` (separated as `PATH`), then
   `<personal plugin dir>/bridge`, then `<global plugin dir>/bridge`, as
   the running Wireshark names those directories (libwsutil's
   `get_plugins_pers_dir`, `get_plugins_dir`). Each place is scanned once.
2. A library is mapped only if it declares one of `kind=wireshark_dissector`,
   `wireshark_tap`, `wireshark_filter_function`, `wireshark_file_type` or
   `wireshark_codec`. A
   guatiao source file found there (one declaring `source=..`, such as the
   guatiao-py bridge) is added with the configuration
   `{"dirs": [its directory], "paths": [its directory]}`, then the registry
   is refreshed once.
3. Each `wireshark_dissector` offer's default instance is asked to
   `describe`; the description becomes a protocol, its header fields and
   preferences registered with it. A description Wireshark would abort on
   (see `libwireshark-api`'s AGENTS.md) is refused and reported. A
   provider built only from a configuration is skipped.
4. One registry, leaked: it lives for the process, as Wireshark's use of
   the protocols does.

## The other kinds

- Each provider of `wireshark_tap`, `wireshark_filter_function`,
  `wireshark_file_type` and `wireshark_codec` is described once and
  registered through `libwireshark::dynamic` (32 filter functions, file
  types and codecs at most; taps have no limit).
  Names are checked (`[a-z][a-z0-9...]`: taps also `_.-`, functions and
  formats `_`); a name another provider of the kind took is skipped.
- Tap: each `-z` invocation `open`s a listener; a packet crosses as a
  `TapPacket` map; a refused `packet` or `reset` is reported once per
  invocation, a refused `draw` when it happens; a refused `open` leaves an
  invocation that reports nothing.
- Filter function: an integer field's value crosses as a number, any
  other as its display text; an answer of the wrong kind is no answer, and
  a refused call is no answer, reported once per function.
- File type (4.6 on): `open` and `read` get a `CaptureSource` lent for the
  call over Wireshark's file (from another thread `read` and `position`
  answer -1, an error); `NOT_FOUND` from `open` means another format, any
  other refusal is reported and counts as another format too (an error
  would stop Wireshark trying the formats after it); a refused `read` is a
  read error. Registered from `epan/`, the format serves the programs that
  dissect, not the wiretap-only tools.
- Codec: a decoder per stream (`open` with its `StreamFormat`); samples
  cross as little-endian bytes. sharkd and Wireshark register codecs, tshark
  only for `-G`.

## Preferences and bindings

- Each time Wireshark applies preferences, the values are handed to the
  provider as a map by name and `dissect_on` answers the bindings; a
  refused or unreadable answer is reported and binds nothing.

## Per packet

- The header is decoded from the captured bytes (each field `data` holds
  whole) and `dissect` gets it with the preferences, a lent `Packet` over
  `libwireshark`'s `PacketView`, and the protocol's map for the packet's
  conversation (kept between calls). An error, a panic, 0 or a negative
  answer declines; an answer past the data counts as all of it. On
  accepting, the header fields are added to the tree.
- `Packet::add_uint`/`add_int` add through a 32-bit field when the value
  fits and the field is not 64 bits wide, else through a 64-bit one; with
  no tree they succeed without adding; from another thread they refuse.

## As a provider: `wireshark_host`

The library also exports guatiao's library entry with one provider,
`WiresharkHost` (`wireshark_host`): `open(config)` starts Wireshark in the
caller's process through `libwireshark::host` and answers a
`wireshark_session` (`dissect`, `open_file`, `next`, crossing the
`libwireshark_api::host` models). Errors cross as `BUSY` (a session open,
or inside Wireshark), `INTERNAL` (start,
symbols), else `BAD_VALUE`. Wireshark itself never calls this entry; a
guatiao host never calls `plugin_register` unless it lists this library
as a plugin.

## Environment

| Variable | Effect |
| --- | --- |
| `LIBWIRESHARK_BRIDGE_PATH` | more places to look for providers, first |
| `LIBWIRESHARK_BRIDGE_LOG` | any value: report what loaded, not only problems |

Problems (a failed load, a refused module, a description that does not
read, a table of the wrong shape) always go to stderr as
`libwireshark-bridge: ...`.

## Gotchas

- Python: the bridge links the Python it was built against; on Windows
  `python3.dll`'s directory must be on `PATH` for Wireshark, and the
  `libwireshark` Python package (which brings guatiao's) importable.
- Two providers describing one protocol name: the second is left out, as
  for any duplicate (Wireshark would abort).
- guatiao comes from a pinned git revision; providers must be built
  against the same guatiao ABI.
