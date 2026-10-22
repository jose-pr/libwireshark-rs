# `libwireshark-guatiao` — API header

A Wireshark plugin (a `cdylib`; the `rlib` exists only for its tests) that
loads guatiao providers of the `wireshark_dissector` kind
(`libwireshark-api`) and registers each as a protocol, through
`libwireshark`'s run-time protocols. No Rust API. Built per Wireshark
release line like any `libwireshark` plugin; installed in `epan/`.

## When Wireshark loads it

1. Search path: `LIBWIRESHARK_GUATIAO_PATH` (separated as `PATH`), then
   `<personal plugin dir>/guatiao`, then `<global plugin dir>/guatiao`, as
   the running Wireshark names those directories (libwsutil's
   `get_plugins_pers_dir`, `get_plugins_dir`). Each place is scanned once.
2. A library is mapped only if it declares `kind=wireshark_dissector`. A
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

## Environment

| Variable | Effect |
| --- | --- |
| `LIBWIRESHARK_GUATIAO_PATH` | more places to look for providers, first |
| `LIBWIRESHARK_GUATIAO_LOG` | any value: report what loaded, not only problems |

Problems (a failed load, a refused module, a description that does not
read, a table of the wrong shape) always go to stderr as
`libwireshark-guatiao: ...`.

## Gotchas

- Python: the bridge links the Python it was built against; on Windows
  `python3.dll`'s directory must be on `PATH` for Wireshark, and the
  `guatiao` package, `wireshark_kinds.py` and `wireshark_dissector.py`
  must be importable.
- Two providers describing one protocol name: the second is left out, as
  for any duplicate (Wireshark would abort).
- guatiao comes from a pinned git revision; providers must be built
  against the same guatiao ABI.
