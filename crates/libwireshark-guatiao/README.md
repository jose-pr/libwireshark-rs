# libwireshark-guatiao

A Wireshark plugin that loads plugins written in any language
[guatiao](https://github.com/Boriken-Dev/guatiao) reaches — Rust, C,
Python and more — and registers them with Wireshark: dissectors, tap
listeners, display-filter functions, capture formats and audio codecs. A provider
implements the kinds of [`libwireshark-api`](../libwireshark-api) and links
no Wireshark: one build serves every Wireshark release line. As with
`libwireshark`'s `Dissector`, a provider declares its header and its
preferences as structs (classes, in Python): the host decodes the header
and adds its fields, registers the preferences, and asks the provider's
`dissect_on` where to bind each time they change.

## Install

1. Build this crate for your Wireshark release line and copy the library
   into Wireshark's plugin directory, under `<major>.<minor>/epan/`
   (`<major>-<minor>` on macOS, renamed to `.so`), as any plugin built
   with `libwireshark`.
2. Put providers in a `guatiao` directory of a plugin directory — the
   personal one (`%APPDATA%\Wireshark\plugins\guatiao`,
   `~/.local/lib/wireshark/plugins/guatiao`) or the global one — or in a
   directory named by `LIBWIRESHARK_GUATIAO_PATH` (several, separated as in
   `PATH`). Not under a release line's directory: a provider serves them all.

A provider is:

- **a library** declaring one of the kinds (`kind=wireshark_dissector`,
  `wireshark_tap`, `wireshark_filter_function`, `wireshark_file_type`,
  `wireshark_codec`): a Rust `cdylib`
  calling `guatiao::providers!`, or a C shared library filling the tables
  of `libwireshark_api.h`;
- **a Python module** with its `*.guatiao-py.toml` manifest, beside the
  guatiao-py bridge library (`guatiao_py.dll`, `libguatiao_py.so`), which
  the host adds as a source serving that directory. Python needs the
  `libwireshark` package (`bindings/python`, which brings guatiao's)
  importable (installed, that directory, or `PYTHONPATH`), and on Windows
  the directory holding `python3.dll` on `PATH`.

Examples of each are in [`examples/guatiao`](../../examples/guatiao).

## Diagnostics

Problems — a library that failed to load, a source that refused a module,
a provider whose description does not read — are written to stderr, as
`libwireshark-guatiao: ...`. Set `LIBWIRESHARK_GUATIAO_LOG` to anything
to see what loaded as well.

License: GPL-2.0-or-later.
