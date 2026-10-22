# `libwireshark-engine` — API header

Wireshark's dissection engine (EPAN with wiretap) running in the caller's
process. A Rust library (`rlib`) and, with the `provider` feature, a guatiao
provider library (`cdylib`) of the `wireshark_engine` kind. Built per
Wireshark release line; the engine exists from 4.6 on (`cfg(engine)`), and
before that every call answers `EngineError::Unsupported`.

## Rust API

```rust
pub use libwireshark_api::engine::{Column, Dissected, EngineConfig, Node};

pub struct Engine;                       // !Clone, Send; drop closes the session
impl Engine {
    pub fn open(config: &EngineConfig) -> Result<Engine, EngineError>;
    pub fn dissect(&mut self, data: &[u8], encapsulation: Encapsulation, time: Duration)
        -> Result<Dissected, EngineError>;   // time: since the Unix epoch
    pub fn read(&mut self, path: &Path, display_filter: Option<&str>)
        -> Result<Capture<'_>, EngineError>;
}
pub struct Capture<'a>;                  // Iterator<Item = Result<Dissected, EngineError>>
pub struct Encapsulation(pub i32);       // WTAP_ENCAP_*: ETHERNET (1), RAW_IP (7)

#[non_exhaustive]
pub enum EngineError {
    Unsupported,                         // built for a line before 4.6
    AlreadyOpen,                         // a session is open in this process
    Configured,                          // Wireshark started with another config
    Symbols(String),                     // a library/function of Wireshark not found
    Init(String),
    Plugin { path: String, reason: String },
    Preference { preference: String, reason: String },
    Filter(String),                      // display filter did not compile
    File(String),                        // capture could not be opened or read
}
```

`EngineConfig` (all optional): `plugins: Vec<String>` (plugin library
paths), `skip_installed_plugins: bool`, `config_dir: Option<String>` (a
profile directory; default the user's), `preferences: BTreeMap<String,
String>` (`"foo.port"` → `"113"`, as `tshark -o`).

`Dissected { frame: u32, columns: Vec<Column { title, text }>, tree:
Vec<Node> }`; `Node { abbrev, name, label, value: Option<String>, offset,
length, hidden, generated, children }` (a text item has empty `abbrev` and
`name`; protocols and `FT_NONE` fields have no `value`). `get(abbrev)` is the
first node depth first, `all(abbrev)` every one; `to_map`/`from_map` cross
as guatiao maps.

## Behaviour

- Wireshark starts once per process, at the first `open`, as tshark starts:
  logging, configuration, the listed plugins' `plugin_register` (their
  `plugin_want_major/minor` must match the running Wireshark), wiretap,
  EPAN (installed plugins unless skipped), the profile's preferences, then
  `preferences` on top. A failed start is final for the process: every
  later `open` answers the same error.
- Later opens must give an equal `EngineConfig` (else `Configured`); one
  session at a time (else `AlreadyOpen`).
- `dissect` frames share conversations and count on from 1; `read` starts a
  fresh capture (numbers and conversations restart) and keeps the frames
  the display filter passes, numbered as in the file. An error ends a read.
- Wireshark's failure reports go to stderr as `libwireshark-engine: ...`;
  its log levels follow `WIRESHARK_LOG_LEVEL` and friends.

## Provider (`--features provider`)

The `cdylib` exports `WiresharkEngine` (`wireshark_engine`): `open(config
map)` answers a `wireshark_session` object whose `dissect(data,
encapsulation, time_ns)` and `next()` answer `Dissected` maps (`next`: an
empty map at the end) and `open_file(path, display_filter)` opens a capture
(empty filter: all frames). Errors cross with guatiao statuses:
`UNSUPPORTED`, `BUSY` (already open), `INTERNAL` (start/symbols), else
`BAD_VALUE`, each with the error's text.

## Environment

| Variable | Effect |
| --- | --- |
| `WIRESHARK_DATA_DIR`, `WIRESHARK_PLUGIN_DIR` | Wireshark's own; on Windows the engine sets them to libwireshark's directory when unset |
| `WIRESHARK_LOG_LEVEL` (and Wireshark's other log variables) | read when Wireshark starts |

## Gotchas

- Wireshark's libraries must be loadable: on Windows its installation
  directory on `PATH`. The crate's tests delay-load libwireshark on MSVC so
  they start without it.
- A plugin both listed in `plugins` and installed registers its protocols
  twice: Wireshark aborts the process. Use `skip_installed_plugins`.
- Only one crate exporting guatiao providers may be linked into a library:
  enable `provider` only for the engine's own `cdylib`.
