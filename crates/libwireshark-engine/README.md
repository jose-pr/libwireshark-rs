# libwireshark-engine

Wireshark's dissection engine in your process: dissect frames and read
capture files with Wireshark's dissectors and the plugins you load, and get
back the protocol tree and the packet list's columns — what `tshark -V`
prints, as data.

```rust,no_run
use core::time::Duration;
use libwireshark_engine::{Encapsulation, Engine, EngineConfig};

let config = EngineConfig {
    plugins: vec!["target/release/basic_dissector.dll".into()],
    ..EngineConfig::default()
};
let mut engine = Engine::open(&config)?;
let frame = std::fs::read("frame.bin")?;
let dissected = engine.dissect(&frame, Encapsulation::ETHERNET, Duration::ZERO)?;
if let Some(version) = dissected.get("foo.version") {
    println!("{}", version.label);
}
for frame in engine.read("capture.pcapng".as_ref(), Some("foo"))? {
    let frame = frame?;
    println!("{}: {:?}", frame.frame, frame.columns);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

The same engine is a guatiao provider of the `wireshark_engine` kind (see
[`libwireshark-api`](../libwireshark-api)), which is how the `libwireshark`
Python package's `Engine` reaches it.

## What to know

- **One release line, 4.6 on.** The engine embeds the host side of EPAN,
  which changes between release lines; on an older line every call answers
  `EngineError::Unsupported`. Build it against the Wireshark it will run
  with, as a plugin.
- **One engine per process.** Wireshark's state is global: it starts once,
  with the first `open`'s configuration, and one session may be open at a
  time. Opening again after closing needs the same configuration.
- **Plugins.** `plugins` are registered before EPAN starts, as Wireshark's
  own loader would; Wireshark's installed plugins load as well unless
  `skip_installed_plugins` is set. A plugin both listed and installed
  registers its protocols twice, which Wireshark does not survive.
- **Where Wireshark is.** On Windows, Wireshark looks for its data files
  and plugins beside the running program; the engine sets
  `WIRESHARK_DATA_DIR` and `WIRESHARK_PLUGIN_DIR` to libwireshark's
  directory when they are unset.
- **Preferences** come from the profile in `config_dir` (the user's by
  default), with `preferences` set on top as `tshark -o` sets them.
- Wireshark's own failure reports are written to stderr, prefixed
  `libwireshark-engine:`.

License: GPL-2.0-or-later.
