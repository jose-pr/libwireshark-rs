# Hosting Wireshark

The other way round from a plugin: a program starts Wireshark's dissection
engine in its own process, with Wireshark's dissectors and the plugins it
names, and gets back each frame's protocol tree and packet-list columns,
which is what `tshark -V` prints, as data.

## From Rust

```console
cargo add libwireshark --features host
```

```rust
use core::time::Duration;
use libwireshark::Encapsulation;
use libwireshark::host::{Host, HostConfig};

let config = HostConfig {
    plugins: vec!["basic_dissector.dll".into()],
    ..HostConfig::default()
};
let mut host = Host::open(&config)?;
let frame = std::fs::read("frame.bin")?;
let dissected = host.dissect(&frame, Encapsulation::ETHERNET, Duration::ZERO)?;
println!("{:?}", dissected.get("foo.version"));
for frame in host.read("capture.pcapng".as_ref(), Some("foo"))? {
    let frame = frame?;
    println!("{}: {:?}", frame.frame, frame.column("Info"));
}
```

`HostConfig` names the plugins (any plugin built for the running release
line), whether Wireshark's installed plugins load too
(`skip_installed_plugins`), a profile directory (`config_dir`) and
preferences set on top, as `tshark -o` sets them.

## From Python and other languages

`libwireshark-bridge` is also a guatiao provider of the `wireshark_host`
kind: a guatiao host loads the same library Wireshark loads as a plugin,
and drives `libwireshark::host` through it. The Python package's `Host` is
that host; see [Python](python.md).

## What to know

- **One start per process.** Wireshark's state is global: it starts at the
  first `open`, with that configuration, and one session is open at a time.
  A later `open` must give the same configuration.
- **Every release line**, 3.0 to 4.6: the program side of Wireshark changed
  across lines, and the host follows each line's calls. Build it against
  the Wireshark it runs with.
- **Not inside Wireshark.** Opening a host from a plugin is refused:
  Wireshark already runs there.
- **A plugin both listed and installed** registers its protocols twice,
  which Wireshark does not survive: set `skip_installed_plugins`.
- On Windows, Wireshark's directory must be on `PATH`; the host points
  Wireshark at its data and plugin directories itself.

The Rust reference is
[`libwireshark::host`](https://jose-pr.github.io/libwireshark-rs/rust/libwireshark/host/index.html).
