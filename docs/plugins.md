# Plugins in Rust

A plugin is a `cdylib` crate depending on `libwireshark`, with one
`plugin!` line at its root. What the plugin provides is a list of types,
one trait each; Wireshark's loader calls nothing else.

```rust
libwireshark::plugin!(
    dissectors = [Foo, Bar],
    taps = [FooStats],
    filters = [PortClass],
);
```

| Key | Types implement | Installed under `<plugins>/<major>.<minor>/` |
| --- | --- | --- |
| `dissectors` | `Dissector` | `epan/` |
| `taps` | `Tap` | `epan/` |
| `filters` | `FilterFunction` (Wireshark 4.4 on) | `epan/` |
| `file_types` | `FileType` (Wireshark 4.6 on) | `wiretap/`, for the whole library |
| `codecs` | `Codec` | `codecs/`, alone in their library |
| `dynamic` | a function answering `Registrations`, called when the plugin loads | `epan/` |

The personal plugin directory is `%APPDATA%\Wireshark\plugins` on Windows
and `~/.local/lib/wireshark/plugins` elsewhere; **Help › About Wireshark ›
Folders** shows it. On macOS the release-line directory is
`<major>-<minor>` and the library must be named `*.so`.

A plugin is built for the release line `libwireshark-sys` finds (the
installed Wireshark, or `WIRESHARK_VERSION` with `WIRESHARK_NO_LINK=1`), and
Wireshark loads it only in that line.

## Dissectors

A `Dissector` names its protocol, says where it gets packets
(`dissect_on`, from its preferences), and dissects one packet at a time.
Its header is a struct deriving `Header`: the fields are registered from it,
decoded from the packet, and added to the tree. Its preferences are a
struct deriving `Preferences`, shown in Wireshark's preferences and handed
to `dissect_on` and `dissect`.

```rust
#[derive(Preferences)]
struct FooPreferences {
    #[preference(title = "UDP port", description = "UDP port FOO is decoded on")]
    port: u16,
}

fn dissect_on(preferences: &FooPreferences) -> Vec<Binding> {
    vec![Binding::udp_port(preferences.port)]
}
```

Beyond a port: `Binding::heuristic` (try every packet of a protocol),
`Binding::postdissector` (see every frame), `TcpFraming` (messages
reassembled from TCP), `PacketView::with_conversation` (state per
conversation), `Dissector::EXPERTS` with `PacketView::add_expert` (expert
findings), and named values with `#[header(values = ...)]`.

## Taps

A `Tap` keeps statistics over the packets a Wireshark tap hands it (its own
protocol's, or `frame`, `ip`, `udp`...) and is offered as
`tshark -q -z <name>[,<filter>]`:

```rust
#[derive(Default)]
struct UdpBytes { packets: u64, bytes: u64 }

impl Tap for UdpBytes {
    const NAME: &'static str = "udpbytes";
    const TAP: &'static str = "udp";

    fn packet(&mut self, packet: &TapPacket<'_>) {
        self.packets += 1;
        self.bytes += u64::from(packet.len());
    }

    fn draw(&self) -> String {
        format!("UDP: {} packets, {} bytes\n", self.packets, self.bytes)
    }
}
```

## Display-filter functions

A `FilterFunction` is `name(field)` in a display filter (Wireshark 4.4 on),
answering a number or text for each value of the field:
`tshark -Y 'port_class(udp.dstport) == "well-known"'`.

## Capture formats and codecs

A `FileType` recognises a file and reads its records through
`CaptureFile`, so `tshark -r capture.rscap` opens it (Wireshark 4.6 on). A
`Codec` decodes an RTP payload type an SDP names, for the RTP player and
sharkd.

## Registered at run time

A plugin that learns what it provides when it loads (from a file, from
other plugins) answers `dynamic::Registrations` from its `dynamic`
function: protocols described by a `ProtocolSpec` and a `DynamicDissector`,
and taps, display-filter functions, capture formats and codecs built the
same way. Formats and codecs registered at run time work from `epan/`, in
the programs that dissect.

## Next

- [Examples](examples.md): a plugin of each kind, run by the test suite.
- The [Rust API reference](https://jose-pr.github.io/libwireshark-rs/rust/libwireshark/index.html).
