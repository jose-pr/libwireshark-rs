//! The example plugins, loaded by the real tshark against a generated capture.
//!
//! Ignored by default: they need tshark from the Wireshark release line
//! `libwireshark-sys` was built for. Run them with `cargo test -- --ignored`;
//! `LIBWIRESHARK_TEST_TSHARK` names the executable when it is not on `PATH`
//! or in Wireshark's default Windows location.

use std::path::{Path, PathBuf};
use std::process::Command;

const PLUGINS: [&str; 3] = ["basic_dissector", "multi_protocol", "stream_protocol"];

/// The client's port: above every server port here and claimed by no
/// dissector, since TCP and UDP offer a packet to the lower port first.
const CLIENT_PORT: u16 = 61000;

/// A transport segment from 192.0.2.1:61000 to 192.0.2.2.
enum Segment<'a> {
    Udp(u16, &'a [u8]),
    /// Destination port, sequence number, payload.
    Tcp(u16, u32, &'a [u8]),
}

/// `segment` in IPv4 in Ethernet.
fn frame(segment: &Segment<'_>) -> Vec<u8> {
    let (protocol, transport) = match segment {
        Segment::Udp(port, payload) => {
            let mut udp = Vec::new();
            udp.extend(CLIENT_PORT.to_be_bytes());
            udp.extend(port.to_be_bytes());
            udp.extend((8 + payload.len() as u16).to_be_bytes());
            udp.extend([0, 0]);
            udp.extend(*payload);
            (17, udp)
        }
        Segment::Tcp(port, seq, payload) => {
            let mut tcp = Vec::new();
            tcp.extend(CLIENT_PORT.to_be_bytes());
            tcp.extend(port.to_be_bytes());
            tcp.extend(seq.to_be_bytes());
            tcp.extend(1u32.to_be_bytes());
            tcp.extend([0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0]);
            tcp.extend(*payload);
            (6, tcp)
        }
    };
    let total = (20 + transport.len()) as u16;
    let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, protocol, 0, 0];
    ip.extend([192, 0, 2, 1, 192, 0, 2, 2]);
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    let sum = ip
        .chunks(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    let sum = !(((sum & 0xffff) + (sum >> 16)) as u16);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    let mut frame = vec![0; 12];
    frame.extend([0x08, 0x00]);
    frame.extend(ip);
    frame.extend(transport);
    frame
}

/// The capture every test reads:
///
/// 1. UDP/111: FOO version 7, flags 1, length 515 (basic-dissector)
/// 2. UDP/4242: BAZ (multi-protocol)
/// 3. TCP/4242: BAR (multi-protocol)
/// 4. UDP/47100: an HBEAT heartbeat, found by heuristics (stream-protocol)
/// 5. TCP/47100: LPM hello, data, and the first two bytes of a third message
/// 6. TCP/47100: the rest of that hello, then a message of unknown kind 9
fn write_capture(path: &Path) {
    let first = [0, 5, 1, b'a', b'b', 0, 4, 2, b'c', 0, 6];
    let second = [1, b'x', b'y', b'z', 0, 4, 9, b'q'];
    let frames = [
        frame(&Segment::Udp(111, &[7, 1, 2, 3])),
        frame(&Segment::Udp(4242, &[3, 9])),
        frame(&Segment::Tcp(4242, 1, &[5, 0, 0])),
        frame(&Segment::Udp(47100, b"HB\x00\x07\x01")),
        frame(&Segment::Tcp(47100, 1, &first)),
        frame(&Segment::Tcp(47100, 1 + first.len() as u32, &second)),
    ];
    let mut pcap = Vec::new();
    pcap.extend(0xa1b2_c3d4u32.to_le_bytes());
    pcap.extend(2u16.to_le_bytes());
    pcap.extend(4u16.to_le_bytes());
    pcap.extend([0u8; 8]);
    pcap.extend(65535u32.to_le_bytes());
    pcap.extend(1u32.to_le_bytes());
    for (second, frame) in frames.iter().enumerate() {
        pcap.extend((1_700_000_000 + second as u32).to_le_bytes());
        pcap.extend(0u32.to_le_bytes());
        pcap.extend((frame.len() as u32).to_le_bytes());
        pcap.extend((frame.len() as u32).to_le_bytes());
        pcap.extend(frame);
    }
    std::fs::write(path, pcap).expect("write the capture");
}

fn tshark() -> PathBuf {
    if let Some(path) = std::env::var_os("LIBWIRESHARK_TEST_TSHARK") {
        return PathBuf::from(path);
    }
    let windows = Path::new(r"C:\Program Files\Wireshark\tshark.exe");
    if windows.is_file() {
        return windows.to_owned();
    }
    PathBuf::from("tshark")
}

/// A built example plugin, beside this test binary.
fn plugin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("a test binary knows its path");
    let file = format!(
        "{}{name}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    exe.ancestors()
        .skip(1)
        .take(2)
        .map(|directory| directory.join(&file))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("{file} was not built beside {}", exe.display()))
}

/// A throwaway home and configuration directory holding the plugins and the
/// capture, so tshark loads them and nothing of the user's.
struct Profile(PathBuf);

impl Profile {
    fn new(test: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("libwireshark-tshark-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // The release line's directory: `4-6` on macOS, whose code signing
        // reads dotted directory names as bundles, `4.6` elsewhere.
        let version = format!(
            "{}{}{}",
            libwireshark::sys::VERSION_MAJOR,
            if cfg!(target_os = "macos") { "-" } else { "." },
            libwireshark::sys::VERSION_MINOR
        );
        for base in [
            root.join("plugins"),
            root.join(".local/lib/wireshark/plugins"),
        ] {
            let directory = base.join(&version).join("epan");
            std::fs::create_dir_all(&directory).expect("create the plugin directory");
            for name in PLUGINS {
                // Wireshark loads only `.dll` on Windows and `.so` everywhere
                // else, macOS included, where Cargo builds a `.dylib`.
                let installed = if cfg!(windows) {
                    format!("{name}.dll")
                } else {
                    format!("{name}.so")
                };
                std::fs::copy(plugin(name), directory.join(installed)).expect("copy a plugin");
            }
        }
        write_capture(&root.join("capture.pcap"));
        Self(root)
    }

    fn capture(&self) -> String {
        self.0
            .join("capture.pcap")
            .to_str()
            .expect("a UTF-8 temporary path")
            .to_owned()
    }

    fn run(&self, args: &[&str]) -> String {
        let output = Command::new(tshark())
            .args(args)
            .env("WIRESHARK_CONFIG_DIR", &self.0)
            .env("HOME", &self.0)
            .output()
            .expect("run tshark");
        assert!(
            output.status.success(),
            "tshark {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
    }

    /// `fields` of each frame of the capture, tab-separated, one line per frame.
    fn fields(&self, extra: &[&str], fields: &[&str]) -> Vec<String> {
        let capture = self.capture();
        let mut args = vec!["-r", capture.as_str()];
        args.extend(extra);
        args.extend(["-T", "fields"]);
        for field in fields {
            args.extend(["-e", field]);
        }
        self.run(&args).lines().map(str::to_owned).collect()
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn tshark_loads_every_example_as_a_dissector_plugin() {
    let profile = Profile::new("load");
    let plugins = profile.run(&["-G", "plugins"]);
    for name in PLUGINS {
        let line = plugins
            .lines()
            .find(|line| line.contains(name))
            .unwrap_or_else(|| panic!("{name} is not loaded:\n{plugins}"));
        assert!(
            line.contains("dissector"),
            "{name} reports its type: {line}"
        );
    }
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn table_bound_protocols_set_their_column_and_fields() {
    let profile = Profile::new("tables");
    let columns = profile.fields(&["-c", "3"], &["_ws.col.Protocol", "_ws.col.Info"]);
    assert_eq!(
        columns,
        [
            "FOO\tFOO version 7, length 515",
            "BAZ\tBAZ version 3, 2 bytes",
            "BAR\tBAR version 5, 3 bytes",
        ]
    );
    let foo = profile.fields(&["-Y", "foo"], &["foo.version", "foo.flags", "foo.length"]);
    assert_eq!(
        foo,
        ["7\t0x01\t515"],
        "the protocol filter matches and its fields nest under it"
    );
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn preferences_rebind_and_relabel() {
    let profile = Profile::new("prefs");
    let moved = profile.fields(&["-c", "1", "-o", "foo.port:4242"], &["_ws.col.Protocol"]);
    assert_eq!(
        moved,
        ["UDP"],
        "a changed port preference detaches the old one"
    );
    let relabelled = profile.fields(&["-c", "1", "-o", "foo.label:XYZ"], &["_ws.col.Info"]);
    assert_eq!(relabelled, ["XYZ version 7, length 515"]);
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn a_heuristic_claims_only_packets_it_recognises() {
    let profile = Profile::new("heuristic");
    let rows = profile.fields(
        &["-Y", "hbeat"],
        &[
            "frame.number",
            "_ws.col.Protocol",
            "hbeat.seq",
            "hbeat.up",
            "_ws.col.Info",
        ],
    );
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = rows[0].split('\t').collect::<Vec<_>>();
    assert_eq!(row[..3], ["4", "HBEAT", "7"]);
    assert!(
        matches!(row[3], "1" | "True"),
        "hbeat.up is set: {}",
        row[3]
    );
    assert_eq!(row[4], "heartbeat 7 (up)");
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn tcp_messages_are_reassembled_counted_and_named() {
    let profile = Profile::new("stream");
    let rows = profile.fields(
        &["-Y", "lpm"],
        &["frame.number", "lpm.kind", "_ws.col.Info"],
    );
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows[0].starts_with("5\t1,2\t"),
        "two whole messages in frame 5: {}",
        rows[0]
    );
    assert!(
        rows[1].starts_with("6\t1,9\t"),
        "the split hello completes in frame 6: {}",
        rows[1]
    );
    assert!(rows[0].ends_with("message 2: data"), "{}", rows[0]);
    assert!(rows[1].ends_with("message 4: unknown"), "{}", rows[1]);

    let capture = profile.capture();
    let tree = profile.run(&["-r", capture.as_str(), "-V"]);
    assert!(
        tree.contains("Kind: hello (1)"),
        "values name the kind:
{tree}"
    );
    assert!(tree.contains("Kind: data (2)"), "{tree}");
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn an_expert_finding_is_reported_and_filterable() {
    let profile = Profile::new("expert");
    let rows = profile.fields(
        &["-Y", "lpm.unknown_kind"],
        &["frame.number", "_ws.expert.message"],
    );
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].starts_with("6\t"), "{}", rows[0]);
    assert!(rows[0].contains("Unknown message kind 9"), "{}", rows[0]);
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn a_postdissector_sees_every_frame_and_leaves_the_columns() {
    let profile = Profile::new("post");
    let rows = profile.fields(&[], &["frame.len", "fsize.len", "_ws.col.Protocol"]);
    assert_eq!(rows.len(), 6);
    for row in &rows {
        let row = row.split('\t').collect::<Vec<_>>();
        assert_eq!(row[0], row[1], "fsize.len is the frame length");
        assert_ne!(row[2], "FSIZE", "the Protocol column is left alone");
    }
}
