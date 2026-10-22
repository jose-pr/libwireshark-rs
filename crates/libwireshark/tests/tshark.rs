//! The example plugins, loaded by the real tshark against a generated capture.
//!
//! Ignored by default: it needs tshark from the Wireshark release line
//! `libwireshark-sys` was built for. Run it with `cargo test -- --ignored`;
//! `LIBWIRESHARK_TEST_TSHARK` names the executable when it is not on `PATH`
//! or in Wireshark's default Windows location.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A UDP or TCP packet from 192.0.2.1:40000 to 192.0.2.2, in Ethernet.
fn frame(udp: bool, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut transport = Vec::new();
    transport.extend(40000u16.to_be_bytes());
    transport.extend(port.to_be_bytes());
    if udp {
        transport.extend((8 + payload.len() as u16).to_be_bytes());
        transport.extend([0, 0]);
    } else {
        transport.extend([0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0]);
    }
    transport.extend(payload);
    let total = (20 + transport.len()) as u16;
    let mut ip = vec![
        0x45,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        64,
        if udp { 17 } else { 6 },
        0,
        0,
        192,
        0,
        2,
        1,
        192,
        0,
        2,
        2,
    ];
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

fn write_capture(path: &Path) {
    let frames = [
        frame(true, 111, &[7, 1, 2, 3]),
        frame(true, 4242, &[3, 9]),
        frame(false, 4242, &[5, 0, 0]),
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

struct Profile(PathBuf);

impl Profile {
    /// A throwaway home and configuration directory holding the plugins, so
    /// tshark loads them and nothing of the user's.
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("libwireshark-tshark-{}", std::process::id()));
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
            for name in ["basic_dissector", "multi_protocol"] {
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
        Self(root)
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
}

impl Drop for Profile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn tshark_loads_the_example_plugins_and_dissects_their_packets() {
    let profile = Profile::new();
    let capture = profile.0.join("ports.pcap");
    write_capture(&capture);
    let capture = capture.to_str().expect("a UTF-8 temporary path");

    let plugins = profile.run(&["-G", "plugins"]);
    for name in ["basic_dissector", "multi_protocol"] {
        let line = plugins
            .lines()
            .find(|line| line.contains(name))
            .unwrap_or_else(|| panic!("{name} is not loaded:\n{plugins}"));
        assert!(
            line.contains("dissector"),
            "{name} reports its type: {line}"
        );
    }

    let protocols = profile.run(&[
        "-r",
        capture,
        "-T",
        "fields",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "_ws.col.Info",
    ]);
    assert_eq!(
        protocols.lines().collect::<Vec<_>>(),
        [
            "FOO\tFOO version 7, length 515",
            "BAZ\tBAZ version 3, 2 bytes",
            "BAR\tBAR version 5, 3 bytes",
        ]
    );

    let fields = profile.run(&[
        "-r",
        capture,
        "-Y",
        "foo",
        "-T",
        "fields",
        "-e",
        "foo.version",
        "-e",
        "foo.flags",
        "-e",
        "foo.length",
    ]);
    assert_eq!(
        fields.trim(),
        "7\t0x01\t515",
        "the protocol filter matches and its fields nest under it"
    );

    let moved = profile.run(&[
        "-r",
        capture,
        "-o",
        "foo.port:4242",
        "-o",
        "foo.label:XYZ",
        "-T",
        "fields",
        "-e",
        "_ws.col.Protocol",
    ]);
    assert_eq!(
        moved.lines().next(),
        Some("UDP"),
        "a changed port preference detaches the old one"
    );
    let relabelled = profile.run(&[
        "-r",
        capture,
        "-o",
        "foo.label:XYZ",
        "-c",
        "1",
        "-T",
        "fields",
        "-e",
        "_ws.col.Info",
    ]);
    assert_eq!(relabelled.trim(), "XYZ version 7, length 515");
}
