//! What the tshark tests share: building captures, installing plugins into
//! a throwaway profile and running Wireshark's programs in it.

#![allow(dead_code, reason = "each test binary uses part of it")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Whether the release line the tests were built for is at least `line`.
pub fn since(line: (u32, u32)) -> bool {
    (
        libwireshark::sys::VERSION_MAJOR,
        libwireshark::sys::VERSION_MINOR,
    ) >= line
}

/// The client's port: above every server port here and claimed by no
/// dissector, since TCP and UDP offer a packet to the lower port first.
pub const CLIENT_PORT: u16 = 61000;

/// A transport segment from 192.0.2.1:61000 to 192.0.2.2.
pub enum Segment<'a> {
    Udp(u16, &'a [u8]),
    /// Destination port, sequence number, payload.
    Tcp(u16, u32, &'a [u8]),
}

/// `segment` in IPv4 in Ethernet.
pub fn frame(segment: &Segment<'_>) -> Vec<u8> {
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

/// The capture time of frame `index` (from 0): one per second.
pub fn capture_time(index: usize) -> u32 {
    1_700_000_000 + index as u32
}

/// `frames` as a pcap file.
pub fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend(0xa1b2_c3d4u32.to_le_bytes());
    pcap.extend(2u16.to_le_bytes());
    pcap.extend(4u16.to_le_bytes());
    pcap.extend([0u8; 8]);
    pcap.extend(65535u32.to_le_bytes());
    pcap.extend(1u32.to_le_bytes());
    for (index, frame) in frames.iter().enumerate() {
        pcap.extend(capture_time(index).to_le_bytes());
        pcap.extend(0u32.to_le_bytes());
        pcap.extend((frame.len() as u32).to_le_bytes());
        pcap.extend((frame.len() as u32).to_le_bytes());
        pcap.extend(frame);
    }
    pcap
}

/// A Wireshark program: from `variable`, Wireshark's default Windows
/// location, or `PATH`.
pub fn program(variable: &str, name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(variable) {
        return PathBuf::from(path);
    }
    let windows = Path::new(r"C:\Program Files\Wireshark").join(format!("{name}.exe"));
    if windows.is_file() {
        return windows;
    }
    PathBuf::from(name)
}

pub fn tshark() -> PathBuf {
    program("LIBWIRESHARK_TEST_TSHARK", "tshark")
}

/// A built example plugin, beside this test binary.
pub fn plugin(name: &str) -> PathBuf {
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
pub struct Profile {
    root: PathBuf,
    env: Vec<(String, String)>,
}

impl Profile {
    /// A profile holding `plugins` (built library name, plugin directory
    /// kind) and a capture of `frames`.
    pub fn new(test: &str, plugins: &[(&str, &str)], frames: &[Vec<u8>]) -> Self {
        let root =
            std::env::temp_dir().join(format!("libwireshark-tshark-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the profile directory");
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
            for &(name, kind) in plugins {
                let directory = base.join(&version).join(kind);
                std::fs::create_dir_all(&directory).expect("create the plugin directory");
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
        std::fs::write(root.join("capture.pcap"), pcap(frames)).expect("write the capture");
        Self {
            root,
            env: Vec::new(),
        }
    }

    /// The profile's directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The same profile, running every program with `name` set to `value`.
    #[must_use]
    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The path of `name` in the profile.
    pub fn file(&self, name: &str) -> String {
        self.root
            .join(name)
            .to_str()
            .expect("a UTF-8 temporary path")
            .to_owned()
    }

    /// Writes `contents` to `name` in the profile; returns its path.
    pub fn write(&self, name: &str, contents: &[u8]) -> String {
        std::fs::write(self.root.join(name), contents).expect("write a file");
        self.file(name)
    }

    pub fn capture(&self) -> String {
        self.file("capture.pcap")
    }

    /// `program` run in this profile, with `input` on its standard input.
    pub fn output(&self, program: &Path, args: &[&str], input: &str) -> Output {
        let mut child = Command::new(program)
            .args(args)
            .env("WIRESHARK_CONFIG_DIR", &self.root)
            .env("HOME", &self.root)
            .envs(self.env.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("run {}: {error}", program.display()));
        child
            .stdin
            .take()
            .expect("a piped standard input")
            .write_all(input.as_bytes())
            .expect("write the standard input");
        child.wait_with_output().expect("wait for the program")
    }

    pub fn run(&self, args: &[&str]) -> String {
        let output = self.output(&tshark(), args, "");
        assert!(
            output.status.success(),
            "tshark {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
    }

    /// `fields` of each frame of the capture, tab-separated, one line per frame.
    pub fn fields(&self, extra: &[&str], fields: &[&str]) -> Vec<String> {
        self.fields_of(&self.capture(), extra, fields)
    }

    /// `fields` of each frame of the capture `file`.
    pub fn fields_of(&self, file: &str, extra: &[&str], fields: &[&str]) -> Vec<String> {
        let mut args = vec!["-r", file];
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
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The base64 standard alphabet's value of `byte`.
fn base64_value(byte: u8) -> Option<u32> {
    let value = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

fn base64_decode(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let values = text.bytes().filter_map(base64_value).collect::<Vec<_>>();
    for chunk in values.chunks(4) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0, |word, (index, value)| word | value << (18 - 6 * index));
        let word = word.to_be_bytes();
        bytes.extend(&word[1..chunk.len()]);
    }
    bytes
}

/// Asserts that sharkd, in `profile`, decodes an RTP stream whose SDP names
/// `codec` as the L8 encoding: each byte less 128, scaled to 16 bits.
pub fn assert_decodes_l8(profile: &Profile, codec: &str) {
    // SDP names payload type 96 `codec` at 8 kHz for RTP to 192.0.2.2:47200.
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
         m=audio 47200 RTP/AVP 96\r\na=rtpmap:96 {codec}/8000\r\n"
    );
    let invite = format!(
        "INVITE sip:bob@192.0.2.2 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:61000;branch=z9hG4bK1\r\n\
         From: <sip:alice@192.0.2.1>;tag=1\r\n\
         To: <sip:bob@192.0.2.2>\r\n\
         Call-ID: 1@192.0.2.1\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{sdp}",
        sdp.len()
    );
    let rtp = |sequence: u16, payload: &[u8]| {
        let mut packet = vec![0x80, 96];
        packet.extend(sequence.to_be_bytes());
        packet.extend((u32::from(sequence) * 160).to_be_bytes());
        packet.extend(0x1122_3344u32.to_be_bytes());
        packet.extend(payload);
        packet
    };
    let frames = [
        frame(&Segment::Udp(5060, invite.as_bytes())),
        frame(&Segment::Udp(47200, &rtp(1, &[128, 255, 0, 192]))),
        frame(&Segment::Udp(47200, &rtp(2, &[64, 129]))),
    ];
    let capture = profile.write("rtp.pcap", &pcap(&frames));
    let requests = format!(
        "{}\n{}\n",
        format_args!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"load","params":{{"file":{capture:?}}}}}"#
        ),
        r#"{"jsonrpc":"2.0","id":2,"method":"download","params":{"token":"rtp:192.0.2.1_61000_192.0.2.2_47200_11223344"}}"#,
    );
    let output = profile.output(
        &program("LIBWIRESHARK_TEST_SHARKD", "sharkd"),
        &["-"],
        &requests,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let data = stdout
        .lines()
        .find(|line| line.contains(r#""id":2"#))
        .and_then(|line| line.split_once(r#""data":""#))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(data, _)| data)
        .unwrap_or_else(|| {
            panic!(
                "no decoded audio:\n{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    let wav = base64_decode(data);
    assert_eq!(&wav[..4], b"RIFF", "a WAV file");
    assert_eq!(
        u32::from_le_bytes(wav[24..28].try_into().unwrap()),
        8000,
        "the rate the codec reported"
    );
    let samples = wav[44..]
        .chunks(2)
        .map(|sample| i16::from_le_bytes([sample[0], sample[1]]))
        .collect::<Vec<_>>();
    assert_eq!(
        samples,
        [0, 127 << 8, -128 << 8, 64 << 8, -64 << 8, 1 << 8],
        "each byte less 128, scaled to 16 bits"
    );
}
