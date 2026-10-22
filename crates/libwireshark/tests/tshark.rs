//! The example plugins, loaded by the real tshark (and sharkd, for the
//! codec) against generated captures.
//!
//! Ignored by default: they need tshark from the Wireshark release line
//! `libwireshark-sys` was built for. Run them with `cargo test -- --ignored`;
//! `LIBWIRESHARK_TEST_TSHARK` and `LIBWIRESHARK_TEST_SHARKD` name the
//! executables when they are not on `PATH` or in Wireshark's default
//! Windows location.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Each example plugin, the directory Wireshark loads it from, and what
/// `-G plugins` reports it as.
const PLUGINS: [(&str, &str, &str); 6] = [
    ("basic_dissector", "epan", "dissector"),
    ("multi_protocol", "epan", "dissector"),
    ("stream_protocol", "epan", "dissector"),
    ("runtime_protocol", "epan", "dissector"),
    ("capture_file", "wiretap", "file type"),
    ("audio_codec", "codecs", "codec"),
];

/// Whether the release line the tests were built for is at least `line`.
fn since(line: (u32, u32)) -> bool {
    (
        libwireshark::sys::VERSION_MAJOR,
        libwireshark::sys::VERSION_MINOR,
    ) >= line
}

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

/// The frames of the capture most tests read:
///
/// 1. UDP/111: FOO version 7, flags 1, length 515 (basic-dissector)
/// 2. UDP/4242: BAZ (multi-protocol)
/// 3. TCP/4242: BAR (multi-protocol)
/// 4. UDP/47100: an HBEAT heartbeat, found by heuristics (stream-protocol)
/// 5. TCP/47100: LPM hello, data, and the first two bytes of a third message
/// 6. TCP/47100: the rest of that hello, then a message of unknown kind 9
fn frames() -> Vec<Vec<u8>> {
    let first = [0, 5, 1, b'a', b'b', 0, 4, 2, b'c', 0, 6];
    let second = [1, b'x', b'y', b'z', 0, 4, 9, b'q'];
    vec![
        frame(&Segment::Udp(111, &[7, 1, 2, 3])),
        frame(&Segment::Udp(4242, &[3, 9])),
        frame(&Segment::Tcp(4242, 1, &[5, 0, 0])),
        frame(&Segment::Udp(47100, b"HB\x00\x07\x01")),
        frame(&Segment::Tcp(47100, 1, &first)),
        frame(&Segment::Tcp(47100, 1 + first.len() as u32, &second)),
    ]
}

/// The capture time of frame `index` (from 0): one per second.
fn capture_time(index: usize) -> u32 {
    1_700_000_000 + index as u32
}

/// `frames` as a pcap file.
fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
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

/// One record of the capture-file example's RSCAP format.
fn rscap_record(nanos: u64, frame: &[u8], original: u32) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend(nanos.to_le_bytes());
    record.extend((frame.len() as u32).to_le_bytes());
    record.extend(original.to_le_bytes());
    record.extend(frame);
    record
}

/// `frames` as an RSCAP file, with the times `pcap` gives them.
fn rscap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut file = b"RSCAP\0\0\x01".to_vec();
    for (index, frame) in frames.iter().enumerate() {
        let nanos = u64::from(capture_time(index)) * 1_000_000_000;
        file.extend(rscap_record(nanos, frame, frame.len() as u32));
    }
    file
}

/// A Wireshark program: from `variable`, Wireshark's default Windows
/// location, or `PATH`.
fn program(variable: &str, name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(variable) {
        return PathBuf::from(path);
    }
    let windows = Path::new(r"C:\Program Files\Wireshark").join(format!("{name}.exe"));
    if windows.is_file() {
        return windows;
    }
    PathBuf::from(name)
}

fn tshark() -> PathBuf {
    program("LIBWIRESHARK_TEST_TSHARK", "tshark")
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
            for (name, kind, _) in PLUGINS {
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
        std::fs::write(root.join("capture.pcap"), pcap(&frames())).expect("write the capture");
        Self(root)
    }

    /// The path of `name` in the profile.
    fn file(&self, name: &str) -> String {
        self.0
            .join(name)
            .to_str()
            .expect("a UTF-8 temporary path")
            .to_owned()
    }

    /// Writes `contents` to `name` in the profile; returns its path.
    fn write(&self, name: &str, contents: &[u8]) -> String {
        std::fs::write(self.0.join(name), contents).expect("write a file");
        self.file(name)
    }

    fn capture(&self) -> String {
        self.file("capture.pcap")
    }

    /// `program` run in this profile, with `input` on its standard input.
    fn output(&self, program: &Path, args: &[&str], input: &str) -> Output {
        let mut child = Command::new(program)
            .args(args)
            .env("WIRESHARK_CONFIG_DIR", &self.0)
            .env("HOME", &self.0)
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

    fn run(&self, args: &[&str]) -> String {
        let output = self.output(&tshark(), args, "");
        assert!(
            output.status.success(),
            "tshark {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
    }

    /// `fields` of each frame of the capture, tab-separated, one line per frame.
    fn fields(&self, extra: &[&str], fields: &[&str]) -> Vec<String> {
        self.fields_of(&self.capture(), extra, fields)
    }

    /// `fields` of each frame of the capture `file`.
    fn fields_of(&self, file: &str, extra: &[&str], fields: &[&str]) -> Vec<String> {
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
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn tshark_loads_every_example_as_its_kind_of_plugin() {
    let profile = Profile::new("load");
    let plugins = profile.run(&["-G", "plugins"]);
    for (name, _, kind) in PLUGINS {
        let line = plugins
            .lines()
            .find(|line| line.contains(name))
            .unwrap_or_else(|| panic!("{name} is not loaded:\n{plugins}"));
        assert!(line.contains(kind), "{name} reports its type: {line}");
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

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn taps_report_statistics_over_a_plugins_own_and_wiresharks_taps() {
    let profile = Profile::new("taps");
    let capture = profile.capture();
    let lpm = profile.run(&["-r", capture.as_str(), "-q", "-z", "lpmstats"]);
    for line in ["LPM messages by kind", "data: 1", "hello: 2", "unknown: 1"] {
        assert!(lpm.contains(line), "{line:?} in:\n{lpm}");
    }
    let udp = profile.run(&["-r", capture.as_str(), "-q", "-z", "udpbytes"]);
    assert!(udp.contains("UDP: 3 packets"), "{udp}");
    let filtered = profile.run(&[
        "-r",
        capture.as_str(),
        "-q",
        "-z",
        "udpbytes,udp.port==4242",
    ]);
    assert!(
        filtered.contains("UDP: 1 packets"),
        "the -z filter applies: {filtered}"
    );
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn filter_functions_work_in_display_filters_from_4_4() {
    let profile = Profile::new("filters");
    let capture = profile.capture();
    let output = profile.output(
        &tshark(),
        &[
            "-r",
            capture.as_str(),
            "-Y",
            r#"port_class(udp.dstport) == "well-known""#,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        "",
    );
    if !since((4, 4)) {
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("does not exist"),
            "before 4.4 the function is not registered"
        );
        return;
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "1",
        "port 111 is well-known"
    );
    let digits = profile.fields(&["-Y", "digits(udp.dstport) == 4"], &["frame.number"]);
    assert_eq!(digits, ["2"], "4242 has four digits");
    let literal = profile.output(
        &tshark(),
        &["-r", capture.as_str(), "-Y", r#"port_class("x") == "y""#],
        "",
    );
    assert!(!literal.status.success(), "a literal argument is refused");
    assert!(
        String::from_utf8_lossy(&literal.stderr).contains("Only fields"),
        "{}",
        String::from_utf8_lossy(&literal.stderr)
    );
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn a_file_type_plugin_opens_its_format_from_4_6() {
    let profile = Profile::new("filetype");
    let file = profile.write("capture.rscap", &rscap(&frames()));
    let fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "_ws.col.Protocol",
        "foo.version",
        "hbeat.seq",
        "lpm.kind",
    ];
    if !since((4, 6)) {
        let output = profile.output(&tshark(), &["-r", &file], "");
        assert!(!output.status.success(), "before 4.6 the format is unknown");
        return;
    }
    let expected = profile.fields(&[], &fields);
    assert_eq!(
        profile.fields_of(&file, &[], &fields),
        expected,
        "the same packets as the pcap, dissected by the other plugins"
    );
    assert_eq!(
        profile.fields_of(&file, &["-2"], &fields),
        expected,
        "the second pass reads each record again from its offset"
    );

    let first = &frames()[0];
    let mut detailed = b"RSCAP\0\0\x01".to_vec();
    detailed.extend(rscap_record(
        1_700_000_000_123_456_789,
        first,
        first.len() as u32 + 100,
    ));
    let detailed = profile.write("detailed.rscap", &detailed);
    assert_eq!(
        profile.fields_of(
            &detailed,
            &[],
            &["frame.time_epoch", "frame.len", "frame.cap_len"]
        ),
        [format!(
            "1700000000.123456789\t{}\t{}",
            first.len() + 100,
            first.len()
        )],
        "nanosecond times and the length on the wire"
    );

    let mut truncated = rscap(&frames());
    truncated.truncate(truncated.len() - 3);
    let truncated = profile.write("truncated.rscap", &truncated);
    let output = profile.output(&tshark(), &["-r", &truncated], "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cut short"),
        "a record past the end is a short read: {stderr}"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).lines().count(),
        5,
        "the whole records before it are read"
    );

    let mut corrupt = b"RSCAP\0\0\x01".to_vec();
    corrupt.extend(rscap_record(0, first, 0));
    let corrupt = profile.write("corrupt.rscap", &corrupt);
    let output = profile.output(&tshark(), &["-r", &corrupt], "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("rscap: record of"),
        "an InvalidData error carries its message: {stderr}"
    );
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

#[test]
#[ignore = "needs sharkd from the release line libwireshark-sys was built for"]
fn a_codec_plugin_decodes_rtp_for_sharkd() {
    let profile = Profile::new("codec");
    // SDP names payload type 96 L8 at 8 kHz for RTP to 192.0.2.2:47200.
    let sdp = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
               m=audio 47200 RTP/AVP 96\r\na=rtpmap:96 L8/8000\r\n";
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

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn the_second_pass_is_not_a_first_pass() {
    let profile = Profile::new("twopass");
    // LPM counts messages only on the first pass, so the second shows each
    // conversation's final count.
    let rows = profile.fields(&["-2", "-Y", "lpm"], &["frame.number", "_ws.col.Info"]);
    assert_eq!(
        rows,
        [
            "5\tmessage 4: data",
            "6\tmessage 4: hellomessage 4: unknown",
        ],
    );
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn a_protocol_described_at_run_time_dissects_like_a_static_one() {
    let profile = Profile::new("runtime");
    let capture = profile.write(
        "rfoo.pcap",
        &pcap(&[frame(&Segment::Udp(112, &[7, 1, 2, 3]))]),
    );
    let rows = profile.fields_of(
        &capture,
        &["-Y", "rfoo"],
        &[
            "_ws.col.Protocol",
            "rfoo.version",
            "rfoo.length",
            "_ws.col.Info",
        ],
    );
    assert_eq!(rows, ["RFOO	7	515	RFOO version 7, length 515"]);
}
