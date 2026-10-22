//! The example plugins, loaded by the real tshark (and sharkd, for the
//! codec) against generated captures.
//!
//! Ignored by default: they need tshark from the Wireshark release line
//! `libwireshark-sys` was built for. Run them with `cargo test -- --ignored`;
//! `LIBWIRESHARK_TEST_TSHARK` and `LIBWIRESHARK_TEST_SHARKD` name the
//! executables when they are not on `PATH` or in Wireshark's default
//! Windows location.

mod harness;

use harness::{Profile, Segment, assert_decodes_l8, capture_time, frame, pcap, since, tshark};

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

/// A profile holding every example plugin and the capture of [`frames`].
fn profile(test: &str) -> Profile {
    let plugins = PLUGINS.map(|(name, kind, _)| (name, kind));
    Profile::new(test, &plugins, &frames())
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

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn tshark_loads_every_example_as_its_kind_of_plugin() {
    let profile = profile("load");
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
    let profile = profile("tables");
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
    let profile = profile("prefs");
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
    let profile = profile("heuristic");
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
    let profile = profile("stream");
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
    let profile = profile("expert");
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
    let profile = profile("post");
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
    let profile = profile("taps");
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
    let profile = profile("filters");
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
    let profile = profile("filetype");
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

#[test]
#[ignore = "needs sharkd from the release line libwireshark-sys was built for"]
fn a_codec_plugin_decodes_rtp_for_sharkd() {
    decodes_rtp_for_sharkd("codec", "L8");
}

#[test]
#[ignore = "needs sharkd from the release line libwireshark-sys was built for"]
fn a_codec_registered_at_run_time_from_epan_decodes_for_sharkd() {
    decodes_rtp_for_sharkd("runtime-codec", "RL8");
}

/// The L8 example codec named `codec`, decoding through sharkd.
fn decodes_rtp_for_sharkd(test: &str, codec: &str) {
    assert_decodes_l8(&profile(test), codec);
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn the_second_pass_is_not_a_first_pass() {
    let profile = profile("twopass");
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
    let profile = profile("runtime");
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
    let moved = profile.fields_of(&capture, &["-o", "rfoo.port:113"], &["_ws.col.Protocol"]);
    assert_eq!(moved, ["UDP"], "dissect_on follows the port preference");
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn a_file_type_registered_at_run_time_from_epan_opens_its_format() {
    let profile = profile("runtime-filetype");
    let mut file = b"RRCAP\0\0\x01".to_vec();
    for (index, frame) in frames().iter().enumerate() {
        let nanos = u64::from(capture_time(index)) * 1_000_000_000;
        file.extend(rscap_record(nanos, frame, frame.len() as u32));
    }
    let file = profile.write("capture.rrcap", &file);
    let fields = [
        "frame.number",
        "frame.time_epoch",
        "_ws.col.Protocol",
        "foo.version",
    ];
    if !since((4, 6)) {
        let output = profile.output(&tshark(), &["-r", &file], "");
        assert!(!output.status.success(), "before 4.6 the format is unknown");
        return;
    }
    assert_eq!(
        profile.fields_of(&file, &[], &fields),
        profile.fields(&[], &fields),
        "the same packets as the pcap"
    );
    assert_eq!(
        profile.fields_of(&file, &["-2"], &fields),
        profile.fields(&[], &fields),
        "the second pass reads each record again"
    );
}

#[test]
#[ignore = "needs tshark from the release line libwireshark-sys was built for"]
fn taps_and_filter_functions_registered_at_run_time_work() {
    let profile = profile("runtime-extras");
    let capture = profile.write(
        "rfoo.pcap",
        &pcap(&[
            frame(&Segment::Udp(112, &[7, 1, 2, 3])),
            frame(&Segment::Udp(112, &[9, 1, 2, 3])),
        ]),
    );
    let report = profile.run(&["-r", capture.as_str(), "-q", "-z", "rtap"]);
    assert!(report.contains("rtap: 2 frames"), "{report}");
    let filtered = profile.output(
        &tshark(),
        &[
            "-r",
            capture.as_str(),
            "-Y",
            "rdouble(rfoo.version) == 14",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        "",
    );
    if !since((4, 4)) {
        assert!(
            String::from_utf8_lossy(&filtered.stderr).contains("does not exist"),
            "before 4.4 the function is not registered"
        );
        return;
    }
    assert_eq!(
        String::from_utf8_lossy(&filtered.stdout).trim(),
        "1",
        "{}",
        String::from_utf8_lossy(&filtered.stderr)
    );
}
