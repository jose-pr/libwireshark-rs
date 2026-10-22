//! The engine dissecting with the example plugins, in this process.
//!
//! Ignored by default: it needs Wireshark's libraries from the release line
//! libwireshark-sys was built for, on the library path (on Windows, its
//! installation directory on `PATH`). Wireshark starts once per process, so
//! this binary holds one test.

#[path = "../../libwireshark/tests/harness/mod.rs"]
mod harness;

use core::time::Duration;
use harness::{Profile, Segment, frame, plugin};
use libwireshark_engine::{Dissected, Encapsulation, Engine, EngineConfig, EngineError};

fn frames() -> Vec<Vec<u8>> {
    vec![
        frame(&Segment::Udp(111, &[7, 1, 2, 3])),
        frame(&Segment::Udp(4242, &[3, 9])),
        frame(&Segment::Udp(111, &[9, 1, 0, 4])),
    ]
}

fn column<'a>(dissected: &'a Dissected, title: &str) -> &'a str {
    dissected
        .columns
        .iter()
        .find(|column| column.title == title)
        .map_or("", |column| column.text.as_str())
}

fn value<'a>(dissected: &'a Dissected, abbrev: &str) -> Option<&'a str> {
    dissected.get(abbrev)?.value.as_deref()
}

#[test]
#[ignore = "needs Wireshark's libraries from the release line libwireshark-sys was built for"]
fn the_engine_dissects_frames_and_captures_with_the_plugins_it_loads() {
    let frames = frames();
    let profile = Profile::new("engine", &[], &frames);
    let config = EngineConfig {
        plugins: ["basic_dissector", "multi_protocol"]
            .map(|name| plugin(name).to_string_lossy().into_owned())
            .to_vec(),
        skip_installed_plugins: true,
        config_dir: Some(profile.root().to_string_lossy().into_owned()),
        ..EngineConfig::default()
    };
    let engine = match Engine::open(&config) {
        Err(EngineError::Unsupported) => {
            eprintln!("skipped: no engine before Wireshark 4.6");
            return;
        }
        result => result.expect("the engine starts"),
    };
    session(engine, &config, &frames, &profile);
    assert_eq!(
        Engine::open(&EngineConfig::default()).err(),
        Some(EngineError::Configured),
        "Wireshark starts once per process"
    );
    let mut again = Engine::open(&config).expect("the same configuration opens again");
    let first = again
        .dissect(&frames[0], Encapsulation::ETHERNET, Duration::ZERO)
        .expect("a frame dissects");
    assert_eq!(first.frame, 1, "a new session counts from 1");
}

/// The first session: it closes when `engine` drops, at the end.
fn session(mut engine: Engine, config: &EngineConfig, frames: &[Vec<u8>], profile: &Profile) {
    assert_eq!(
        Engine::open(config).err(),
        Some(EngineError::AlreadyOpen),
        "one session at a time"
    );

    let first = engine
        .dissect(
            &frames[0],
            Encapsulation::ETHERNET,
            Duration::from_secs(1_700_000_000),
        )
        .expect("a frame dissects");
    assert_eq!(first.frame, 1);
    assert_eq!(value(&first, "foo.version"), Some("7"));
    assert_eq!(value(&first, "foo.length"), Some("515"));
    assert_eq!(value(&first, "ip.dst"), Some("192.0.2.2"));
    assert_eq!(column(&first, "Protocol"), "FOO");
    assert_eq!(column(&first, "Info"), "FOO version 7, length 515");
    let protocol = first.get("foo").expect("the protocol's own item");
    assert!(
        protocol
            .children
            .iter()
            .any(|child| child.abbrev == "foo.flags"),
        "fields nest under their protocol: {protocol:?}"
    );

    let second = engine
        .dissect(
            &frames[1],
            Encapsulation::ETHERNET,
            Duration::from_secs(1_700_000_001),
        )
        .expect("a frame dissects");
    assert_eq!(second.frame, 2, "frames count on within a session");
    assert_eq!(column(&second, "Protocol"), "BAZ");

    let read = engine
        .read(profile.capture().as_ref(), Some("foo"))
        .expect("the capture opens")
        .collect::<Result<Vec<_>, _>>()
        .expect("the capture reads");
    assert_eq!(
        read.iter()
            .map(|frame| (frame.frame, value(frame, "foo.version")))
            .collect::<Vec<_>>(),
        [(1, Some("7")), (3, Some("9"))],
        "a file starts the count over, and the filter keeps FOO frames"
    );

    assert!(matches!(
        engine.read(profile.capture().as_ref(), Some("foo ==")),
        Err(EngineError::Filter(_))
    ));
    assert!(matches!(
        engine.read(profile.root().join("missing.pcap").as_ref(), None),
        Err(EngineError::File(_))
    ));
}
