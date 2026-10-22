//! Three protocols that show the other ways Wireshark hands a plugin packets:
//! LPM, length-prefixed messages reassembled from TCP; HBEAT, found by
//! heuristics in UDP; and FSIZE, a post-dissector that sees every frame.

#![forbid(unsafe_code)]

use libwireshark::{
    Binding, DissectResult, Dissector, Expert, ExpertGroup, Header, NoPreferences, PacketView,
    Severity, TcpFraming,
};

/// LPM message kinds, shown by name in the tree and in filters.
const KINDS: &[(u32, &str)] = &[(1, "hello"), (2, "data"), (3, "bye")];

/// An LPM message: a two-byte length (the whole message) and a kind.
#[derive(Header)]
struct Message {
    #[header(name = "Length")]
    length: u16,
    #[header(name = "Kind", values = KINDS)]
    kind: u8,
}

/// How many messages a conversation has carried so far.
#[derive(Default)]
struct Count(u32);

struct Lpm;

impl Dissector for Lpm {
    type Preferences = NoPreferences;
    type Header = Message;

    const NAME: &'static str = "Length-Prefixed Messages";
    const SHORT_NAME: &'static str = "LPM";
    const FILTER_NAME: &'static str = "lpm";
    const EXPERTS: &'static [Expert] = &[Expert::new(
        "unknown_kind",
        ExpertGroup::Protocol,
        Severity::Warning,
        "Unknown message kind",
    )];

    fn dissect_on(_: &NoPreferences) -> Vec<Binding> {
        vec![Binding::tcp_port(47100)]
    }

    fn tcp_framing() -> Option<TcpFraming> {
        Some(TcpFraming::new(2, |header| {
            Some(usize::from(u16::from_be_bytes([header[0], header[1]])))
        }))
    }

    fn dissect(_: &NoPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<Message>> {
        let message = Message::decode(packet.bytes())?;
        let first_pass = packet.is_first_pass();
        let number = packet.with_conversation(|count: &mut Count| {
            if first_pass {
                count.0 += 1;
            }
            count.0
        })?;
        let kind = KINDS
            .iter()
            .find(|(value, _)| *value == u32::from(message.kind))
            .map(|(_, name)| *name);
        if kind.is_none() {
            packet
                .add_expert_text(
                    "unknown_kind",
                    &format!("Unknown message kind {}", message.kind),
                )
                .ok();
        }
        let info = format!("message {number}: {}", kind.unwrap_or("unknown"));
        let size = usize::from(message.length);
        Some(DissectResult::new(message, size).with_info(info))
    }
}

/// An HBEAT heartbeat: the magic `HB`, a sequence number and a status flag.
#[derive(Header)]
struct Heartbeat {
    #[header(name = "Magic")]
    magic: [u8; 2],
    #[header(name = "Sequence")]
    seq: u16,
    #[header(name = "Up")]
    up: bool,
}

struct Hbeat;

impl Dissector for Hbeat {
    type Preferences = NoPreferences;
    type Header = Heartbeat;

    const NAME: &'static str = "HBEAT Heartbeat";
    const SHORT_NAME: &'static str = "HBEAT";
    const FILTER_NAME: &'static str = "hbeat";

    fn dissect_on(_: &NoPreferences) -> Vec<Binding> {
        vec![Binding::heuristic("udp")]
    }

    fn dissect(_: &NoPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<Heartbeat>> {
        let heartbeat = Heartbeat::decode(packet.bytes()).filter(|beat| &beat.magic == b"HB")?;
        let info = format!(
            "heartbeat {} ({})",
            heartbeat.seq,
            if heartbeat.up { "up" } else { "down" }
        );
        Some(DissectResult::new(heartbeat, Heartbeat::SIZE).with_info(info))
    }
}

/// FSIZE's one field: the frame's length.
#[derive(Header)]
struct FrameSize {
    #[header(name = "Frame length")]
    len: u32,
}

struct Fsize;

impl Dissector for Fsize {
    type Preferences = NoPreferences;
    type Header = FrameSize;

    const NAME: &'static str = "FSIZE Frame Size";
    const SHORT_NAME: &'static str = "FSIZE";
    const FILTER_NAME: &'static str = "fsize";

    fn dissect_on(_: &NoPreferences) -> Vec<Binding> {
        vec![Binding::postdissector()]
    }

    fn dissect(_: &NoPreferences, packet: &mut PacketView<'_>) -> Option<DissectResult<FrameSize>> {
        let len = u32::try_from(packet.captured_len()).ok()?;
        Some(DissectResult::new(FrameSize { len }, 0))
    }
}

libwireshark::plugin!(Lpm, Hbeat, Fsize);
