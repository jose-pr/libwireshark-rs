//! The contract a built provider depends on: the kinds' hashes, the C
//! header, the Python classes, and the description's encoding.

use libwireshark_api::engine::{Engine, Session};
use libwireshark_api::guatiao::library::Kind;
use libwireshark_api::guatiao::{FromValue, Map, Schema, ToValue};
use libwireshark_api::{
    Base, Binding, Description, Dissector, Expert, ExpertGroup, Field, FieldType, NamedValue,
    Packet, Preference, PreferenceType, Severity, header_fields, preference_list,
};
use libwireshark_api::{
    CaptureReader, CaptureRecord, CaptureSource, Codec, CodecDescription, Decoder, FileType,
    FileTypeDescription, FilterDescription, FilterFunction, FilterReturn, StreamFormat, Tap,
    TapDescription, TapListener, TapPacket,
};

/// Changing either breaks every provider already built: only in a commit
/// that means to.
const DISSECTOR_FLOOR_HASH: u32 = 1_003_939_949;
const PACKET_FLOOR_HASH: u32 = 2_387_250_941;
const ENGINE_FLOOR_HASH: u32 = 2_496_675_255;
const SESSION_FLOOR_HASH: u32 = 1_680_421_174;

/// Every other kind: its name, its C table and its hash.
fn other_kinds() -> [(&'static str, &'static str, u32, u32); 8] {
    [
        (
            "wireshark_tap",
            "wireshark_tap_vtable",
            floor_hash::<dyn Tap>(),
            2_408_697_858,
        ),
        (
            "wireshark_tap_listener",
            "wireshark_tap_listener_vtable",
            floor_hash::<dyn TapListener>(),
            1_080_358_107,
        ),
        (
            "wireshark_filter_function",
            "wireshark_filter_function_vtable",
            floor_hash::<dyn FilterFunction>(),
            3_420_581_637,
        ),
        (
            "wireshark_file_type",
            "wireshark_file_type_vtable",
            floor_hash::<dyn FileType>(),
            633_579_420,
        ),
        (
            "wireshark_capture_reader",
            "wireshark_capture_reader_vtable",
            floor_hash::<dyn CaptureReader>(),
            2_879_541_183,
        ),
        (
            "wireshark_capture_source",
            "wireshark_capture_source_vtable",
            floor_hash::<dyn CaptureSource>(),
            4_254_949_812,
        ),
        (
            "wireshark_codec",
            "wireshark_codec_vtable",
            floor_hash::<dyn Codec>(),
            3_823_197_131,
        ),
        (
            "wireshark_decoder",
            "wireshark_decoder_vtable",
            floor_hash::<dyn Decoder>(),
            223_420_870,
        ),
    ]
}

#[test]
fn the_other_kinds_hashes_are_pinned_in_rust_c_and_python() {
    let header = shipped("include/libwireshark_api.h");
    let python = shipped("../../bindings/python/src/libwireshark/kinds.py");
    for (kind, table, actual, pinned) in other_kinds() {
        assert_eq!(actual, pinned, "{kind}'s hash");
        assert!(
            header.contains(&format!("#define {table}_FLOOR_HASH {pinned}")),
            "{table} in the header"
        );
        let class = python
            .split("class ")
            .find(|class| class.contains(&format!("kind=\"{kind}\"")))
            .unwrap_or_else(|| panic!("{kind} in the Python classes"));
        assert!(
            class.contains(&format!("floor_hash={pinned}")),
            "{kind}'s hash in the Python classes"
        );
    }
}

#[test]
fn the_other_kinds_models_cross_as_maps() {
    let tap = TapDescription {
        name: "rstap".into(),
        tap: "frame".into(),
    };
    assert_eq!(
        TapDescription::from_map(&tap.to_map().unwrap()).unwrap(),
        tap
    );
    let packet = TapPacket {
        frame: 3,
        len: 60,
        time_ns: 1_700_000_000_000_000_000,
        source: "192.0.2.1".into(),
        destination: "192.0.2.2".into(),
        src_port: 61000,
        dst_port: 113,
    };
    assert_eq!(
        TapPacket::from_map(&packet.to_map().unwrap()).unwrap(),
        packet
    );
    let filter = FilterDescription {
        name: "rs_double".into(),
        returns: FilterReturn::Text,
    };
    let map = filter.to_map().unwrap();
    assert_eq!(texts_of(&map, "returns"), "text");
    assert_eq!(FilterDescription::from_map(&map).unwrap(), filter);
    let format = FileTypeDescription {
        name: "rscap2".into(),
        description: "An example".into(),
        extensions: vec!["rs2".into()],
    };
    assert_eq!(
        FileTypeDescription::from_map(&format.to_map().unwrap()).unwrap(),
        format
    );
    let record = CaptureRecord {
        data: vec![1, 2, 3].into(),
        time_ns: Some(5),
        original_len: None,
    };
    assert_eq!(
        CaptureRecord::from_map(&record.to_map().unwrap()).unwrap(),
        Some(record)
    );
    assert_eq!(
        CaptureRecord::from_map(&Map::new()).unwrap(),
        None,
        "the end"
    );
    let codec = CodecDescription {
        name: "RL16".into(),
    };
    assert_eq!(
        CodecDescription::from_map(&codec.to_map().unwrap()).unwrap(),
        codec
    );
    let stream = StreamFormat {
        sample_rate: Some(8000),
        channels: None,
    };
    assert_eq!(
        StreamFormat::from_map(&stream.to_map().unwrap()).unwrap(),
        stream
    );
}

/// A map's text entry `key`.
fn texts_of(map: &Map, key: &str) -> String {
    String::from_value(map.get(key).expect("the key")).expect("text")
}

fn floor_hash<K: Kind + ?Sized>() -> u32 {
    K::FLOOR_HASH
}

#[test]
fn the_kinds_hashes_are_pinned() {
    assert_eq!(floor_hash::<dyn Dissector>(), DISSECTOR_FLOOR_HASH);
    assert_eq!(floor_hash::<dyn Packet>(), PACKET_FLOOR_HASH);
    assert_eq!(<dyn Dissector as Kind>::NAME, "wireshark_dissector");
    assert_eq!(<dyn Packet as Kind>::NAME, "wireshark_packet");
    assert_eq!(floor_hash::<dyn Engine>(), ENGINE_FLOOR_HASH);
    assert_eq!(floor_hash::<dyn Session>(), SESSION_FLOOR_HASH);
    assert_eq!(<dyn Engine as Kind>::NAME, "wireshark_engine");
    assert_eq!(<dyn Session as Kind>::NAME, "wireshark_session");
}

fn shipped(path: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_c_header_and_the_python_classes_carry_the_same_hashes() {
    let header = shipped("include/libwireshark_api.h");
    let python = shipped("../../bindings/python/src/libwireshark/kinds.py");
    for (table, kind, hash) in [
        (
            "wireshark_dissector_vtable",
            "wireshark_dissector",
            DISSECTOR_FLOOR_HASH,
        ),
        (
            "wireshark_packet_vtable",
            "wireshark_packet",
            PACKET_FLOOR_HASH,
        ),
        (
            "wireshark_engine_vtable",
            "wireshark_engine",
            ENGINE_FLOOR_HASH,
        ),
        (
            "wireshark_session_vtable",
            "wireshark_session",
            SESSION_FLOOR_HASH,
        ),
    ] {
        assert!(
            header.contains(&format!("#define {table}_FLOOR_HASH {hash}")),
            "{table} in the header"
        );
        let class = python
            .split("class ")
            .find(|class| class.contains(&format!("kind=\"{kind}\"")))
            .unwrap_or_else(|| panic!("{kind} in the Python classes"));
        assert!(
            class.contains(&format!("floor_hash={hash}")),
            "{kind}'s hash in the Python classes"
        );
    }
}

#[cfg(feature = "c-header")]
#[test]
fn the_committed_header_is_the_rendered_one() {
    let rendered = std::fs::read_to_string(env!("LIBWIRESHARK_API_GENERATED_HEADER"))
        .expect("the build rendered the header");
    assert_eq!(
        shipped("include/libwireshark_api.h"),
        rendered,
        "regenerate: GUATIAO_WRITE_HEADER=1 cargo build -p libwireshark-api --features c-header"
    );
}

fn foo() -> Description {
    let mut version = Field::new("version", "Version", FieldType::U8);
    version.values = vec![NamedValue {
        value: 7,
        name: "seven".into(),
    }];
    version.base = Some(Base::Dec);
    Description {
        name: "Foo Protocol".into(),
        short_name: "FOO".into(),
        filter_name: "foo".into(),
        header: vec![version, Field::new("length", "Length", FieldType::U16)],
        fields: vec![Field::new("payload", "Payload", FieldType::Bytes)],
        experts: vec![Expert {
            abbrev: "odd".into(),
            group: ExpertGroup::Malformed,
            severity: Severity::Warn,
            summary: "Odd length".into(),
        }],
        preferences: vec![Preference {
            name: "port".into(),
            title: Some("UDP port".into()),
            description: None,
            kind: PreferenceType::Uint,
            default: 113u32.into(),
        }],
        tcp_header_len: Some(2),
    }
}

#[test]
fn a_description_crosses_as_a_map_and_back() {
    let description = foo();
    let map = description.to_map().expect("a description builds");
    assert_eq!(
        Description::from_map(&map).expect("and reads back"),
        description
    );
}

/// The `key` of every map in the list under `list`, as text.
fn texts(map: &Map, list: &str, key: &str) -> Vec<String> {
    let maps = Vec::<Map>::from_value(map.get(list).expect("the list")).expect("maps");
    maps.iter()
        .map(|item| String::from_value(item.get(key).expect("the key")).expect("text"))
        .collect()
}

#[test]
fn the_description_encoding_is_stable_text() {
    let map = foo().to_map().expect("a description builds");
    assert_eq!(texts(&map, "header", "type"), ["u8", "u16"]);
    assert_eq!(texts(&map, "header", "abbrev"), ["version", "length"]);
    assert_eq!(texts(&map, "fields", "type"), ["bytes"]);
    assert_eq!(texts(&map, "preferences", "type"), ["uint"]);
    assert_eq!(texts(&map, "experts", "group"), ["malformed"]);
    assert_eq!(texts(&map, "experts", "severity"), ["warn"]);
}

#[test]
fn a_description_missing_a_name_is_refused_with_the_key() {
    let mut map = foo().to_map().expect("a description builds");
    map.remove("short_name");
    let error = Description::from_map(&map).expect_err("short_name is required");
    assert!(
        error.message().contains("short_name"),
        "{}",
        error.message()
    );
}

#[test]
fn the_description_has_a_schema() {
    Description::schema().expect("the schema builds");
}

/// Every value a Rust enum crosses as, as the map holds it.
fn encoded<T: ToValue>(values: &[T]) -> Vec<String> {
    values
        .iter()
        .map(|value| String::from_value(&value.to_value().expect("encodes")).expect("text"))
        .collect()
}

#[test]
fn the_python_helpers_spell_every_value_as_the_map_does() {
    let python = shipped("../../bindings/python/src/libwireshark/_dissector.py");
    let spellings = [
        encoded(&[
            FieldType::U8,
            FieldType::U16,
            FieldType::U24,
            FieldType::U32,
            FieldType::U64,
            FieldType::I8,
            FieldType::I16,
            FieldType::I24,
            FieldType::I32,
            FieldType::I64,
            FieldType::Bool,
            FieldType::Bytes,
            FieldType::String,
            FieldType::Ipv4,
            FieldType::Ipv6,
            FieldType::Ether,
            FieldType::None,
        ]),
        encoded(&[Base::Dec, Base::Hex, Base::Oct, Base::DecHex, Base::HexDec]),
        encoded(&[
            ExpertGroup::Checksum,
            ExpertGroup::Sequence,
            ExpertGroup::ResponseCode,
            ExpertGroup::RequestCode,
            ExpertGroup::Undecoded,
            ExpertGroup::Reassemble,
            ExpertGroup::Malformed,
            ExpertGroup::Debug,
            ExpertGroup::Protocol,
            ExpertGroup::Security,
            ExpertGroup::Comments,
            ExpertGroup::Decryption,
            ExpertGroup::Assumption,
            ExpertGroup::Deprecated,
        ]),
        encoded(&[
            Severity::Comment,
            Severity::Chat,
            Severity::Note,
            Severity::Warn,
            Severity::Error,
        ]),
    ];
    for spelling in spellings.iter().flatten() {
        assert!(
            python.contains(&format!("= \"{spelling}\"")),
            "{spelling} in the Python package"
        );
    }
}

#[test]
fn bindings_cross_as_a_list_tagged_by_on() {
    let bindings = [
        Binding::udp_port(113),
        Binding::Heuristic { list: "udp".into() },
        Binding::Postdissector,
    ];
    let list = Binding::to_list(&bindings).expect("a list builds");
    let maps = Vec::<Map>::from_value(&list.to_value().expect("a value")).expect("maps");
    let tags = maps
        .iter()
        .map(|map| String::from_value(map.get("on").expect("on")).expect("text"))
        .collect::<Vec<_>>();
    assert_eq!(tags, ["table", "heuristic", "postdissector"]);
    assert_eq!(Binding::from_list(&list).expect("reads back"), bindings);
}

/// A header and preferences as structs, as a Rust provider writes them.
#[derive(Schema, FromValue)]
#[map(crate = ::libwireshark_api::guatiao)]
#[allow(dead_code)]
struct FooHeader {
    /// The protocol version.
    #[schema(title = "Version")]
    version: u8,
    flags: u8,
    length: u16,
    signed: i32,
    big: u64,
    up: bool,
}

#[derive(Schema, FromValue, ToValue)]
#[map(crate = ::libwireshark_api::guatiao)]
struct FooPreferences {
    /// UDP port FOO is decoded on.
    #[schema(title = "UDP port")]
    port: u16,
    verbose: bool,
    label: String,
}

impl Default for FooPreferences {
    fn default() -> Self {
        Self {
            port: 113,
            verbose: true,
            label: "FOO".into(),
        }
    }
}

#[test]
fn a_header_struct_is_laid_out_from_its_types_and_docs() {
    let fields = header_fields::<FooHeader>().expect("integers and bool lay out");
    let kinds = fields.iter().map(|field| field.kind).collect::<Vec<_>>();
    assert_eq!(
        kinds,
        [
            FieldType::U8,
            FieldType::U8,
            FieldType::U16,
            FieldType::I32,
            FieldType::U64,
            FieldType::Bool
        ]
    );
    assert_eq!(fields[0].name, "Version", "the title is the label");
    assert_eq!(fields[1].name, "flags", "else the name");
    assert_eq!(fields[0].blurb.as_deref(), Some("The protocol version."));
}

#[derive(Schema)]
#[map(crate = ::libwireshark_api::guatiao)]
#[allow(dead_code)]
struct WithText {
    name: String,
}

#[test]
fn a_header_field_with_no_width_is_named() {
    let error = header_fields::<WithText>().expect_err("a String has no width");
    assert!(error.message().contains("`name`"), "{}", error.message());
}

#[test]
fn a_preferences_struct_declares_its_defaults_and_docs() {
    let preferences = preference_list::<FooPreferences>().expect("they declare");
    let kinds = preferences.iter().map(|p| p.kind).collect::<Vec<_>>();
    assert_eq!(
        kinds,
        [
            PreferenceType::Uint,
            PreferenceType::Bool,
            PreferenceType::String
        ]
    );
    assert_eq!(preferences[0].title.as_deref(), Some("UDP port"));
    assert_eq!(
        preferences[0].description.as_deref(),
        Some("UDP port FOO is decoded on.")
    );
    assert_eq!(
        u32::from_value(&preferences[0].default).expect("a number"),
        113
    );
    assert_eq!(
        String::from_value(&preferences[2].default).expect("text"),
        "FOO"
    );
}

#[test]
fn the_python_helpers_carry_the_kind_slots() {
    let python = shipped("../../bindings/python/src/libwireshark/kinds.py");
    for slot in [
        "def describe(",
        "def dissect_on(",
        "def dissect(",
        "def message_len(",
    ] {
        assert!(python.contains(slot), "{slot}");
    }
}
