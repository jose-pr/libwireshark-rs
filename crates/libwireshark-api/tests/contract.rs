//! The contract a built provider depends on: the kinds' hashes, the C
//! header, the Python classes, and the description's encoding.

use libwireshark_api::guatiao::library::Kind;
use libwireshark_api::guatiao::{FromValue, Map, Schema};
use libwireshark_api::{
    Base, Binding, Description, Dissector, Expert, ExpertGroup, Field, FieldType, NamedValue,
    Packet, Severity,
};

/// Changing either breaks every provider already built: only in a commit
/// that means to.
const DISSECTOR_FLOOR_HASH: u32 = 3_883_230_505;
const PACKET_FLOOR_HASH: u32 = 2_387_250_941;

fn floor_hash<K: Kind + ?Sized>() -> u32 {
    K::FLOOR_HASH
}

#[test]
fn the_kinds_hashes_are_pinned() {
    assert_eq!(floor_hash::<dyn Dissector>(), DISSECTOR_FLOOR_HASH);
    assert_eq!(floor_hash::<dyn Packet>(), PACKET_FLOOR_HASH);
    assert_eq!(<dyn Dissector as Kind>::NAME, "wireshark_dissector");
    assert_eq!(<dyn Packet as Kind>::NAME, "wireshark_packet");
}

fn shipped(path: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_c_header_and_the_python_classes_carry_the_same_hashes() {
    let header = shipped("include/libwireshark_api.h");
    let python = shipped("python/wireshark_kinds.py");
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
    ] {
        assert!(
            header.contains(&format!("#define {table}_FLOOR_HASH {hash}")),
            "{table} in the header"
        );
        assert!(
            python.contains(&format!("kind=\"{kind}\", floor_hash={hash}")),
            "{kind} in the Python classes"
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
        fields: vec![version, Field::new("length", "Length", FieldType::U16)],
        experts: vec![Expert {
            abbrev: "odd".into(),
            group: ExpertGroup::Malformed,
            severity: Severity::Warn,
            summary: "Odd length".into(),
        }],
        bindings: vec![
            Binding::Table {
                table: "udp.port".into(),
                value: 113,
            },
            Binding::Heuristic { list: "udp".into() },
            Binding::Postdissector,
        ],
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
    assert_eq!(texts(&map, "fields", "type"), ["u8", "u16"]);
    assert_eq!(texts(&map, "fields", "abbrev"), ["version", "length"]);
    assert_eq!(
        texts(&map, "bindings", "on"),
        ["table", "heuristic", "postdissector"]
    );
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
