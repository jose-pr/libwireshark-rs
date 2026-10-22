# libwireshark-api

The [guatiao](https://github.com/Boriken-Dev/guatiao) kinds of a Wireshark
plugin written in any language guatiao reaches (Rust, C, Python and more):
the contract between a provider and the `libwireshark-guatiao` host plugin,
which loads providers and registers what they describe with Wireshark.

- `Dissector` (`wireshark_dissector`): a protocol's description, where it
  gets packets for given preference values (`dissect_on`), and its
  dissection of each packet.
- `Packet` (`wireshark_packet`): one packet, lent by the host for a call:
  fields, columns, expert findings.
- `Description` and the types it holds: the shape `describe` answers.
- `engine::Engine` and `engine::Session` (`wireshark_engine`,
  `wireshark_session`): the other direction, which `libwireshark-engine`
  provides — a host opens Wireshark's engine and dissects with it.

A protocol is written in each language as `libwireshark`'s `Dissector` is
in Rust: its **header** is a struct, laid out field by field, which the
host decodes for `dissect` and adds to the tree; its **preferences** are a
struct whose defaults and doc strings Wireshark shows, and which
`dissect_on` and `dissect` receive filled in. The kinds name no Wireshark
type, so one provider build serves every Wireshark release line.

## Rust

Implement `ProtocolDissector`, then write `dissector!` for the type:

```rust
use libwireshark_api::guatiao::library::ProviderError;
use libwireshark_api::guatiao::{self, FromValue, Map, Provider, Schema, ToValue};
use libwireshark_api::{Binding, Packet, ProtocolDissector};

/// FOO's header: field names are the abbreviations, doc comments the blurbs.
#[derive(Schema, FromValue)]
#[map(crate = ::libwireshark_api::guatiao)]
struct FooHeader {
    /// The protocol version.
    #[schema(title = "Version")]
    version: u8,
    flags: u8,
    length: u16,
}

/// FOO's preferences: doc comments are their descriptions.
#[derive(Schema, FromValue, ToValue)]
#[map(crate = ::libwireshark_api::guatiao)]
struct FooPreferences {
    /// UDP port FOO is decoded on.
    #[schema(title = "UDP port")]
    port: u16,
}

impl Default for FooPreferences {
    fn default() -> Self {
        Self { port: 113 }
    }
}

#[derive(Default, Provider)]
#[provider(libwireshark_api::Dissector, crate = ::libwireshark_api::guatiao)]
struct Foo;

impl ProtocolDissector for Foo {
    const NAME: &'static str = "Foo Protocol";
    const SHORT_NAME: &'static str = "FOO";
    const FILTER_NAME: &'static str = "foo";
    type Header = FooHeader;
    type Preferences = FooPreferences;

    fn dissect_on(&self, preferences: &FooPreferences) -> Vec<Binding> {
        vec![Binding::udp_port(preferences.port)]
    }

    fn dissect(
        &self,
        data: &[u8],
        header: &FooHeader,
        _preferences: &FooPreferences,
        packet: &mut dyn Packet,
        _conversation: &mut Map,
    ) -> Result<i64, ProviderError> {
        packet.set_info(&format!("FOO version {}", header.version));
        Ok(data.len() as i64)
    }
}

libwireshark_api::dissector!(Foo);
// In the provider's cdylib: guatiao::providers!(Foo);
```

## Python

The [`libwireshark` Python package](../../bindings/python) (in
`bindings/python`): subclass its `ProtocolDissector`; the header and the
preferences are annotated classes, the string under an attribute its blurb
or description, and expert findings are `Expert` subclasses
(`libwireshark.kinds` holds the kinds themselves):

```python
class FooHeader(Header):
    version: Annotated[U8, Meta(name="Version", values={7: "seven"})]
    "The protocol version"

    flags: Annotated[U8, Meta(base=Base.HEX)]
    length: U16


class FooPreferences(Preferences):
    port: Annotated[int, Meta(title="UDP port")] = 113
    "UDP port FOO is decoded on"


class UnknownVersion(Expert):
    "Unknown version"

    GROUP = ExpertGroup.MALFORMED
    SEVERITY = Severity.WARN


class Foo(provide.Provider, ProtocolDissector):
    NAME = "Foo Protocol"
    SHORT_NAME = "FOO"
    FILTER_NAME = "foo"
    HEADER = FooHeader
    PREFERENCES = FooPreferences
    EXPERTS = [UnknownVersion]

    def dissect_on(self, preferences: FooPreferences) -> List[Binding]:
        return [Table.udp_port(preferences.port)]

    def dissect(self, data: bytes, header: FooHeader, preferences: FooPreferences,
                packet: TypedPacket, conversation: Map) -> int:
        if header.version != 7:
            packet.add_expert(UnknownVersion())   # or UnknownVersion("its own text")
        packet.set_info(f"FOO version {header.version}")
        return len(data)
```

## C

Fill the tables in `include/libwireshark_api.h`; the description and the
bindings can be literal trees (`GUATIAO_VALUE_MAP_LIT` and friends), and
`dissect` reads the decoded header from the map it is given.

License: GPL-2.0-or-later.
