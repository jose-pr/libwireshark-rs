# libwireshark-api

The [guatiao](https://github.com/Boriken-Dev/guatiao) kinds of a Wireshark
plugin written in any language guatiao reaches (Rust, C, Python and more):
the contract between a provider and the `libwireshark-guatiao` host plugin,
which loads providers and registers what they describe with Wireshark.

- `Dissector` (`wireshark_dissector`): a protocol's description, and its
  dissection of each packet.
- `Packet` (`wireshark_packet`): one packet, lent by the host for a call:
  fields, columns, expert findings.
- `Description` and the types it holds: the shape `Dissector::describe`
  answers, as a guatiao map.

The kinds name no Wireshark type, so one provider build serves every
Wireshark release line. C providers fill the tables in
`include/libwireshark_api.h`; Python providers implement the classes in
`python/wireshark_kinds.py`.

```rust
use libwireshark_api::guatiao::library::ProviderError;
use libwireshark_api::guatiao::{Map, Provider};
use libwireshark_api::{Binding, Description, Dissector, Field, FieldType, Packet};

#[derive(Default, Provider)]
#[provider(Dissector, crate = ::libwireshark_api::guatiao)]
struct Foo;

impl Dissector for Foo {
    fn describe(&self) -> Result<Map, ProviderError> {
        Description {
            name: "Foo Protocol".into(),
            short_name: "FOO".into(),
            filter_name: "foo".into(),
            fields: vec![Field::new("version", "Version", FieldType::U8)],
            bindings: vec![Binding::Table { table: "udp.port".into(), value: 113 }],
            ..Description::default()
        }
        .to_map()
    }

    fn dissect(
        &self,
        data: &[u8],
        packet: &mut dyn Packet,
        _conversation: &mut Map,
    ) -> Result<i64, ProviderError> {
        let Some(&version) = data.first() else { return Ok(0) };
        packet.add_uint("version", 0, version.into())?;
        packet.set_info(&format!("FOO version {version}"));
        Ok(data.len() as i64)
    }
}
```

A provider library is then a `cdylib` holding one line,
`libwireshark_api::guatiao::providers!(Foo);`.

License: GPL-2.0-or-later.
