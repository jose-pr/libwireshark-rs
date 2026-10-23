//! A provider's [`Description`] as the protocol libwireshark registers.

use guatiao::{FromValue, Map, Value as Tree};
use libwireshark::dynamic::ProtocolSpec;
use libwireshark::prefs::{Declaration, PreferenceMap, Value};
use libwireshark::{Base, Binding, Expert, ExpertGroup, FieldInfo, FieldType, Severity};
use libwireshark_api as api;
use std::collections::HashMap;
use std::sync::Mutex;

/// Text Wireshark keeps for the process.
pub(crate) fn leak(text: &str) -> &'static str {
    String::from(text).leak()
}

/// `name`, kept for the process, when it is a lower-case letter followed by
/// lower-case letters, digits and `others`; else why not, for a `what`.
pub(crate) fn name(what: &str, name: &str, others: &str) -> Result<&'static str, String> {
    let mut chars = name.chars();
    if chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || others.contains(c))
    {
        Ok(leak(name))
    } else {
        Err(format!(
            "{what} name {name:?}: a lower-case letter, then lower-case letters, digits or {others:?}"
        ))
    }
}

/// The protocol `description` describes: its header fields first, then the
/// rest.
///
/// # Errors
///
/// A preference whose default does not fit its type, by name.
pub(crate) fn protocol(description: &api::Description) -> Result<ProtocolSpec, String> {
    check(description)?;
    let fields = description
        .header
        .iter()
        .chain(&description.fields)
        .map(field)
        .collect();
    let experts = description.experts.iter().map(expert).collect();
    let preferences = description
        .preferences
        .iter()
        .map(preference)
        .collect::<Result<_, _>>()?;
    Ok(ProtocolSpec::new(
        leak(&description.name),
        leak(&description.short_name),
        leak(&description.filter_name),
    )
    .with_fields(fields)
    .with_experts(experts)
    .with_preferences(preferences))
}

/// Refuses what Wireshark would abort the process on, naming it.
fn check(description: &api::Description) -> Result<(), String> {
    if description.name.is_empty() || description.short_name.is_empty() {
        return Err("a protocol needs a name and a short name".into());
    }
    let filter = &description.filter_name;
    let mut chars = filter.chars();
    if !chars.next().is_some_and(|first| first.is_ascii_lowercase())
        || !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
    {
        return Err(format!(
            "filter name {filter:?}: a lower-case letter, then lower-case letters, digits, '-', '_' and '.'"
        ));
    }
    let abbrev_fits = |abbrev: &str| {
        !abbrev.is_empty()
            && !abbrev.starts_with('.')
            && !abbrev.ends_with('.')
            && abbrev
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    };
    for field in description.header.iter().chain(&description.fields) {
        let abbrev = &field.abbrev;
        if !abbrev_fits(abbrev) {
            return Err(format!(
                "field {abbrev:?}: letters, digits, '-', '_' and inner '.'"
            ));
        }
        let integer = field.kind.width().is_some()
            && !matches!(
                field.kind,
                api::FieldType::Ipv4 | api::FieldType::Ipv6 | api::FieldType::Ether
            );
        if field.bitmask.is_some() && !integer {
            return Err(format!(
                "field {abbrev}: a bitmask needs an integer or bool"
            ));
        }
        if field.kind.is_signed() && field.base.is_some_and(|base| base != api::Base::Dec) {
            return Err(format!(
                "field {abbrev}: a signed integer is shown in decimal"
            ));
        }
        if field.base.is_some() && !integer {
            return Err(format!("field {abbrev}: only an integer has a base"));
        }
    }
    for expert in &description.experts {
        if !abbrev_fits(&expert.abbrev) {
            return Err(format!(
                "expert {:?}: letters, digits, '-', '_' and inner '.'",
                expert.abbrev
            ));
        }
    }
    for preference in &description.preferences {
        let name = &preference.name;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(format!(
                "preference {name:?}: lower-case letters, digits and '_'"
            ));
        }
    }
    if description.tcp_header_len == Some(0) {
        return Err("tcp_header_len: a framed message has a header".into());
    }
    Ok(())
}

fn preference(preference: &api::Preference) -> Result<Declaration, String> {
    let default = match preference.kind {
        api::PreferenceType::Bool => bool::from_value(&preference.default).map(Value::Bool),
        api::PreferenceType::Uint => u32::from_value(&preference.default).map(Value::Uint),
        api::PreferenceType::String => String::from_value(&preference.default).map(Value::String),
    }
    .map_err(|error| format!("preference {}: {error}", preference.name))?;
    Ok(Declaration::new(
        leak(&preference.name),
        leak(preference.title.as_deref().unwrap_or(&preference.name)),
        leak(preference.description.as_deref().unwrap_or_default()),
        default,
    ))
}

/// Wireshark's preference values as the map a provider reads.
pub(crate) fn preference_map(values: &PreferenceMap) -> Map {
    let mut map = Map::new();
    for (name, value) in values {
        let value: Tree = match value {
            Value::Bool(value) => (*value).into(),
            Value::Uint(value) => (*value).into(),
            Value::String(value) => value.as_str().into(),
            _ => continue,
        };
        map.set(name, value);
    }
    map
}

fn field(field: &api::Field) -> FieldInfo {
    let mut info = FieldInfo::new(
        leak(&field.name),
        leak(&field.abbrev),
        field_type(field.kind),
    );
    if let Some(base) = field.base {
        info = info.with_base(match base {
            api::Base::Dec => Base::Dec,
            api::Base::Hex => Base::Hex,
            api::Base::Oct => Base::Oct,
            api::Base::DecHex => Base::DecHex,
            api::Base::HexDec => Base::HexDec,
        });
    }
    if let Some(bitmask) = field.bitmask {
        info = info.with_bitmask(bitmask);
    }
    if let Some(blurb) = &field.blurb {
        info = info.with_blurb(leak(blurb));
    }
    if !field.values.is_empty() {
        let values: Vec<(u32, &'static str)> = field
            .values
            .iter()
            .map(|named| (named.value, leak(&named.name)))
            .collect();
        info = info.with_values(values.leak());
    }
    info
}

fn field_type(kind: api::FieldType) -> FieldType {
    match kind {
        api::FieldType::U8 => FieldType::U8,
        api::FieldType::U16 => FieldType::U16,
        api::FieldType::U24 => FieldType::U24,
        api::FieldType::U32 => FieldType::U32,
        api::FieldType::U64 => FieldType::U64,
        api::FieldType::I8 => FieldType::I8,
        api::FieldType::I16 => FieldType::I16,
        api::FieldType::I24 => FieldType::I24,
        api::FieldType::I32 => FieldType::I32,
        api::FieldType::I64 => FieldType::I64,
        api::FieldType::Bool => FieldType::Bool,
        api::FieldType::Bytes => FieldType::Bytes,
        api::FieldType::String => FieldType::String,
        api::FieldType::Ipv4 => FieldType::Ipv4,
        api::FieldType::Ipv6 => FieldType::Ipv6,
        api::FieldType::Ether => FieldType::Ether,
        api::FieldType::None => FieldType::None,
    }
}

fn expert(expert: &api::Expert) -> Expert {
    let group = match expert.group {
        api::ExpertGroup::Checksum => ExpertGroup::Checksum,
        api::ExpertGroup::Sequence => ExpertGroup::Sequence,
        api::ExpertGroup::ResponseCode => ExpertGroup::ResponseCode,
        api::ExpertGroup::RequestCode => ExpertGroup::RequestCode,
        api::ExpertGroup::Undecoded => ExpertGroup::Undecoded,
        api::ExpertGroup::Reassemble => ExpertGroup::Reassemble,
        api::ExpertGroup::Malformed => ExpertGroup::Malformed,
        api::ExpertGroup::Debug => ExpertGroup::Debug,
        api::ExpertGroup::Protocol => ExpertGroup::Protocol,
        api::ExpertGroup::Security => ExpertGroup::Security,
        api::ExpertGroup::Comments => ExpertGroup::Comments,
        api::ExpertGroup::Decryption => ExpertGroup::Decryption,
        api::ExpertGroup::Assumption => ExpertGroup::Assumption,
        api::ExpertGroup::Deprecated => ExpertGroup::Deprecated,
    };
    let severity = match expert.severity {
        api::Severity::Comment => Severity::Comment,
        api::Severity::Chat => Severity::Chat,
        api::Severity::Note => Severity::Note,
        api::Severity::Warn => Severity::Warning,
        api::Severity::Error => Severity::Error,
    };
    Expert::new(leak(&expert.abbrev), group, severity, leak(&expert.summary))
}

/// Table and list names Wireshark keeps, each leaked once however often
/// preferences are applied.
#[derive(Debug, Default)]
pub(crate) struct Names(Mutex<HashMap<String, &'static str>>);

impl Names {
    fn get(&self, name: &str) -> &'static str {
        let mut names = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        names.entry(name.to_owned()).or_insert_with(|| leak(name))
    }

    pub(crate) fn binding(&self, binding: &api::Binding) -> Binding {
        match binding {
            api::Binding::Table { table, value } => Binding::uint(self.get(table), *value),
            api::Binding::Heuristic { list } => Binding::heuristic(self.get(list)),
            api::Binding::Postdissector => Binding::postdissector(),
        }
    }
}
