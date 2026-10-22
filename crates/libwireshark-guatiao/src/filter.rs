//! Display-filter functions from providers.

use crate::describe;
use crate::host::{report, served};
use alloc::sync::Arc;
use guatiao::{FromValue, Value};
use libwireshark::FieldValue;
use libwireshark::dynamic::{DynamicFilterFunction, FilterFunction, FilterReturn, FilterValue};
use libwireshark_api::{self as api, FilterDescription};
use std::collections::HashSet;

/// Every display-filter function offered; a name taken earlier is skipped.
pub(crate) fn functions(registry: &guatiao::library::Registry) -> Vec<FilterFunction> {
    let mut names = HashSet::new();
    let mut functions = Vec::new();
    for (key, function) in served::<dyn api::FilterFunction>(registry) {
        let description = match function
            .describe()
            .and_then(|map| FilterDescription::from_map(&map))
        {
            Ok(description) => description,
            Err(error) => {
                report(true, &format!("{key}: describe: {}", error.message()));
                continue;
            }
        };
        let name = match describe::name("filter function", &description.name, "_") {
            Ok(name) => name,
            Err(error) => {
                report(true, &format!("{key}: {error}"));
                continue;
            }
        };
        if !names.insert(name) {
            report(
                true,
                &format!("{key}: the function {name} is offered already"),
            );
            continue;
        }
        let returns = match description.returns {
            api::FilterReturn::Count => FilterReturn::Count,
            api::FilterReturn::Text => FilterReturn::Text,
        };
        report(
            false,
            &format!("{key} is the display-filter function {name}"),
        );
        functions.push(FilterFunction::new(
            name,
            returns,
            Provided {
                key: describe::leak(&key),
                function,
                returns,
            },
        ));
    }
    functions
}

/// One provider's function, as libwireshark calls it.
struct Provided {
    key: &'static str,
    function: Arc<dyn api::FilterFunction>,
    returns: FilterReturn,
}

impl DynamicFilterFunction for Provided {
    fn call(&self, value: &FieldValue<'_>) -> Option<FilterValue> {
        let argument = match (value.as_u64(), value.as_i64()) {
            (Some(number), _) => Value::from(number),
            (None, Some(number)) => Value::from(number),
            (None, None) => Value::from(value.to_text().as_str()),
        };
        let answer = match self.function.call(&argument) {
            Ok(answer) => answer,
            Err(error) => {
                report(true, &format!("{}: call: {}", self.key, error.message()));
                return None;
            }
        };
        match self.returns {
            FilterReturn::Count => u32::from_value(&answer).ok().map(FilterValue::Count),
            FilterReturn::Text => String::from_value(&answer).ok().map(FilterValue::Text),
        }
    }
}
