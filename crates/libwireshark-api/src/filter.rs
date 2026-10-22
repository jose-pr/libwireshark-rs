//! Display-filter functions: `name(field)` in a display filter, from
//! Wireshark 4.4.

use alloc::string::String;
use guatiao::library::ProviderError;
use guatiao::{FromValue, Map, Schema, ToValue, Value};

/// A display-filter function: `wireshark_filter_function`.
///
/// The host asks for [`describe`](Self::describe) once and registers the
/// function; a filter then calls [`call`](Self::call) on each value of the
/// field passed, on Wireshark's dissection thread.
#[guatiao::kind(name = "wireshark_filter_function")]
pub trait FilterFunction: Send + Sync {
    /// The function, as a map in the shape of [`FilterDescription`].
    fn describe(&self) -> Result<Map, ProviderError>;

    /// The answer for one value: an integer field's value crosses as a
    /// number, any other as the text Wireshark displays. Answer a number
    /// for [`FilterReturn::Count`], text for [`FilterReturn::Text`], or
    /// null (or anything else) for no answer for this value.
    fn call(&self, value: &Value) -> Result<Value, ProviderError>;
}

/// What a filter function answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, ToValue, FromValue, Schema)]
#[map(rename_all = "snake_case")]
pub enum FilterReturn {
    /// An unsigned 32-bit number.
    #[default]
    Count,
    /// Text.
    Text,
}

/// What [`FilterFunction::describe`] answers.
#[derive(Clone, Debug, Default, PartialEq, Eq, ToValue, FromValue, Schema)]
pub struct FilterDescription {
    /// The function's name in a display filter: `[a-z][a-z0-9_]*`.
    pub name: String,
    /// What it answers.
    pub returns: FilterReturn,
}

impl FilterDescription {
    /// The map [`FilterFunction::describe`] answers.
    ///
    /// # Errors
    ///
    /// When the map cannot be built (an allocation failed).
    pub fn to_map(&self) -> Result<Map, ProviderError> {
        Map::from_value(&self.to_value()?).map_err(crate::model::refused)
    }

    /// The description a [`FilterFunction::describe`] map holds.
    ///
    /// # Errors
    ///
    /// When the map is not in this shape.
    pub fn from_map(map: &Map) -> Result<Self, ProviderError> {
        Self::from_value(&map.to_value()?).map_err(crate::model::refused)
    }
}
