//! Typed protocol preferences: a struct describes them, Wireshark stores
//! them, and the dissector reads a snapshot of the struct.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use std::collections::HashMap;

/// A struct of preferences a protocol registers and its dissector reads.
///
/// `#[derive(Preferences)]` (feature `derive`) writes both methods for a
/// struct whose fields implement [`PreferenceValue`]. The struct's `Default`
/// supplies the registered defaults.
pub trait Preferences: Default + Send + Sync + 'static {
    /// The preferences to register, in the order Wireshark shows them.
    fn declarations() -> Vec<Declaration>;

    /// Builds the struct from Wireshark's current values, keyed by
    /// [`Declaration::name`]. A missing key keeps the field's default.
    ///
    /// # Errors
    ///
    /// [`PreferenceError`] when a value does not fit its field.
    fn from_values(values: &PreferenceMap) -> Result<Self, PreferenceError>;
}

/// Current preference values, keyed by preference name.
pub type PreferenceMap = HashMap<&'static str, Value>;

/// The preferences of a protocol that registers none.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoPreferences;

impl Preferences for NoPreferences {
    fn declarations() -> Vec<Declaration> {
        Vec::new()
    }

    fn from_values(_: &PreferenceMap) -> Result<Self, PreferenceError> {
        Ok(Self)
    }
}

/// One preference value as Wireshark stores it.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    /// A checkbox.
    Bool(bool),
    /// An unsigned integer.
    Uint(u32),
    /// A text field.
    String(String),
}

/// A field type that can be a preference.
pub trait PreferenceValue: Sized {
    /// This value as Wireshark stores it.
    fn to_value(&self) -> Value;

    /// Reads a stored value back.
    ///
    /// # Errors
    ///
    /// [`PreferenceError::WrongKind`] for a value of another kind,
    /// [`PreferenceError::OutOfRange`] for one this type cannot hold.
    fn from_value(value: &Value) -> Result<Self, PreferenceError>;
}

impl PreferenceValue for bool {
    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }

    fn from_value(value: &Value) -> Result<Self, PreferenceError> {
        match value {
            Value::Bool(value) => Ok(*value),
            _ => Err(PreferenceError::WrongKind),
        }
    }
}

impl PreferenceValue for u32 {
    fn to_value(&self) -> Value {
        Value::Uint(*self)
    }

    fn from_value(value: &Value) -> Result<Self, PreferenceError> {
        match value {
            Value::Uint(value) => Ok(*value),
            _ => Err(PreferenceError::WrongKind),
        }
    }
}

impl PreferenceValue for u16 {
    fn to_value(&self) -> Value {
        Value::Uint(u32::from(*self))
    }

    fn from_value(value: &Value) -> Result<Self, PreferenceError> {
        match value {
            Value::Uint(value) => Self::try_from(*value).map_err(|_| PreferenceError::OutOfRange),
            _ => Err(PreferenceError::WrongKind),
        }
    }
}

impl PreferenceValue for u8 {
    fn to_value(&self) -> Value {
        Value::Uint(u32::from(*self))
    }

    fn from_value(value: &Value) -> Result<Self, PreferenceError> {
        match value {
            Value::Uint(value) => Self::try_from(*value).map_err(|_| PreferenceError::OutOfRange),
            _ => Err(PreferenceError::WrongKind),
        }
    }
}

impl PreferenceValue for String {
    fn to_value(&self) -> Value {
        Value::String(self.clone())
    }

    fn from_value(value: &Value) -> Result<Self, PreferenceError> {
        match value {
            Value::String(value) => Ok(value.clone()),
            _ => Err(PreferenceError::WrongKind),
        }
    }
}

/// One registered preference: its key, label, description and default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Declaration {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    default: Value,
    base: u32,
}

impl Declaration {
    /// A preference keyed `name` (`<protocol>.<name>` on the command line),
    /// shown as `title`, defaulting to `default`. Integers are shown in decimal.
    pub fn new(
        name: &'static str,
        title: &'static str,
        description: &'static str,
        default: Value,
    ) -> Self {
        Self {
            name,
            title,
            description,
            default,
            base: 10,
        }
    }

    /// The same preference with an integer shown and entered in `base`
    /// (8, 10 or 16).
    #[must_use]
    pub fn with_base(mut self, base: u32) -> Self {
        self.base = base;
        self
    }

    /// The preference's key.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The label Wireshark shows.
    pub fn title(&self) -> &'static str {
        self.title
    }

    /// The description Wireshark shows.
    pub fn description(&self) -> &'static str {
        self.description
    }

    /// The default value, which also fixes the preference's kind.
    pub fn default_value(&self) -> &Value {
        &self.default
    }

    /// The base an integer preference uses.
    pub fn base(&self) -> u32 {
        self.base
    }
}

/// A stored preference value does not fit its field.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreferenceError {
    /// The value is of another kind than the field.
    WrongKind,
    /// The value is outside the field type's range.
    OutOfRange,
}

impl fmt::Display for PreferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongKind => "preference value has the wrong kind",
            Self::OutOfRange => "preference value is out of range for its field",
        })
    }
}

impl core::error::Error for PreferenceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_preference_refuses_a_value_above_u16() {
        assert_eq!(
            u16::from_value(&Value::Uint(70_000)),
            Err(PreferenceError::OutOfRange)
        );
        assert_eq!(u16::from_value(&Value::Uint(4242)), Ok(4242));
    }

    #[test]
    fn values_round_trip_through_their_field_types() {
        assert_eq!(bool::from_value(&true.to_value()), Ok(true));
        assert_eq!(u32::from_value(&7u32.to_value()), Ok(7));
        let text = String::from("FOO");
        assert_eq!(String::from_value(&text.to_value()), Ok(text));
    }

    #[test]
    fn a_value_of_another_kind_is_refused() {
        assert_eq!(
            bool::from_value(&Value::Uint(1)),
            Err(PreferenceError::WrongKind)
        );
    }
}
