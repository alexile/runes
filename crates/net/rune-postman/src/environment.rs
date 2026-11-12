//! Postman environment and globals exports.

use serde_json::Value;

use crate::{PostmanError, json};

/// One variable of an environment, globals export or collection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Variable {
    /// The name used in `{{name}}` placeholders.
    pub key: String,
    /// The value, as text.
    pub value: String,
    /// Whether the variable is in effect. Disabled variables are kept but
    /// not used for resolution.
    pub enabled: bool,
    /// Whether Postman marks it secret (`"type": "secret"`).
    pub secret: bool,
}

impl Variable {
    /// An enabled, non-secret variable.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            enabled: true,
            secret: false,
        }
    }

    /// Reads `{"key", "value", "enabled" | "disabled", "type"}`; `None`
    /// without a key.
    pub(crate) fn from_json(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let key = json::non_empty(object, "key").or_else(|| json::non_empty(object, "id"))?;
        let enabled = match object.get("enabled") {
            None | Some(Value::Null) => !json::disabled(object),
            Some(flag) => json::flag(Some(flag)),
        };
        Some(Self {
            key,
            value: json::field(object, "value").unwrap_or_default(),
            enabled,
            secret: json::field(object, "type").as_deref() == Some("secret"),
        })
    }
}

/// A Postman environment, or a globals export (same shape).
///
/// ```
/// let environment = rune_postman::parse_environment(br#"{
///     "name": "staging",
///     "values": [
///         {"key": "baseUrl", "value": "https://staging.test", "enabled": true},
///         {"key": "old", "value": "x", "enabled": false}
///     ],
///     "_postman_variable_scope": "environment"
/// }"#)?;
/// assert_eq!(environment.name, "staging");
/// assert_eq!(environment.get("baseUrl"), Some("https://staging.test"));
/// assert_eq!(environment.get("old"), None);
/// # Ok::<(), rune_postman::PostmanError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Environment {
    /// The environment's name.
    pub name: String,
    /// Postman's id for it, when exported.
    pub id: Option<String>,
    /// `environment` or `globals` (`_postman_variable_scope`), when given.
    pub scope: Option<String>,
    /// The variables, in file order.
    pub values: Vec<Variable>,
}

impl Environment {
    /// An empty environment.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// Adds an enabled variable.
    #[must_use]
    pub fn with_value(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.values.push(Variable::new(key, value));
        self
    }

    /// The value of an enabled variable. When a key repeats, the last
    /// enabled one wins, as in Postman.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|variable| variable.enabled && variable.key == key)
            .map(|variable| variable.value.as_str())
    }

    /// The enabled variables, later keys overriding earlier ones.
    pub(crate) fn enabled(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .filter(|variable| variable.enabled)
            .map(|variable| (variable.key.as_str(), variable.value.as_str()))
    }
}

/// Parses a Postman environment or globals export.
///
/// Variables without a key are skipped. The `values` list is required;
/// `name` may be missing.
///
/// # Errors
///
/// [`PostmanError::Json`] when the input is not JSON,
/// [`PostmanError::NotEnvironment`] when it has no `values` array.
pub fn parse_environment(input: &[u8]) -> Result<Environment, PostmanError> {
    let document = json::parse(input)?;
    let Value::Object(object) = document else {
        return Err(PostmanError::NotEnvironment(
            "the document is not a JSON object",
        ));
    };
    // The Postman API wraps exports: `{"environment": {…}}`.
    let object = match object.get("environment") {
        Some(Value::Object(inner)) => inner,
        _ => &object,
    };
    let Some(Value::Array(values)) = object.get("values") else {
        return Err(PostmanError::NotEnvironment("no `values` array"));
    };
    Ok(Environment {
        name: json::field(object, "name").unwrap_or_default(),
        id: json::non_empty(object, "id"),
        scope: json::non_empty(object, "_postman_variable_scope"),
        values: values.iter().filter_map(Variable::from_json).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_flags_types_and_wrappers() {
        let environment = parse_environment(
            br#"{"environment": {"id": "e1", "name": "prod", "values": [
                {"key": "a", "value": 1},
                {"key": "b", "value": "x", "enabled": "false"},
                {"key": "c", "value": "s", "type": "secret"},
                {"key": "d", "value": "x", "disabled": true},
                {"value": "no key"},
                7,
                {"key": "a", "value": "2"}
            ]}}"#,
        )
        .unwrap();
        assert_eq!(environment.id.as_deref(), Some("e1"));
        assert_eq!(environment.values.len(), 5);
        assert_eq!(environment.get("a"), Some("2"));
        assert_eq!(environment.get("b"), None);
        assert_eq!(environment.get("d"), None);
        assert!(environment.values[2].secret);
    }

    #[test]
    fn rejects_other_documents() {
        assert_eq!(
            parse_environment(b"[]").unwrap_err().code(),
            "not_environment"
        );
        assert_eq!(
            parse_environment(br#"{"item": []}"#).unwrap_err().code(),
            "not_environment"
        );
        assert_eq!(parse_environment(b"{").unwrap_err().code(), "invalid_json");
    }
}
