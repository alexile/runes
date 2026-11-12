//! [`ToolCategory`]: an open set of `snake_case` grouping names.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

/// Longest accepted category, in bytes.
const MAX_CATEGORY_LEN: usize = 64;

/// The broad area a tool belongs to, used for grouping and discovery.
///
/// Categories are an open set: any `snake_case` identifier of 1 to 64 bytes
/// (`[a-z][a-z0-9_]*`) is valid, so a catalog can add its own without a new
/// release. The associated constants cover the common ones, and serialize
/// to their `snake_case` names.
///
/// ```
/// use rune_tool_schema::ToolCategory;
///
/// assert_eq!(ToolCategory::ENCODING.as_str(), "encoding");
/// let custom = ToolCategory::new("threat_intel")?;
/// assert_eq!(custom.to_string(), "threat_intel");
/// assert!(ToolCategory::new("Not Snake").is_err());
/// # Ok::<(), rune_tool_schema::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ToolCategory(Cow<'static, str>);

impl ToolCategory {
    /// Asset and endpoint discovery.
    pub const DISCOVERY: Self = Self::known("discovery");
    /// Service, OS and technology fingerprinting.
    pub const FINGERPRINT: Self = Self::known("fingerprint");
    /// Non-HTTP network and transport checks.
    pub const NETWORK: Self = Self::known("network");
    /// DNS and email-record checks.
    pub const DNS: Self = Self::known("dns");
    /// HTTP application checks.
    pub const WEB: Self = Self::known("web");
    /// Browser and client-side checks.
    pub const CLIENT: Self = Self::known("client");
    /// Authentication and identity checks.
    pub const AUTH: Self = Self::known("auth");
    /// API-surface checks (`OpenAPI`, `GraphQL`, `gRPC`, `WebSocket`, MCP).
    pub const API: Self = Self::known("api");
    /// Cloud-platform checks.
    pub const CLOUD: Self = Self::known("cloud");
    /// Container and registry checks.
    pub const CONTAINER: Self = Self::known("container");
    /// Kubernetes checks.
    pub const KUBERNETES: Self = Self::known("kubernetes");
    /// Source-code checks.
    pub const CODE: Self = Self::known("code");
    /// Open-source intelligence collection.
    pub const OSINT: Self = Self::known("osint");
    /// Report generation and aggregation.
    pub const REPORTING: Self = Self::known("reporting");
    /// Interception, logging and traffic capture.
    pub const INTERCEPTION: Self = Self::known("interception");
    /// Data transforms and other utilities.
    pub const UTILITY: Self = Self::known("utility");
    /// Confirming or refuting reported issues.
    pub const VERIFICATION: Self = Self::known("verification");
    /// Encoding and decoding (hex, base64, ...).
    pub const ENCODING: Self = Self::known("encoding");
    /// Hashing and digests.
    pub const HASHING: Self = Self::known("hashing");
    /// Content analysis (entropy, string extraction, ...).
    pub const ANALYSIS: Self = Self::known("analysis");
    /// Classical ciphers and cryptanalysis.
    pub const CIPHER: Self = Self::known("cipher");
    /// Search and retrieval.
    pub const SEARCH: Self = Self::known("search");
    /// File-system access.
    pub const FILESYSTEM: Self = Self::known("filesystem");

    /// A constant category; the caller guarantees the name is valid (checked
    /// by a unit test for every constant).
    const fn known(name: &'static str) -> Self {
        Self(Cow::Borrowed(name))
    }

    /// Validate and wrap a category name.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCategory`] unless `name` is 1 to 64 bytes of
    /// `[a-z0-9_]` starting with a lowercase letter.
    pub fn new(name: impl Into<Cow<'static, str>>) -> Result<Self, Error> {
        let name = name.into();
        if is_valid_category(&name) {
            Ok(Self(name))
        } else {
            Err(Error::InvalidCategory(name.into_owned()))
        }
    }

    /// The category name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `name` is a valid category: `[a-z][a-z0-9_]*`, at most 64 bytes.
fn is_valid_category(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_CATEGORY_LEN
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

impl fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ToolCategory {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for ToolCategory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl Serialize for ToolCategory {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ToolCategory {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::new(name).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for ToolCategory {
    fn schema_name() -> Cow<'static, str> {
        "ToolCategory".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^[a-z][a-z0-9_]*$",
            "minLength": 1,
            "maxLength": MAX_CATEGORY_LEN,
            "description": "Broad area a tool belongs to (snake_case)."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ToolCategory; 23] = [
        ToolCategory::DISCOVERY,
        ToolCategory::FINGERPRINT,
        ToolCategory::NETWORK,
        ToolCategory::DNS,
        ToolCategory::WEB,
        ToolCategory::CLIENT,
        ToolCategory::AUTH,
        ToolCategory::API,
        ToolCategory::CLOUD,
        ToolCategory::CONTAINER,
        ToolCategory::KUBERNETES,
        ToolCategory::CODE,
        ToolCategory::OSINT,
        ToolCategory::REPORTING,
        ToolCategory::INTERCEPTION,
        ToolCategory::UTILITY,
        ToolCategory::VERIFICATION,
        ToolCategory::ENCODING,
        ToolCategory::HASHING,
        ToolCategory::ANALYSIS,
        ToolCategory::CIPHER,
        ToolCategory::SEARCH,
        ToolCategory::FILESYSTEM,
    ];

    #[test]
    fn every_constant_is_valid() {
        for category in ALL {
            assert!(is_valid_category(category.as_str()), "{category}");
        }
    }

    #[test]
    fn rejects_bad_names() {
        for bad in ["", "Web", "1abc", "_x", "a-b", "a b", "é", &"a".repeat(65)] {
            assert!(ToolCategory::new(bad.to_owned()).is_err(), "{bad:?}");
        }
        assert!(ToolCategory::new("a".repeat(64)).is_ok());
    }

    #[test]
    fn serde_is_a_plain_string() {
        let json = serde_json::to_string(&ToolCategory::WEB).unwrap();
        assert_eq!(json, "\"web\"");
        let back: ToolCategory = serde_json::from_str("\"threat_intel\"").unwrap();
        assert_eq!(back.as_str(), "threat_intel");
        assert!(serde_json::from_str::<ToolCategory>("\"Bad\"").is_err());
    }
}
