//! String (de)serialization behind the `serde` feature. Deserializing
//! validates, so a malformed name in a config file is an error.

use serde::de::{Deserialize, Deserializer, Error as _};
use serde::ser::{Serialize, Serializer};

use crate::{CertName, HostAllowlist, HostPattern, Hostname};

macro_rules! string_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = std::borrow::Cow::<'de, str>::deserialize(deserializer)?;
                Self::parse(&text).map_err(D::Error::custom)
            }
        }
    };
}

string_serde!(Hostname);
string_serde!(HostPattern);
string_serde!(CertName);

/// Serialized as a sequence of pattern strings.
impl Serialize for HostAllowlist {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'de> Deserialize<'de> for HostAllowlist {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<HostPattern>::deserialize(deserializer).map(Self::from_iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_as_strings() {
        let allow: HostAllowlist =
            serde_json::from_str(r#"["Example.com.", "*.example.org"]"#).unwrap();
        assert!(allow.allows("www.example.org"));
        assert_eq!(
            serde_json::to_string(&allow).unwrap(),
            r#"["example.com","*.example.org"]"#
        );
        let name: CertName = serde_json::from_str(r#""*.example.com""#).unwrap();
        assert_eq!(serde_json::to_string(&name).unwrap(), r#""*.example.com""#);
        let host: Hostname = serde_json::from_str(r#""WWW.example.com""#).unwrap();
        assert_eq!(host.as_str(), "www.example.com");
    }

    #[test]
    fn rejects_malformed_values() {
        assert!(serde_json::from_str::<HostPattern>(r#""f*o.example.com""#).is_err());
        assert!(serde_json::from_str::<CertName>(r#""*.com""#).is_err());
        assert!(serde_json::from_str::<Hostname>(r#""10.0.0.1""#).is_err());
        assert!(serde_json::from_str::<HostAllowlist>(r#"["ok.com", "*"]"#).is_err());
    }
}
