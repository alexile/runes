//! `serde` support: vectors as strings, scores as numbers.

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

use crate::{Score, Vector, Vector3, Vector4, Version};

/// Deserializes a value from a string with its `FromStr`.
struct FromStrVisitor<T>(PhantomData<T>, &'static str);

impl<T> Visitor<'_> for FromStrVisitor<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.1)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        text.parse().map_err(E::custom)
    }
}

macro_rules! string_serde {
    ($ty:ty, $expecting:literal) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_str(FromStrVisitor(PhantomData, $expecting))
            }
        }
    };
}

string_serde!(Vector, "a CVSS v3.0, v3.1 or v4.0 vector string");
string_serde!(Vector3, "a CVSS v3.0 or v3.1 vector string");
string_serde!(Vector4, "a CVSS v4.0 vector string");

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct VersionVisitor;

        impl Visitor<'_> for VersionVisitor {
            type Value = Version;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("\"3.0\", \"3.1\" or \"4.0\"")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Version, E> {
                match text {
                    "3.0" => Ok(Version::V3_0),
                    "3.1" => Ok(Version::V3_1),
                    "4.0" => Ok(Version::V4_0),
                    _ => Err(E::invalid_value(de::Unexpected::Str(text), &self)),
                }
            }
        }

        deserializer.deserialize_str(VersionVisitor)
    }
}

impl Serialize for Score {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_f64(self.value())
    }
}

impl<'de> Deserialize<'de> for Score {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = f64::deserialize(deserializer)?;
        Self::try_from(value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Score, Severity, Vector, Version};

    #[test]
    fn json_shapes() {
        let text = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let vector: Vector = serde_json::from_str(&format!("\"{text}\"")).unwrap();
        assert_eq!(
            serde_json::to_string(&vector).unwrap(),
            format!("\"{text}\"")
        );
        assert!(serde_json::from_str::<Vector>("\"CVSS:3.1/AV:N\"").is_err());
        assert!(serde_json::from_str::<Vector>("42").is_err());

        let score = vector.base_score();
        assert_eq!(serde_json::to_string(&score).unwrap(), "9.8");
        assert_eq!(serde_json::from_str::<Score>("9.8").unwrap(), score);
        assert_eq!(serde_json::from_str::<Score>("10").unwrap(), Score::MAX);
        assert!(serde_json::from_str::<Score>("9.85").is_err());
        assert!(serde_json::from_str::<Score>("11").is_err());

        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"Critical\""
        );
        assert_eq!(serde_json::to_string(&Version::V4_0).unwrap(), "\"4.0\"");
        assert_eq!(
            serde_json::from_str::<Version>("\"3.0\"").unwrap(),
            Version::V3_0
        );
        assert!(serde_json::from_str::<Version>("\"2.0\"").is_err());
    }
}
