//! Serde helpers that store byte fields as hex strings.
//!
//! Use the module with `#[serde(with = "...")]`:
//!
//! - `rune_hex::serde` for `Vec<u8>`, `[u8; N]` and anything else that is
//!   `AsRef<[u8]>` and `TryFrom<Vec<u8>>`; writes lowercase.
//! - `rune_hex::serde::upper`, the same but writes uppercase.
//! - `rune_hex::serde::option` for `Option<..>` of the above.
//!
//! Deserializing accepts what [`decode`](crate::decode) accepts: either case
//! and an optional `0x` prefix. Fixed-size targets reject the wrong length.
//!
//! # Examples
//!
//! ```rust
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Blob {
//!     #[serde(with = "rune_hex::serde")]
//!     digest: [u8; 4],
//!     #[serde(with = "rune_hex::serde::upper")]
//!     data: Vec<u8>,
//!     #[serde(with = "rune_hex::serde::option", default)]
//!     salt: Option<Vec<u8>>,
//! }
//!
//! let blob = Blob { digest: [0xde, 0xad, 0xbe, 0xef], data: vec![0xab], salt: None };
//! let json = serde_json::to_string(&blob)?;
//! assert_eq!(json, r#"{"digest":"deadbeef","data":"AB","salt":null}"#);
//! assert_eq!(serde_json::from_str::<Blob>(&json)?, blob);
//! # Ok::<(), serde_json::Error>(())
//! ```

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use ::serde::{Deserializer, Serializer, de};

/// Serializes bytes as a lowercase hex string.
///
/// # Errors
///
/// Whatever the serializer reports.
pub fn serialize<S, T>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]> + ?Sized,
{
    serializer.collect_str(&crate::display(bytes))
}

/// Deserializes bytes from a hex string.
///
/// # Errors
///
/// Invalid hex, or a length the target type does not accept.
pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFrom<Vec<u8>>,
{
    deserializer.deserialize_str(HexVisitor(PhantomData))
}

struct HexVisitor<T>(PhantomData<T>);

impl<T: TryFrom<Vec<u8>>> de::Visitor<'_> for HexVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a hex string")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        self.visit_bytes(text.as_bytes())
    }

    fn visit_bytes<E: de::Error>(self, text: &[u8]) -> Result<T, E> {
        let bytes = crate::decode(text).map_err(E::custom)?;
        let len = bytes.len();
        T::try_from(bytes).map_err(|_| E::invalid_length(len, &self))
    }
}

/// Like the parent module, but serializes uppercase hex.
pub mod upper {
    use super::{Deserializer, Serializer, Vec};

    /// Serializes bytes as an uppercase hex string.
    ///
    /// # Errors
    ///
    /// Whatever the serializer reports.
    pub fn serialize<S, T>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]> + ?Sized,
    {
        serializer.collect_str(&format_args!("{:X}", crate::display(bytes)))
    }

    /// Deserializes bytes from a hex string in either case.
    ///
    /// # Errors
    ///
    /// Invalid hex, or a length the target type does not accept.
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
    {
        super::deserialize(deserializer)
    }
}

/// For `Option` fields: `None` maps to the format's null.
pub mod option {
    use super::{Deserializer, HexVisitor, PhantomData, Serializer, Vec, de, fmt};

    /// Serializes `Some(bytes)` as a lowercase hex string and `None` as null.
    ///
    /// # Errors
    ///
    /// Whatever the serializer reports.
    #[allow(clippy::ref_option, reason = "signature fixed by serde(with)")]
    pub fn serialize<S, T>(bytes: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        match bytes {
            Some(bytes) => serializer.serialize_some(&Wrap(bytes.as_ref())),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes an optional hex string.
    ///
    /// # Errors
    ///
    /// Invalid hex, or a length the target type does not accept.
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
    {
        deserializer.deserialize_option(OptionVisitor(PhantomData))
    }

    struct Wrap<'a>(&'a [u8]);

    impl ::serde::Serialize for Wrap<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            super::serialize(self.0, serializer)
        }
    }

    struct OptionVisitor<T>(PhantomData<T>);

    impl<'de, T: TryFrom<Vec<u8>>> de::Visitor<'de> for OptionVisitor<T> {
        type Value = Option<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a hex string or null")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer
                .deserialize_str(HexVisitor(PhantomData))
                .map(Some)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Record {
        #[serde(with = "crate::serde")]
        key: [u8; 2],
        #[serde(with = "crate::serde::option", default)]
        tag: Option<Vec<u8>>,
    }

    #[test]
    fn round_trip_and_errors() -> Result<(), serde_json::Error> {
        let rec = Record {
            key: [0x01, 0xff],
            tag: Some(vec![0xab]),
        };
        let json = serde_json::to_string(&rec)?;
        assert_eq!(json, r#"{"key":"01ff","tag":"ab"}"#);
        assert_eq!(serde_json::from_str::<Record>(&json)?, rec);

        let none: Record = serde_json::from_str(r#"{"key":"0x01FF"}"#)?;
        assert_eq!(none.tag, None);

        let err = serde_json::from_str::<Record>(r#"{"key":"01"}"#).unwrap_err();
        assert!(err.to_string().contains("invalid length 1"), "{err}");
        let err = serde_json::from_str::<Record>(r#"{"key":"01zz"}"#).unwrap_err();
        assert!(err.to_string().contains("'z' at offset 2"), "{err}");
        Ok(())
    }
}
