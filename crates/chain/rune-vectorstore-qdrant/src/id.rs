//! Mapping record ids to Qdrant point ids.

use std::fmt;

use serde::{Serialize, Serializer};
use sha1::{Digest, Sha1};

/// Namespace for `UUIDv5` point ids:
/// `uuid5(NAMESPACE_URL, "https://crates.io/crates/rune-vectorstore-qdrant")`,
/// i.e. `cba6f372-9dfc-553a-aec5-bcaecab7c479`.
pub const ID_NAMESPACE: [u8; 16] = [
    0xcb, 0xa6, 0xf3, 0x72, 0x9d, 0xfc, 0x55, 0x3a, 0xae, 0xc5, 0xbc, 0xae, 0xca, 0xb7, 0xc4, 0x79,
];

/// A Qdrant point id: an unsigned integer or a UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PointId {
    /// Integer id.
    Num(u64),
    /// UUID in lowercase hyphenated form.
    Uuid(String),
}

impl PointId {
    /// The point id for a record id. The mapping is deterministic and
    /// one-to-one in practice:
    ///
    /// - a canonical decimal `u64` (`"0"`, `"42"`, no sign or leading zeros)
    ///   becomes that integer;
    /// - a lowercase hyphenated UUID is used as is;
    /// - anything else becomes `uuid5(ID_NAMESPACE, id)`, so other languages
    ///   can compute the same ids.
    ///
    /// The original id is also stored in the payload, so hits always carry it.
    ///
    /// # Example
    ///
    /// ```
    /// use rune_vectorstore_qdrant::PointId;
    ///
    /// assert_eq!(PointId::from_record_id("42"), PointId::Num(42));
    /// assert_eq!(
    ///     PointId::from_record_id("doc-1").to_string(),
    ///     "b078ced4-e7d0-548d-a825-d9133395950e"
    /// );
    /// ```
    #[must_use]
    pub fn from_record_id(id: &str) -> Self {
        if let Some(n) = canonical_u64(id) {
            return Self::Num(n);
        }
        if is_canonical_uuid(id) {
            return Self::Uuid(id.to_owned());
        }
        Self::Uuid(format_uuid(&uuid_v5(&ID_NAMESPACE, id.as_bytes())))
    }
}

impl fmt::Display for PointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Num(n) => write!(f, "{n}"),
            Self::Uuid(s) => f.write_str(s),
        }
    }
}

impl Serialize for PointId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Num(n) => s.serialize_u64(*n),
            Self::Uuid(u) => s.serialize_str(u),
        }
    }
}

fn canonical_u64(id: &str) -> Option<u64> {
    let b = id.as_bytes();
    let ok = !b.is_empty() && b.iter().all(u8::is_ascii_digit) && (b[0] != b'0' || b.len() == 1);
    if ok { id.parse().ok() } else { None }
}

fn is_canonical_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// RFC 4122 name-based UUID, version 5 (SHA-1).
pub fn uuid_v5(namespace: &[u8; 16], name: &[u8]) -> [u8; 16] {
    let digest = Sha1::new()
        .chain_update(namespace)
        .chain_update(name)
        .finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out[6] = (out[6] & 0x0f) | 0x50;
    out[8] = (out[8] & 0x3f) | 0x80;
    out
}

fn format_uuid(b: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(char::from(HEX[usize::from(byte >> 4)]));
        s.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMESPACE_DNS: [u8; 16] = [
        0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ];
    const NAMESPACE_URL: [u8; 16] = [
        0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ];

    #[test]
    fn uuid_v5_matches_python() {
        // uuid.uuid5(uuid.NAMESPACE_DNS, "python.org")
        assert_eq!(
            format_uuid(&uuid_v5(&NAMESPACE_DNS, b"python.org")),
            "886313e1-3b8a-5372-9b90-0c9aee199e5d"
        );
        assert_eq!(
            uuid_v5(
                &NAMESPACE_URL,
                b"https://crates.io/crates/rune-vectorstore-qdrant"
            ),
            ID_NAMESPACE
        );
    }

    #[test]
    fn record_ids_map_like_python() {
        // uuid.uuid5(ns, s) with ns = ID_NAMESPACE
        for (id, want) in [
            ("doc-1", "b078ced4-e7d0-548d-a825-d9133395950e"),
            ("slug#0", "c8f70ecb-dd25-5196-9067-2b36f2160f68"),
            ("é", "6894d7fb-848c-55ba-a1c6-a89b00a96ec0"),
        ] {
            assert_eq!(PointId::from_record_id(id), PointId::Uuid(want.into()));
        }
    }

    #[test]
    fn integers_and_uuids_pass_through_only_when_canonical() {
        assert_eq!(PointId::from_record_id("0"), PointId::Num(0));
        assert_eq!(
            PointId::from_record_id("18446744073709551615"),
            PointId::Num(u64::MAX)
        );
        for not_int in ["042", "+1", "-1", "18446744073709551616", "1 ", "00"] {
            assert!(
                matches!(PointId::from_record_id(not_int), PointId::Uuid(_)),
                "{not_int}"
            );
        }
        // "042" and "42" must not collide.
        assert_ne!(
            PointId::from_record_id("042"),
            PointId::from_record_id("42")
        );

        let u = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(PointId::from_record_id(u), PointId::Uuid(u.into()));
        // Upper case is a different record id, so it must map elsewhere.
        let upper = u.to_ascii_uppercase();
        assert_ne!(PointId::from_record_id(&upper), PointId::Uuid(u.into()));
        assert_eq!(serde_json::to_string(&PointId::Num(7)).unwrap(), "7");
        assert_eq!(PointId::from_record_id("7").to_string(), "7");
    }
}
