//! Entries, records and their hashes.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

/// Domain separator mixed into every record hash, so a digest from this
/// log can never be confused with one computed for another purpose.
const DOMAIN: &[u8] = b"rune-audit-log/v1\0";

/// A SHA-256 digest: a record's hash, or the previous record's hash it
/// links to. Serialized as 64 lowercase hex characters.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The all-zero digest that the first record links to.
    pub const GENESIS: Self = Self([0; 32]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&rune_hex::encode(self.0))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

/// The text is not 64 hex characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseDigestError;

impl fmt::Display for ParseDigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected 64 hex characters")
    }
}

impl std::error::Error for ParseDigestError {}

impl FromStr for Digest {
    type Err = ParseDigestError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = rune_hex::decode(text).map_err(|_| ParseDigestError)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Self)
            .map_err(|_| ParseDigestError)
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// What happened: who did what to which target, with free-form fields.
///
/// ```
/// use rune_audit_log::Entry;
///
/// let entry = Entry::new("alice", "secret.read")
///     .with_target("vault/db-password")
///     .with_field("ip", "10.0.0.7");
/// assert_eq!(entry.fields["ip"], "10.0.0.7");
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Entry {
    /// Who acted: a user, service or process.
    pub actor: String,
    /// What they did, such as `"login"` or `"policy.update"`.
    pub action: String,
    /// What it was done to, if anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Further details, ordered by key so the hash is deterministic.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl Entry {
    /// An entry with an actor and an action.
    #[must_use]
    pub fn new(actor: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            action: action.into(),
            target: None,
            fields: BTreeMap::new(),
        }
    }

    /// Sets [`target`](Self::target).
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Adds (or replaces) one of [`fields`](Self::fields).
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

/// One sealed, chained record of the log.
///
/// Stored as one JSON object per line:
/// `{"seq":0,"ts":…,"actor":…,"action":…,"prev":"00…","hash":"…"}`, plus
/// `target`, `fields` and `sig` when present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Record {
    /// Position in the log, from 0, without gaps.
    pub seq: u64,
    /// When it was appended, in milliseconds since the Unix epoch.
    pub ts: u64,
    /// What happened.
    #[serde(flatten)]
    pub entry: Entry,
    /// The previous record's [`hash`](Self::hash), or
    /// [`Digest::GENESIS`] for the first record.
    pub prev: Digest,
    /// SHA-256 over all the fields above (see [`Record::compute_hash`]).
    pub hash: Digest,
    /// A [`Signer`](crate::Signer)'s signature over [`hash`](Self::hash),
    /// hex-encoded in JSON.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_bytes")]
    pub sig: Option<Vec<u8>>,
}

impl Record {
    /// The hash a record with these contents must carry.
    ///
    /// SHA-256 of a domain separator, `prev`, `seq` and `ts` (big-endian
    /// `u64`), then actor, action, target and each field key and value,
    /// every string length-prefixed so that no two different records
    /// encode to the same bytes.
    #[must_use]
    pub fn compute_hash(seq: u64, ts: u64, entry: &Entry, prev: &Digest) -> Digest {
        fn put(hasher: &mut Sha256, text: &str) {
            hasher.update((text.len() as u64).to_be_bytes());
            hasher.update(text.as_bytes());
        }
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(prev.0);
        hasher.update(seq.to_be_bytes());
        hasher.update(ts.to_be_bytes());
        put(&mut hasher, &entry.actor);
        put(&mut hasher, &entry.action);
        match &entry.target {
            None => hasher.update([0]),
            Some(target) => {
                hasher.update([1]);
                put(&mut hasher, target);
            }
        }
        hasher.update((entry.fields.len() as u64).to_be_bytes());
        for (key, value) in &entry.fields {
            put(&mut hasher, key);
            put(&mut hasher, value);
        }
        Digest(hasher.finalize().into())
    }

    /// Whether [`hash`](Self::hash) matches the record's contents.
    #[must_use]
    pub fn hash_is_valid(&self) -> bool {
        Self::compute_hash(self.seq, self.ts, &self.entry, &self.prev) == self.hash
    }

    /// The record as one line of JSON, without the trailing newline.
    ///
    /// # Errors
    ///
    /// [`Error::Json`](crate::Error::Json) if serialization fails (it
    /// does not for records built by this crate).
    pub fn to_json(&self) -> Result<String, crate::Error> {
        serde_json::to_string(self).map_err(crate::Error::Json)
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    // `serde(with)` passes `&Option<Vec<u8>>`.
    #[allow(clippy::ref_option, reason = "signature fixed by serde(with)")]
    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => s.serialize_some(&rune_hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|text| rune_hex::decode(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trips_through_hex() {
        let digest = Digest([0xab; 32]);
        assert_eq!(digest.to_string().parse::<Digest>(), Ok(digest));
        assert_eq!("abc".parse::<Digest>(), Err(ParseDigestError));
        assert_eq!("zz".repeat(32).parse::<Digest>(), Err(ParseDigestError));
    }

    #[test]
    fn hash_is_unambiguous() {
        let prev = Digest::GENESIS;
        let a = Entry::new("ab", "c");
        let b = Entry::new("a", "bc");
        assert_ne!(
            Record::compute_hash(0, 0, &a, &prev),
            Record::compute_hash(0, 0, &b, &prev)
        );
        let empty_target = Entry::new("a", "b").with_target("");
        assert_ne!(
            Record::compute_hash(0, 0, &Entry::new("a", "b"), &prev),
            Record::compute_hash(0, 0, &empty_target, &prev)
        );
    }

    #[test]
    fn json_shape() {
        let entry = Entry::new("alice", "login").with_field("ip", "1.2.3.4");
        let hash = Record::compute_hash(0, 5, &entry, &Digest::GENESIS);
        let record = Record {
            seq: 0,
            ts: 5,
            entry,
            prev: Digest::GENESIS,
            hash,
            sig: Some(vec![1, 2]),
        };
        let json = record.to_json().unwrap();
        assert!(json.starts_with(r#"{"seq":0,"ts":5,"actor":"alice","action":"login","fields":{"ip":"1.2.3.4"},"prev":"0000"#));
        assert!(json.ends_with(r#","sig":"0102"}"#));
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert!(back.hash_is_valid());
    }
}
