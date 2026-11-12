//! A small in-memory database of known fingerprints.

use std::collections::HashMap;
use std::fmt;

use crate::Error;

/// Which scheme a fingerprint belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Kind {
    /// JA3 (TLS client, MD5).
    Ja3,
    /// JA3S (TLS server, MD5).
    Ja3s,
    /// JA4 (TLS client).
    Ja4,
    /// JA4S (TLS server).
    Ja4s,
    /// JA4H (HTTP client).
    Ja4h,
    /// JA4T (TCP client).
    Ja4t,
}

impl Kind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Ja3,
        Self::Ja3s,
        Self::Ja4,
        Self::Ja4s,
        Self::Ja4h,
        Self::Ja4t,
    ];

    /// The lowercase name used in fingerprint lists: `ja3`, `ja4s`, ….
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ja3 => "ja3",
            Self::Ja3s => "ja3s",
            Self::Ja4 => "ja4",
            Self::Ja4s => "ja4s",
            Self::Ja4h => "ja4h",
            Self::Ja4t => "ja4t",
        }
    }

    /// The kind with the given [`name`](Kind::name), ignoring ASCII case.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.name().eq_ignore_ascii_case(name))
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Published example fingerprints shipped with [`Database::builtin`], as a
/// fingerprint list (see [`Database::parse`]).
///
/// Sources: the JA3 README (Salesforce, BSD-3-Clause) and the JA4
/// technical details (`FoxIO`, BSD-3-Clause). These are illustrations, not
/// threat intelligence: a client's fingerprint changes with its version and
/// configuration.
pub const BUILTIN: &str = "\
# JA3 README examples
ja3,e7d705a3286e19ea42f587b344ee6865,Tor client
ja3,6734f37431670b3ab4292b8f60f29984,Trickbot malware
ja3,4d7a28d6f2263ed61de88ca66eb011e3,Emotet malware
ja3s,623de93db17d313345d7ea481e7443cf,Trickbot command-and-control server response
ja3s,80b3a14bccc8598a1f3bbe83e71f735f,Emotet command-and-control server response
# JA4 technical details example
ja4,t13d1516h2_8daaf6152771_e5627efa2ab1,Chromium-based browser
";

/// Known fingerprints with labels, for lookup.
///
/// Fingerprints are matched exactly, ignoring ASCII case. One fingerprint
/// may carry several labels: many applications share a TLS stack.
///
/// ```
/// use rune_ja::{Database, Kind};
///
/// let mut db = Database::builtin();
/// db.extend_from_list("ja4t,64240_2-1-3-1-1-4_1460_8,Windows 10/11 TCP stack\n")?;
/// assert_eq!(db.lookup(Kind::Ja3, "E7D705A3286E19EA42F587B344EE6865"), ["Tor client"]);
/// assert_eq!(db.lookup(Kind::Ja4t, "64240_2-1-3-1-1-4_1460_8"), ["Windows 10/11 TCP stack"]);
/// assert!(db.lookup(Kind::Ja4, "t13d0000_000000000000_000000000000").is_empty());
/// # Ok::<(), rune_ja::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Database {
    entries: HashMap<(Kind, String), Vec<String>>,
}

impl Database {
    /// An empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A database holding the [`BUILTIN`] examples.
    #[must_use]
    pub fn builtin() -> Self {
        let mut db = Self::new();
        // BUILTIN is a constant checked by the tests; a bad line is a bug
        // there, and skipping it beats panicking at runtime.
        let _ = db.extend_from_list(BUILTIN);
        db
    }

    /// Reads a fingerprint list: one `kind,fingerprint,label` entry per
    /// line, with `kind` a [`Kind::name`]. The label is the rest of the line
    /// and may contain commas. Blank lines and lines starting with `#` are
    /// skipped; surrounding whitespace is trimmed.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDatabaseLine`] for a line with fewer than three
    /// fields, an unknown kind, or an empty fingerprint or label.
    pub fn parse(list: &str) -> Result<Self, Error> {
        let mut db = Self::new();
        db.extend_from_list(list)?;
        Ok(db)
    }

    /// Adds the entries of a fingerprint list (see [`Database::parse`]).
    /// On error, no entry of the list is added.
    ///
    /// # Errors
    ///
    /// As [`Database::parse`].
    pub fn extend_from_list(&mut self, list: &str) -> Result<(), Error> {
        let mut parsed = Vec::new();
        for (index, line) in list.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let invalid = |reason| Error::InvalidDatabaseLine {
                line: index + 1,
                reason,
            };
            let mut fields = line.splitn(3, ',');
            let (Some(kind), Some(fingerprint), Some(label)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(invalid("expected `kind,fingerprint,label`"));
            };
            let kind = Kind::from_name(kind.trim()).ok_or_else(|| invalid("unknown kind"))?;
            let (fingerprint, label) = (fingerprint.trim(), label.trim());
            if fingerprint.is_empty() {
                return Err(invalid("empty fingerprint"));
            }
            if label.is_empty() {
                return Err(invalid("empty label"));
            }
            parsed.push((kind, fingerprint, label));
        }
        for (kind, fingerprint, label) in parsed {
            self.insert(kind, fingerprint, label);
        }
        Ok(())
    }

    /// Adds a label for a fingerprint. A label already recorded for it is
    /// not added twice.
    pub fn insert(&mut self, kind: Kind, fingerprint: &str, label: impl Into<String>) {
        let label = label.into();
        let labels = self
            .entries
            .entry((kind, fingerprint.to_ascii_lowercase()))
            .or_default();
        if !labels.contains(&label) {
            labels.push(label);
        }
    }

    /// The labels recorded for a fingerprint, in insertion order; empty if
    /// it is unknown.
    #[must_use]
    pub fn lookup(&self, kind: Kind, fingerprint: &str) -> &[String] {
        self.entries
            .get(&(kind, fingerprint.to_ascii_lowercase()))
            .map_or(&[], Vec::as_slice)
    }

    /// The number of distinct fingerprints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every `(kind, fingerprint, labels)` entry, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (Kind, &str, &[String])> + '_ {
        self.entries
            .iter()
            .map(|((kind, fingerprint), labels)| (*kind, fingerprint.as_str(), labels.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_list_parses() {
        let db = Database::parse(BUILTIN).unwrap();
        assert_eq!(db, Database::builtin());
        assert_eq!(db.len(), 6);
        assert_eq!(
            db.lookup(Kind::Ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1"),
            ["Chromium-based browser"]
        );
        // Kinds are separate namespaces.
        assert_eq!(
            db.lookup(Kind::Ja3s, "e7d705a3286e19ea42f587b344ee6865"),
            [] as [String; 0]
        );
    }

    #[test]
    fn labels_accumulate_without_duplicates() {
        let mut db = Database::new();
        assert!(db.is_empty());
        db.insert(Kind::Ja3, "ABC", "one");
        db.insert(Kind::Ja3, "abc", "two, with comma");
        db.insert(Kind::Ja3, "abc", "one");
        assert_eq!(db.lookup(Kind::Ja3, "abc"), ["one", "two, with comma"]);
        assert_eq!(db.iter().count(), 1);
    }

    #[test]
    fn bad_lines_are_reported_and_nothing_is_added() {
        let mut db = Database::new();
        let err = db
            .extend_from_list("# ok\nja3,abc,fine\n\nja5,abc,unknown kind\n")
            .unwrap_err();
        assert_eq!(
            err,
            Error::InvalidDatabaseLine {
                line: 4,
                reason: "unknown kind"
            }
        );
        assert!(db.is_empty());
        for bad in ["ja3,abc", "ja3,,label", "ja3,abc, ", "nonsense"] {
            assert!(Database::parse(bad).is_err(), "{bad}");
        }
        let db = Database::parse(" JA4H , ge11nn01enus_x_y_z , curl, maybe \n").unwrap();
        assert_eq!(db.lookup(Kind::Ja4h, "ge11nn01enus_x_y_z"), ["curl, maybe"]);
        assert_eq!(Kind::from_name("JA4T"), Some(Kind::Ja4t));
        assert_eq!(Kind::Ja3s.to_string(), "ja3s");
    }
}
