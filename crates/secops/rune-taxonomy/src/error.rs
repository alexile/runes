//! The crate's error type.

use core::fmt;

use rune_finding::Taxonomy;

/// Errors returned by this crate.
///
/// Parsing an id never trims or case-folds its input, so `"CWE-79 "`,
/// `"cwe-79"` and `""` are errors rather than silently accepted. Inputs are
/// echoed back in the error, cut to [`Error::MAX_ECHO`] characters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The id is the empty string.
    #[error("empty {kind} id")]
    Empty {
        /// What kind of id was expected.
        kind: IdKind,
    },
    /// The id is not in the taxonomy's notation.
    #[error("malformed {kind} id {input:?}: expected {}", kind.expected())]
    Malformed {
        /// What kind of id was expected.
        kind: IdKind,
        /// The rejected input, possibly shortened.
        input: String,
    },
    /// The id is well formed but the embedded dataset has no such entry.
    #[error("unknown {kind} id {id}")]
    Unknown {
        /// What kind of id it is.
        kind: IdKind,
        /// The id, in canonical notation.
        id: String,
    },
    /// The ATT&CK technique was revoked by MITRE and replaced by another.
    #[error("ATT&CK technique {id} was revoked; use {replaced_by}")]
    Revoked {
        /// The revoked technique id.
        id: String,
        /// The technique that replaced it.
        replaced_by: String,
    },
    /// The id belongs to a different taxonomy than the one it is filed
    /// under, such as `A03:2025` filed under OWASP Top 10 2021.
    #[error("id {id} does not belong to {expected}")]
    WrongTaxonomy {
        /// The id, in canonical notation.
        id: String,
        /// The taxonomy it was filed under.
        expected: Taxonomy,
    },
    /// This crate has no dataset for the taxonomy (PCI DSS, WSTG and custom
    /// taxonomies).
    #[error("no dataset for taxonomy {0}")]
    Unsupported(Taxonomy),
}

impl Error {
    /// How many characters of a rejected input an error keeps.
    pub const MAX_ECHO: usize = 64;

    pub(crate) fn malformed(kind: IdKind, input: &str) -> Self {
        if input.is_empty() {
            return Self::Empty { kind };
        }
        let mut echo: String = input.chars().take(Self::MAX_ECHO).collect();
        if echo.len() < input.len() {
            echo.push('…');
        }
        Self::Malformed { kind, input: echo }
    }

    pub(crate) fn unknown(kind: IdKind, id: impl fmt::Display) -> Self {
        Self::Unknown {
            kind,
            id: id.to_string(),
        }
    }
}

/// The kinds of id this crate parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdKind {
    /// [`CweId`](crate::CweId), `CWE-79`.
    Cwe,
    /// [`CapecId`](crate::CapecId), `CAPEC-66`.
    Capec,
    /// [`AttackId`](crate::AttackId), `T1059` or `T1059.007`.
    Attack,
    /// [`OwaspId`](crate::OwaspId), `A03:2021`, `A05:2025` or `API1:2023`.
    Owasp,
    /// [`AsvsId`](crate::AsvsId), `V5`, `V5.3` or `V5.3.4`.
    Asvs,
}

impl IdKind {
    /// The notation this kind of id is written in, for error messages.
    #[must_use]
    pub const fn expected(self) -> &'static str {
        match self {
            Self::Cwe => "`CWE-` and a number without leading zeros, e.g. CWE-79",
            Self::Capec => "`CAPEC-` and a number without leading zeros, e.g. CAPEC-66",
            Self::Attack => "`T`, four digits and optionally `.` and three digits, e.g. T1059.007",
            Self::Owasp => "A01:2021 to A10:2021, A01:2025 to A10:2025 or API1:2023 to API10:2023",
            Self::Asvs => "`V` and one to three dot-separated numbers, e.g. V5.3.4",
        }
    }
}

impl fmt::Display for IdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cwe => "CWE",
            Self::Capec => "CAPEC",
            Self::Attack => "ATT&CK",
            Self::Owasp => "OWASP",
            Self::Asvs => "ASVS",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_is_bounded() {
        let long = "é".repeat(500);
        let Error::Malformed { input, .. } = Error::malformed(IdKind::Cwe, &long) else {
            panic!("expected Malformed");
        };
        assert_eq!(input.chars().count(), Error::MAX_ECHO + 1);
        assert!(input.ends_with('…'));
        assert_eq!(
            Error::malformed(IdKind::Asvs, ""),
            Error::Empty { kind: IdKind::Asvs }
        );
        assert_eq!(
            Error::malformed(IdKind::Cwe, "CWE-79 ").to_string(),
            "malformed CWE id \"CWE-79 \": expected `CWE-` and a number without leading zeros, e.g. CWE-79"
        );
    }
}
