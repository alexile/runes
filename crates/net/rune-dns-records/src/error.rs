//! The crate's error type.

use core::fmt;

/// The kind of record a parser or check works on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RecordKind {
    /// Sender Policy Framework `TXT` record (RFC 7208).
    Spf,
    /// DKIM public key `TXT` record (RFC 6376 §3.6.1).
    Dkim,
    /// DMARC policy `TXT` record (RFC 7489).
    Dmarc,
    /// MTA-STS `TXT` record at `_mta-sts.<domain>` (RFC 8461 §3.1).
    MtaSts,
    /// MTA-STS policy file served over HTTPS (RFC 8461 §3.2).
    MtaStsPolicy,
    /// SMTP TLS Reporting `TXT` record at `_smtp._tls.<domain>` (RFC 8460).
    TlsRpt,
    /// BIMI assertion `TXT` record at `<selector>._bimi.<domain>`.
    Bimi,
    /// Certification Authority Authorization records (RFC 8659).
    Caa,
    /// DANE `TLSA` records (RFC 6698).
    Tlsa,
    /// DNSSEC `DS`, `DNSKEY` and `RRSIG` records (RFC 4034).
    Dnssec,
}

impl RecordKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::Spf,
        Self::Dkim,
        Self::Dmarc,
        Self::MtaSts,
        Self::MtaStsPolicy,
        Self::TlsRpt,
        Self::Bimi,
        Self::Caa,
        Self::Tlsa,
        Self::Dnssec,
    ];

    /// The lowercase identifier used in check ids, e.g. `mta_sts`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spf => "spf",
            Self::Dkim => "dkim",
            Self::Dmarc => "dmarc",
            Self::MtaSts => "mta_sts",
            Self::MtaStsPolicy => "mta_sts_policy",
            Self::TlsRpt => "tls_rpt",
            Self::Bimi => "bimi",
            Self::Caa => "caa",
            Self::Tlsa => "tlsa",
            Self::Dnssec => "dnssec",
        }
    }

    /// The conventional display name, e.g. `MTA-STS`.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Spf => "SPF",
            Self::Dkim => "DKIM",
            Self::Dmarc => "DMARC",
            Self::MtaSts => "MTA-STS",
            Self::MtaStsPolicy => "MTA-STS policy",
            Self::TlsRpt => "TLS-RPT",
            Self::Bimi => "BIMI",
            Self::Caa => "CAA",
            Self::Tlsa => "TLSA",
            Self::Dnssec => "DNSSEC",
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Errors returned by the parsers of this crate.
///
/// Every variant names the [`RecordKind`] it concerns, so a caller can turn
/// any error into an "invalid record" [`Issue`](crate::Issue) with
/// [`Issue::invalid`](crate::Issue::invalid).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text is not a record of this kind: the version tag is missing or
    /// wrong.
    #[error("not a {record} record: {reason}")]
    NotThisRecord {
        /// The record kind that was expected.
        record: RecordKind,
        /// What is missing or wrong.
        reason: &'static str,
    },
    /// More than one record of a kind that must be unique was published.
    #[error("{count} {record} records published where at most one is allowed")]
    MultipleRecords {
        /// The record kind.
        record: RecordKind,
        /// How many were found.
        count: usize,
    },
    /// A term, field or value does not match the record's grammar.
    #[error("invalid {record} record: {reason} in `{token}`")]
    Syntax {
        /// The record kind.
        record: RecordKind,
        /// The offending text (truncated to 64 characters).
        token: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A tag or field appears more than once.
    #[error("{record} tag `{tag}` appears more than once")]
    DuplicateTag {
        /// The record kind.
        record: RecordKind,
        /// The repeated tag.
        tag: String,
    },
    /// A required tag or field is missing.
    #[error("{record} record lacks the required `{tag}` tag")]
    MissingTag {
        /// The record kind.
        record: RecordKind,
        /// The missing tag.
        tag: &'static str,
    },
    /// A known tag or field has a value outside its grammar.
    #[error("invalid value for {record} tag `{tag}`: {reason}")]
    InvalidTag {
        /// The record kind.
        record: RecordKind,
        /// The tag.
        tag: String,
        /// What is wrong with its value.
        reason: &'static str,
    },
    /// The input is longer than the format allows.
    #[error("{record} input of {len} bytes is longer than the limit of {max}")]
    TooLong {
        /// The record kind.
        record: RecordKind,
        /// Length of the input.
        len: usize,
        /// The limit.
        max: usize,
    },
}

impl Error {
    /// The record kind the error concerns.
    #[must_use]
    pub const fn record(&self) -> RecordKind {
        match self {
            Self::NotThisRecord { record, .. }
            | Self::MultipleRecords { record, .. }
            | Self::Syntax { record, .. }
            | Self::DuplicateTag { record, .. }
            | Self::MissingTag { record, .. }
            | Self::InvalidTag { record, .. }
            | Self::TooLong { record, .. } => *record,
        }
    }

    /// A [`Error::Syntax`] carrying at most 64 characters of `token`.
    pub(crate) fn syntax(record: RecordKind, token: &str, reason: &'static str) -> Self {
        Self::Syntax {
            record,
            token: truncate(token),
            reason,
        }
    }

    /// An [`Error::InvalidTag`].
    pub(crate) fn invalid_tag(record: RecordKind, tag: &str, reason: &'static str) -> Self {
        Self::InvalidTag {
            record,
            tag: truncate(tag),
            reason,
        }
    }
}

/// `text` cut to 64 characters, with `…` when something was cut.
pub fn truncate(text: &str) -> String {
    const MAX: usize = 64;
    let mut chars = text.char_indices();
    match chars.nth(MAX) {
        None => text.to_owned(),
        Some((end, _)) => format!("{}…", &text[..end]),
    }
}
