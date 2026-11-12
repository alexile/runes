//! What kinds of sensitive data the redactor knows about.

use std::fmt;

/// A class of sensitive data.
///
/// The declaration order is also the **priority** order: when detections of
/// two categories overlap, the one listed first wins and the other is
/// dropped. Specific credential formats come before generic PII, and the
/// entropy heuristic comes last.
///
/// # Example
///
/// ```rust
/// use rune_redact::Category;
///
/// assert_eq!(Category::Email.label(), "EMAIL");
/// assert_eq!(Category::from_name("credit_card"), Some(Category::CreditCard));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Category {
    /// `Authorization: Bearer <token>` values.
    BearerToken,
    /// PEM private-key headers (`-----BEGIN RSA PRIVATE KEY-----`), from
    /// `rune-regex-sec`.
    PrivateKey,
    /// JSON Web Tokens (`eyJ….….…`), from `rune-regex-sec`.
    Jwt,
    /// Provider credentials (AWS, GitHub, Slack, Stripe, generic
    /// `password = "…"` assignments, …) found by the `rune-leak` ruleset.
    Credential,
    /// Visa, Mastercard, Amex and Discover card numbers.
    CreditCard,
    /// US social security numbers (`123-45-6789`).
    Ssn,
    /// Email addresses, from `rune-regex-sec`.
    Email,
    /// IPv4 addresses, from `rune-regex-sec`.
    Ipv4,
    /// IPv6 addresses, from `rune-regex-sec`.
    Ipv6,
    /// US phone numbers.
    Phone,
    /// Whitespace-delimited tokens whose Shannon entropy is above a threshold:
    /// API keys and random secrets with no fixed format.
    HighEntropy,
}

impl Category {
    /// Every category, in priority order.
    pub const ALL: [Self; 11] = [
        Self::BearerToken,
        Self::PrivateKey,
        Self::Jwt,
        Self::Credential,
        Self::CreditCard,
        Self::Ssn,
        Self::Email,
        Self::Ipv4,
        Self::Ipv6,
        Self::Phone,
        Self::HighEntropy,
    ];

    /// The placeholder label, used as `[LABEL]` by
    /// [`Replacement::Label`](crate::Replacement::Label).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BearerToken => "BEARER",
            Self::PrivateKey => "PRIVATE_KEY",
            Self::Jwt => "JWT",
            Self::Credential => "CREDENTIAL",
            Self::CreditCard => "CC",
            Self::Ssn => "SSN",
            Self::Email => "EMAIL",
            Self::Ipv4 | Self::Ipv6 => "IP",
            Self::Phone => "PHONE",
            Self::HighEntropy => "SECRET",
        }
    }

    /// The stable snake-case name (`"credit_card"`), for configuration files.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BearerToken => "bearer_token",
            Self::PrivateKey => "private_key",
            Self::Jwt => "jwt",
            Self::Credential => "credential",
            Self::CreditCard => "credit_card",
            Self::Ssn => "ssn",
            Self::Email => "email",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Phone => "phone",
            Self::HighEntropy => "high_entropy",
        }
    }

    /// Parses a [`name`](Self::name), case-insensitively.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|c| c.name().eq_ignore_ascii_case(name))
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for c in Category::ALL {
            assert_eq!(Category::from_name(c.name()), Some(c));
            assert_eq!(c.to_string(), c.name());
        }
        assert_eq!(Category::from_name("EMAIL"), Some(Category::Email));
        assert_eq!(Category::from_name("nope"), None);
    }

    #[test]
    fn all_is_sorted_by_priority() {
        let mut sorted = Category::ALL;
        sorted.sort();
        assert_eq!(sorted, Category::ALL);
    }
}
