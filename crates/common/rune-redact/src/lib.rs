//! Redact PII and secrets from text, streams, writers and logs.
//!
//! A [`Policy`] chooses the [`Category`]s to redact and how each one is
//! replaced; a [`Redactor`] compiles it once and is cheap to clone and share.
//! The detectors reuse the workspace's existing patterns instead of copying
//! them:
//!
//! - **Credentials** ([`Category::Credential`]): the `rune-leak` ruleset
//!   (AWS, GitHub, Slack, Stripe, private-key, `password = "…"`, …), plus
//!   any extra [`SecretRule`]s.
//! - **Structured tokens and PII**: `rune-regex-sec` for emails, IPv4, IPv6,
//!   JWTs and PEM private-key headers; local patterns for bearer tokens,
//!   credit cards, SSNs and US phone numbers.
//! - **Entropy** ([`Category::HighEntropy`]): `rune-entropy` flags any
//!   whitespace-delimited token above a threshold (default `4.5` bits/byte).
//!
//! Replacements ([`Replacement`]): a `[LABEL]` placeholder, a mask
//! (`****1234`), a keyed hash (`[EMAIL:3f2a9c1b04d7e6a8]`), or a numbered
//! token (`[EMAIL_1]`) that maps the same value to the same token and can be
//! [restored](Redactor::restore), e.g. in an LLM's reply.
//!
//! # Quick start
//!
//! ```rust
//! use rune_redact::redact;
//!
//! let clean = redact("Email me at user@example.com or call 555-123-4567");
//! assert_eq!(clean, "Email me at [EMAIL] or call [PHONE]");
//! ```
//!
//! # Policies
//!
//! ```rust
//! use rune_redact::{Category, Policy, Redactor, Replacement};
//!
//! let redactor = Redactor::new(
//!     Policy::default()
//!         .with_replacement(Replacement::Tokenize)
//!         .with_override(Category::CreditCard, Replacement::Mask { fill: '*', keep_last: 4 }),
//! )?;
//! let out = redactor.redact("bob@example.com paid with 4111 1111 1111 1234; cc bob@example.com");
//! assert_eq!(out, "[EMAIL_1] paid with ***************1234; cc [EMAIL_1]");
//! # Ok::<(), rune_redact::Error>(())
//! ```
//!
//! # Streams and writers
//!
//! [`StreamRedactor`] (sans-I/O), [`RedactingWriter`] (`std::io::Write`) and,
//! with the `tokio` feature, `AsyncRedactingWriter` redact on the fly without
//! buffering the whole payload. A value split across two writes is still
//! caught.
//!
//! ```rust
//! use std::io::Write;
//! use rune_redact::{RedactingWriter, Redactor};
//!
//! let mut w = RedactingWriter::new(Vec::new(), Redactor::default());
//! w.write_all(b"key=AKIAIOSFOD")?;
//! w.write_all(b"NN7EXAMPLE\n")?;
//! assert_eq!(w.finish()?, b"key=[CREDENTIAL]\n");
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! # Tracing
//!
//! With the `tracing` feature, `RedactingMakeWriter` redacts everything a
//! `tracing-subscriber` fmt layer writes, and `RedactingFields` redacts only
//! event and span fields.
//!
//! # Feature flags
//!
//! | Feature   | Adds |
//! |-----------|------|
//! | `tokio`   | `AsyncRedactingWriter` |
//! | `tracing` | `RedactingMakeWriter`, `RedactingFields` |
//! | `cli`     | the `rune-redact` binary |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::OnceLock;

mod category;
mod error;
mod hmac;
mod policy;
mod redactor;
mod stream;
mod vault;

#[cfg(feature = "tokio")]
mod async_io;
#[cfg(feature = "tracing")]
mod tracing;

#[cfg(feature = "tokio")]
pub use async_io::AsyncRedactingWriter;
pub use category::Category;
pub use error::Error;
pub use policy::{
    DEFAULT_ENTROPY_THRESHOLD, DEFAULT_MIN_ENTROPY_LEN, DEFAULT_VAULT_CAPACITY, Policy, Replacement,
};
pub use redactor::{Detection, Redactor};
pub use rune_leak::SecretRule;
pub use stream::{DEFAULT_MAX_BUFFER, DEFAULT_WINDOW, RedactingWriter, StreamRedactor};
#[cfg(feature = "tracing")]
pub use tracing::{RedactingFields, RedactingMakeWriter};
pub use vault::TokenVault;

/// Controls which of the original seven redaction rules are active.
///
/// Kept for compatibility; [`Policy`] covers every [`Category`] and the
/// replacement styles. [`redact_with`] converts a config to a policy with
/// `[LABEL]` placeholders.
///
/// # Example
///
/// ```rust
/// use rune_redact::RedactConfig;
///
/// // Only redact emails and high-entropy secrets
/// let config = RedactConfig {
///     emails: true,
///     high_entropy_tokens: true,
///     ..RedactConfig::none()
/// };
/// assert!(!config.ipv4);
/// ```
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent, documented switch"
)]
#[derive(Debug, Clone)]
pub struct RedactConfig {
    /// `user@example.com` → `[EMAIL]`
    pub emails: bool,
    /// `192.168.1.1` → `[IP]`
    pub ipv4: bool,
    /// `4111 1111 1111 1111` → `[CC]`
    pub credit_cards: bool,
    /// `555-123-4567` → `[PHONE]`
    pub phones: bool,
    /// `123-45-6789` → `[SSN]`
    pub ssns: bool,
    /// `Bearer eyJ...` → `[BEARER]`
    pub bearer_tokens: bool,
    /// Tokens whose Shannon entropy exceeds [`entropy_threshold`](Self::entropy_threshold)
    /// and whose length is at least [`min_token_length`](Self::min_token_length) → `[SECRET]`
    pub high_entropy_tokens: bool,
    /// Minimum entropy in bits/byte to flag a token as a secret. Default: `4.5`.
    /// Normal prose sits around 3–4; API keys and random tokens are typically above 4.5.
    pub entropy_threshold: f64,
    /// Tokens shorter than this are never flagged by entropy analysis. Default: `16`.
    pub min_token_length: usize,
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            emails: true,
            ipv4: true,
            credit_cards: true,
            phones: true,
            ssns: true,
            bearer_tokens: true,
            high_entropy_tokens: true,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            min_token_length: DEFAULT_MIN_ENTROPY_LEN,
        }
    }
}

impl RedactConfig {
    /// All rules disabled — enable only what you need.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_redact::RedactConfig;
    ///
    /// let config = RedactConfig { ssns: true, ..RedactConfig::none() };
    /// assert!(!config.emails);
    /// assert!(config.ssns);
    /// ```
    #[must_use]
    pub const fn none() -> Self {
        Self {
            emails: false,
            ipv4: false,
            credit_cards: false,
            phones: false,
            ssns: false,
            bearer_tokens: false,
            high_entropy_tokens: false,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            min_token_length: DEFAULT_MIN_ENTROPY_LEN,
        }
    }
}

impl From<&RedactConfig> for Policy {
    fn from(config: &RedactConfig) -> Self {
        let flags = [
            (config.emails, Category::Email),
            (config.ipv4, Category::Ipv4),
            (config.credit_cards, Category::CreditCard),
            (config.phones, Category::Phone),
            (config.ssns, Category::Ssn),
            (config.bearer_tokens, Category::BearerToken),
            (config.high_entropy_tokens, Category::HighEntropy),
        ];
        Self::none()
            .with_categories(flags.into_iter().filter(|(on, _)| *on).map(|(_, c)| c))
            .with_entropy_threshold(config.entropy_threshold)
            .with_min_entropy_len(config.min_token_length)
    }
}

/// Redacts every [`Category`] in `text` with `[LABEL]` placeholders, using
/// a shared [`Redactor::default()`].
///
/// # Example
///
/// ```rust
/// use rune_redact::redact;
///
/// let out = redact("Contact user@example.com, key AKIAIOSFODNN7EXAMPLE");
/// assert_eq!(out, "Contact [EMAIL], key [CREDENTIAL]");
/// ```
#[must_use]
pub fn redact(text: &str) -> String {
    static DEFAULT: OnceLock<Redactor> = OnceLock::new();
    DEFAULT.get_or_init(Redactor::default).redact(text)
}

/// Redacts `text` with the rules enabled in `config`, using `[LABEL]`
/// placeholders. Compiles the config on every call: for repeated use, build
/// a [`Redactor`] from [`Policy::from`] once.
///
/// # Example
///
/// ```rust
/// use rune_redact::{redact_with, RedactConfig};
///
/// let config = RedactConfig { phones: true, ..RedactConfig::none() };
/// let out = redact_with("Call 555-123-4567 or email a@b.com", &config);
/// assert_eq!(out, "Call [PHONE] or email a@b.com");
/// ```
#[must_use]
pub fn redact_with(text: &str, config: &RedactConfig) -> String {
    // Only a non-finite or negative threshold fails; then fall back to the
    // other rules rather than returning the text unredacted.
    Redactor::new(Policy::from(config))
        .or_else(|_| Redactor::new(Policy::from(config).without_category(Category::HighEntropy)))
        .map_or_else(|_| String::new(), |r| r.redact(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_email() {
        assert_eq!(
            redact("Send to user@example.com please"),
            "Send to [EMAIL] please"
        );
    }

    #[test]
    fn redacts_multiple_emails() {
        let out = redact("a@b.com and c@d.org are both here");
        assert_eq!(out.matches("[EMAIL]").count(), 2);
        assert!(!out.contains("a@b.com"));
    }

    #[test]
    fn redacts_ipv4() {
        assert_eq!(
            redact("Server at 192.168.1.100 is down"),
            "Server at [IP] is down"
        );
    }

    #[test]
    fn redacts_ssn() {
        assert_eq!(redact("SSN is 123-45-6789 on file"), "SSN is [SSN] on file");
    }

    #[test]
    fn redacts_credit_card() {
        let out = redact("Card: 4111 1111 1111 1111");
        assert_eq!(out, "Card: [CC]");
    }

    #[test]
    fn redacts_phone() {
        assert_eq!(redact("Call 555-123-4567 now"), "Call [PHONE] now");
    }

    #[test]
    fn redacts_bearer_token() {
        let out = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
        assert_eq!(out, "Authorization: [BEARER]");
    }

    #[test]
    fn redacts_high_entropy_token() {
        // Pure hex strings (sha hashes) sit at ~4.0 bits/byte and are not
        // flagged; this token is ~5.8 bits/byte.
        let token = "sK3xPq9mNbYrVwZuAtJhCf7DgLeW2oI5qR8eMvXn";
        let out = redact(&format!("API key: {token}"));
        assert!(
            out.contains("[SECRET]") || out.contains("[CREDENTIAL]"),
            "got: {out}"
        );
        assert!(!out.contains(token));
    }

    #[test]
    fn leaves_normal_prose_alone() {
        let text = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(redact(text), text);
    }

    #[test]
    fn config_none_redacts_nothing() {
        let text = "user@example.com and 123-45-6789";
        assert_eq!(redact_with(text, &RedactConfig::none()), text);
    }

    #[test]
    fn selective_config() {
        let config = RedactConfig {
            emails: true,
            ..RedactConfig::none()
        };
        assert_eq!(
            redact_with("user@example.com and 123-45-6789", &config),
            "[EMAIL] and 123-45-6789"
        );
    }

    #[test]
    fn invalid_threshold_still_redacts_the_rest() {
        let config = RedactConfig {
            entropy_threshold: f64::NAN,
            ..RedactConfig::default()
        };
        assert_eq!(redact_with("a@b.io", &config), "[EMAIL]");
    }

    #[test]
    fn short_tokens_not_flagged_by_entropy() {
        let out = redact("token: secretx");
        assert!(!out.contains("[SECRET]"));
    }
}
