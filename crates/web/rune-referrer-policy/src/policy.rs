//! Referrer policies, what they send, and header / meta parsing.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// A referrer policy ([Referrer Policy §3](https://www.w3.org/TR/referrer-policy/#referrer-policies)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[non_exhaustive]
pub enum ReferrerPolicy {
    /// `no-referrer`: never send a referrer.
    NoReferrer,
    /// `same-origin`: the full URL to the same origin, nothing elsewhere.
    SameOrigin,
    /// `strict-origin`: the origin, except on HTTPS → HTTP.
    StrictOrigin,
    /// `strict-origin-when-cross-origin`: the full URL to the same origin,
    /// the origin cross-origin, nothing on HTTPS → HTTP. The browser
    /// default.
    #[default]
    StrictOriginWhenCrossOrigin,
    /// `origin`: the origin, always (also over HTTP).
    Origin,
    /// `origin-when-cross-origin`: the full URL to the same origin, the
    /// origin elsewhere (also over HTTP).
    OriginWhenCrossOrigin,
    /// `no-referrer-when-downgrade`: the full URL everywhere except on
    /// HTTPS → HTTP. The default of older browsers.
    NoReferrerWhenDowngrade,
    /// `unsafe-url`: the full URL everywhere, also over HTTP.
    UnsafeUrl,
}

/// Where a request goes, relative to the document sending it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RequestKind {
    /// Same origin.
    SameOrigin,
    /// Another origin, without a downgrade (HTTPS → HTTPS, or from HTTP).
    CrossOrigin,
    /// From an HTTPS document to an `http://` URL.
    Downgrade,
}

impl RequestKind {
    /// Every kind, for tables.
    pub const ALL: [Self; 3] = [Self::SameOrigin, Self::CrossOrigin, Self::Downgrade];
}

/// What a request carries in `Referer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Referrer {
    /// No `Referer` header.
    None,
    /// The origin only (`https://example.com/`).
    Origin,
    /// The full URL without fragment and credentials: path and query too.
    Full,
}

/// How leak-prone a policy is, worst exposure first wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Verdict {
    /// Nothing beyond the origin leaves the site, and nothing goes over
    /// plain HTTP.
    Safe,
    /// The origin is sent over plain HTTP on downgrades.
    OriginOnDowngrade,
    /// Full URLs (paths, query tokens) go to other origins over HTTPS.
    FullUrlCrossOrigin,
    /// Full URLs go to every origin, also over plain HTTP.
    FullUrlEverywhere,
}

impl ReferrerPolicy {
    /// Every policy, from strictest to loosest.
    pub const ALL: [Self; 8] = [
        Self::NoReferrer,
        Self::SameOrigin,
        Self::StrictOrigin,
        Self::StrictOriginWhenCrossOrigin,
        Self::Origin,
        Self::OriginWhenCrossOrigin,
        Self::NoReferrerWhenDowngrade,
        Self::UnsafeUrl,
    ];

    /// The keyword, as written in headers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::SameOrigin => "same-origin",
            Self::StrictOrigin => "strict-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Self::Origin => "origin",
            Self::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Self::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Self::UnsafeUrl => "unsafe-url",
        }
    }

    /// The policy named by `token`, ignoring ASCII case as browsers do.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(token))
    }

    /// What a request of `kind` carries under this policy (Fetch,
    /// "determine request's referrer").
    #[must_use]
    pub const fn referrer(self, kind: RequestKind) -> Referrer {
        use RequestKind as K;
        match (self, kind) {
            (Self::NoReferrer, _)
            | (Self::SameOrigin, K::CrossOrigin | K::Downgrade)
            | (
                Self::StrictOrigin
                | Self::StrictOriginWhenCrossOrigin
                | Self::NoReferrerWhenDowngrade,
                K::Downgrade,
            ) => Referrer::None,
            (Self::Origin | Self::StrictOrigin, _)
            | (
                Self::OriginWhenCrossOrigin | Self::StrictOriginWhenCrossOrigin,
                K::CrossOrigin | K::Downgrade,
            ) => Referrer::Origin,
            _ => Referrer::Full,
        }
    }

    /// How leak-prone the policy is.
    #[must_use]
    pub const fn verdict(self) -> Verdict {
        match (
            self.referrer(RequestKind::CrossOrigin),
            self.referrer(RequestKind::Downgrade),
        ) {
            (_, Referrer::Full) => Verdict::FullUrlEverywhere,
            (Referrer::Full, _) => Verdict::FullUrlCrossOrigin,
            (_, Referrer::Origin) => Verdict::OriginOnDowngrade,
            _ => Verdict::Safe,
        }
    }
}

impl fmt::Display for ReferrerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReferrerPolicy {
    type Err = Error;

    /// One policy keyword, trimmed, ignoring ASCII case.
    fn from_str(s: &str) -> Result<Self, Error> {
        let t = s.trim_matches([' ', '\t']);
        Self::from_token(t).ok_or_else(|| Error::UnknownPolicy {
            token: t.to_owned(),
        })
    }
}

/// One comma-separated token of a `Referrer-Policy` header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Token {
    /// The token as written, without surrounding whitespace.
    pub raw: String,
    /// The policy it names, if it names one.
    pub policy: Option<ReferrerPolicy>,
}

/// A parsed `Referrer-Policy` header: every token, in order.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct Header {
    /// Every non-empty token, in order.
    pub tokens: Vec<Token>,
}

impl Header {
    /// Splits a header value (or several field values joined with `,`)
    /// into tokens. Never fails: browsers skip unknown tokens.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        let tokens = value
            .split(',')
            .map(|t| t.trim_matches([' ', '\t']))
            .filter(|t| !t.is_empty())
            .map(|t| Token {
                raw: t.to_owned(),
                policy: ReferrerPolicy::from_token(t),
            })
            .collect();
        Self { tokens }
    }

    /// The policy browsers apply: the last recognised token (Referrer
    /// Policy §8.1). `None` when no token is recognised, in which case the
    /// browser default applies.
    #[must_use]
    pub fn policy(&self) -> Option<ReferrerPolicy> {
        self.tokens.iter().rev().find_map(|t| t.policy)
    }

    /// Tokens that name no policy.
    pub fn unknown(&self) -> impl Iterator<Item = &str> {
        self.tokens
            .iter()
            .filter(|t| t.policy.is_none())
            .map(|t| t.raw.as_str())
    }
}

/// A legacy `<meta name="referrer">` keyword and the policy HTML maps it
/// to.
const META_LEGACY: &[(&str, ReferrerPolicy)] = &[
    ("never", ReferrerPolicy::NoReferrer),
    ("default", ReferrerPolicy::StrictOriginWhenCrossOrigin),
    ("always", ReferrerPolicy::UnsafeUrl),
    (
        "origin-when-crossorigin",
        ReferrerPolicy::OriginWhenCrossOrigin,
    ),
];

/// The value of a `<meta name="referrer" content=…>` element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MetaValue {
    /// The policy it sets.
    pub policy: ReferrerPolicy,
    /// The content used a legacy keyword (`never`, `default`, `always`,
    /// `origin-when-crossorigin`).
    pub legacy: bool,
}

/// Parses a `<meta name="referrer">` `content` value (HTML §4.2.5.3): one
/// keyword, ignoring ASCII case, legacy keywords included.
///
/// # Errors
///
/// [`Error::UnknownPolicy`] when the content names no policy; the meta
/// element is then ignored.
pub fn parse_meta(content: &str) -> Result<MetaValue, Error> {
    let t = content.trim_matches([' ', '\t', '\n', '\r', '\x0c']);
    if let Some(policy) = ReferrerPolicy::from_token(t) {
        return Ok(MetaValue {
            policy,
            legacy: false,
        });
    }
    META_LEGACY
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(t))
        .map(|&(_, policy)| MetaValue {
            policy,
            legacy: true,
        })
        .ok_or_else(|| Error::UnknownPolicy {
            token: t.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use Referrer::{Full, None as No, Origin as O};
    use ReferrerPolicy as P;

    #[test]
    fn referrer_table() {
        // Columns: same-origin, cross-origin, downgrade.
        let table = [
            (P::NoReferrer, [No, No, No], Verdict::Safe),
            (P::SameOrigin, [Full, No, No], Verdict::Safe),
            (P::StrictOrigin, [O, O, No], Verdict::Safe),
            (P::StrictOriginWhenCrossOrigin, [Full, O, No], Verdict::Safe),
            (P::Origin, [O, O, O], Verdict::OriginOnDowngrade),
            (
                P::OriginWhenCrossOrigin,
                [Full, O, O],
                Verdict::OriginOnDowngrade,
            ),
            (
                P::NoReferrerWhenDowngrade,
                [Full, Full, No],
                Verdict::FullUrlCrossOrigin,
            ),
            (P::UnsafeUrl, [Full, Full, Full], Verdict::FullUrlEverywhere),
        ];
        for (p, sent, verdict) in table {
            let got = RequestKind::ALL.map(|k| p.referrer(k));
            assert_eq!(got, sent, "{p}");
            assert_eq!(p.verdict(), verdict, "{p}");
        }
        assert_eq!(table.map(|t| t.0), P::ALL);
    }

    #[test]
    fn keywords_round_trip() {
        for p in P::ALL {
            assert_eq!(p.as_str().parse(), Ok(p));
            assert_eq!(p.as_str().to_ascii_uppercase().parse(), Ok(p));
        }
        assert_eq!(
            " nope ".parse::<P>(),
            Err(Error::UnknownPolicy {
                token: "nope".into()
            })
        );
        assert_eq!(P::default(), P::StrictOriginWhenCrossOrigin);
    }

    #[test]
    fn header_last_valid_wins() {
        let h = Header::parse("no-referrer, , foo ,strict-origin-when-cross-origin,bar");
        assert_eq!(h.policy(), Some(P::StrictOriginWhenCrossOrigin));
        assert_eq!(h.unknown().collect::<Vec<_>>(), ["foo", "bar"]);
        assert_eq!(h.tokens.len(), 4);
        assert_eq!(Header::parse("").policy(), None);
        assert_eq!(Header::parse("unsafe_url").policy(), None);
    }

    #[test]
    fn meta_values() {
        assert_eq!(
            parse_meta(" Never "),
            Ok(MetaValue {
                policy: P::NoReferrer,
                legacy: true
            })
        );
        assert_eq!(parse_meta("always").map(|m| m.policy), Ok(P::UnsafeUrl));
        assert_eq!(
            parse_meta("origin-when-crossorigin").map(|m| m.policy),
            Ok(P::OriginWhenCrossOrigin)
        );
        assert_eq!(
            parse_meta("same-origin"),
            Ok(MetaValue {
                policy: P::SameOrigin,
                legacy: false
            })
        );
        assert!(parse_meta("no-referrer, origin").is_err());
    }
}
