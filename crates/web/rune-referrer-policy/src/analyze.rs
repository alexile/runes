//! Weakness analysis and the mapping to `rune_finding`.

use std::fmt;

use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};

use crate::{Header, ReferrerPolicy, Verdict, parse_meta};

/// The Referrer Policy specification.
const SPEC_URL: &str = "https://www.w3.org/TR/referrer-policy/";
/// OWASP guidance on the header.
const OWASP_URL: &str = "https://owasp.org/www-project-secure-headers/#referrer-policy";

/// The class of a [`Weakness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WeaknessKind {
    /// No `Referrer-Policy`: the browser default applies, which is
    /// `no-referrer-when-downgrade` (full URLs cross-origin) in older
    /// browsers.
    MissingHeader,
    /// The header names no policy browsers know, so the default applies.
    InvalidHeader,
    /// `unsafe-url`: full URLs go to every origin, also over plain HTTP.
    UnsafeUrl,
    /// `no-referrer-when-downgrade`: full URLs, with paths and query
    /// strings, go to every HTTPS origin.
    FullUrlCrossOrigin,
    /// `origin` / `origin-when-cross-origin`: the origin is sent over plain
    /// HTTP on downgrades.
    OriginOnDowngrade,
    /// A token that names no policy; browsers skip it.
    UnknownToken,
    /// The effective (last) policy leaks more than an earlier fallback
    /// token: browsers that know it use the weaker one.
    WeakerFallback,
    /// A legacy `<meta name="referrer">` keyword (`never`, `always`, …).
    LegacyKeyword,
}

impl WeaknessKind {
    /// The `snake_case` name, used in [`WeaknessKind::check_id`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingHeader => "missing_header",
            Self::InvalidHeader => "invalid_header",
            Self::UnsafeUrl => "unsafe_url",
            Self::FullUrlCrossOrigin => "full_url_cross_origin",
            Self::OriginOnDowngrade => "origin_on_downgrade",
            Self::UnknownToken => "unknown_token",
            Self::WeakerFallback => "weaker_fallback",
            Self::LegacyKeyword => "legacy_keyword",
        }
    }

    /// The stable `rune_finding` check id, `referrer_policy.<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("referrer_policy.{}", self.as_str())
    }

    /// What to do about it.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::MissingHeader
            | Self::InvalidHeader
            | Self::UnsafeUrl
            | Self::FullUrlCrossOrigin
            | Self::OriginOnDowngrade
            | Self::WeakerFallback => {
                "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer / \
                 same-origin for sensitive pages)."
            }
            Self::UnknownToken => "Remove or fix the token; browsers ignore it.",
            Self::LegacyKeyword => "Use the current keyword (no-referrer, unsafe-url, …).",
        }
    }

    /// CWE-200 for leaks, CWE-319 when they go over plain HTTP, CWE-598 for
    /// query strings in full URLs; CWE-693 otherwise.
    const fn cwes(self) -> &'static [u32] {
        match self {
            Self::UnsafeUrl => &[200, 319, 598],
            Self::FullUrlCrossOrigin | Self::MissingHeader | Self::InvalidHeader => &[200, 598],
            Self::OriginOnDowngrade => &[200, 319],
            Self::WeakerFallback => &[200],
            _ => &[693],
        }
    }
}

impl fmt::Display for WeaknessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One weakness found in a policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Weakness {
    /// The class of weakness.
    pub kind: WeaknessKind,
    /// How much it matters, in context.
    pub severity: Severity,
    /// The token concerned, when there is one.
    pub token: Option<String>,
    /// A human-readable explanation.
    pub message: String,
}

impl Weakness {
    fn new(kind: WeaknessKind, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            kind,
            severity,
            token: None,
            message: message.into(),
        }
    }

    fn at(mut self, token: &str) -> Self {
        self.token = Some(token.to_owned());
        self
    }

    /// Converts the weakness into a [`rune_finding::Finding`] with check id
    /// `referrer_policy.<kind>`, CWE references and a remediation. The
    /// token, when there is one, becomes evidence.
    #[must_use]
    pub fn to_finding<X: Default>(&self, location: &Location) -> Finding<X> {
        let mut finding = Finding::<X>::new(
            self.kind.check_id(),
            self.message.clone(),
            self.severity,
            Confidence::Firm,
            location.clone(),
        )
        .with_remediation(
            Remediation::new(self.kind.remediation())
                .push_reference(SPEC_URL)
                .push_reference(OWASP_URL),
        );
        for cwe in self.kind.cwes() {
            finding = finding.push_taxonomy(TaxonomyRef::cwe(*cwe));
        }
        if let Some(t) = &self.token {
            finding = finding.push_evidence(Evidence::new("token", t.clone()));
        }
        finding
    }
}

/// Settings for [`run`] and [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The page links to, embeds or requests other origins, so its
    /// referrer can reach them. On by default; off lowers the severity of
    /// leaks and of a missing policy one step.
    pub cross_origin: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { cross_origin: true }
    }
}

impl Options {
    /// Sets [`Options::cross_origin`].
    #[must_use]
    pub const fn with_cross_origin(mut self, cross_origin: bool) -> Self {
        self.cross_origin = cross_origin;
        self
    }

    const fn scale(&self, severity: Severity) -> Severity {
        if self.cross_origin {
            return severity;
        }
        match severity {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            _ => Severity::Informational,
        }
    }
}

/// The result of [`run`], [`run_fields`] and [`run_meta`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The policy the page sets, if any token was recognised.
    pub policy: Option<ReferrerPolicy>,
    /// Weaknesses, most severe first.
    pub weaknesses: Vec<Weakness>,
}

impl Report {
    /// The policy browsers apply: the one set, or the default
    /// (`strict-origin-when-cross-origin`).
    #[must_use]
    pub fn effective(&self) -> ReferrerPolicy {
        self.policy.unwrap_or_default()
    }

    /// The policy in canonical form (its keyword), if one is set.
    #[must_use]
    pub fn canonical(&self) -> Option<&'static str> {
        self.policy.map(ReferrerPolicy::as_str)
    }

    /// The most severe weakness level, if any.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.weaknesses.iter().map(|w| w.severity).max()
    }

    /// Every weakness as a [`rune_finding::Finding`] at `location`.
    #[must_use]
    pub fn to_findings<X: Default>(&self, location: &Location) -> Vec<Finding<X>> {
        self.weaknesses
            .iter()
            .map(|w| w.to_finding(location))
            .collect()
    }
}

/// Parses and analyzes one `Referrer-Policy` header value.
#[must_use]
pub fn run(header: &str, options: &Options) -> Report {
    run_fields([header], options)
}

/// Analyzes every `Referrer-Policy` field of one response; the fields are
/// combined into one comma-separated list, as browsers do. No field gives
/// [`WeaknessKind::MissingHeader`].
#[must_use]
pub fn run_fields<'a>(fields: impl IntoIterator<Item = &'a str>, options: &Options) -> Report {
    let fields: Vec<&str> = fields.into_iter().collect();
    let mut weaknesses = Vec::new();
    if fields.is_empty() {
        weaknesses.push(Weakness::new(
            WeaknessKind::MissingHeader,
            options.scale(Severity::Low),
            "No Referrer-Policy header: the browser default applies, and older browsers send \
             full URLs to other origins",
        ));
        return Report {
            policy: None,
            weaknesses,
        };
    }
    let header = Header::parse(&fields.join(","));
    for raw in header.unknown() {
        weaknesses.push(
            Weakness::new(
                WeaknessKind::UnknownToken,
                Severity::Informational,
                format!("Unknown referrer policy {raw} is ignored"),
            )
            .at(raw),
        );
    }
    let policy = header.policy();
    match policy {
        None => weaknesses.push(Weakness::new(
            WeaknessKind::InvalidHeader,
            options.scale(Severity::Low),
            "Referrer-Policy names no known policy, so the browser default applies",
        )),
        Some(p) => {
            weaknesses.extend(analyze(p, options));
            let earlier = header
                .tokens
                .iter()
                .filter_map(|t| t.policy)
                .filter(|e| e.verdict() < p.verdict())
                .min_by_key(|e| e.verdict());
            if let Some(e) = earlier {
                weaknesses.push(
                    Weakness::new(
                        WeaknessKind::WeakerFallback,
                        Severity::Low,
                        format!(
                            "{p} is the effective policy, but the header also lists the \
                             stricter {e}; browsers apply the last policy they know"
                        ),
                    )
                    .at(p.as_str()),
                );
            }
        }
    }
    sort(&mut weaknesses);
    Report { policy, weaknesses }
}

/// Analyzes a `<meta name="referrer">` `content` value. An unknown value
/// is an [`WeaknessKind::InvalidHeader`]: the element is ignored.
#[must_use]
pub fn run_meta(content: &str, options: &Options) -> Report {
    let mut weaknesses = Vec::new();
    let policy = match parse_meta(content) {
        Ok(m) => {
            if m.legacy {
                let raw = content.trim();
                weaknesses.push(
                    Weakness::new(
                        WeaknessKind::LegacyKeyword,
                        Severity::Informational,
                        format!("Legacy keyword {raw} stands for {}", m.policy),
                    )
                    .at(raw),
                );
            }
            weaknesses.extend(analyze(m.policy, options));
            Some(m.policy)
        }
        Err(e) => {
            weaknesses.push(Weakness::new(
                WeaknessKind::InvalidHeader,
                options.scale(Severity::Low),
                format!("The referrer meta element is ignored: {e}"),
            ));
            None
        }
    };
    sort(&mut weaknesses);
    Report { policy, weaknesses }
}

/// The weaknesses of one policy, from its [`Verdict`].
#[must_use]
pub fn analyze(policy: ReferrerPolicy, options: &Options) -> Vec<Weakness> {
    let w = match policy.verdict() {
        Verdict::Safe => return Vec::new(),
        Verdict::FullUrlEverywhere => Weakness::new(
            WeaknessKind::UnsafeUrl,
            options.scale(Severity::High),
            format!(
                "{policy} sends full URLs, with paths and query strings, to every origin, also \
                 over plain HTTP"
            ),
        ),
        Verdict::FullUrlCrossOrigin => Weakness::new(
            WeaknessKind::FullUrlCrossOrigin,
            options.scale(Severity::Medium),
            format!("{policy} sends full URLs, with paths and query strings, to other origins"),
        ),
        Verdict::OriginOnDowngrade => Weakness::new(
            WeaknessKind::OriginOnDowngrade,
            options.scale(Severity::Low),
            format!("{policy} sends the origin over plain HTTP when an HTTPS page links to HTTP"),
        ),
    };
    vec![w.at(policy.as_str())]
}

fn sort(weaknesses: &mut [Weakness]) {
    weaknesses.sort_by_key(|w| std::cmp::Reverse(w.severity));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(header: &str) -> Vec<(WeaknessKind, Severity)> {
        run(header, &Options::default())
            .weaknesses
            .into_iter()
            .map(|w| (w.kind, w.severity))
            .collect()
    }

    #[test]
    fn value_table_verdicts() {
        use Severity::{High, Low, Medium};
        use WeaknessKind as K;
        let table: [(&str, &[(K, Severity)]); 8] = [
            ("no-referrer", &[]),
            ("same-origin", &[]),
            ("strict-origin", &[]),
            ("strict-origin-when-cross-origin", &[]),
            ("origin", &[(K::OriginOnDowngrade, Low)]),
            ("origin-when-cross-origin", &[(K::OriginOnDowngrade, Low)]),
            (
                "no-referrer-when-downgrade",
                &[(K::FullUrlCrossOrigin, Medium)],
            ),
            ("unsafe-url", &[(K::UnsafeUrl, High)]),
        ];
        for (value, expected) in table {
            assert_eq!(kinds(value), expected, "{value}");
            assert_eq!(kinds(&value.to_ascii_uppercase()), expected, "{value}");
        }
    }

    #[test]
    fn missing_and_invalid() {
        let r = run_fields([], &Options::default());
        assert_eq!(r.weaknesses[0].kind, WeaknessKind::MissingHeader);
        assert_eq!(r.weaknesses[0].severity, Severity::Low);
        assert_eq!(r.effective(), ReferrerPolicy::StrictOriginWhenCrossOrigin);
        let r = run_fields([], &Options::default().with_cross_origin(false));
        assert_eq!(r.weaknesses[0].severity, Severity::Informational);
        assert_eq!(
            kinds("unsafe_url"),
            [
                (WeaknessKind::InvalidHeader, Severity::Low),
                (WeaknessKind::UnknownToken, Severity::Informational)
            ]
        );
        assert_eq!(kinds(""), [(WeaknessKind::InvalidHeader, Severity::Low)]);
    }

    #[test]
    fn fallbacks() {
        assert_eq!(kinds("no-referrer, strict-origin-when-cross-origin"), []);
        assert_eq!(
            kinds("no-referrer, unsafe-url, bogus"),
            [
                (WeaknessKind::UnsafeUrl, Severity::High),
                (WeaknessKind::WeakerFallback, Severity::Low),
                (WeaknessKind::UnknownToken, Severity::Informational),
            ]
        );
        let r = run_fields(["origin", "same-origin"], &Options::default());
        assert_eq!(r.canonical(), Some("same-origin"));
        assert_eq!(r.weaknesses, []);
    }

    #[test]
    fn context_and_meta() {
        let opts = Options::default().with_cross_origin(false);
        assert_eq!(
            run("unsafe-url", &opts).max_severity(),
            Some(Severity::Medium)
        );
        let r = run_meta("always", &Options::default());
        let k: Vec<_> = r.weaknesses.iter().map(|w| w.kind).collect();
        assert_eq!(k, [WeaknessKind::UnsafeUrl, WeaknessKind::LegacyKeyword]);
        let r = run_meta("bogus", &Options::default());
        assert_eq!(r.policy, None);
        assert_eq!(r.weaknesses[0].kind, WeaknessKind::InvalidHeader);
    }

    #[test]
    fn findings() {
        let r = run("unsafe-url", &Options::default());
        let f = r.to_findings::<()>(&Location::url("https://example.com/"));
        assert_eq!(f[0].check_id, "referrer_policy.unsafe_url");
        assert_eq!(f[0].severity, Severity::High);
    }
}
