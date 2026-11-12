//! Weakness analysis and the mapping to `rune_finding`.

use std::fmt;

use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};

use crate::preload::{PRELOAD_MIN_MAX_AGE, RFC_URL, header_issues};
use crate::{Error, Hsts};

/// OWASP cheat sheet with deployment guidance.
const CHEAT_SHEET_URL: &str = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html";

/// One day, in seconds.
const DAY: u64 = 86_400;

/// Directive names that look like a known directive misspelled.
const MISSPELLINGS: &[(&str, &str)] = &[
    ("maxage", "max-age"),
    ("max_age", "max-age"),
    ("includesubdomain", "includeSubDomains"),
    ("include-subdomains", "includeSubDomains"),
    ("include_subdomains", "includeSubDomains"),
    ("include-sub-domains", "includeSubDomains"),
    ("preloaded", "preload"),
    ("pre-load", "preload"),
];

/// The class of a [`Weakness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WeaknessKind {
    /// The response has no `Strict-Transport-Security` header.
    MissingHeader,
    /// The header has no `max-age`, so browsers ignore it.
    MissingMaxAge,
    /// `max-age` is not a number, so browsers ignore the header.
    InvalidMaxAge,
    /// `max-age` or `includeSubDomains` is repeated (browsers ignore the
    /// header), or another directive is repeated.
    DuplicateDirective,
    /// The header breaks the grammar in another way, so browsers ignore it.
    InvalidHeader,
    /// `max-age=0`: browsers delete the host's HSTS policy.
    MaxAgeZero,
    /// `max-age` is below the configured minimum.
    ShortMaxAge,
    /// No `includeSubDomains`: subdomains stay reachable over HTTP, which
    /// allows cookie injection.
    MissingIncludeSubdomains,
    /// `preload` is set but the header does not meet the preload list's
    /// requirements.
    PreloadIneligible,
    /// A directive that takes no value has one and is not honored.
    ValuedDirective,
    /// A directive name that looks like a misspelled known directive.
    MisspelledDirective,
    /// A directive no specification defines; browsers ignore it.
    UnknownDirective,
    /// Several header fields; browsers honor only the first.
    MultipleHeaders,
    /// The header came over plain HTTP, where browsers ignore it.
    InsecureTransport,
}

impl WeaknessKind {
    /// The `snake_case` name, used in [`WeaknessKind::check_id`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingHeader => "missing_header",
            Self::MissingMaxAge => "missing_max_age",
            Self::InvalidMaxAge => "invalid_max_age",
            Self::DuplicateDirective => "duplicate_directive",
            Self::InvalidHeader => "invalid_header",
            Self::MaxAgeZero => "max_age_zero",
            Self::ShortMaxAge => "short_max_age",
            Self::MissingIncludeSubdomains => "missing_include_subdomains",
            Self::PreloadIneligible => "preload_ineligible",
            Self::ValuedDirective => "valued_directive",
            Self::MisspelledDirective => "misspelled_directive",
            Self::UnknownDirective => "unknown_directive",
            Self::MultipleHeaders => "multiple_headers",
            Self::InsecureTransport => "insecure_transport",
        }
    }

    /// The stable `rune_finding` check id, `hsts.<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("hsts.{}", self.as_str())
    }

    /// What to do about it.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::MissingHeader
            | Self::MissingMaxAge
            | Self::InvalidMaxAge
            | Self::InvalidHeader
            | Self::MaxAgeZero
            | Self::ShortMaxAge => {
                "Send Strict-Transport-Security: max-age=63072000; includeSubDomains on every \
                 HTTPS response."
            }
            Self::DuplicateDirective => "List each directive once.",
            Self::MissingIncludeSubdomains => {
                "Add includeSubDomains once every subdomain serves HTTPS."
            }
            Self::PreloadIneligible => {
                "Use max-age of at least 31536000 with includeSubDomains, or drop preload."
            }
            Self::ValuedDirective => "Write includeSubDomains and preload without a value.",
            Self::MisspelledDirective => {
                "Fix the directive name: max-age, includeSubDomains, preload."
            }
            Self::UnknownDirective => "Remove the directive; browsers ignore it.",
            Self::MultipleHeaders => "Send a single Strict-Transport-Security header.",
            Self::InsecureTransport => {
                "Redirect HTTP to HTTPS and send the header on HTTPS responses only."
            }
        }
    }

    /// CWE-693 for all, plus CWE-319 when traffic may go out in clear text.
    const fn cwes(self) -> &'static [u32] {
        match self {
            Self::MissingHeader
            | Self::MissingMaxAge
            | Self::InvalidMaxAge
            | Self::InvalidHeader
            | Self::MaxAgeZero
            | Self::ShortMaxAge
            | Self::MissingIncludeSubdomains => &[693, 319],
            _ => &[693],
        }
    }
}

impl fmt::Display for WeaknessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One weakness found in a header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Weakness {
    /// The class of weakness.
    pub kind: WeaknessKind,
    /// How much it matters, in context.
    pub severity: Severity,
    /// The directive concerned, when there is one (lowercase).
    pub directive: Option<String>,
    /// A human-readable explanation.
    pub message: String,
}

impl Weakness {
    fn new(kind: WeaknessKind, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            kind,
            severity,
            directive: None,
            message: message.into(),
        }
    }

    fn at(mut self, directive: &str) -> Self {
        self.directive = Some(directive.to_owned());
        self
    }

    /// Converts the weakness into a [`rune_finding::Finding`] with check id
    /// `hsts.<kind>`, CWE references and a remediation. The directive, when
    /// there is one, becomes the location parameter and evidence.
    #[must_use]
    pub fn to_finding<X: Default>(&self, location: &Location) -> Finding<X> {
        let location = self.directive.as_ref().map_or_else(
            || location.clone(),
            |d| location.clone().with_parameter(d.clone()),
        );
        let mut finding = Finding::<X>::new(
            self.kind.check_id(),
            self.message.clone(),
            self.severity,
            Confidence::Firm,
            location,
        )
        .with_remediation(
            Remediation::new(self.kind.remediation())
                .push_reference(RFC_URL)
                .push_reference(CHEAT_SHEET_URL),
        );
        for cwe in self.kind.cwes() {
            finding = finding.push_taxonomy(TaxonomyRef::cwe(*cwe));
        }
        if let Some(d) = &self.directive {
            finding = finding.push_evidence(Evidence::new("directive", d.clone()));
        }
        finding
    }
}

/// Settings for [`run`] and [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// `max-age` below this is a [`WeaknessKind::ShortMaxAge`]. Defaults
    /// to one year ([`PRELOAD_MIN_MAX_AGE`]), as OWASP recommends.
    pub min_max_age: u64,
    /// Report a missing `includeSubDomains`. On by default.
    pub check_include_subdomains: bool,
    /// The header came over plain HTTP. Adds a
    /// [`WeaknessKind::InsecureTransport`] weakness.
    pub insecure_transport: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            min_max_age: PRELOAD_MIN_MAX_AGE,
            check_include_subdomains: true,
            insecure_transport: false,
        }
    }
}

impl Options {
    /// Sets [`Options::min_max_age`].
    #[must_use]
    pub const fn with_min_max_age(mut self, seconds: u64) -> Self {
        self.min_max_age = seconds;
        self
    }

    /// Sets [`Options::check_include_subdomains`].
    #[must_use]
    pub const fn with_check_include_subdomains(mut self, check: bool) -> Self {
        self.check_include_subdomains = check;
        self
    }

    /// Sets [`Options::insecure_transport`].
    #[must_use]
    pub const fn with_insecure_transport(mut self, insecure: bool) -> Self {
        self.insecure_transport = insecure;
        self
    }
}

/// The result of [`run`] and [`run_fields`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The effective policy, when the (first) header parsed.
    pub hsts: Option<Hsts>,
    /// Why the header did not parse, if it did not.
    pub error: Option<Error>,
    /// Weaknesses, most severe first.
    pub weaknesses: Vec<Weakness>,
}

impl Report {
    /// The policy in canonical form, if it parsed.
    #[must_use]
    pub fn canonical(&self) -> Option<String> {
        self.hsts.as_ref().map(ToString::to_string)
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

/// Parses and analyzes one `Strict-Transport-Security` header value.
#[must_use]
pub fn run(header: &str, options: &Options) -> Report {
    run_fields([header], options)
}

/// Analyzes every `Strict-Transport-Security` field of one response.
///
/// No field gives [`WeaknessKind::MissingHeader`]; several give
/// [`WeaknessKind::MultipleHeaders`], and only the first is analyzed, as
/// browsers honor only the first (RFC 6797 §8.1).
#[must_use]
pub fn run_fields<'a>(fields: impl IntoIterator<Item = &'a str>, options: &Options) -> Report {
    let mut fields = fields.into_iter();
    let mut weaknesses = Vec::new();
    let Some(first) = fields.next() else {
        weaknesses.push(Weakness::new(
            WeaknessKind::MissingHeader,
            Severity::Medium,
            "No Strict-Transport-Security header: first visits and typed URLs can be \
             downgraded to HTTP",
        ));
        return Report {
            hsts: None,
            error: None,
            weaknesses,
        };
    };
    let extra = fields.count();
    if extra > 0 {
        weaknesses.push(Weakness::new(
            WeaknessKind::MultipleHeaders,
            Severity::Low,
            format!(
                "{} Strict-Transport-Security headers; browsers honor only the first",
                extra + 1
            ),
        ));
    }
    if options.insecure_transport {
        weaknesses.push(Weakness::new(
            WeaknessKind::InsecureTransport,
            Severity::Informational,
            "Strict-Transport-Security sent over plain HTTP is ignored by browsers",
        ));
    }
    let (hsts, error) = match Hsts::parse(first.trim()) {
        Ok(h) => {
            weaknesses.extend(analyze(&h, options));
            (Some(h), None)
        }
        Err(e) => {
            weaknesses.push(error_weakness(&e));
            (None, Some(e))
        }
    };
    sort(&mut weaknesses);
    Report {
        hsts,
        error,
        weaknesses,
    }
}

fn error_weakness(e: &Error) -> Weakness {
    let message = format!("Strict-Transport-Security is ignored by browsers: {e}");
    let (kind, directive) = match e {
        Error::MissingMaxAge => (WeaknessKind::MissingMaxAge, None),
        Error::InvalidMaxAge { .. } => (WeaknessKind::InvalidMaxAge, Some("max-age")),
        Error::DuplicateDirective { name } => {
            (WeaknessKind::DuplicateDirective, Some(name.as_str()))
        }
        Error::MissingValue { name } | Error::UnexpectedValue { name } => {
            (WeaknessKind::InvalidHeader, Some(name.as_str()))
        }
        _ => (WeaknessKind::InvalidHeader, None),
    };
    let w = Weakness::new(kind, Severity::Medium, message);
    match directive {
        Some(d) => w.at(d),
        None => w,
    }
}

/// Analyzes a parsed policy; weaknesses come most severe first.
#[must_use]
pub fn analyze(hsts: &Hsts, options: &Options) -> Vec<Weakness> {
    let mut out = Vec::new();
    if hsts.max_age == 0 {
        out.push(
            Weakness::new(
                WeaknessKind::MaxAgeZero,
                Severity::Medium,
                "max-age=0 makes browsers forget the HSTS policy",
            )
            .at("max-age"),
        );
    } else if hsts.max_age < options.min_max_age {
        let severity = if hsts.max_age < DAY {
            Severity::Medium
        } else {
            Severity::Low
        };
        out.push(
            Weakness::new(
                WeaknessKind::ShortMaxAge,
                severity,
                format!(
                    "max-age={} is below the recommended {} seconds; the policy lapses between \
                     visits",
                    hsts.max_age, options.min_max_age
                ),
            )
            .at("max-age"),
        );
    }
    if options.check_include_subdomains && !hsts.include_subdomains && hsts.max_age > 0 {
        out.push(Weakness::new(
            WeaknessKind::MissingIncludeSubdomains,
            Severity::Low,
            "No includeSubDomains: subdomains can be reached over HTTP and set cookies for \
             the parent domain",
        ));
    }
    if hsts.preload {
        let issues = header_issues(hsts);
        if !issues.is_empty() {
            let reasons: Vec<_> = issues.iter().map(|i| i.message.as_str()).collect();
            out.push(
                Weakness::new(
                    WeaknessKind::PreloadIneligible,
                    Severity::Low,
                    format!(
                        "preload is set but the header is not preload-eligible: {}",
                        reasons.join("; ")
                    ),
                )
                .at("preload"),
            );
        }
    }
    let mut seen_preload = hsts.preload;
    let mut seen = Vec::new();
    for ext in &hsts.extensions {
        let name = ext.name.as_str();
        let w = if name == "preload" {
            if ext.value.is_some() {
                Weakness::new(
                    WeaknessKind::ValuedDirective,
                    Severity::Low,
                    "preload has a value; the preload list expects a bare preload token",
                )
            } else if seen_preload {
                Weakness::new(
                    WeaknessKind::DuplicateDirective,
                    Severity::Informational,
                    "preload is repeated",
                )
            } else {
                seen_preload = true;
                continue;
            }
        } else if let Some((_, correct)) = MISSPELLINGS.iter().find(|(m, _)| *m == name) {
            Weakness::new(
                WeaknessKind::MisspelledDirective,
                Severity::Low,
                format!("Directive {name} looks like a misspelling of {correct} and is ignored"),
            )
        } else if seen.contains(&name) {
            Weakness::new(
                WeaknessKind::DuplicateDirective,
                Severity::Informational,
                format!("Directive {name} is repeated"),
            )
        } else {
            seen.push(name);
            Weakness::new(
                WeaknessKind::UnknownDirective,
                Severity::Informational,
                format!("Unknown directive {name} is ignored"),
            )
        };
        out.push(w.at(name));
    }
    sort(&mut out);
    out
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
    fn good_header_is_clean() {
        assert_eq!(kinds("max-age=63072000; includeSubDomains; preload"), []);
        assert_eq!(kinds("max-age=31536000; includeSubDomains"), []);
    }

    #[test]
    fn max_age_levels() {
        assert_eq!(
            kinds("max-age=0"),
            [(WeaknessKind::MaxAgeZero, Severity::Medium)]
        );
        assert_eq!(
            kinds("max-age=300; includeSubDomains"),
            [(WeaknessKind::ShortMaxAge, Severity::Medium)]
        );
        assert_eq!(
            kinds("max-age=15768000; includeSubDomains"),
            [(WeaknessKind::ShortMaxAge, Severity::Low)]
        );
        let opts = Options::default().with_min_max_age(DAY);
        assert_eq!(
            run("max-age=86400; includesubdomains", &opts).weaknesses,
            []
        );
    }

    #[test]
    fn misspellings_and_extensions() {
        let k = kinds("max-age=31536000; include_subdomains; preload=1; preload; foo; foo");
        assert!(k.contains(&(WeaknessKind::MisspelledDirective, Severity::Low)));
        assert!(k.contains(&(WeaknessKind::MissingIncludeSubdomains, Severity::Low)));
        assert!(k.contains(&(WeaknessKind::ValuedDirective, Severity::Low)));
        assert!(k.contains(&(WeaknessKind::PreloadIneligible, Severity::Low)));
        assert!(k.contains(&(WeaknessKind::UnknownDirective, Severity::Informational)));
        assert!(k.contains(&(WeaknessKind::DuplicateDirective, Severity::Informational)));
    }

    #[test]
    fn errors_map_to_kinds() {
        assert_eq!(
            kinds("includeSubDomains"),
            [(WeaknessKind::MissingMaxAge, Severity::Medium)]
        );
        assert_eq!(
            kinds("max-age=1 day"),
            [(WeaknessKind::InvalidHeader, Severity::Medium)]
        );
        assert_eq!(
            kinds("max-age=\"1y\""),
            [(WeaknessKind::InvalidMaxAge, Severity::Medium)]
        );
        assert_eq!(
            kinds("max-age=1; max-age=1"),
            [(WeaknessKind::DuplicateDirective, Severity::Medium)]
        );
    }

    #[test]
    fn fields_and_transport() {
        let r = run_fields([], &Options::default());
        assert_eq!(r.weaknesses[0].kind, WeaknessKind::MissingHeader);
        let r = run_fields(
            ["max-age=31536000; includeSubDomains", "max-age=0"],
            &Options::default().with_insecure_transport(true),
        );
        let k: Vec<_> = r.weaknesses.iter().map(|w| w.kind).collect();
        assert_eq!(
            k,
            [
                WeaknessKind::MultipleHeaders,
                WeaknessKind::InsecureTransport
            ]
        );
        assert_eq!(r.hsts.map(|h| h.max_age), Some(31_536_000));
    }
}
