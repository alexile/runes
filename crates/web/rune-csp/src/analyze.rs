//! Weakness analysis and the mapping to `rune_finding`.

use std::fmt;

use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};

use crate::policy::{Directive, ParseIssue, Policy, parse_header};
use crate::source::{HostSource, Keyword, Source};

/// CSP Level 3 specification.
const SPEC_URL: &str = "https://www.w3.org/TR/CSP3/";
/// OWASP cheat sheet with deployment guidance.
const CHEAT_SHEET_URL: &str =
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html";

/// Fewest base64 characters for a nonce of at least 128 bits (CSP3 §7.1).
const MIN_NONCE_CHARS: usize = 22;

/// Directive names that look like keywords someone forgot to quote.
const UNQUOTED_KEYWORDS: &[&str] = &[
    "self",
    "none",
    "unsafe-inline",
    "unsafe-eval",
    "unsafe-hashes",
    "strict-dynamic",
    "report-sample",
    "wasm-unsafe-eval",
];

/// The class of a [`Weakness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WeaknessKind {
    /// The header holds no directives.
    EmptyPolicy,
    /// Neither `script-src` nor `default-src` restricts scripts.
    MissingScriptSrc,
    /// Neither `object-src` nor `default-src` restricts plugins, or the
    /// effective list is not `'none'`.
    MissingObjectSrc,
    /// No `base-uri`: an injected `<base>` can redirect relative script URLs.
    MissingBaseUri,
    /// No `frame-ancestors`: framing is not restricted by CSP.
    MissingFrameAncestors,
    /// No `report-to` or `report-uri`: violations go unnoticed.
    MissingReporting,
    /// `'unsafe-inline'` allows inline code.
    UnsafeInline,
    /// `'unsafe-eval'` allows string-to-code sinks.
    UnsafeEval,
    /// `'unsafe-hashes'` lets hashes match event handler attributes.
    UnsafeHashes,
    /// A source matches any host: `*`, a scheme-only `https:`, or `*.tld`.
    WildcardSource,
    /// `data:`, `blob:`, `filesystem:` or `javascript:` in a script context.
    UnsafeScheme,
    /// A source over plain `http:` or `ws:`.
    InsecureScheme,
    /// `'strict-dynamic'` without a nonce or hash, so no script can load.
    StrictDynamicWithoutNonce,
    /// A nonce shorter than 128 bits.
    WeakNonce,
    /// A hash whose length does not match its algorithm.
    MalformedHash,
    /// A nonce or hash in a directive that ignores them.
    MisplacedNonceOrHash,
    /// `'none'` combined with other sources, which makes it ineffective.
    NoneWithOtherSources,
    /// An unquoted keyword such as `self`, which is read as a host name.
    UnquotedKeyword,
    /// A token that is not a valid source expression.
    InvalidSource,
    /// A directive repeated later in the policy; the repeat is ignored.
    DuplicateDirective,
    /// A directive name that is not valid; the directive is ignored.
    InvalidDirectiveName,
    /// A directive no specification defines.
    UnknownDirective,
    /// A directive browsers have removed or deprecated.
    DeprecatedDirective,
    /// The policy is delivered as `Content-Security-Policy-Report-Only`.
    ReportOnly,
}

impl WeaknessKind {
    /// The `snake_case` name, used in [`WeaknessKind::check_id`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyPolicy => "empty_policy",
            Self::MissingScriptSrc => "missing_script_src",
            Self::MissingObjectSrc => "missing_object_src",
            Self::MissingBaseUri => "missing_base_uri",
            Self::MissingFrameAncestors => "missing_frame_ancestors",
            Self::MissingReporting => "missing_reporting",
            Self::UnsafeInline => "unsafe_inline",
            Self::UnsafeEval => "unsafe_eval",
            Self::UnsafeHashes => "unsafe_hashes",
            Self::WildcardSource => "wildcard_source",
            Self::UnsafeScheme => "unsafe_scheme",
            Self::InsecureScheme => "insecure_scheme",
            Self::StrictDynamicWithoutNonce => "strict_dynamic_without_nonce",
            Self::WeakNonce => "weak_nonce",
            Self::MalformedHash => "malformed_hash",
            Self::MisplacedNonceOrHash => "misplaced_nonce_or_hash",
            Self::NoneWithOtherSources => "none_with_other_sources",
            Self::UnquotedKeyword => "unquoted_keyword",
            Self::InvalidSource => "invalid_source",
            Self::DuplicateDirective => "duplicate_directive",
            Self::InvalidDirectiveName => "invalid_directive_name",
            Self::UnknownDirective => "unknown_directive",
            Self::DeprecatedDirective => "deprecated_directive",
            Self::ReportOnly => "report_only",
        }
    }

    /// The stable `rune_finding` check id, `csp.<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("csp.{}", self.as_str())
    }

    /// What to do about it.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::EmptyPolicy | Self::MissingScriptSrc => {
                "Restrict scripts with a nonce- or hash-based script-src, e.g. \
                 script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'."
            }
            Self::MissingObjectSrc => "Set object-src 'none'.",
            Self::MissingBaseUri => "Set base-uri 'none' (or 'self').",
            Self::MissingFrameAncestors => {
                "Set frame-ancestors 'none' or 'self' to prevent clickjacking."
            }
            Self::MissingReporting => "Add report-to (and report-uri for older browsers).",
            Self::UnsafeInline | Self::UnsafeHashes => {
                "Remove 'unsafe-inline'/'unsafe-hashes'; move inline code to files or allow it \
                 with nonces or hashes."
            }
            Self::UnsafeEval => {
                "Remove 'unsafe-eval' and refactor eval(), new Function() and string timers."
            }
            Self::WildcardSource | Self::UnsafeScheme => {
                "Replace broad allowlists with nonces or hashes plus 'strict-dynamic', or list \
                 specific https:// hosts."
            }
            Self::InsecureScheme => "Use https:// and wss:// sources only.",
            Self::StrictDynamicWithoutNonce => {
                "Add a per-response nonce or script hashes next to 'strict-dynamic'."
            }
            Self::WeakNonce => {
                "Generate a fresh nonce of at least 128 random bits (22+ base64 characters) per response."
            }
            Self::MalformedHash => {
                "Recompute the hash: base64 of the full digest of the inline content."
            }
            Self::MisplacedNonceOrHash => {
                "Nonces and hashes only apply to script and style directives; remove them here."
            }
            Self::NoneWithOtherSources => "Use either 'none' alone or a list of sources.",
            Self::UnquotedKeyword => "Quote keywords with single quotes, e.g. 'self'.",
            Self::InvalidSource => "Fix or remove the source expression; browsers ignore it.",
            Self::DuplicateDirective => "Merge the repeated directive into the first occurrence.",
            Self::InvalidDirectiveName => "Fix the directive name; browsers ignore the directive.",
            Self::UnknownDirective => "Check the directive name for typos.",
            Self::DeprecatedDirective => "Remove the deprecated directive or use its replacement.",
            Self::ReportOnly => {
                "Enforce the policy with Content-Security-Policy once its reports are clean."
            }
        }
    }

    /// CWE classification: CWE-693 for all, plus CWE-79 for script
    /// injection exposure or CWE-1021 for framing.
    const fn cwes(self) -> &'static [u32] {
        match self {
            Self::EmptyPolicy
            | Self::MissingScriptSrc
            | Self::MissingObjectSrc
            | Self::MissingBaseUri
            | Self::UnsafeInline
            | Self::UnsafeEval
            | Self::UnsafeHashes
            | Self::WildcardSource
            | Self::UnsafeScheme
            | Self::InsecureScheme
            | Self::WeakNonce => &[693, 79],
            Self::MissingFrameAncestors => &[693, 1021],
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
    /// Index of the policy in the header (0 for a single policy).
    pub policy: usize,
    /// The directive concerned, when there is one.
    pub directive: Option<String>,
    /// The offending source or token, when there is one.
    pub source: Option<String>,
    /// A human-readable explanation.
    pub message: String,
}

impl Weakness {
    const fn new(kind: WeaknessKind, severity: Severity, policy: usize, message: String) -> Self {
        Self {
            kind,
            severity,
            policy,
            directive: None,
            source: None,
            message,
        }
    }

    fn at(mut self, directive: &str) -> Self {
        self.directive = Some(directive.to_owned());
        self
    }

    fn token(mut self, source: &impl ToString) -> Self {
        self.source = Some(source.to_string());
        self
    }

    /// Converts the weakness into a [`rune_finding::Finding`] with check id
    /// `csp.<kind>`, CWE references and a remediation. For a
    /// [`Location::Url`] the directive becomes the location parameter, so
    /// weaknesses in different directives fingerprint differently.
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
                .push_reference(SPEC_URL)
                .push_reference(CHEAT_SHEET_URL),
        );
        for cwe in self.kind.cwes() {
            finding = finding.push_taxonomy(TaxonomyRef::cwe(*cwe));
        }
        if let Some(d) = &self.directive {
            finding = finding.push_evidence(Evidence::new("directive", d.clone()));
        }
        if let Some(s) = &self.source {
            finding = finding.push_evidence(Evidence::new("source", s.clone()));
        }
        finding
    }
}

/// Settings for [`run`] and [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The policy came from `Content-Security-Policy-Report-Only` and is not
    /// enforced. Adds a [`WeaknessKind::ReportOnly`] weakness.
    pub report_only: bool,
    /// Report a missing `report-to`/`report-uri`. On by default.
    pub check_reporting: bool,
    /// Report a missing `frame-ancestors`. On by default; turn it off when
    /// `X-Frame-Options` is checked separately.
    pub check_frame_ancestors: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            report_only: false,
            check_reporting: true,
            check_frame_ancestors: true,
        }
    }
}

impl Options {
    /// Sets [`Options::report_only`].
    #[must_use]
    pub const fn with_report_only(mut self, report_only: bool) -> Self {
        self.report_only = report_only;
        self
    }

    /// Sets [`Options::check_reporting`].
    #[must_use]
    pub const fn with_check_reporting(mut self, check: bool) -> Self {
        self.check_reporting = check;
        self
    }

    /// Sets [`Options::check_frame_ancestors`].
    #[must_use]
    pub const fn with_check_frame_ancestors(mut self, check: bool) -> Self {
        self.check_frame_ancestors = check;
        self
    }
}

/// The result of [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The parsed policies, in header order.
    pub policies: Vec<Policy>,
    /// Weaknesses across all policies, most severe first.
    pub weaknesses: Vec<Weakness>,
}

impl Report {
    /// The policies in canonical form (see [`crate::serialize_header`]).
    #[must_use]
    pub fn canonical(&self) -> String {
        crate::serialize_header(&self.policies)
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

/// Parses a header value and analyzes every policy in it.
///
/// Each policy of a multi-policy header is analyzed on its own, so a
/// weakness that another enforced policy happens to mitigate is still
/// reported.
#[must_use]
pub fn run(header: &str, options: &Options) -> Report {
    let policies = parse_header(header);
    let mut weaknesses = Vec::new();
    if policies.iter().all(Policy::is_empty) {
        weaknesses.push(Weakness::new(
            WeaknessKind::EmptyPolicy,
            Severity::High,
            0,
            "Content-Security-Policy has no directives and restricts nothing".to_owned(),
        ));
    }
    for (index, policy) in policies.iter().enumerate() {
        weaknesses.extend(analyze_at(policy, index, options));
    }
    sort(&mut weaknesses);
    Report {
        policies,
        weaknesses,
    }
}

/// Analyzes one policy; weaknesses carry policy index 0, most severe first.
#[must_use]
pub fn analyze(policy: &Policy, options: &Options) -> Vec<Weakness> {
    let mut weaknesses = analyze_at(policy, 0, options);
    sort(&mut weaknesses);
    weaknesses
}

fn sort(weaknesses: &mut [Weakness]) {
    weaknesses.sort_by_key(|w| std::cmp::Reverse(w.severity));
}

fn analyze_at(policy: &Policy, index: usize, options: &Options) -> Vec<Weakness> {
    let mut a = Analyzer {
        index,
        out: Vec::new(),
    };
    if policy.is_empty() {
        a.push(
            WeaknessKind::EmptyPolicy,
            Severity::High,
            "Policy has no valid directives and restricts nothing".to_owned(),
        );
    } else {
        a.parse_issues(policy);
        a.directive_names(policy);
        a.scripts(policy);
        a.styles(policy);
        a.objects(policy);
        a.base_uri(policy);
        a.frame_ancestors(policy, options);
        for directive in policy.directives() {
            a.generic_sources(directive);
        }
        if options.check_reporting
            && policy.directive("report-to").is_none()
            && policy.directive("report-uri").is_none()
        {
            a.push(
                WeaknessKind::MissingReporting,
                Severity::Informational,
                "No report-to or report-uri: violations are not reported".to_owned(),
            );
        }
    }
    if options.report_only {
        a.push(
            WeaknessKind::ReportOnly,
            Severity::Low,
            "Policy is report-only and does not block anything".to_owned(),
        );
    }
    a.out
}

struct Analyzer {
    index: usize,
    out: Vec<Weakness>,
}

/// Facts about a source list used by several checks.
struct ListFacts {
    sources: Vec<Source>,
    has_nonce_or_hash: bool,
    has_strict_dynamic: bool,
}

impl ListFacts {
    fn of(directive: &Directive) -> Self {
        let sources = directive.sources();
        let has_nonce_or_hash = sources.iter().any(Source::is_nonce_or_hash);
        let has_strict_dynamic = sources.contains(&Source::Keyword(Keyword::StrictDynamic));
        Self {
            sources,
            has_nonce_or_hash,
            has_strict_dynamic,
        }
    }

    fn has(&self, keyword: Keyword) -> bool {
        self.sources.contains(&Source::Keyword(keyword))
    }

    fn is_none_only(&self) -> bool {
        self.sources
            .iter()
            .all(|s| matches!(s, Source::None | Source::Invalid(_)))
    }
}

impl Analyzer {
    fn push(&mut self, kind: WeaknessKind, severity: Severity, message: String) {
        self.out
            .push(Weakness::new(kind, severity, self.index, message));
    }

    fn push_w(&mut self, weakness: Weakness) {
        self.out.push(weakness);
    }

    const fn weakness(&self, kind: WeaknessKind, severity: Severity, message: String) -> Weakness {
        Weakness::new(kind, severity, self.index, message)
    }

    fn parse_issues(&mut self, policy: &Policy) {
        for issue in policy.issues() {
            let w = match issue {
                ParseIssue::DuplicateDirective { name } => self
                    .weakness(
                        WeaknessKind::DuplicateDirective,
                        Severity::Low,
                        format!("Directive {name} is repeated; browsers ignore the repeat"),
                    )
                    .at(name),
                ParseIssue::InvalidDirectiveName { name } => self
                    .weakness(
                        WeaknessKind::InvalidDirectiveName,
                        Severity::Low,
                        format!("Directive name {name:?} is invalid; browsers ignore it"),
                    )
                    .token(name),
            };
            self.push_w(w);
        }
    }

    fn directive_names(&mut self, policy: &Policy) {
        for d in policy.directives() {
            if !d.is_known() {
                let w = self
                    .weakness(
                        WeaknessKind::UnknownDirective,
                        Severity::Informational,
                        format!("Unknown directive {}", d.name()),
                    )
                    .at(d.name());
                self.push_w(w);
            } else if d.is_deprecated() {
                let w = self
                    .weakness(
                        WeaknessKind::DeprecatedDirective,
                        Severity::Informational,
                        format!("Directive {} is deprecated", d.name()),
                    )
                    .at(d.name());
                self.push_w(w);
            }
        }
    }

    /// Script checks on `script-src` (or its `default-src` fallback) and on
    /// any explicit `script-src-elem`/`script-src-attr`.
    fn scripts(&mut self, policy: &Policy) {
        let Some(main) = policy.effective_directive("script-src") else {
            self.push(
                WeaknessKind::MissingScriptSrc,
                Severity::High,
                "No script-src or default-src: scripts from any origin and inline scripts run"
                    .to_owned(),
            );
            return;
        };
        self.script_list(main);
        for name in ["script-src-elem", "script-src-attr"] {
            if let Some(d) = policy.directive(name) {
                self.script_list(d);
            }
        }
    }

    fn script_list(&mut self, d: &Directive) {
        let name = d.name();
        let facts = ListFacts::of(d);
        if facts.is_none_only() {
            return;
        }
        if facts.has(Keyword::UnsafeInline) {
            let w = if facts.has_nonce_or_hash || facts.has_strict_dynamic {
                self.weakness(
                    WeaknessKind::UnsafeInline,
                    Severity::Informational,
                    format!(
                        "'unsafe-inline' in {name} is ignored by CSP2+ browsers because a nonce, \
                         hash or 'strict-dynamic' is present (fallback for old browsers)"
                    ),
                )
            } else {
                self.weakness(
                    WeaknessKind::UnsafeInline,
                    Severity::High,
                    format!("'unsafe-inline' in {name} allows injected inline scripts"),
                )
            };
            self.push_w(w.at(name).token(&"'unsafe-inline'"));
        }
        if facts.has(Keyword::UnsafeEval) {
            let w = self
                .weakness(
                    WeaknessKind::UnsafeEval,
                    Severity::Medium,
                    format!("'unsafe-eval' in {name} allows eval() and similar sinks"),
                )
                .at(name)
                .token(&"'unsafe-eval'");
            self.push_w(w);
        }
        if facts.has(Keyword::UnsafeHashes) {
            let w = self
                .weakness(
                    WeaknessKind::UnsafeHashes,
                    Severity::Low,
                    format!("'unsafe-hashes' in {name} allows hashed inline event handlers"),
                )
                .at(name)
                .token(&"'unsafe-hashes'");
            self.push_w(w);
        }
        if facts.has_strict_dynamic && !facts.has_nonce_or_hash {
            let w = self
                .weakness(
                    WeaknessKind::StrictDynamicWithoutNonce,
                    Severity::Low,
                    format!(
                        "'strict-dynamic' in {name} without a nonce or hash: the allowlist is \
                         ignored and no script can load"
                    ),
                )
                .at(name)
                .token(&"'strict-dynamic'");
            self.push_w(w);
        }
        // With 'strict-dynamic' and a nonce or hash, CSP3 browsers ignore
        // host and scheme sources, so allowlist breadth does not matter.
        if !(facts.has_strict_dynamic && facts.has_nonce_or_hash) {
            self.allowlist(name, &facts.sources, Severity::High, true);
        }
    }

    fn styles(&mut self, policy: &Policy) {
        let Some(d) = policy.effective_directive("style-src") else {
            return;
        };
        let facts = ListFacts::of(d);
        if facts.has(Keyword::UnsafeInline) && !facts.has_nonce_or_hash {
            let w = self
                .weakness(
                    WeaknessKind::UnsafeInline,
                    Severity::Low,
                    format!(
                        "'unsafe-inline' in {} allows injected styles (CSS-based data exfiltration)",
                        d.name()
                    ),
                )
                .at(d.name())
                .token(&"'unsafe-inline'");
            self.push_w(w);
        }
    }

    fn objects(&mut self, policy: &Policy) {
        match policy.effective_directive("object-src") {
            None => self.push(
                WeaknessKind::MissingObjectSrc,
                Severity::High,
                "No object-src or default-src: plugin content (<object>, <embed>) can load script"
                    .to_owned(),
            ),
            Some(d) => {
                let facts = ListFacts::of(d);
                if facts.is_none_only() {
                    return;
                }
                if d.name() == "default-src" {
                    let w = self
                        .weakness(
                            WeaknessKind::MissingObjectSrc,
                            Severity::Low,
                            "object-src falls back to default-src, which is not 'none'".to_owned(),
                        )
                        .at("default-src");
                    self.push_w(w);
                } else {
                    self.allowlist(d.name(), &facts.sources, Severity::Medium, true);
                }
            }
        }
    }

    fn base_uri(&mut self, policy: &Policy) {
        match policy.directive("base-uri") {
            None => {
                let nonce_based = policy
                    .effective_directive("script-src")
                    .is_some_and(|d| ListFacts::of(d).has_nonce_or_hash);
                let severity = if nonce_based {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                self.push(
                    WeaknessKind::MissingBaseUri,
                    severity,
                    "No base-uri: an injected <base> tag can redirect relative script URLs"
                        .to_owned(),
                );
            }
            Some(d) => {
                let sources = d.sources();
                self.allowlist(d.name(), &sources, Severity::Medium, false);
            }
        }
    }

    fn frame_ancestors(&mut self, policy: &Policy, options: &Options) {
        match policy.directive("frame-ancestors") {
            None if options.check_frame_ancestors => self.push(
                WeaknessKind::MissingFrameAncestors,
                Severity::Informational,
                "No frame-ancestors: framing is only restricted if X-Frame-Options is set"
                    .to_owned(),
            ),
            None => {}
            Some(d) => {
                let sources = d.sources();
                self.allowlist(d.name(), &sources, Severity::Medium, false);
            }
        }
    }

    /// Wildcard, scheme and plain-HTTP checks for an allowlist.
    fn allowlist(&mut self, name: &str, sources: &[Source], severity: Severity, script: bool) {
        for source in sources {
            let w = match source {
                Source::Host(h) if h.is_any_host() || h.is_tld_wildcard() => self.weakness(
                    WeaknessKind::WildcardSource,
                    severity,
                    format!("{name} allows {source}, which matches any site"),
                ),
                Source::Scheme(s) if matches!(s.as_str(), "http" | "https" | "ws" | "wss") => self
                    .weakness(
                        WeaknessKind::WildcardSource,
                        severity,
                        format!("{name} allows the whole {s}: scheme, which matches any host"),
                    ),
                Source::Scheme(s)
                    if script
                        && matches!(s.as_str(), "data" | "blob" | "filesystem" | "javascript") =>
                {
                    self.weakness(
                        WeaknessKind::UnsafeScheme,
                        severity,
                        format!("{name} allows {s}: URLs, which attackers can fill with code"),
                    )
                }
                Source::Host(HostSource {
                    scheme: Some(s), ..
                }) if matches!(s.as_str(), "http" | "ws") => self.weakness(
                    WeaknessKind::InsecureScheme,
                    Severity::Medium,
                    format!("{name} allows {source} over an unencrypted connection"),
                ),
                _ => continue,
            };
            self.push_w(w.at(name).token(source));
        }
    }

    /// Checks that apply to every source-list directive.
    fn generic_sources(&mut self, d: &Directive) {
        let name = d.name();
        let sources = d.sources();
        if sources.contains(&Source::None) && sources.len() > 1 {
            let w = self
                .weakness(
                    WeaknessKind::NoneWithOtherSources,
                    Severity::Informational,
                    format!("{name} combines 'none' with other sources; 'none' is ignored"),
                )
                .at(name);
            self.push_w(w);
        }
        for source in &sources {
            let w = match source {
                Source::Invalid(token) => self.weakness(
                    WeaknessKind::InvalidSource,
                    Severity::Low,
                    format!("{name} contains {token:?}, which is not a valid source"),
                ),
                Source::Host(HostSource {
                    scheme: None,
                    host,
                    port: None,
                    path: None,
                }) if UNQUOTED_KEYWORDS.contains(&host.as_str()) => self.weakness(
                    WeaknessKind::UnquotedKeyword,
                    Severity::Medium,
                    format!("{name} contains {host} without quotes; it is read as a host name"),
                ),
                Source::Nonce(_) | Source::Hash { .. } if !d.accepts_nonces() => self.weakness(
                    WeaknessKind::MisplacedNonceOrHash,
                    Severity::Informational,
                    format!("{name} ignores nonces and hashes"),
                ),
                Source::Nonce(value) if value.trim_end_matches('=').len() < MIN_NONCE_CHARS => self
                    .weakness(
                        WeaknessKind::WeakNonce,
                        Severity::Medium,
                        format!("Nonce in {name} is shorter than 128 bits and may be guessable"),
                    ),
                Source::Hash { algorithm, value }
                    if decoded_len(value) != algorithm.digest_len() =>
                {
                    self.weakness(
                        WeaknessKind::MalformedHash,
                        Severity::Low,
                        format!(
                            "{} hash in {name} is {} bytes, not {}; it matches nothing",
                            algorithm.name(),
                            decoded_len(value),
                            algorithm.digest_len()
                        ),
                    )
                }
                _ => continue,
            };
            self.push_w(w.at(name).token(source));
        }
    }
}

/// Decoded byte length of a base64 (standard or URL-safe) value.
fn decoded_len(value: &str) -> usize {
    value.trim_end_matches('=').len() * 6 / 8
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

    fn has(header: &str, kind: WeaknessKind, severity: Severity) -> bool {
        kinds(header).contains(&(kind, severity))
    }

    #[test]
    fn decoded_lengths() {
        // sha256 of "" in base64.
        assert_eq!(
            decoded_len("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            32
        );
        assert_eq!(decoded_len("abcd"), 3);
    }

    #[test]
    fn report_only_and_options() {
        let opts = Options::default()
            .with_report_only(true)
            .with_check_reporting(false)
            .with_check_frame_ancestors(false);
        let r = run("default-src 'none'; base-uri 'none'", &opts);
        let k: Vec<_> = r.weaknesses.iter().map(|w| w.kind).collect();
        assert_eq!(k, [WeaknessKind::ReportOnly]);
    }

    #[test]
    fn style_unsafe_inline_is_low() {
        assert!(has(
            "default-src 'self'; style-src 'self' 'unsafe-inline'",
            WeaknessKind::UnsafeInline,
            Severity::Low
        ));
    }

    #[test]
    fn misplaced_nonce() {
        assert!(has(
            "default-src 'self'; img-src 'nonce-abcdefghijklmnopqrstuvwx'",
            WeaknessKind::MisplacedNonceOrHash,
            Severity::Informational
        ));
    }

    #[test]
    fn insecure_host() {
        assert!(has(
            "script-src http://cdn.example",
            WeaknessKind::InsecureScheme,
            Severity::Medium
        ));
    }
}
