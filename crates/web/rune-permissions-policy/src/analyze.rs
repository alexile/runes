//! Weakness analysis and the mapping to `rune_finding`.

use std::collections::{HashMap, HashSet};
use std::fmt;

use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};

use crate::features::{Sensitivity, Status, feature};
use crate::{Error, Member, PermissionsPolicy, Syntax};

/// The Permissions Policy specification.
const SPEC_URL: &str = "https://www.w3.org/TR/permissions-policy/";
/// OWASP guidance on the header.
const OWASP_URL: &str = "https://owasp.org/www-project-secure-headers/#permissions-policy";

/// High-sensitivity features worth denying explicitly (`feature=()`) on
/// sites that do not use them; a starting point for
/// [`Options::with_restricted_features`].
pub const RECOMMENDED_RESTRICTED: &[&str] = &[
    "camera",
    "display-capture",
    "geolocation",
    "microphone",
    "payment",
    "usb",
];

/// The class of a [`Weakness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WeaknessKind {
    /// The response sends neither `Permissions-Policy` nor `Feature-Policy`.
    MissingHeader,
    /// The header is not a valid structured-field dictionary, so browsers
    /// ignore all of it.
    InvalidHeader,
    /// The header declares no feature.
    EmptyPolicy,
    /// `feature=*`: every origin, including any third-party frame given
    /// `allow=`, may use the feature.
    AllowAll,
    /// An `http://` origin is granted the feature.
    InsecureOrigin,
    /// An allowlist member browsers ignore (`"self"`, `none`, a string that
    /// is not an origin).
    InvalidMember,
    /// `src` in a header; it only means something in an iframe `allow`
    /// attribute.
    SrcInHeader,
    /// A member that adds nothing: repeated, or next to `*`.
    RedundantMember,
    /// A feature declared more than once; only one declaration counts.
    DuplicateFeature,
    /// A feature name no browser or specification defines.
    UnknownFeature,
    /// A feature browsers have removed or renamed.
    DeprecatedFeature,
    /// The policy uses the legacy `Feature-Policy` header.
    LegacyFeaturePolicy,
    /// A feature the caller wants restricted is not declared, so it keeps
    /// its default allowlist.
    UnrestrictedFeature,
}

impl WeaknessKind {
    /// The `snake_case` name, used in [`WeaknessKind::check_id`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingHeader => "missing_header",
            Self::InvalidHeader => "invalid_header",
            Self::EmptyPolicy => "empty_policy",
            Self::AllowAll => "allow_all",
            Self::InsecureOrigin => "insecure_origin",
            Self::InvalidMember => "invalid_member",
            Self::SrcInHeader => "src_in_header",
            Self::RedundantMember => "redundant_member",
            Self::DuplicateFeature => "duplicate_feature",
            Self::UnknownFeature => "unknown_feature",
            Self::DeprecatedFeature => "deprecated_feature",
            Self::LegacyFeaturePolicy => "legacy_feature_policy",
            Self::UnrestrictedFeature => "unrestricted_feature",
        }
    }

    /// The stable `rune_finding` check id, `permissions_policy.<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("permissions_policy.{}", self.as_str())
    }

    /// What to do about it.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::MissingHeader | Self::EmptyPolicy | Self::UnrestrictedFeature => {
                "Send Permissions-Policy denying the powerful features the site does not use, \
                 e.g. camera=(), microphone=(), geolocation=()."
            }
            Self::InvalidHeader => {
                "Fix the syntax: feature=(self \"https://origin\"), comma-separated, tokens \
                 unquoted and origins double-quoted."
            }
            Self::AllowAll => "Replace * with self and the specific origins that need the feature.",
            Self::InsecureOrigin => "Grant the feature to the https:// origin instead.",
            Self::InvalidMember => {
                "Use only *, self and double-quoted origins; use () to deny a feature."
            }
            Self::SrcInHeader => "Remove src; use it in iframe allow attributes only.",
            Self::RedundantMember => "Remove the redundant allowlist members.",
            Self::DuplicateFeature => "Declare each feature once.",
            Self::UnknownFeature => "Check the feature name; browsers ignore unknown ones.",
            Self::DeprecatedFeature => "Remove the feature; browsers no longer support it.",
            Self::LegacyFeaturePolicy => {
                "Send the policy as Permissions-Policy and drop Feature-Policy."
            }
        }
    }

    /// CWE-693 for all, plus CWE-732 for over-broad grants.
    const fn cwes(self) -> &'static [u32] {
        match self {
            Self::AllowAll | Self::InsecureOrigin | Self::UnrestrictedFeature => &[693, 732],
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
    /// The feature concerned, when there is one.
    pub feature: Option<String>,
    /// A human-readable explanation.
    pub message: String,
}

impl Weakness {
    fn new(kind: WeaknessKind, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            kind,
            severity,
            feature: None,
            message: message.into(),
        }
    }

    fn at(mut self, feature: &str) -> Self {
        self.feature = Some(feature.to_owned());
        self
    }

    /// Converts the weakness into a [`rune_finding::Finding`] with check id
    /// `permissions_policy.<kind>`, CWE references and a remediation. The
    /// feature, when there is one, becomes the location parameter and
    /// evidence.
    #[must_use]
    pub fn to_finding<X: Default>(&self, location: &Location) -> Finding<X> {
        let location = self.feature.as_ref().map_or_else(
            || location.clone(),
            |f| location.clone().with_parameter(f.clone()),
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
                .push_reference(OWASP_URL),
        );
        for cwe in self.kind.cwes() {
            finding = finding.push_taxonomy(TaxonomyRef::cwe(*cwe));
        }
        if let Some(f) = &self.feature {
            finding = finding.push_evidence(Evidence::new("feature", f.clone()));
        }
        finding
    }
}

/// Settings for [`run`] and [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Report feature names this crate does not know. On by default.
    pub check_unknown_features: bool,
    /// Features that must be declared; a missing one is a
    /// [`WeaknessKind::UnrestrictedFeature`]. Empty by default; see
    /// [`RECOMMENDED_RESTRICTED`].
    pub restricted_features: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            check_unknown_features: true,
            restricted_features: Vec::new(),
        }
    }
}

impl Options {
    /// Sets [`Options::check_unknown_features`].
    #[must_use]
    pub const fn with_check_unknown_features(mut self, check: bool) -> Self {
        self.check_unknown_features = check;
        self
    }

    /// Sets [`Options::restricted_features`].
    #[must_use]
    pub fn with_restricted_features<S: Into<String>>(
        mut self,
        features: impl IntoIterator<Item = S>,
    ) -> Self {
        self.restricted_features = features.into_iter().map(Into::into).collect();
        self
    }
}

/// The result of [`run`], [`run_feature_policy`] and [`run_fields`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The policy, when a header was present and parsed.
    pub policy: Option<PermissionsPolicy>,
    /// Why the header did not parse, if it did not.
    pub error: Option<Error>,
    /// Weaknesses, most severe first.
    pub weaknesses: Vec<Weakness>,
}

impl Report {
    /// The policy in canonical form, if it parsed.
    #[must_use]
    pub fn canonical(&self) -> Option<String> {
        self.policy.as_ref().map(ToString::to_string)
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

/// Parses and analyzes one `Permissions-Policy` header value.
#[must_use]
pub fn run(header: &str, options: &Options) -> Report {
    run_fields([header], [], options)
}

/// Parses and analyzes one legacy `Feature-Policy` header value.
#[must_use]
pub fn run_feature_policy(header: &str, options: &Options) -> Report {
    run_fields([], [header], options)
}

/// Analyzes the `Permissions-Policy` and `Feature-Policy` fields of one
/// response.
///
/// `Permissions-Policy` fields are combined into one dictionary, as RFC 8941
/// prescribes. When there are none, the `Feature-Policy` fields (joined with
/// `;`) are analyzed instead. When both are present, `Permissions-Policy` is
/// analyzed and the legacy header reported.
#[must_use]
pub fn run_fields<'a, 'b>(
    permissions_policy: impl IntoIterator<Item = &'a str>,
    feature_policy: impl IntoIterator<Item = &'b str>,
    options: &Options,
) -> Report {
    let pp: Vec<&str> = permissions_policy.into_iter().map(str::trim).collect();
    let fp: Vec<&str> = feature_policy.into_iter().map(str::trim).collect();
    let mut weaknesses = Vec::new();
    let parsed = if !pp.is_empty() {
        let joined: Vec<&str> = pp.into_iter().filter(|f| !f.is_empty()).collect();
        if !fp.is_empty() {
            weaknesses.push(Weakness::new(
                WeaknessKind::LegacyFeaturePolicy,
                Severity::Informational,
                "Feature-Policy is sent alongside Permissions-Policy; browsers that support \
                 Permissions-Policy give it precedence",
            ));
        }
        PermissionsPolicy::parse(&joined.join(", "))
    } else if !fp.is_empty() {
        PermissionsPolicy::parse_feature_policy(&fp.join("; "))
    } else {
        weaknesses.push(Weakness::new(
            WeaknessKind::MissingHeader,
            Severity::Low,
            "No Permissions-Policy header: powerful features keep their default allowlists \
             and can be delegated to any embedded frame",
        ));
        let mut out = Vec::new();
        restricted(None, options, &mut out);
        weaknesses.extend(out);
        sort(&mut weaknesses);
        return Report {
            policy: None,
            error: None,
            weaknesses,
        };
    };
    let (policy, error) = match parsed {
        Ok(p) => {
            weaknesses.extend(analyze(&p, options));
            (Some(p), None)
        }
        Err(e) => {
            weaknesses.push(Weakness::new(
                WeaknessKind::InvalidHeader,
                Severity::Medium,
                format!("Permissions-Policy is ignored by browsers: {e}"),
            ));
            (None, Some(e))
        }
    };
    sort(&mut weaknesses);
    Report {
        policy,
        error,
        weaknesses,
    }
}

/// Analyzes a parsed policy; weaknesses come most severe first.
#[must_use]
pub fn analyze(policy: &PermissionsPolicy, options: &Options) -> Vec<Weakness> {
    let mut out = Vec::new();
    let legacy = policy.syntax == Syntax::FeaturePolicy;
    if legacy {
        out.push(Weakness::new(
            WeaknessKind::LegacyFeaturePolicy,
            Severity::Informational,
            "Feature-Policy is deprecated; current browsers only honor Permissions-Policy",
        ));
    }
    if policy.directives.is_empty() {
        out.push(Weakness::new(
            WeaknessKind::EmptyPolicy,
            Severity::Informational,
            "The policy declares no feature",
        ));
    }
    let mut declared: HashMap<&str, usize> = HashMap::new();
    for d in &policy.directives {
        // Report a repeated feature once, at its second declaration.
        let earlier = declared.entry(d.feature.as_str()).or_insert(0);
        *earlier += 1;
        if *earlier == 2 {
            let which = if legacy { "first" } else { "last" };
            out.push(
                Weakness::new(
                    WeaknessKind::DuplicateFeature,
                    Severity::Low,
                    format!(
                        "{} is declared more than once; only the {which} declaration counts",
                        d.feature
                    ),
                )
                .at(&d.feature),
            );
        }
    }
    for d in policy.effective() {
        let name = d.feature.as_str();
        let known = feature(&name.to_ascii_lowercase());
        match known {
            None if options.check_unknown_features => out.push(
                Weakness::new(
                    WeaknessKind::UnknownFeature,
                    Severity::Informational,
                    format!("Unknown feature {name} is ignored"),
                )
                .at(name),
            ),
            Some(f) if f.status == Status::Deprecated => out.push(
                Weakness::new(
                    WeaknessKind::DeprecatedFeature,
                    Severity::Informational,
                    format!("Feature {name} is deprecated and ignored by current browsers"),
                )
                .at(name),
            ),
            _ => {}
        }
        let sensitivity = known.map(|f| f.sensitivity);
        let members = &d.allowlist.members;
        let allows_all = d.allowlist.allows_all();
        if allows_all && let Some(s) = sensitivity {
            let severity = match s {
                Sensitivity::High => Severity::Medium,
                Sensitivity::Moderate => Severity::Low,
                _ => Severity::Informational,
            };
            out.push(
                Weakness::new(
                    WeaknessKind::AllowAll,
                    severity,
                    format!(
                        "{name}=* lets every origin use {name} (a {} sensitivity feature), \
                             including any third-party frame it is delegated to",
                        s.as_str()
                    ),
                )
                .at(name),
            );
        }
        let mut src_seen = false;
        let mut seen = HashSet::new();
        for m in members {
            if !seen.insert(m) || (m != &Member::All && allows_all) {
                out.push(
                    Weakness::new(
                        WeaknessKind::RedundantMember,
                        Severity::Informational,
                        format!("{name}: member {} adds nothing", member_text(m, legacy)),
                    )
                    .at(name),
                );
                continue;
            }
            match m {
                Member::Src if !src_seen => {
                    src_seen = true;
                    out.push(
                        Weakness::new(
                            WeaknessKind::SrcInHeader,
                            Severity::Informational,
                            format!("{name}: src only applies in iframe allow attributes"),
                        )
                        .at(name),
                    );
                }
                Member::Origin(o) if m.is_insecure_origin() => {
                    let severity = if sensitivity == Some(Sensitivity::High) {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };
                    out.push(
                        Weakness::new(
                            WeaknessKind::InsecureOrigin,
                            severity,
                            format!(
                                "{name} is granted to {o}, which network attackers can \
                                 impersonate"
                            ),
                        )
                        .at(name),
                    );
                }
                Member::Other(raw) => out.push(
                    Weakness::new(
                        WeaknessKind::InvalidMember,
                        Severity::Low,
                        format!("{name}: member {raw} is ignored{}", hint(raw, legacy)),
                    )
                    .at(name),
                ),
                _ => {}
            }
        }
    }
    restricted(Some(policy), options, &mut out);
    sort(&mut out);
    out
}

fn restricted(policy: Option<&PermissionsPolicy>, options: &Options, out: &mut Vec<Weakness>) {
    for name in &options.restricted_features {
        if policy.and_then(|p| p.get(name)).is_none() {
            out.push(
                Weakness::new(
                    WeaknessKind::UnrestrictedFeature,
                    Severity::Low,
                    format!("{name} is not declared and keeps its default allowlist"),
                )
                .at(name),
            );
        }
    }
}

fn member_text(m: &Member, legacy: bool) -> String {
    match (m, legacy) {
        (Member::All, _) => "*".into(),
        (Member::SelfOrigin, false) => "self".into(),
        (Member::SelfOrigin, true) => "'self'".into(),
        (Member::Src, false) => "src".into(),
        (Member::Src, true) => "'src'".into(),
        (Member::Origin(o) | Member::Other(o), _) => o.clone(),
    }
}

/// A hint for a common mistake behind an ignored member.
fn hint(raw: &str, legacy: bool) -> &'static str {
    let bare = raw.trim_matches(['"', '\'']).to_ascii_lowercase();
    match (bare.as_str(), legacy) {
        ("self" | "src", false) => " (write self and src as bare tokens, without quotes)",
        ("*", false) => " (write * without quotes)",
        ("none", false) => " (use () to deny the feature)",
        ("self" | "src" | "none", true) => " (write 'self', 'src' and 'none' in single quotes)",
        _ => " (not *, self or an origin such as \"https://example.com\")",
    }
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
    fn strict_policy_is_clean() {
        assert_eq!(
            kinds(
                "camera=(), microphone=(), geolocation=(self \"https://maps.example\"), \
                 payment=(self);report-to=pp, fullscreen=*"
            ),
            [(WeaknessKind::AllowAll, Severity::Informational)]
        );
        assert_eq!(kinds("camera=()"), []);
    }

    #[test]
    fn dangerous_grants() {
        assert_eq!(
            kinds("camera=*"),
            [(WeaknessKind::AllowAll, Severity::Medium)]
        );
        assert_eq!(
            kinds("gyroscope=*"),
            [(WeaknessKind::AllowAll, Severity::Low)]
        );
        assert_eq!(
            kinds("microphone=(self \"http://a.example\")"),
            [(WeaknessKind::InsecureOrigin, Severity::Medium)]
        );
        assert_eq!(
            kinds("autoplay=(\"http://a.example\")"),
            [(WeaknessKind::InsecureOrigin, Severity::Low)]
        );
    }

    #[test]
    fn mistakes() {
        let k = kinds("camera=(\"self\"), geolocation=none, usb=(src self self), x-foo=()");
        assert!(k.contains(&(WeaknessKind::InvalidMember, Severity::Low)));
        assert!(k.contains(&(WeaknessKind::SrcInHeader, Severity::Informational)));
        assert!(k.contains(&(WeaknessKind::RedundantMember, Severity::Informational)));
        assert!(k.contains(&(WeaknessKind::UnknownFeature, Severity::Informational)));
        let r = run("camera=(\"self\")", &Options::default());
        assert!(r.weaknesses[0].message.contains("bare tokens"));
        assert_eq!(
            kinds("camera=(* self), interest-cohort=()"),
            [
                (WeaknessKind::AllowAll, Severity::Medium),
                (WeaknessKind::RedundantMember, Severity::Informational),
                (WeaknessKind::DeprecatedFeature, Severity::Informational),
            ]
        );
        assert_eq!(
            kinds("camera=*, camera=(), camera=()"),
            [(WeaknessKind::DuplicateFeature, Severity::Low)]
        );
    }

    #[test]
    fn headers_and_options() {
        assert_eq!(
            kinds("camera='none'"),
            [(WeaknessKind::InvalidHeader, Severity::Medium)]
        );
        assert_eq!(
            kinds(""),
            [(WeaknessKind::EmptyPolicy, Severity::Informational)]
        );
        let r = run_fields([], [], &Options::default());
        assert_eq!(r.weaknesses[0].kind, WeaknessKind::MissingHeader);
        let opts = Options::default()
            .with_restricted_features(RECOMMENDED_RESTRICTED.iter().copied())
            .with_check_unknown_features(false);
        let r = run("camera=(), x-foo=*, usb=*", &opts);
        let unrestricted = r
            .weaknesses
            .iter()
            .filter(|w| w.kind == WeaknessKind::UnrestrictedFeature)
            .count();
        assert_eq!(unrestricted, RECOMMENDED_RESTRICTED.len() - 2);
        assert!(
            !r.weaknesses
                .iter()
                .any(|w| w.kind == WeaknessKind::UnknownFeature)
        );
        let r = run_fields(
            ["camera=()", "", "usb=()"],
            ["camera *"],
            &Options::default(),
        );
        assert_eq!(r.canonical().as_deref(), Some("camera=(), usb=()"));
        assert_eq!(
            r.weaknesses.iter().map(|w| w.kind).collect::<Vec<_>>(),
            [WeaknessKind::LegacyFeaturePolicy]
        );
    }

    #[test]
    fn legacy_header() {
        let r = run_feature_policy("camera *; geolocation self", &Options::default());
        let k: Vec<_> = r.weaknesses.iter().map(|w| w.kind).collect();
        assert_eq!(
            k,
            [
                WeaknessKind::AllowAll,
                WeaknessKind::InvalidMember,
                WeaknessKind::LegacyFeaturePolicy
            ]
        );
        assert!(r.weaknesses[1].message.contains("single quotes"));
    }

    #[test]
    fn findings() {
        let r = run("camera=*", &Options::default());
        let f = r.to_findings::<()>(&Location::url("https://example.com/"));
        assert_eq!(f[0].check_id, "permissions_policy.allow_all");
        assert_eq!(f[0].severity, Severity::Medium);
    }
}
