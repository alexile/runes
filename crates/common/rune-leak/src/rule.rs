//! Secret rules as data: [`SecretRule`] and the built-in [`default_rules`].

use rune_finding::{Severity, TaxonomyRef};

/// CWE-798, Use of Hard-coded Credentials: the default CWE of every rule.
pub const CWE_HARDCODED_CREDENTIALS: u32 = 798;

/// Rule id of the built-in entropy detector (`secret.high_entropy_string`).
pub const HIGH_ENTROPY_RULE_ID: &str = "high_entropy_string";

/// A CWE reference, named when it is CWE-798.
pub fn cwe_ref(cwe: u32) -> TaxonomyRef {
    let reference = TaxonomyRef::cwe(cwe);
    if cwe == CWE_HARDCODED_CREDENTIALS {
        reference.with_name("Use of Hard-coded Credentials")
    } else {
        reference
    }
}

/// One secret-detection rule. Rules are plain data: build them in code, load
/// them from TOML (`toml` feature, [`rules_from_toml`](crate::rules_from_toml))
/// or start from [`default_rules`], then compile them into a
/// [`Ruleset`](crate::Ruleset).
///
/// Matching is line by line:
///
/// 1. If `keywords` is not empty, the rule only runs on lines that contain
///    one of them, ignoring ASCII case. This is a cheap pre-filter.
/// 2. `pattern` (Rust [`regex`](https://docs.rs/regex) syntax) is applied.
///    When it has a capture group, group 1 is the secret; otherwise the whole
///    match is.
/// 3. With an `entropy_threshold`, a secret whose Shannon entropy (bits per
///    byte) is below it is dropped.
///
/// A match becomes a finding with check id `secret.<id>`.
///
/// # Examples
///
/// ```rust
/// use rune_finding::Severity;
/// use rune_leak::SecretRule;
///
/// let rule = SecretRule::new("acme_token", "ACME API token", r"acme_([0-9a-f]{32})", Severity::High)
///     .with_keywords(["acme_"])
///     .with_entropy_threshold(3.0);
/// assert_eq!(rule.cwe, 798);
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
#[non_exhaustive]
pub struct SecretRule {
    /// Stable rule id (`[a-z0-9_.-]+`); the finding check id is `secret.<id>`.
    pub id: String,
    /// Human name of what the rule detects; the finding title.
    pub name: String,
    /// Regular expression applied to each line.
    pub pattern: String,
    /// Minimum Shannon entropy (bits per byte) of the secret, if any.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub entropy_threshold: Option<f64>,
    /// Case-insensitive pre-filter: the rule only runs on lines containing
    /// one of these. Empty means every line.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub keywords: Vec<String>,
    /// Severity of a match.
    #[cfg_attr(feature = "serde", serde(default = "default_severity"))]
    pub severity: Severity,
    /// CWE number of the weakness. Defaults to 798.
    #[cfg_attr(feature = "serde", serde(default = "default_cwe"))]
    pub cwe: u32,
}

#[cfg(feature = "serde")]
const fn default_severity() -> Severity {
    Severity::Medium
}

#[cfg(feature = "serde")]
const fn default_cwe() -> u32 {
    CWE_HARDCODED_CREDENTIALS
}

impl SecretRule {
    /// A rule with no keywords, no entropy threshold and CWE-798.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        pattern: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            pattern: pattern.into(),
            entropy_threshold: None,
            keywords: Vec::new(),
            severity,
            cwe: CWE_HARDCODED_CREDENTIALS,
        }
    }

    /// Sets the keyword pre-filter.
    #[must_use]
    pub fn with_keywords<I, S>(mut self, keywords: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.keywords = keywords.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the minimum entropy of the secret.
    #[must_use]
    pub const fn with_entropy_threshold(mut self, bits_per_byte: f64) -> Self {
        self.entropy_threshold = Some(bits_per_byte);
        self
    }

    /// Sets the CWE number.
    #[must_use]
    pub const fn with_cwe(mut self, cwe: u32) -> Self {
        self.cwe = cwe;
        self
    }

    /// The finding check id, `secret.<id>`.
    #[must_use]
    pub fn check_id(&self) -> String {
        format!("secret.{}", self.id)
    }
}

/// The built-in ruleset of 15 rules.
///
/// It covers cloud keys (AWS, GCP), forge and registry tokens (GitHub,
/// GitLab, npm, `PyPI`), service keys (Slack, Stripe, `SendGrid`), private key
/// blocks, JWTs and generic `password = "…"` assignments.
///
/// Rule ids are stable `snake_case` names
/// (`aws_access_key`, `private_key_block`, `generic_assignment`, …). Specific
/// rules come first: on one line, a later rule does not report a secret an
/// earlier rule already did.
///
/// # Examples
///
/// ```rust
/// let rules = rune_leak::default_rules();
/// assert!(rules.iter().any(|r| r.id == "aws_access_key"));
/// assert!(rules.len() >= 15);
/// ```
#[must_use]
pub fn default_rules() -> Vec<SecretRule> {
    use Severity::{High, Medium};
    vec![
        SecretRule::new(
            "aws_access_key",
            "AWS access key id",
            r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
            High,
        )
        .with_keywords(["a3t", "akia", "asia", "abia", "acca"]),
        SecretRule::new(
            "aws_secret",
            "Possible AWS secret access key near an \"aws\" marker",
            r#"(?i)aws[^\n]{0,24}['"=:\s]([0-9a-z/+]{40})(?:['"\s]|$)"#,
            High,
        )
        .with_keywords(["aws"])
        .with_entropy_threshold(3.5),
        SecretRule::new(
            "gcp_api_key",
            "Google Cloud API key",
            r"AIza[0-9A-Za-z_\-]{35}",
            High,
        )
        .with_keywords(["aiza"]),
        SecretRule::new(
            "github_token",
            "GitHub personal, OAuth, user, server or refresh token",
            r"\bgh[pousr]_[0-9A-Za-z]{36}\b",
            High,
        )
        .with_keywords(["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]),
        SecretRule::new(
            "github_fine_grained_pat",
            "GitHub fine-grained personal access token",
            r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
            High,
        )
        .with_keywords(["github_pat_"]),
        SecretRule::new(
            "gitlab_pat",
            "GitLab personal access token",
            r"\bglpat-[0-9A-Za-z_\-]{20}\b",
            High,
        )
        .with_keywords(["glpat-"]),
        SecretRule::new(
            "slack_token",
            "Slack token",
            r"xox[baprs]-[0-9A-Za-z-]{10,}",
            High,
        )
        .with_keywords(["xox"]),
        SecretRule::new(
            "slack_webhook",
            "Slack incoming webhook URL",
            r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+",
            Medium,
        )
        .with_keywords(["hooks.slack.com"]),
        SecretRule::new(
            "stripe_live",
            "Stripe live secret or restricted key",
            r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}",
            High,
        )
        .with_keywords(["_live_"]),
        SecretRule::new(
            "sendgrid_api_key",
            "SendGrid API key",
            r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b",
            High,
        )
        .with_keywords(["sg."]),
        SecretRule::new(
            "npm_token",
            "npm access token",
            r"\bnpm_[0-9A-Za-z]{36}\b",
            High,
        )
        .with_keywords(["npm_"]),
        SecretRule::new(
            "pypi_token",
            "PyPI upload token",
            r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,}",
            High,
        )
        .with_keywords(["pypi-ageichlwas5vcmc"]),
        SecretRule::new(
            "private_key_block",
            "Private key block header",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
            High,
        )
        .with_keywords(["private key"]),
        SecretRule::new(
            "jwt",
            "JSON Web Token",
            r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            Medium,
        )
        .with_keywords(["eyj"]),
        SecretRule::new(
            "generic_assignment",
            "Generic credential assignment",
            r#"(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*["']?([^\s"'(){}\[\]<>;,$]{12,})(?:["'\s;,]|$)"#,
            Medium,
        )
        .with_keywords(["key", "secret", "passw", "token"])
        .with_entropy_threshold(3.0),
    ]
}
