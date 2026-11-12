//! The NVD CVE API 2.0 record model.
//!
//! Field names and nesting follow NVD's
//! [`cve_api_json_2.0` schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema),
//! so a record serializes back to the shape it was read from. Unknown
//! fields are ignored, and every optional member defaults when missing.

use serde::{Deserialize, Serialize};

use crate::{Bound, Cpe, CveId, Error, VersionRange};

/// One page of the NVD CVE API 2.0, or an NVD 2.0 JSON data feed file
/// (`nvdcve-2.0-*.json`), which has the same shape.
///
/// # Examples
///
/// ```
/// use rune_cve::NvdFeed;
///
/// let feed = NvdFeed::from_json(br#"{
///   "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
///   "vulnerabilities": [{"cve": {"id": "CVE-2014-0160",
///     "descriptions": [{"lang": "en", "value": "Heartbleed."}]}}]
/// }"#)?;
/// assert_eq!(feed.total_results, 1);
/// let cves = feed.into_cves();
/// assert_eq!(cves[0].id.to_string(), "CVE-2014-0160");
/// assert_eq!(cves[0].description("en"), Some("Heartbleed."));
/// # Ok::<(), rune_cve::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NvdFeed {
    /// Records on this page.
    #[serde(default)]
    pub results_per_page: u64,
    /// Index of this page's first record in the whole result.
    #[serde(default)]
    pub start_index: u64,
    /// Records in the whole result, across pages.
    #[serde(default)]
    pub total_results: u64,
    /// `NVD_CVE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// The API version, `2.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// When NVD produced the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// The records.
    #[serde(default)]
    pub vulnerabilities: Vec<Vulnerability>,
}

impl NvdFeed {
    /// Parses a page or feed file from JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the JSON is malformed or a record does not fit
    /// the schema (including an invalid CVE id or CPE name).
    pub fn from_json(json: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(json)?)
    }

    /// The records, without their wrappers.
    #[must_use]
    pub fn into_cves(self) -> Vec<Cve> {
        self.vulnerabilities.into_iter().map(|v| v.cve).collect()
    }
}

/// The wrapper NVD puts around each record in a page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Vulnerability {
    /// The record.
    pub cve: Cve,
}

/// A CVE record as NVD publishes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Cve {
    /// The CVE id.
    pub id: CveId,
    /// Who assigned the CVE (a CNA's contact address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identifier: Option<String>,
    /// Publication time, ISO 8601 without zone (UTC), e.g.
    /// `2021-12-10T10:15:09.143`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    /// Last modification time, same format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// NVD status: `Analyzed`, `Modified`, `Awaiting Analysis`,
    /// `Rejected`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_status: Option<String>,
    /// Tags such as `disputed` or `unsupported-when-assigned`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve_tags: Vec<CveTag>,
    /// Descriptions, one per language.
    #[serde(default)]
    pub descriptions: Vec<LangString>,
    /// CVSS scores from NVD and CNAs.
    #[serde(default, skip_serializing_if = "Metrics::is_empty")]
    pub metrics: Metrics,
    /// CWE classifications.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weaknesses: Vec<Weakness>,
    /// Which products are affected, as CPE match criteria.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configurations: Vec<Configuration>,
    /// Advisories, patches and other references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,
    /// Date CISA added the CVE to its Known Exploited Vulnerabilities
    /// catalog, `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cisa_exploit_add: Option<String>,
    /// The KEV remediation due date for US federal agencies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cisa_action_due: Option<String>,
    /// The KEV required action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cisa_required_action: Option<String>,
    /// The KEV vulnerability name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cisa_vulnerability_name: Option<String>,
}

/// A tag on a CVE, from one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CveTag {
    /// Who tagged it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identifier: Option<String>,
    /// The tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Text in one language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LangString {
    /// Language code, e.g. `en`.
    pub lang: String,
    /// The text.
    pub value: String,
}

/// CVSS metrics by version.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Metrics {
    /// CVSS v4.0.
    #[serde(
        rename = "cvssMetricV40",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cvss_v40: Vec<CvssMetric>,
    /// CVSS v3.1.
    #[serde(
        rename = "cvssMetricV31",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cvss_v31: Vec<CvssMetric>,
    /// CVSS v3.0.
    #[serde(
        rename = "cvssMetricV30",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cvss_v30: Vec<CvssMetric>,
    /// CVSS v2.
    #[serde(
        rename = "cvssMetricV2",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cvss_v2: Vec<CvssMetric>,
}

impl Metrics {
    /// Whether there is no metric at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.all().next().is_none()
    }

    /// Every metric: v4.0, then v3.1, v3.0 and v2.
    pub fn all(&self) -> impl Iterator<Item = &CvssMetric> {
        self.cvss_v40
            .iter()
            .chain(&self.cvss_v31)
            .chain(&self.cvss_v30)
            .chain(&self.cvss_v2)
    }

    /// The score to act on: the newest CVSS version scored by the
    /// [`Primary`](MetricType::Primary) source (NVD), else the newest
    /// version from any source; v2 only when nothing newer exists.
    #[must_use]
    pub fn preferred(&self) -> Option<&CvssMetric> {
        let v3_up = || {
            self.cvss_v40
                .iter()
                .chain(&self.cvss_v31)
                .chain(&self.cvss_v30)
        };
        v3_up()
            .find(|m| m.kind == MetricType::Primary)
            .or_else(|| v3_up().next())
            .or_else(|| {
                self.cvss_v2
                    .iter()
                    .find(|m| m.kind == MetricType::Primary)
                    .or_else(|| self.cvss_v2.first())
            })
    }
}

/// Whether a score comes from the primary source (NVD) or another one
/// (usually the CNA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MetricType {
    /// NVD's own analysis.
    Primary,
    /// Another source, typically the CNA.
    #[default]
    Secondary,
}

/// One CVSS score from one source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CvssMetric {
    /// Who scored it, e.g. `nvd@nist.gov`.
    #[serde(default)]
    pub source: String,
    /// Primary or secondary.
    #[serde(rename = "type", default)]
    pub kind: MetricType,
    /// The vector and score.
    pub cvss_data: CvssData,
    /// The v2 severity rating (`LOW`, `MEDIUM`, `HIGH`); for v3 and v4 it
    /// is in [`CvssData::base_severity`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_severity: Option<String>,
    /// The v2/v3 exploitability subscore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploitability_score: Option<f64>,
    /// The v2/v3 impact subscore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact_score: Option<f64>,
}

/// The `cvssData` of a metric: the members every CVSS version shares.
/// The individual metric values are in the vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CvssData {
    /// `2.0`, `3.0`, `3.1` or `4.0`.
    pub version: String,
    /// The vector string.
    pub vector_string: String,
    /// The base score as published.
    pub base_score: f64,
    /// The v3/v4 rating, e.g. `CRITICAL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_severity: Option<String>,
}

impl CvssMetric {
    /// Parses the vector with `rune-cvss` (v3.0, v3.1 and v4.0).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCvssVersion`] for CVSS v2, [`Error::Cvss`] for
    /// an invalid vector.
    pub fn vector(&self) -> Result<rune_cvss::Vector, Error> {
        if self.cvss_data.version.starts_with('2') {
            return Err(Error::UnsupportedCvssVersion(
                self.cvss_data.version.clone(),
            ));
        }
        Ok(self.cvss_data.vector_string.parse()?)
    }

    /// The score as a `rune_finding::Cvss`, with the published base score.
    #[must_use]
    pub fn to_finding_cvss(&self) -> rune_finding::Cvss {
        rune_finding::Cvss::new(&self.cvss_data.vector_string, self.cvss_data.base_score)
    }
}

/// A CWE classification from one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Weakness {
    /// Who classified it.
    #[serde(default)]
    pub source: String,
    /// Primary or secondary.
    #[serde(rename = "type", default)]
    pub kind: MetricType,
    /// The CWE ids, as `CWE-79` (or `NVD-CWE-Other`, `NVD-CWE-noinfo`).
    #[serde(default)]
    pub description: Vec<LangString>,
}

/// A reference URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Reference {
    /// The URL.
    pub url: String,
    /// Who added it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// NVD tags such as `Patch`, `Vendor Advisory`, `Exploit`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// How a node or configuration combines its children.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Operator {
    /// Every child must match.
    #[serde(rename = "AND")]
    And,
    /// At least one child must match.
    #[serde(rename = "OR")]
    #[default]
    Or,
}

/// An applicability statement: a tree of CPE match criteria.
///
/// The common shapes are one `OR` node of vulnerable products, and an
/// `AND` of a vulnerable application node with a non-vulnerable platform
/// node ("running on").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Configuration {
    /// How the nodes combine; `OR` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<Operator>,
    /// Negates the result.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub negate: bool,
    /// The nodes.
    #[serde(default)]
    pub nodes: Vec<Node>,
}

/// A node of a [`Configuration`]: match criteria combined by an operator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Node {
    /// How the criteria combine.
    #[serde(default)]
    pub operator: Operator,
    /// Negates the result.
    #[serde(default)]
    pub negate: bool,
    /// The criteria.
    #[serde(default)]
    pub cpe_match: Vec<CpeMatch>,
}

/// One CPE match criterion: a CPE name, optionally with a version range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CpeMatch {
    /// Whether matching products are vulnerable (`false` for platforms
    /// that only qualify an `AND`).
    pub vulnerable: bool,
    /// The CPE name, usually with version `*` when a range is given.
    pub criteria: Cpe,
    /// NVD's id for this criterion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_criteria_id: Option<String>,
    /// Lowest affected version, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_start_including: Option<String>,
    /// Lowest affected version, exclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_start_excluding: Option<String>,
    /// Highest affected version, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_end_including: Option<String>,
    /// First fixed version (exclusive end).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_end_excluding: Option<String>,
}

impl CpeMatch {
    /// A criterion with no version range.
    #[must_use]
    pub const fn new(criteria: Cpe, vulnerable: bool) -> Self {
        Self {
            vulnerable,
            criteria,
            match_criteria_id: None,
            version_start_including: None,
            version_start_excluding: None,
            version_end_including: None,
            version_end_excluding: None,
        }
    }

    /// The criterion with `range` as its version bounds.
    #[must_use]
    pub fn with_range(mut self, range: VersionRange) -> Self {
        (self.version_start_including, self.version_start_excluding) = match range.start {
            Some(Bound::Including(v)) => (Some(v), None),
            Some(Bound::Excluding(v)) => (None, Some(v)),
            None => (None, None),
        };
        (self.version_end_including, self.version_end_excluding) = match range.end {
            Some(Bound::Including(v)) => (Some(v), None),
            Some(Bound::Excluding(v)) => (None, Some(v)),
            None => (None, None),
        };
        self
    }

    /// The version bounds. When a record has both an including and an
    /// excluding bound at the same end (it should not), the including one
    /// wins.
    #[must_use]
    pub fn range(&self) -> VersionRange {
        let pick = |inc: &Option<String>, exc: &Option<String>| {
            inc.clone()
                .map(Bound::Including)
                .or_else(|| exc.clone().map(Bound::Excluding))
        };
        VersionRange::new(
            pick(&self.version_start_including, &self.version_start_excluding),
            pick(&self.version_end_including, &self.version_end_excluding),
        )
    }

    /// Whether `target` (an installed product, normally with a literal
    /// version) meets this criterion.
    ///
    /// Without a range, this is [`Cpe::matches`]. With one, every
    /// attribute but the version must match by name, and the target's
    /// version must be a literal inside the range: a target whose version
    /// is ANY, NA or a pattern never meets a ranged criterion.
    #[must_use]
    pub fn matches(&self, target: &Cpe) -> bool {
        let range = self.range();
        if range.is_unbounded() {
            return self.criteria.matches(target);
        }
        let Some(version) = target.version() else {
            return false;
        };
        let version_ok = match self.criteria.get(crate::Attribute::Version) {
            crate::Component::Any => true,
            c => c.as_literal() == Some(version),
        };
        version_ok && self.criteria.matches_except_version(target) && range.contains(version)
    }
}

impl Node {
    fn eval(&self, platform: &[Cpe], hit: &mut bool) -> bool {
        let mut any = false;
        let mut all = !self.cpe_match.is_empty();
        for m in &self.cpe_match {
            let ok = platform.iter().any(|p| m.matches(p));
            if ok && m.vulnerable {
                *hit = true;
            }
            any |= ok;
            all &= ok;
        }
        let result = match self.operator {
            Operator::And => all,
            Operator::Or => any,
        };
        result != self.negate
    }
}

impl Configuration {
    /// Whether the configuration holds for a system made of `platform`
    /// (the installed applications, operating system and hardware), with
    /// at least one *vulnerable* criterion met.
    #[must_use]
    pub fn applies_to(&self, platform: &[Cpe]) -> bool {
        let mut hit = false;
        let mut any = false;
        let mut all = !self.nodes.is_empty();
        for node in &self.nodes {
            let ok = node.eval(platform, &mut hit);
            any |= ok;
            all &= ok;
        }
        let result = match self.operator.unwrap_or_default() {
            Operator::And => all,
            Operator::Or => any,
        };
        hit && result != self.negate
    }

    /// Every criterion in the configuration.
    pub fn criteria(&self) -> impl Iterator<Item = &CpeMatch> {
        self.nodes.iter().flat_map(|n| &n.cpe_match)
    }
}

impl Cve {
    /// A record with only an id.
    #[must_use]
    pub fn new(id: CveId) -> Self {
        Self {
            id,
            source_identifier: None,
            published: None,
            last_modified: None,
            vuln_status: None,
            cve_tags: Vec::new(),
            descriptions: Vec::new(),
            metrics: Metrics::default(),
            weaknesses: Vec::new(),
            configurations: Vec::new(),
            references: Vec::new(),
            cisa_exploit_add: None,
            cisa_action_due: None,
            cisa_required_action: None,
            cisa_vulnerability_name: None,
        }
    }

    /// Parses one record (the object under `"cve"`) from JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when the JSON does not fit the schema.
    pub fn from_json(json: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice(json)?)
    }

    /// The description in `lang` (e.g. `"en"`).
    #[must_use]
    pub fn description(&self, lang: &str) -> Option<&str> {
        self.descriptions
            .iter()
            .find(|d| d.lang.eq_ignore_ascii_case(lang))
            .map(|d| d.value.as_str())
    }

    /// Whether NVD rejected the CVE (withdrawn or a duplicate).
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        self.vuln_status.as_deref() == Some("Rejected")
    }

    /// Whether the CVE is in CISA's Known Exploited Vulnerabilities
    /// catalog, as NVD records it.
    #[must_use]
    pub const fn is_known_exploited(&self) -> bool {
        self.cisa_exploit_add.is_some()
    }

    /// The CWE numbers of every source's classification, sorted and
    /// deduplicated. `NVD-CWE-Other` and `NVD-CWE-noinfo` are left out.
    #[must_use]
    pub fn cwes(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self
            .weaknesses
            .iter()
            .flat_map(|w| &w.description)
            .filter_map(|d| d.value.strip_prefix("CWE-")?.parse().ok())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The preferred score (see [`Metrics::preferred`]) as a
    /// `rune_finding::Cvss`.
    #[must_use]
    pub fn cvss(&self) -> Option<rune_finding::Cvss> {
        self.metrics.preferred().map(CvssMetric::to_finding_cvss)
    }

    /// The severity of the preferred score, or `None` when the CVE is not
    /// scored yet.
    #[must_use]
    pub fn severity(&self) -> Option<rune_finding::Severity> {
        self.metrics
            .preferred()
            .map(|m| rune_finding::Severity::from_cvss_score(m.cvss_data.base_score))
    }

    /// Whether some vulnerable criterion of any configuration matches
    /// `target`, ignoring `AND` platform conditions.
    ///
    /// This is the question "is this product at this version affected?"
    /// when only the product is known. It can report a CVE that needs a
    /// platform the target does not run on; use
    /// [`applies_to`](Self::applies_to) when the whole platform is known.
    #[must_use]
    pub fn affects(&self, target: &Cpe) -> bool {
        self.matching_criteria(target).next().is_some()
    }

    /// The vulnerable criteria that `target` meets.
    pub fn matching_criteria<'a>(
        &'a self,
        target: &'a Cpe,
    ) -> impl Iterator<Item = &'a CpeMatch> + 'a {
        self.configurations
            .iter()
            .flat_map(Configuration::criteria)
            .filter(move |m| m.vulnerable && m.matches(target))
    }

    /// Whether any configuration applies to a system made of `platform`,
    /// evaluating `AND`/`OR` nodes and negation fully (see
    /// [`Configuration::applies_to`]).
    #[must_use]
    pub fn applies_to(&self, platform: &[Cpe]) -> bool {
        self.configurations.iter().any(|c| c.applies_to(platform))
    }

    /// A `rune_finding::Finding` reporting this CVE at `location`.
    ///
    /// The check id is the CVE id, the title the KEV name or the first
    /// line of the English description, the taxonomy its CWEs, the CVSS
    /// score the preferred one, and the references become remediation
    /// references. An unscored CVE (awaiting analysis) is
    /// `Severity::Medium` so it is not hidden; confidence is `Firm`, as a
    /// version match is not proof of exploitability. Adjust either on the
    /// returned finding as needed.
    #[must_use]
    pub fn to_finding(&self, location: rune_finding::Location) -> rune_finding::Finding {
        let title = self
            .cisa_vulnerability_name
            .as_deref()
            .or_else(|| self.description("en").and_then(|d| d.lines().next()))
            .map_or_else(|| self.id.to_string(), |t| format!("{}: {t}", self.id));
        let mut finding = rune_finding::Finding::<()>::new(
            self.id.to_string(),
            title,
            self.severity().unwrap_or(rune_finding::Severity::Medium),
            rune_finding::Confidence::Firm,
            location,
        )
        .with_taxonomy(
            self.cwes()
                .into_iter()
                .map(rune_finding::TaxonomyRef::cwe)
                .collect(),
        )
        .with_remediation_refs(self.references.iter().map(|r| r.url.clone()).collect());
        if let Some(cvss) = self.cvss() {
            finding = finding.with_cvss(cvss);
        }
        finding
    }
}
