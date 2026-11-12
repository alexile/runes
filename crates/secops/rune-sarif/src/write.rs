//! Writing findings as a SARIF log: [`write()`], its [`Options`], and the
//! [`ToSarif`] hook for extension data.

use std::collections::HashMap;

use rune_finding::{Finding, Severity, Taxonomy, TaxonomyRef};
use serde_json::Value;

use crate::model::{
    self, Level, Log, Message, MultiformatMessageString, ReportingDescriptor,
    ReportingDescriptorReference, Run, RunAutomationDetails, Tool, ToolComponent,
    ToolComponentReference,
};
use crate::{keys, location};

/// What [`write()`] puts in the log besides the findings.
///
/// # Examples
///
/// ```
/// use rune_sarif::Options;
///
/// let options = Options::default()
///     .with_tool_name("payload-fuzzer")
///     .with_tool_version("0.1.0")
///     .with_category("dast/");
/// assert_eq!(options.tool_name, "payload-fuzzer");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// `tool.driver.name`. Default: `rune-sarif`; set it to the scanner's
    /// name.
    pub tool_name: String,
    /// `tool.driver.semanticVersion`.
    pub tool_version: Option<String>,
    /// `tool.driver.organization`.
    pub tool_organization: Option<String>,
    /// `tool.driver.informationUri`.
    pub tool_information_uri: Option<String>,
    /// The log's `$schema`. Default: [`model::SCHEMA_URI`].
    pub schema_uri: Option<String>,
    /// `run.automationDetails.id`, which GitHub code scanning uses as the
    /// upload's category, e.g. `dast/` or `sast/python/`.
    pub category: Option<String>,
    /// Whether to store the finding members SARIF has no slot for, so that
    /// [`read`](crate::read) gives the same findings back. Default: `true`.
    ///
    /// With it on, each result's property bag also holds `evidence`,
    /// `cvss`, `remediation` and `remediationRefs` (when set), its location
    /// a hint where the URI alone is ambiguous (see
    /// [`location`](crate::location)), and each rule the remediation
    /// summary as `help`.
    ///
    /// With it off, the output is leaner; a [`ToSarif`] hook can still add
    /// legacy tags and HTTP exchanges.
    pub details: bool,
    /// Whether to fill each `taxa` entry from rune-taxonomy's datasets:
    /// `shortDescription` with the entry's name, and `name` too when the
    /// finding gave none. Ids the datasets do not know are left as they
    /// are. Default: `false`, so the output does not depend on the feature.
    ///
    /// [`read`](crate::read) takes a taxon's `name` back, so a reference
    /// written without a name reads back with the dataset's.
    #[cfg(feature = "taxonomy")]
    pub taxonomy_names: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            tool_name: env!("CARGO_PKG_NAME").to_owned(),
            tool_version: None,
            tool_organization: None,
            tool_information_uri: None,
            schema_uri: Some(model::SCHEMA_URI.to_owned()),
            category: None,
            details: true,
            #[cfg(feature = "taxonomy")]
            taxonomy_names: false,
        }
    }
}

impl Options {
    /// Set the tool name.
    #[must_use]
    pub fn with_tool_name(mut self, name: impl Into<String>) -> Self {
        self.tool_name = name.into();
        self
    }

    /// Set the tool's semantic version.
    #[must_use]
    pub fn with_tool_version(mut self, version: impl Into<String>) -> Self {
        self.tool_version = Some(version.into());
        self
    }

    /// Set the organization that makes the tool.
    #[must_use]
    pub fn with_tool_organization(mut self, organization: impl Into<String>) -> Self {
        self.tool_organization = Some(organization.into());
        self
    }

    /// Set the tool's home page.
    #[must_use]
    pub fn with_tool_information_uri(mut self, uri: impl Into<String>) -> Self {
        self.tool_information_uri = Some(uri.into());
        self
    }

    /// Set the `$schema` URI, or leave it out with `None`.
    #[must_use]
    pub fn with_schema_uri(mut self, uri: Option<String>) -> Self {
        self.schema_uri = uri;
        self
    }

    /// Set the run's category (`automationDetails.id`).
    #[must_use]
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Store finding details for a lossless round trip (on by default).
    #[must_use]
    pub const fn with_details(mut self, details: bool) -> Self {
        self.details = details;
        self
    }

    /// Name and describe `taxa` from rune-taxonomy (off by default).
    ///
    /// ```
    /// use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
    /// use rune_sarif::{Options, write};
    ///
    /// let finding = Finding::<()>::new(
    ///     "py.sqli",
    ///     "SQL injection",
    ///     Severity::High,
    ///     Confidence::Firm,
    ///     Location::file("src/app.py"),
    /// )
    /// .push_taxonomy(TaxonomyRef::cwe(89));
    ///
    /// let log = write(&[finding], &Options::default().with_taxonomy_names(true));
    /// let taxon = &log.runs[0].taxonomies[0].taxa[0];
    /// assert!(taxon.name.as_deref().is_some_and(|name| name.contains("SQL")));
    /// assert!(taxon.short_description.is_some());
    /// ```
    #[cfg(feature = "taxonomy")]
    #[must_use]
    pub const fn with_taxonomy_names(mut self, taxonomy_names: bool) -> Self {
        self.taxonomy_names = taxonomy_names;
        self
    }
}

/// How a finding's extension adds to its SARIF rule and result.
///
/// [`write()`] builds the rule and the result from the finding's core members
/// first, then calls these hooks, which may change anything. The default
/// methods do nothing, so `impl ToSarif for MyExt {}` is enough when the
/// extension has nothing to add.
///
/// # Examples
///
/// Emit a taint path as a SARIF code flow:
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity};
/// use rune_sarif::model::{CodeFlow, ThreadFlowLocation};
/// use rune_sarif::{Options, ToSarif, location, write};
///
/// #[derive(Default)]
/// struct SastExt {
///     dataflow: Vec<Location>,
/// }
///
/// impl ToSarif for SastExt {
///     fn write_result(finding: &Finding<Self>, result: &mut rune_sarif::model::Result) {
///         if !finding.dataflow.is_empty() {
///             let steps = finding.dataflow.iter().map(location::to_sarif);
///             result
///                 .code_flows
///                 .push(CodeFlow::single(steps.map(ThreadFlowLocation::new)));
///         }
///     }
/// }
///
/// let mut finding = Finding::<SastExt>::new(
///     "py.sqli",
///     "SQL injection",
///     Severity::High,
///     Confidence::Firm,
///     Location::file("app.py").with_lines(15, 15),
/// );
/// finding.dataflow = vec![
///     Location::file("app.py").with_lines(11, 11),
///     Location::file("app.py").with_lines(15, 15),
/// ];
/// let log = write(&[finding], &Options::default());
/// assert_eq!(log.runs[0].results[0].code_flows[0].thread_flows[0].locations.len(), 2);
/// ```
pub trait ToSarif: Sized {
    /// Adjust the rule written for `finding.check_id`. Called once per rule,
    /// with the first finding that has the check id.
    fn write_rule(finding: &Finding<Self>, rule: &mut ReportingDescriptor) {
        let _ = (finding, rule);
    }

    /// Adjust the result written for `finding`.
    fn write_result(finding: &Finding<Self>, result: &mut model::Result) {
        let _ = (finding, result);
    }
}

impl ToSarif for () {}

/// Write findings as a SARIF 2.1.0 log with one run.
///
/// Each distinct check id becomes a rule (`tool.driver.rules`), built from
/// the first finding with that id, and each finding a result:
///
/// - `ruleId` is the check id and `message.text` the title;
/// - [`Severity`] gives `level` ([`Severity::sarif_level`]) and the
///   `security-severity` property on the rule and the result
///   ([`Severity::security_severity`]), which GitHub code scanning reads;
/// - the confidence is the `confidence` property;
/// - the location is the single entry of `locations` (see
///   [`location`](crate::location));
/// - [`Finding::fingerprint`] is `partialFingerprints["netsecFingerprint/v1"]`
///   ([`keys::FINGERPRINT`]);
/// - each [`TaxonomyRef`] is a `taxa` reference into `run.taxonomies`, which
///   has one component per taxonomy in use (CWE, OWASP, ...), and CWE
///   entries also become `external/cwe/cwe-<n>` rule tags next to
///   `security`, as GitHub expects;
/// - the first remediation reference is the rule's `helpUri`, and (with
///   [`Options::details`]) the remediation summary its `help`;
/// - with [`Options::details`], the members SARIF has no slot for go in the
///   result's property bag.
///
/// The extension's [`ToSarif`] hooks run last.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
/// use rune_sarif::{Options, write};
///
/// let finding = Finding::<()>::new(
///     "py.sqli",
///     "SQL injection",
///     Severity::High,
///     Confidence::Firm,
///     Location::file("src/app.py").with_lines(15, 15),
/// )
/// .push_taxonomy(TaxonomyRef::cwe(89));
///
/// let log = write(&[finding], &Options::default().with_tool_name("my-scanner"));
/// let run = &log.runs[0];
/// assert_eq!(run.tool.driver.rules[0].properties.tags, ["security", "external/cwe/cwe-89"]);
/// assert_eq!(run.results[0].level, Some(rune_sarif::model::Level::Error));
/// assert_eq!(run.taxonomies[0].name, "CWE");
/// ```
#[must_use]
pub fn write<X: ToSarif>(findings: &[Finding<X>], options: &Options) -> Log {
    let mut rules: Vec<ReportingDescriptor> = Vec::new();
    let mut rule_ids: HashMap<&str, usize> = HashMap::new();
    let mut taxonomies = TaxonomyTable::default();
    #[cfg(feature = "taxonomy")]
    {
        taxonomies.names = options.taxonomy_names;
    }
    let mut results = Vec::with_capacity(findings.len());

    for finding in findings {
        if !rule_ids.contains_key(finding.check_id.as_str()) {
            let mut rule = rule(finding, options);
            X::write_rule(finding, &mut rule);
            rule_ids.insert(&finding.check_id, rules.len());
            rules.push(rule);
        }
        let mut result = result(finding, options, &mut taxonomies);
        X::write_result(finding, &mut result);
        results.push(result);
    }

    let mut driver = ToolComponent::new(options.tool_name.clone());
    driver.organization.clone_from(&options.tool_organization);
    driver.semantic_version.clone_from(&options.tool_version);
    driver
        .information_uri
        .clone_from(&options.tool_information_uri);
    driver.rules = rules;

    let run = Run {
        tool: Tool {
            driver,
            ..Tool::default()
        },
        results,
        taxonomies: taxonomies.components,
        automation_details: options.category.as_ref().map(|id| RunAutomationDetails {
            id: Some(id.clone()),
            guid: None,
        }),
        ..Run::default()
    };

    let mut log = Log::new();
    log.schema.clone_from(&options.schema_uri);
    log.runs.push(run);
    log
}

/// The SARIF level of a severity.
#[must_use]
pub const fn level(severity: Severity) -> Level {
    match severity {
        Severity::Informational => Level::Note,
        Severity::Low | Severity::Medium => Level::Warning,
        Severity::High | Severity::Critical => Level::Error,
    }
}

fn rule<X>(finding: &Finding<X>, options: &Options) -> ReportingDescriptor {
    let mut rule = ReportingDescriptor::new(finding.check_id.clone());
    rule.name = Some(finding.title.clone());
    rule.short_description = Some(MultiformatMessageString::text(finding.title.clone()));
    rule.help_uri = finding
        .remediation
        .as_ref()
        .and_then(|remediation| remediation.references.first())
        .or_else(|| finding.remediation_refs.first())
        .cloned();
    rule.help = finding
        .remediation
        .as_ref()
        .filter(|_| options.details)
        .map(|remediation| MultiformatMessageString::text(remediation.summary.clone()));
    rule.properties.security_severity = Some(finding.severity.security_severity().to_owned());
    rule.properties.tags.push("security".to_owned());
    for cwe in finding.taxonomy.iter().filter_map(TaxonomyRef::cwe_number) {
        let tag = format!("external/cwe/cwe-{cwe}");
        if !rule.properties.tags.contains(&tag) {
            rule.properties.tags.push(tag);
        }
    }
    rule
}

fn result<X>(
    finding: &Finding<X>,
    options: &Options,
    taxonomies: &mut TaxonomyTable,
) -> model::Result {
    let mut result = model::Result {
        rule_id: Some(finding.check_id.clone()),
        level: Some(level(finding.severity)),
        message: Message::text(finding.title.clone()),
        locations: vec![if options.details {
            location::to_sarif(&finding.location)
        } else {
            location::to_sarif_plain(&finding.location)
        }],
        ..model::Result::default()
    };

    let properties = &mut result.properties;
    properties.security_severity = Some(finding.severity.security_severity().to_owned());
    properties.insert(keys::CONFIDENCE, Value::from(finding.confidence.as_str()));
    if options.details {
        let mut put = |key: &str, value: Result<Value, serde_json::Error>| {
            if let Ok(value) = value {
                properties.insert(key, value);
            }
        };
        if !finding.evidence.is_empty() {
            put(keys::EVIDENCE, serde_json::to_value(&finding.evidence));
        }
        if let Some(cvss) = &finding.cvss {
            put(keys::CVSS, serde_json::to_value(cvss));
        }
        if let Some(remediation) = &finding.remediation {
            put(keys::REMEDIATION, serde_json::to_value(remediation));
        }
        if !finding.remediation_refs.is_empty() {
            put(
                keys::REMEDIATION_REFS,
                serde_json::to_value(&finding.remediation_refs),
            );
        }
    }

    result
        .partial_fingerprints
        .insert(keys::FINGERPRINT.to_owned(), finding.fingerprint());
    result.taxa = finding
        .taxonomy
        .iter()
        .map(|entry| taxonomies.reference(entry))
        .collect();
    result
}

/// Taxonomy components accumulated over a run, in first-use order.
#[derive(Default)]
struct TaxonomyTable {
    frameworks: Vec<Taxonomy>,
    components: Vec<ToolComponent>,
    /// [`Options::taxonomy_names`].
    #[cfg(feature = "taxonomy")]
    names: bool,
}

impl TaxonomyTable {
    /// A `taxa` reference to `entry`, adding its component and taxon on
    /// first use. Taxa are shared by id and written name, so a name read
    /// back is always the one the finding had, or the dataset's when it had
    /// none.
    fn reference(&mut self, entry: &TaxonomyRef) -> ReportingDescriptorReference {
        let component_index = self
            .frameworks
            .iter()
            .position(|framework| *framework == entry.framework)
            .unwrap_or_else(|| {
                let framework = &entry.framework;
                let mut component = ToolComponent::new(framework.display_name());
                component.organization = framework.organization().map(str::to_owned);
                component.information_uri = framework.information_uri().map(str::to_owned);
                self.frameworks.push(framework.clone());
                self.components.push(component);
                self.components.len() - 1
            });
        #[cfg(feature = "taxonomy")]
        let names = self.names;
        let (component_name, taxa) = match self.components.get_mut(component_index) {
            Some(component) => (component.name.clone(), &mut component.taxa),
            // Unreachable: the index was found or pushed above.
            None => return ReportingDescriptorReference::default(),
        };
        let mut taxon = ReportingDescriptor::new(entry.id.clone());
        taxon.name.clone_from(&entry.name);
        #[cfg(feature = "taxonomy")]
        if names {
            describe_taxon(&mut taxon, entry);
        }
        // Match on the taxon as written: with taxonomy names on, a reference
        // without a name gets the dataset's, and must share that taxon
        // rather than repeat it (SARIF requires `taxa` items to be unique).
        let taxon_index = taxa
            .iter()
            .position(|written| written.id == taxon.id && written.name == taxon.name)
            .unwrap_or_else(|| {
                taxa.push(taxon);
                taxa.len() - 1
            });
        ReportingDescriptorReference {
            id: Some(entry.id.clone()),
            index: Some(index(taxon_index)),
            tool_component: Some(ToolComponentReference {
                name: Some(component_name),
                index: Some(index(component_index)),
            }),
        }
    }
}

/// Fills a taxon from rune-taxonomy, if the datasets know `entry`.
#[cfg(feature = "taxonomy")]
fn describe_taxon(taxon: &mut ReportingDescriptor, entry: &TaxonomyRef) {
    let Some(name) = rune_taxonomy::resolve(entry)
        .ok()
        .and_then(|found| found.name())
    else {
        return;
    };
    if taxon.name.is_none() {
        taxon.name = Some(name.to_owned());
    }
    taxon.short_description = Some(MultiformatMessageString::text(name));
}

fn index(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use rune_finding::{Confidence, Cvss, Evidence, Location, Remediation};

    use super::*;

    fn finding() -> Finding {
        Finding::<()>::new(
            "tls.weak_protocol",
            "TLS 1.0 accepted",
            Severity::High,
            Confidence::Certain,
            Location::network("example.test", 443),
        )
        .push_taxonomy(TaxonomyRef::cwe(327))
        .with_remediation(
            Remediation::new("Disable TLS 1.0").push_reference("https://example.test/ref"),
        )
    }

    #[test]
    fn one_rule_per_check_id() {
        let log = write(&[finding(), finding()], &Options::default());
        let run = &log.runs[0];
        assert_eq!(run.tool.driver.rules.len(), 1);
        assert_eq!(run.results.len(), 2);
        let rule = &run.tool.driver.rules[0];
        assert_eq!(rule.help_uri.as_deref(), Some("https://example.test/ref"));
        assert_eq!(
            rule.help.as_ref().map(|help| help.text.as_str()),
            Some("Disable TLS 1.0")
        );
        assert_eq!(rule.properties.security_severity.as_deref(), Some("8.0"));
        assert_eq!(run.taxonomies.len(), 1);
        assert_eq!(run.taxonomies[0].taxa.len(), 1);
        assert_eq!(
            run.results[1].taxa[0]
                .tool_component
                .as_ref()
                .and_then(|c| c.name.as_deref()),
            Some("CWE")
        );
    }

    #[test]
    fn levels_follow_severity() {
        let levels: Vec<_> = Severity::ALL.into_iter().map(level).collect();
        assert_eq!(
            levels,
            [
                Level::Note,
                Level::Warning,
                Level::Warning,
                Level::Error,
                Level::Error
            ]
        );
        for severity in Severity::ALL {
            assert_eq!(level(severity).as_str(), severity.sarif_level());
        }
    }

    #[test]
    fn details_switch() {
        let rich = finding()
            .push_evidence(Evidence::new("tls_version", "TLSv1.0"))
            .with_cvss(Cvss::new("CVSS:3.1/AV:N", 5.9))
            .push_remediation_ref("https://example.test/more");
        let with = write(std::slice::from_ref(&rich), &Options::default());
        let properties = &with.runs[0].results[0].properties;
        for key in [
            keys::EVIDENCE,
            keys::CVSS,
            keys::REMEDIATION,
            keys::REMEDIATION_REFS,
        ] {
            assert!(properties.get(key).is_some(), "{key}");
        }
        let without = write(&[rich], &Options::default().with_details(false));
        let properties = &without.runs[0].results[0].properties;
        assert_eq!(
            properties.additional.keys().collect::<Vec<_>>(),
            [keys::CONFIDENCE]
        );
    }

    #[test]
    fn taxa_with_different_names_stay_apart() {
        let named = finding().with_taxonomy(vec![TaxonomyRef::cwe(79).with_name("XSS")]);
        let bare = finding().with_taxonomy(vec![TaxonomyRef::cwe(79), TaxonomyRef::cwe(79)]);
        let log = write(&[named, bare], &Options::default());
        let run = &log.runs[0];
        assert_eq!(run.taxonomies[0].taxa.len(), 2);
        assert_eq!(run.results[1].taxa[0].index, Some(1));
        assert_eq!(run.results[1].taxa[1].index, Some(1));
    }

    #[test]
    fn options_fill_the_driver() {
        let options = Options::default()
            .with_tool_name("t")
            .with_tool_version("1.2.3")
            .with_tool_organization("o")
            .with_tool_information_uri("https://t.test/")
            .with_category("dast/")
            .with_schema_uri(None);
        let log = write::<()>(&[], &options);
        assert_eq!(log.schema, None);
        let driver = &log.runs[0].tool.driver;
        assert_eq!(
            (
                driver.name.as_str(),
                driver.semantic_version.as_deref(),
                driver.organization.as_deref()
            ),
            ("t", Some("1.2.3"), Some("o"))
        );
        assert_eq!(
            log.runs[0]
                .automation_details
                .as_ref()
                .and_then(|d| d.id.as_deref()),
            Some("dast/")
        );
    }

    #[cfg(feature = "taxonomy")]
    #[test]
    fn taxonomy_names_fill_known_taxa_only() {
        let findings = [finding().with_taxonomy(vec![
            TaxonomyRef::cwe(79),
            TaxonomyRef::cwe(89).with_name("SQLi"),
            TaxonomyRef::new(Taxonomy::Custom("acme".to_owned()), "X-1"),
            TaxonomyRef::cwe(999_999),
        ])];
        let expected_79 = rune_taxonomy::named(&TaxonomyRef::cwe(79)).unwrap().name;
        let expected_89 = rune_taxonomy::named(&TaxonomyRef::cwe(89)).unwrap().name;

        // Off by default: the feature alone changes nothing.
        let plain = write(&findings, &Options::default());
        assert_eq!(
            plain,
            write(&findings, &Options::default().with_taxonomy_names(false))
        );
        assert!(
            plain.runs[0]
                .taxonomies
                .iter()
                .flat_map(|c| &c.taxa)
                .all(|t| t.short_description.is_none())
        );

        let log = write(&findings, &Options::default().with_taxonomy_names(true));
        let cwe = &log.runs[0].taxonomies[0].taxa;
        let short = |t: &ReportingDescriptor| t.short_description.as_ref().map(|d| d.text.clone());
        assert_eq!(cwe[0].name, expected_79);
        assert_eq!(short(&cwe[0]), expected_79);
        // A finding's own name wins; the description is the dataset's.
        assert_eq!(cwe[1].name.as_deref(), Some("SQLi"));
        assert_eq!(short(&cwe[1]), expected_89);
        // Unknown ids and custom taxonomies stay bare.
        assert_eq!((cwe[2].name.as_ref(), short(&cwe[2])), (None, None));
        let acme = &log.runs[0].taxonomies[1].taxa[0];
        assert_eq!((acme.name.as_ref(), short(acme)), (None, None));
    }

    #[cfg(feature = "taxonomy")]
    #[test]
    fn named_taxa_are_not_repeated() {
        let findings = [
            finding().with_taxonomy(vec![TaxonomyRef::cwe(79)]),
            finding().with_taxonomy(vec![TaxonomyRef::cwe(79)]),
            finding().with_taxonomy(vec![
                TaxonomyRef::cwe(79).with_name(rune_taxonomy::cwe(79).unwrap().name),
            ]),
        ];
        let log = write(&findings, &Options::default().with_taxonomy_names(true));
        let taxa = &log.runs[0].taxonomies[0].taxa;
        assert_eq!(taxa.len(), 1, "{taxa:?}");
        assert!(
            log.runs[0]
                .results
                .iter()
                .all(|result| result.taxa[0].index == Some(0))
        );
    }
}
