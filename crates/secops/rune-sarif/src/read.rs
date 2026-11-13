//! Reading findings from a SARIF log: [`read`], the [`FromSarif`] hook, and
//! [`Imported`], the extension that keeps what the finding model has no
//! member for.

use std::collections::{BTreeMap, HashSet};

use rune_finding::{
    Confidence, Cvss, Evidence, Finding, Location, Remediation, Severity, Taxonomy, TaxonomyRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{
    self, Level, Log, ReportingDescriptor, ReportingDescriptorReference, ResultKind, Run,
    ToolComponent,
};
use crate::write::ToSarif;
use crate::{Error, keys, location};

/// Result properties the reader maps onto finding members. The others are
/// "unknown" and go to the extension.
const MAPPED: [&str; 5] = [
    keys::CONFIDENCE,
    keys::EVIDENCE,
    keys::CVSS,
    keys::REMEDIATION,
    keys::REMEDIATION_REFS,
];

/// How a finding's extension is filled from the SARIF it was read from.
///
/// Implemented by `()` (keep nothing) and [`Imported`] (keep the tool,
/// fingerprints, code flows and unknown properties). Implement it for a
/// product extension to pick what that product needs.
pub trait FromSarif: Sized {
    /// Build the extension for one result.
    fn from_sarif(context: &ResultContext<'_>) -> Self;

    /// Roughly how many bytes of text the extension holds, counted against
    /// [`ReadOptions::with_max_text_bytes`]. Count at least everything
    /// copied from the rule or the run: those are shared by many results,
    /// so they are what can make the findings much larger than the log.
    /// [`json_len`] measures anything serializable.
    fn text_len(&self) -> usize;
}

impl FromSarif for () {
    fn from_sarif(_: &ResultContext<'_>) -> Self {}

    fn text_len(&self) -> usize {
        0
    }
}

/// Limits for [`read_with`].
///
/// # Examples
///
/// ```
/// use rune_sarif::ReadOptions;
///
/// let options = ReadOptions::default().with_max_text_bytes(1 << 20);
/// assert_eq!(options.max_text_bytes(), 1 << 20);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOptions {
    max_text_bytes: usize,
}

impl ReadOptions {
    /// The default budget: 256 MiB.
    pub const DEFAULT_MAX_TEXT_BYTES: usize = 256 << 20;

    /// Cap the total size of the findings read, measured as the length of
    /// each finding's JSON form plus its extension's
    /// [`FromSarif::text_len`]. The total is checked after each finding is
    /// built, so reading stops before it goes far past the cap.
    /// `usize::MAX` turns the cap off.
    #[must_use]
    pub const fn with_max_text_bytes(mut self, bytes: usize) -> Self {
        self.max_text_bytes = bytes;
        self
    }

    /// The cap set by [`with_max_text_bytes`](Self::with_max_text_bytes).
    #[must_use]
    pub const fn max_text_bytes(&self) -> usize {
        self.max_text_bytes
    }
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            max_text_bytes: Self::DEFAULT_MAX_TEXT_BYTES,
        }
    }
}

/// The length of `value`'s compact JSON form, without building it.
///
/// A helper for [`FromSarif::text_len`].
///
/// # Examples
///
/// ```
/// assert_eq!(rune_sarif::json_len(&vec!["ab", "c"]), 10);
/// ```
#[must_use]
pub fn json_len<T: Serialize + ?Sized>(value: &T) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    // A value that fails to serialize part way still counts what it wrote.
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}

/// The SARIF a finding is read from, for [`FromSarif`].
#[derive(Debug, Clone, Copy)]
pub struct ResultContext<'a> {
    run: &'a Run,
    result: &'a model::Result,
    rule: Option<&'a ReportingDescriptor>,
    mapped: [bool; MAPPED.len()],
}

impl<'a> ResultContext<'a> {
    /// The run the result belongs to.
    #[must_use]
    pub const fn run(&self) -> &'a Run {
        self.run
    }

    /// The result.
    #[must_use]
    pub const fn result(&self) -> &'a model::Result {
        self.result
    }

    /// The result's rule, wherever it is defined (the driver or an
    /// extension), when the log has it.
    #[must_use]
    pub const fn rule(&self) -> Option<&'a ReportingDescriptor> {
        self.rule
    }

    /// The result's properties that no finding member was read from:
    /// everything except `security-severity`, `tags` and the properties the
    /// writer stores finding members in ([`keys`]) when they parsed.
    pub fn unknown_properties(&self) -> impl Iterator<Item = (&'a String, &'a Value)> + '_ {
        self.result.properties.additional.iter().filter(|(key, _)| {
            !MAPPED
                .iter()
                .zip(self.mapped)
                .any(|(mapped, used)| used && key.as_str() == *mapped)
        })
    }
}

/// A finding extension that keeps what a SARIF result says beyond the
/// finding model: which tool reported it, its fingerprints, tags, code
/// flows, related locations, and every unknown property.
///
/// Serialized (with `Finding<Imported>`) as extra members next to the
/// finding's own, each left out when empty.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Imported {
    /// `tool.driver.name` of the run.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool: String,
    /// The driver's `semanticVersion`, else its `version`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    /// The run's `automationDetails.id` (GitHub's category).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The rule's `helpUri`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    /// Tags of the rule and the result, without duplicates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The result's `partialFingerprints`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub partial_fingerprints: BTreeMap<String, String>,
    /// The result's `fingerprints`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fingerprints: BTreeMap<String, String>,
    /// Each thread flow of each code flow, as its steps in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<Vec<Step>>,
    /// The result's `relatedLocations`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<Step>,
    /// Whether an accepted suppression applies to the result.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub suppressed: bool,
    /// The result's unknown properties
    /// ([`ResultContext::unknown_properties`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Value>,
}

/// A location with what happens there: a code flow step or a related
/// location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Step {
    /// Where.
    pub location: Location,
    /// What happens there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Step {
    /// A step at `location`.
    #[must_use]
    pub const fn new(location: Location, message: Option<String>) -> Self {
        Self { location, message }
    }

    fn from_sarif(location: &model::Location) -> Option<Self> {
        Some(Self::new(
            location::from_sarif(location)?,
            location.message.as_ref().and_then(message_text),
        ))
    }

    fn to_sarif(&self) -> model::Location {
        let mut location = location::to_sarif(&self.location);
        location.message = self.message.clone().map(model::Message::text);
        location
    }
}

impl FromSarif for Imported {
    fn from_sarif(context: &ResultContext<'_>) -> Self {
        let run = context.run();
        let result = context.result();
        let driver = &run.tool.driver;
        let mut tags: Vec<String> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let rule_tags = context.rule().map(|rule| rule.properties.tags.iter());
        for tag in rule_tags
            .into_iter()
            .flatten()
            .chain(&result.properties.tags)
        {
            if seen.insert(tag) {
                tags.push(tag.clone());
            }
        }
        Self {
            tool: driver.name.clone(),
            tool_version: driver
                .semantic_version
                .clone()
                .or_else(|| driver.version.clone()),
            category: run
                .automation_details
                .as_ref()
                .and_then(|details| details.id.clone()),
            help_uri: context.rule().and_then(|rule| rule.help_uri.clone()),
            tags,
            partial_fingerprints: result.partial_fingerprints.clone(),
            fingerprints: result.fingerprints.clone(),
            code_flows: result
                .code_flows
                .iter()
                .flat_map(|flow| &flow.thread_flows)
                .map(|thread| {
                    thread
                        .locations
                        .iter()
                        .filter_map(|step| {
                            let location = step.location.as_ref()?;
                            Step::from_sarif(location)
                        })
                        .collect()
                })
                .collect(),
            related_locations: result
                .related_locations
                .iter()
                .filter_map(Step::from_sarif)
                .collect(),
            suppressed: result.suppressions.iter().any(|suppression| {
                suppression
                    .status
                    .as_deref()
                    .is_none_or(|status| status == "accepted")
            }),
            properties: context
                .unknown_properties()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }

    fn text_len(&self) -> usize {
        json_len(self)
    }
}

/// Writing an imported finding back keeps its code flows, related
/// locations, fingerprints, tags and unknown properties. Members the writer
/// sets itself win over imported ones with the same key.
impl ToSarif for Imported {
    fn write_rule(finding: &Finding<Self>, rule: &mut ReportingDescriptor) {
        if rule.help_uri.is_none() {
            rule.help_uri.clone_from(&finding.help_uri);
        }
        for tag in &finding.tags {
            if !rule.properties.tags.contains(tag) {
                rule.properties.tags.push(tag.clone());
            }
        }
    }

    fn write_result(finding: &Finding<Self>, result: &mut model::Result) {
        for (key, value) in &finding.properties {
            result
                .properties
                .additional
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
        for (key, value) in &finding.partial_fingerprints {
            result
                .partial_fingerprints
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
        result.fingerprints.clone_from(&finding.fingerprints);
        result.code_flows = finding
            .code_flows
            .iter()
            .map(|steps| {
                model::CodeFlow::single(
                    steps
                        .iter()
                        .map(|step| model::ThreadFlowLocation::new(step.to_sarif())),
                )
            })
            .collect();
        result.related_locations = finding
            .related_locations
            .iter()
            .map(Step::to_sarif)
            .collect();
        if finding.suppressed {
            result.suppressions.push(model::Suppression {
                kind: "external".to_owned(),
                status: None,
                justification: None,
            });
        }
    }
}

/// Read the findings of every run of a log, in order.
///
/// Results of kind `pass` or `notApplicable` are not findings and are
/// skipped. For each other result:
///
/// - **check id**: `ruleId`, else `rule.id`, else the rule's id;
/// - **title**: `message.text`, else `message.markdown`, else the rule's
///   short description, else the check id;
/// - **severity**: `security-severity` (result, then rule) through
///   [`Severity::from_cvss_score`]; else the level (result, then the
///   rule's default, else `warning`): `error` is high, `warning` medium,
///   `note` low and `none` informational;
/// - **confidence**: the `confidence` property, else a Semgrep-style
///   `HIGH CONFIDENCE` tag (`LOW`, `MEDIUM` and `HIGH` are tentative, firm
///   and certain), else the `precision` property of the result or rule
///   (`very-high` is certain, `high` and `medium` firm, `low` tentative),
///   else firm;
/// - **location**: the first of `locations`, see
///   [`location`](crate::location); a result with only a logical location
///   gets a file location named after its fully qualified name, and one
///   with no location at all an empty file path;
/// - **taxonomy**: the `taxa` references, resolved through
///   `run.taxonomies` (a component named like a known
///   [`Taxonomy::display_name`] is that taxonomy, others are custom). In a
///   run without `taxonomies`, results take CWE and OWASP entries from the
///   tags of the result and its rule instead: `CodeQL`'s
///   `external/cwe/cwe-089`, Semgrep's `CWE-89: …` and
///   `OWASP-A03:2021 - Injection`. (A run with taxonomies classifies
///   through `taxa` alone, because a rule's tags may come from another
///   result.);
/// - **evidence**, **cvss**, **remediation** and **remediation refs**: the
///   properties [`write()`](crate::write) stores them in. Without those, the
///   CVSS comes from Trivy's `cvssv3_vector`/`cvssv3_baseScore` rule
///   properties and the remediation from the first fix's description;
/// - **extension**: [`FromSarif::from_sarif`].
///
/// A member that does not parse is left out of the finding, and stays
/// available to the extension.
///
/// Reads with [`ReadOptions::default`]; see [`read_with`].
///
/// # Errors
///
/// [`Error::TooLarge`] when the findings would hold more than
/// [`ReadOptions::DEFAULT_MAX_TEXT_BYTES`] of text.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
/// use rune_sarif::{Imported, Log, Options, read, write};
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
/// let json = write(&[finding.clone()], &Options::default()).to_json()?;
/// let log = Log::from_json(&json)?;
/// assert_eq!(read::<()>(&log)?, [finding]);
///
/// let imported: Vec<Finding<Imported>> = read(&log)?;
/// assert_eq!(imported[0].tool, "rune-sarif");
/// # Ok::<(), rune_sarif::Error>(())
/// ```
pub fn read<X: FromSarif>(log: &Log) -> Result<Vec<Finding<X>>, Error> {
    read_with(log, &ReadOptions::default())
}

/// [`read`] with a size budget for the findings.
///
/// Each finding owns copies of what it takes from its rule and run (rule
/// id, short description, tags, taxonomy names, help URI, tool name), so a
/// log that gives thousands of tiny results one rule with megabytes of
/// text would make findings far larger than the log. The budget
/// ([`ReadOptions::with_max_text_bytes`]) caps their total size, checked
/// as each finding is built.
///
/// # Errors
///
/// [`Error::TooLarge`] when the findings would go over the budget.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity};
/// use rune_sarif::{Error, Log, Options, ReadOptions, read_with, write};
///
/// let finding = Finding::<()>::new(
///     "py.sqli",
///     "SQL injection",
///     Severity::High,
///     Confidence::Firm,
///     Location::file("src/app.py"),
/// );
/// let log = write(&[finding.clone(), finding], &Options::default());
///
/// let roomy = ReadOptions::default().with_max_text_bytes(1 << 20);
/// assert_eq!(read_with::<()>(&log, &roomy)?.len(), 2);
///
/// let tight = ReadOptions::default().with_max_text_bytes(10);
/// assert!(matches!(read_with::<()>(&log, &tight), Err(Error::TooLarge { .. })));
/// # Ok::<(), rune_sarif::Error>(())
/// ```
pub fn read_with<X: FromSarif>(log: &Log, options: &ReadOptions) -> Result<Vec<Finding<X>>, Error> {
    let limit = options.max_text_bytes;
    let mut total: usize = 0;
    let mut findings = Vec::new();
    for run in &log.runs {
        for result in &run.results {
            if matches!(
                result.kind,
                Some(ResultKind::Pass | ResultKind::NotApplicable)
            ) {
                continue;
            }
            let (finding, size) = read_result::<X>(run, result);
            total = total.saturating_add(size);
            if total > limit {
                return Err(Error::TooLarge { limit });
            }
            findings.push(finding);
        }
    }
    Ok(findings)
}

/// One finding and its size for the budget.
fn read_result<X: FromSarif>(run: &Run, result: &model::Result) -> (Finding<X>, usize) {
    let rule = find_rule(run, result);
    let properties = &result.properties;
    let rule_properties = rule.map(|rule| &rule.properties);

    let check_id = result
        .rule_id
        .clone()
        .or_else(|| {
            result
                .rule
                .as_ref()
                .and_then(|reference| reference.id.clone())
        })
        .or_else(|| rule.map(|rule| rule.id.clone()))
        .unwrap_or_default();
    let title = message_text(&result.message)
        .or_else(|| {
            rule.and_then(|rule| rule.short_description.as_ref())
                .map(|text| text.text.clone())
        })
        .unwrap_or_else(|| check_id.clone());

    let confidence_property = properties
        .get_str(keys::CONFIDENCE)
        .and_then(|text| text.parse::<Confidence>().ok());
    let evidence: Option<Vec<Evidence>> = parse_property(properties.get(keys::EVIDENCE));
    let cvss: Option<Cvss> = parse_property(properties.get(keys::CVSS));
    let remediation: Option<Remediation> = parse_property(properties.get(keys::REMEDIATION));
    let remediation_refs: Option<Vec<String>> =
        parse_property(properties.get(keys::REMEDIATION_REFS));
    let mapped = [
        confidence_property.is_some(),
        evidence.is_some(),
        cvss.is_some(),
        remediation.is_some(),
        remediation_refs.is_some(),
    ];

    let severity = properties
        .security_severity
        .as_deref()
        .or_else(|| rule_properties.and_then(|bag| bag.security_severity.as_deref()))
        .and_then(|score| score.trim().parse::<f64>().ok())
        .filter(|score| score.is_finite())
        .map_or_else(
            || severity_of_level(result, rule),
            Severity::from_cvss_score,
        );
    let confidence = confidence_property
        .or_else(|| {
            properties
                .tags
                .iter()
                .chain(rule_properties.map_or(&[][..], |bag| &bag.tags[..]))
                .find_map(|tag| confidence_of_tag(tag))
        })
        .or_else(|| {
            properties
                .get_str("precision")
                .or_else(|| rule_properties.and_then(|bag| bag.get_str("precision")))
                .and_then(confidence_of_precision)
        })
        .unwrap_or(Confidence::Firm);

    let location = result
        .locations
        .first()
        .and_then(|location| {
            location::from_sarif(location).or_else(|| {
                let logical = location.logical_locations.first()?;
                logical
                    .fully_qualified_name
                    .clone()
                    .or_else(|| logical.name.clone())
                    .map(Location::file)
            })
        })
        .unwrap_or_else(|| Location::file(""));

    let mut taxonomy: Vec<TaxonomyRef> = result
        .taxa
        .iter()
        .filter_map(|reference| taxonomy_ref(run, reference))
        .collect();
    if run.taxonomies.is_empty() {
        let tags = rule_properties
            .map(|bag| bag.tags.iter())
            .into_iter()
            .flatten()
            .chain(&properties.tags);
        let mut seen: HashSet<TaxonomyRef> = taxonomy.iter().cloned().collect();
        for entry in tags.filter_map(|tag| taxonomy_from_tag(tag)) {
            if !seen.contains(&entry) {
                seen.insert(entry.clone());
                taxonomy.push(entry);
            }
        }
    }

    let cvss = cvss.or_else(|| rule_properties.and_then(trivy_cvss));
    let remediation = remediation.or_else(|| {
        result
            .fixes
            .first()
            .and_then(|fix| fix.description.as_ref())
            .and_then(message_text)
            .map(Remediation::new)
    });

    let context = ResultContext {
        run,
        result,
        rule,
        mapped,
    };
    let mut core = Finding::<()>::new(check_id, title, severity, confidence, location)
        .with_evidence(evidence.unwrap_or_default())
        .with_taxonomy(taxonomy)
        .with_remediation_refs(remediation_refs.unwrap_or_default());
    core.remediation = remediation;
    core.cvss = cvss;
    let ext = X::from_sarif(&context);
    let size = json_len(&core).saturating_add(ext.text_len());
    (core.with_ext(ext), size)
}

fn parse_property<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> Option<T> {
    value.and_then(|value| T::deserialize(value).ok())
}

fn message_text(message: &model::Message) -> Option<String> {
    message.text.clone().or_else(|| message.markdown.clone())
}

fn severity_of_level(result: &model::Result, rule: Option<&ReportingDescriptor>) -> Severity {
    let level = result.level.or_else(|| {
        rule.and_then(|rule| rule.default_configuration.as_ref())
            .and_then(|configuration| configuration.level)
    });
    match level {
        Some(Level::Error) => Severity::High,
        Some(Level::Note) => Severity::Low,
        Some(Level::None) => Severity::Informational,
        None if result.kind == Some(ResultKind::Informational) => Severity::Informational,
        Some(Level::Warning) | None => Severity::Medium,
    }
}

/// Semgrep tags rules `LOW CONFIDENCE`, `MEDIUM CONFIDENCE` or
/// `HIGH CONFIDENCE`.
fn confidence_of_tag(tag: &str) -> Option<Confidence> {
    let level = tag.strip_suffix(" CONFIDENCE")?;
    match level {
        "LOW" => Some(Confidence::Tentative),
        "MEDIUM" => Some(Confidence::Firm),
        "HIGH" => Some(Confidence::Certain),
        _ => None,
    }
}

fn confidence_of_precision(precision: &str) -> Option<Confidence> {
    match precision {
        "very-high" => Some(Confidence::Certain),
        "high" | "medium" => Some(Confidence::Firm),
        "low" => Some(Confidence::Tentative),
        _ => None,
    }
}

/// Trivy puts the CVSS v3 vector and score in the rule's properties.
fn trivy_cvss(bag: &model::PropertyBag) -> Option<Cvss> {
    let vector = bag.get_str("cvssv3_vector")?;
    let score = bag.get("cvssv3_baseScore")?.as_f64()?;
    Cvss::try_new(vector, score).ok()
}

/// The rule a result refers to: by index, then by id, in the component
/// the reference names (the driver by default), then anywhere in the tool.
fn find_rule<'a>(run: &'a Run, result: &model::Result) -> Option<&'a ReportingDescriptor> {
    let tool = &run.tool;
    let reference = result.rule.as_ref();
    let component = reference
        .and_then(|reference| reference.tool_component.as_ref())
        .and_then(|component| {
            component
                .index
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| tool.extensions.get(index))
                .or_else(|| {
                    let name = component.name.as_deref()?;
                    tool.extensions
                        .iter()
                        .find(|extension| extension.name == name)
                })
        })
        .unwrap_or(&tool.driver);
    let id = result
        .rule_id
        .as_deref()
        .or_else(|| reference.and_then(|reference| reference.id.as_deref()));
    let index = result
        .rule_index
        .or_else(|| reference.and_then(|reference| reference.index))
        .and_then(|index| usize::try_from(index).ok());

    if let Some(rule) = index.and_then(|index| component.rules.get(index))
        && id.is_none_or(|id| id == rule.id)
    {
        return Some(rule);
    }
    let id = id?;
    std::iter::once(component)
        .chain(std::iter::once(&tool.driver))
        .chain(&tool.extensions)
        .flat_map(|component| &component.rules)
        .find(|rule| rule.id == id)
}

/// A `taxa` reference resolved through `run.taxonomies`.
fn taxonomy_ref(run: &Run, reference: &ReportingDescriptorReference) -> Option<TaxonomyRef> {
    let component_reference = reference.tool_component.as_ref();
    let component: Option<&ToolComponent> = component_reference
        .and_then(|component| component.index)
        .and_then(|index| usize::try_from(index).ok())
        .and_then(|index| run.taxonomies.get(index))
        .or_else(|| {
            let name = component_reference?.name.as_deref()?;
            run.taxonomies.iter().find(|taxonomy| taxonomy.name == name)
        });
    let name = component
        .map(|component| component.name.as_str())
        .or_else(|| component_reference?.name.as_deref())?;
    let taxa = component.map_or(&[][..], |component| &component.taxa[..]);
    let taxon = reference
        .index
        .and_then(|index| usize::try_from(index).ok())
        .and_then(|index| taxa.get(index))
        .filter(|taxon| reference.id.as_ref().is_none_or(|id| *id == taxon.id))
        .or_else(|| {
            let id = reference.id.as_deref()?;
            taxa.iter().find(|taxon| taxon.id == id)
        });
    let id = reference
        .id
        .clone()
        .or_else(|| taxon.map(|taxon| taxon.id.clone()))?;
    let mut entry = TaxonomyRef::new(taxonomy_named(name), id);
    entry.name = taxon.and_then(|taxon| taxon.name.clone());
    Some(entry)
}

/// The taxonomy a SARIF taxonomy component's name stands for.
fn taxonomy_named(name: &str) -> Taxonomy {
    Taxonomy::KNOWN
        .into_iter()
        .find(|known| known.display_name() == name)
        .unwrap_or_else(|| Taxonomy::Custom(name.to_owned()))
}

/// A CWE or OWASP classification from a tag, in the forms `CodeQL`
/// (`external/cwe/cwe-089`) and Semgrep (`CWE-89: Improper …`,
/// `OWASP-A03:2021 - Injection`) write.
fn taxonomy_from_tag(tag: &str) -> Option<TaxonomyRef> {
    let tag = tag.trim();
    if let Some(number) = strip_prefix_ignore_case(tag, "external/cwe/cwe-") {
        return cwe(number, None);
    }
    if let Some(rest) = strip_prefix_ignore_case(tag, "CWE-") {
        let (number, name) = rest
            .split_once(':')
            .map_or((rest, None), |(number, name)| (number, Some(name.trim())));
        return cwe(number, name.filter(|name| !name.is_empty()));
    }
    if let Some(rest) = strip_prefix_ignore_case(tag, "OWASP-") {
        let (id, name) = rest
            .split_once(" - ")
            .map_or((rest, None), |(id, name)| (id.trim(), Some(name.trim())));
        if id.is_empty() || !id.contains(':') {
            return None;
        }
        let entry = TaxonomyRef::owasp(id);
        return Some(match name.filter(|name| !name.is_empty()) {
            Some(name) => entry.with_name(name),
            None => entry,
        });
    }
    None
}

fn cwe(number: &str, name: Option<&str>) -> Option<TaxonomyRef> {
    let number = number.trim();
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let entry = TaxonomyRef::cwe(number.parse().ok()?);
    Some(match name {
        Some(name) => entry.with_name(name),
        None => entry,
    })
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| text.get(prefix.len()..))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: a rule's tags come
    // from the first finding written for it, so another finding of the
    // rule without taxonomy must not pick them up when read back.
    #[test]
    fn taxonomies_win_over_tags() {
        let at = || Location::file("a.py").with_lines(1, 1);
        let with = Finding::<()>::new("r", "t", Severity::Low, Confidence::Firm, at())
            .push_taxonomy(TaxonomyRef::cwe(79));
        let without = Finding::<()>::new("r", "t", Severity::Low, Confidence::Firm, at());
        let log = crate::write(&[with.clone(), without.clone()], &crate::Options::default());
        assert_eq!(
            log.runs[0].tool.driver.rules[0].properties.tags[1],
            "external/cwe/cwe-79"
        );
        assert_eq!(read::<()>(&log).unwrap(), [with, without]);
    }

    #[test]
    fn tags_to_taxonomy() {
        assert_eq!(
            taxonomy_from_tag("external/cwe/cwe-089"),
            Some(TaxonomyRef::cwe(89))
        );
        assert_eq!(
            taxonomy_from_tag("CWE-78: Improper Neutralization"),
            Some(TaxonomyRef::cwe(78).with_name("Improper Neutralization"))
        );
        assert_eq!(taxonomy_from_tag("cwe-22"), Some(TaxonomyRef::cwe(22)));
        assert_eq!(
            taxonomy_from_tag("OWASP-A03:2021 - Injection"),
            Some(TaxonomyRef::owasp("A03:2021").with_name("Injection"))
        );
        assert_eq!(
            taxonomy_from_tag("OWASP-A01:2017 - Injection").map(|entry| entry.framework),
            Some(Taxonomy::Custom("owasp".to_owned()))
        );
        for other in [
            "security",
            "HIGH CONFIDENCE",
            "CWE-",
            "CWE-x",
            "OWASP-",
            "external/cwe/cwe-",
        ] {
            assert_eq!(taxonomy_from_tag(other), None, "{other}");
        }
        assert_eq!(taxonomy_from_tag("CWE-99999999999"), None);
    }

    #[test]
    fn taxonomy_names() {
        for known in Taxonomy::KNOWN {
            assert_eq!(taxonomy_named(known.display_name()), known);
        }
        assert_eq!(taxonomy_named("acme"), Taxonomy::Custom("acme".to_owned()));
    }

    #[test]
    fn severity_from_level() {
        let mut result = model::Result::default();
        let cases = [
            (Some(Level::Error), Severity::High),
            (Some(Level::Warning), Severity::Medium),
            (Some(Level::Note), Severity::Low),
            (Some(Level::None), Severity::Informational),
            (None, Severity::Medium),
        ];
        for (level, severity) in cases {
            result.level = level;
            assert_eq!(severity_of_level(&result, None), severity);
        }
        result.level = None;
        result.kind = Some(ResultKind::Informational);
        assert_eq!(severity_of_level(&result, None), Severity::Informational);
    }

    #[test]
    fn precision_to_confidence() {
        assert_eq!(
            confidence_of_precision("very-high"),
            Some(Confidence::Certain)
        );
        assert_eq!(confidence_of_precision("medium"), Some(Confidence::Firm));
        assert_eq!(confidence_of_precision("low"), Some(Confidence::Tentative));
        assert_eq!(confidence_of_precision("?"), None);
        assert_eq!(
            confidence_of_tag("HIGH CONFIDENCE"),
            Some(Confidence::Certain)
        );
        assert_eq!(
            confidence_of_tag("MEDIUM CONFIDENCE"),
            Some(Confidence::Firm)
        );
        assert_eq!(
            confidence_of_tag("LOW CONFIDENCE"),
            Some(Confidence::Tentative)
        );
        assert_eq!(confidence_of_tag("security"), None);
    }
}
