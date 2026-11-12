//! Writing the risk view back out as SARIF (`serde` feature).

use rune_finding::Finding;
use rune_sarif::model;
use rune_sarif::{Log, ToSarif};

use crate::{Provenance, Report};

/// Result property holding the [`Provenance`] sources (their JSON shape).
pub const SOURCES_PROPERTY: &str = "aspmSources";

/// Each result carries its original reports in the [`SOURCES_PROPERTY`]
/// property, and the partial fingerprints of every report.
impl ToSarif for Provenance {
    fn write_result(finding: &Finding<Self>, result: &mut model::Result) {
        if let Ok(value) = serde_json::to_value(&finding.ext.sources) {
            result.properties.insert(SOURCES_PROPERTY, value);
        }
        for source in &finding.ext.sources {
            for (name, value) in &source.partial_fingerprints {
                result
                    .partial_fingerprints
                    .entry(name.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }
}

impl Report {
    /// The risk view as a SARIF 2.1.0 log with one run, most urgent issue
    /// first, each result listing its original reports.
    ///
    /// # Examples
    ///
    /// ```
    /// use rune_aspm_correlate::{Batch, Options, sarif::SOURCES_PROPERTY};
    /// use rune_finding::{Confidence, Finding, Location, Severity};
    ///
    /// let mut batch = Batch::new();
    /// batch.add_findings("dast-scanner", [Finding::<()>::new(
    ///     "hsts.missing", "No HSTS", Severity::Low, Confidence::Certain,
    ///     Location::url("https://shop.test/"),
    /// )]);
    /// let log = batch.correlate(&Options::default())
    ///     .to_sarif(&rune_sarif::Options::default().with_tool_name("aspm"));
    /// assert!(log.runs[0].results[0].properties.get(SOURCES_PROPERTY).is_some());
    /// ```
    #[must_use]
    pub fn to_sarif(&self, options: &rune_sarif::Options) -> Log {
        let findings: Vec<Finding<Provenance>> = self.findings().cloned().collect();
        rune_sarif::write(&findings, options)
    }
}
