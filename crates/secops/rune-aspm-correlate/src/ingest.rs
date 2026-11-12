//! [`Batch`]: collecting findings from SARIF logs and native scanners.

use rune_finding::{Finding, Location};
use rune_sarif::{Imported, Log};

use crate::{Error, Kind, Options, Provenance, Report, Source};

/// Tool name for SARIF runs whose driver has no name.
const UNNAMED_TOOL: &str = "sarif";

/// The findings of one correlation run, from every tool, each with its
/// [`Provenance`].
///
/// Add SARIF logs (`CodeQL`, Semgrep, Trivy, Gitleaks, ZAP or any other
/// SARIF 2.1.0 producer) and native findings (a DAST scanner's findings), then [`correlate`](Self::correlate).
///
/// # Examples
///
/// ```
/// use rune_aspm_correlate::{Batch, Kind};
/// use rune_finding::{Confidence, Finding, Location, Severity};
///
/// let mut batch = Batch::new();
/// let sarif = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},
///   "results":[{"ruleId":"aws-key","message":{"text":"AWS key"},
///   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"config.py"}}}]}]}]}"#;
/// assert_eq!(batch.add_sarif_json_as(sarif, Kind::Secrets)?, 1);
/// batch.add_findings("dast-scanner", [Finding::<()>::new(
///     "tls.weak", "TLS 1.0", Severity::Medium, Confidence::Certain,
///     Location::network("shop.test", 443),
/// )]);
///
/// let kinds: Vec<Kind> = batch.findings().iter().map(|f| f.ext.sources[0].kind).collect();
/// assert_eq!(kinds, [Kind::Secrets, Kind::Dast]);
/// # Ok::<(), rune_aspm_correlate::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Batch {
    findings: Vec<Finding<Provenance>>,
}

impl Batch {
    /// An empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Add every result of a SARIF log; each result's kind comes from its
    /// location ([`Kind::infer`]) and its tool from its run's driver.
    /// Returns how many findings were added.
    ///
    /// Code flow steps and related locations go to [`Source::flow`],
    /// `partialFingerprints` to [`Source::partial_fingerprints`], and an
    /// accepted suppression sets [`Source::suppressed`].
    pub fn add_sarif(&mut self, log: &Log) -> usize {
        self.add_sarif_with(log, None)
    }

    /// [`add_sarif`](Self::add_sarif), with every result of `kind`.
    pub fn add_sarif_as(&mut self, log: &Log, kind: Kind) -> usize {
        self.add_sarif_with(log, Some(kind))
    }

    /// Parse SARIF 2.1.0 JSON and [`add_sarif`](Self::add_sarif) it.
    ///
    /// # Errors
    ///
    /// [`Error::Sarif`] when the text is not a SARIF 2.1.0 log.
    pub fn add_sarif_json(&mut self, json: &str) -> Result<usize, Error> {
        Ok(self.add_sarif(&Log::from_json(json)?))
    }

    /// Parse SARIF 2.1.0 JSON and [`add_sarif_as`](Self::add_sarif_as) it.
    ///
    /// # Errors
    ///
    /// [`Error::Sarif`] when the text is not a SARIF 2.1.0 log.
    pub fn add_sarif_json_as(&mut self, json: &str, kind: Kind) -> Result<usize, Error> {
        Ok(self.add_sarif_as(&Log::from_json(json)?, kind))
    }

    fn add_sarif_with(&mut self, log: &Log, kind: Option<Kind>) -> usize {
        let before = self.findings.len();
        for finding in rune_sarif::read::<Imported>(log) {
            let (core, imported) = finding.into_parts();
            let tool = if imported.tool.is_empty() {
                UNNAMED_TOOL
            } else {
                imported.tool.as_str()
            };
            let flow: Vec<Location> = imported
                .code_flows
                .iter()
                .flatten()
                .chain(&imported.related_locations)
                .map(|step| step.location.clone())
                .collect();
            let mut source = Source::of(tool, &core)
                .with_partial_fingerprints(imported.partial_fingerprints.clone())
                .with_flow(flow);
            source.suppressed = imported.suppressed;
            if let Some(kind) = kind {
                source = source.with_kind(kind);
            }
            self.findings.push(core.with_ext(Provenance::new(source)));
        }
        self.findings.len() - before
    }

    /// Add native findings reported by `tool`; each one's kind comes from
    /// its location ([`Kind::infer`]). Their extension is dropped: the
    /// correlated finding carries [`Provenance`] instead. Returns how many
    /// findings were added.
    pub fn add_findings<X>(
        &mut self,
        tool: &str,
        findings: impl IntoIterator<Item = Finding<X>>,
    ) -> usize {
        self.add_findings_with(tool, None, findings)
    }

    /// [`add_findings`](Self::add_findings), with every finding of `kind`.
    pub fn add_findings_as<X>(
        &mut self,
        tool: &str,
        kind: Kind,
        findings: impl IntoIterator<Item = Finding<X>>,
    ) -> usize {
        self.add_findings_with(tool, Some(kind), findings)
    }

    fn add_findings_with<X>(
        &mut self,
        tool: &str,
        kind: Option<Kind>,
        findings: impl IntoIterator<Item = Finding<X>>,
    ) -> usize {
        let before = self.findings.len();
        for finding in findings {
            let (core, _) = finding.into_parts();
            let mut source = Source::of(tool, &core);
            if let Some(kind) = kind {
                source = source.with_kind(kind);
            }
            self.findings.push(core.with_ext(Provenance::new(source)));
        }
        self.findings.len() - before
    }

    /// Add a finding that already has its provenance.
    pub fn push(&mut self, finding: Finding<Provenance>) {
        self.findings.push(finding);
    }

    /// The findings, in the order they were added.
    #[must_use]
    pub fn findings(&self) -> &[Finding<Provenance>] {
        &self.findings
    }

    /// The findings, in the order they were added.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding<Provenance>> {
        self.findings
    }

    /// How many findings were added.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.findings.len()
    }

    /// Whether nothing was added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Correlate the findings: [`correlate`](crate::correlate).
    #[must_use]
    pub fn correlate(self, options: &Options) -> Report {
        crate::correlate(self.findings, options)
    }
}

impl Extend<Finding<Provenance>> for Batch {
    fn extend<I: IntoIterator<Item = Finding<Provenance>>>(&mut self, iter: I) {
        self.findings.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use rune_finding::{Confidence, Severity, TaxonomyRef};
    use rune_sarif::{Options as SarifOptions, write};

    use super::*;

    fn sast(line: u32) -> Finding {
        Finding::<()>::new(
            "py.sqli",
            "SQLi",
            Severity::High,
            Confidence::Firm,
            Location::file("src/app.py").with_lines(line, line),
        )
        .push_taxonomy(TaxonomyRef::cwe(89))
    }

    #[test]
    fn sarif_results_keep_provenance() {
        let log = write(
            &[sast(3), sast(4)],
            &SarifOptions::default().with_tool_name("sast-tool"),
        );
        let mut batch = Batch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.add_sarif(&log), 2);
        assert_eq!(batch.add_sarif_as(&log, Kind::Other), 2);
        assert_eq!(batch.len(), 4);
        let first = &batch.findings()[0];
        let source = &first.ext.sources[0];
        assert_eq!(source.tool, "sast-tool");
        assert_eq!(source.kind, Kind::Sast);
        assert_eq!(source.cwes, [89]);
        assert_eq!(source.fingerprint, sast(3).fingerprint());
        assert!(
            source
                .partial_fingerprints
                .contains_key(rune_sarif::keys::FINGERPRINT)
        );
        assert_eq!(batch.findings()[3].ext.sources[0].kind, Kind::Other);
    }

    #[test]
    fn sarif_flows_suppressions_and_unnamed_tools() {
        let json = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":""}},"results":[{
          "ruleId":"r","message":{"text":"m"},
          "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.py"},"region":{"startLine":9}}}],
          "relatedLocations":[{"physicalLocation":{"artifactLocation":{"uri":"src/x.py"}}}],
          "codeFlows":[{"threadFlows":[{"locations":[
            {"location":{"physicalLocation":{"artifactLocation":{"uri":"src/users.py"},"region":{"startLine":3}}}},
            {"location":{"physicalLocation":{"artifactLocation":{"uri":"src/db.py"},"region":{"startLine":9}}}}
          ]}]}],
          "suppressions":[{"kind":"inSource"}]
        }]}]}"#;
        let mut batch = Batch::new();
        assert_eq!(batch.add_sarif_json(json).unwrap(), 1);
        let source = &batch.findings()[0].ext.sources[0];
        assert_eq!(source.tool, "sarif");
        assert!(source.suppressed);
        assert_eq!(source.flow.len(), 3);
        assert!(matches!(
            &source.flow[0],
            Location::File { path, start_line: Some(3), .. } if path == "src/users.py"
        ));
        assert!(matches!(
            batch.add_sarif_json("{}"),
            Err(Error::Sarif(rune_sarif::Error::Json(_)))
        ));
        assert!(batch.add_sarif_json_as("[", Kind::Sast).is_err());
    }

    #[test]
    fn native_findings() {
        let mut batch = Batch::new();
        let dast = Finding::<()>::new(
            "xss",
            "XSS",
            Severity::High,
            Confidence::Firm,
            Location::url("https://a.test/"),
        )
        .with_ext(7_u8);
        assert_eq!(batch.add_findings("dast-scanner", [dast.clone()]), 1);
        assert_eq!(batch.add_findings_as("zap", Kind::Other, [dast]), 1);
        batch.push(sast(1).with_ext(Provenance::default()));
        batch.extend([sast(2).with_ext(Provenance::default())]);
        let kinds: Vec<_> = batch.findings()[..2]
            .iter()
            .map(|f| (f.ext.sources[0].tool.as_str(), f.ext.sources[0].kind))
            .collect();
        assert_eq!(kinds, [("dast-scanner", Kind::Dast), ("zap", Kind::Other)]);
        assert_eq!(batch.into_findings().len(), 4);
    }
}
