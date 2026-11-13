//! Where a correlated finding came from: [`Kind`], [`Source`] and the
//! [`Provenance`] finding extension.

use std::collections::{BTreeMap, BTreeSet};

use rune_finding::{Confidence, Finding, Location, Severity, Taxonomy, TaxonomyRef};

/// The kind of testing that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Kind {
    /// Static analysis of source code (`CodeQL`, Semgrep).
    Sast,
    /// Dynamic testing of a running application or service (ZAP).
    Dast,
    /// Software composition analysis: vulnerable dependencies and images.
    Sca,
    /// Secret scanning (Gitleaks, rune-leak).
    Secrets,
    /// Infrastructure and cluster configuration.
    Iac,
    /// Anything else.
    Other,
}

impl Kind {
    /// The usual kind of a finding at `location`: a file is SAST, a URL or
    /// a network endpoint DAST, a binary artifact SCA, a cluster object
    /// `IaC`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rune_aspm_correlate::Kind;
    /// use rune_finding::Location;
    ///
    /// assert_eq!(Kind::infer(&Location::file("src/app.py")), Kind::Sast);
    /// assert_eq!(Kind::infer(&Location::url("https://shop.test/")), Kind::Dast);
    /// ```
    #[must_use]
    pub const fn infer(location: &Location) -> Self {
        match location {
            Location::File { .. } => Self::Sast,
            Location::Url { .. } | Location::Network { .. } => Self::Dast,
            Location::Artifact { .. } => Self::Sca,
            Location::ClusterObject { .. } => Self::Iac,
            _ => Self::Other,
        }
    }

    /// The kind's name in snake case, e.g. `sast`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sast => "sast",
            Self::Dast => "dast",
            Self::Sca => "sca",
            Self::Secrets => "secrets",
            Self::Iac => "iac",
            Self::Other => "other",
        }
    }
}

impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One original report behind a correlated finding: which tool said what,
/// where.
///
/// Merging keeps one representative check id, title and location on the
/// finding itself; every report that went into it stays here, unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Source {
    /// The tool that reported it, e.g. `semgrep` or `zap`.
    pub tool: String,
    /// The kind of testing.
    pub kind: Kind,
    /// The tool's check id.
    pub check_id: String,
    /// The tool's title or message.
    pub title: String,
    /// The tool's severity.
    pub severity: Severity,
    /// The tool's confidence.
    pub confidence: Confidence,
    /// Where the tool saw it.
    pub location: Location,
    /// The CWE numbers the tool classified it under, sorted.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub cwes: Vec<u32>,
    /// [`Finding::fingerprint`] of the original report.
    pub fingerprint: String,
    /// The SARIF `partialFingerprints` of the original result, if any.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub partial_fingerprints: BTreeMap<String, String>,
    /// Further locations of a SAST result: its code flow steps and related
    /// locations, in order. A taint flow that starts in a route handler
    /// links the result to that route even when the sink is elsewhere.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub flow: Vec<Location>,
    /// Whether the SARIF result carried an accepted suppression.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "core::ops::Not::not")
    )]
    pub suppressed: bool,
}

impl Source {
    /// The source of `finding`, as reported by `tool`. Its kind comes from
    /// the location ([`Kind::infer`]); its fingerprint and CWEs from the
    /// finding.
    #[must_use]
    pub fn of<X>(tool: impl Into<String>, finding: &Finding<X>) -> Self {
        Self {
            tool: tool.into(),
            kind: Kind::infer(&finding.location),
            check_id: finding.check_id.clone(),
            title: finding.title.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            location: finding.location.clone(),
            cwes: cwes_of(&finding.taxonomy),
            fingerprint: finding.fingerprint(),
            partial_fingerprints: BTreeMap::new(),
            flow: Vec::new(),
            suppressed: false,
        }
    }

    /// Set the [`kind`](Self::kind).
    #[must_use]
    pub const fn with_kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the [`partial_fingerprints`](Self::partial_fingerprints).
    #[must_use]
    pub fn with_partial_fingerprints(mut self, fingerprints: BTreeMap<String, String>) -> Self {
        self.partial_fingerprints = fingerprints;
        self
    }

    /// Set the [`flow`](Self::flow) locations.
    #[must_use]
    pub fn with_flow(mut self, flow: Vec<Location>) -> Self {
        self.flow = flow;
        self
    }

    /// The primary location, then the [`flow`](Self::flow) locations.
    pub fn locations(&self) -> impl Iterator<Item = &Location> {
        core::iter::once(&self.location).chain(&self.flow)
    }

    fn sort_key(&self) -> (Kind, &str, &str, &str, &str, Severity, Confidence) {
        (
            self.kind,
            &self.tool,
            &self.check_id,
            &self.fingerprint,
            &self.title,
            self.severity,
            self.confidence,
        )
    }

    /// Kind, tool, check id and fingerprint first, then every other
    /// member, so equal sources always end up next to each other.
    fn order(&self, other: &Self) -> core::cmp::Ordering {
        self.sort_key()
            .cmp(&other.sort_key())
            .then_with(|| self.location.cmp(&other.location))
            .then_with(|| self.cwes.cmp(&other.cwes))
            .then_with(|| self.partial_fingerprints.cmp(&other.partial_fingerprints))
            .then_with(|| self.flow.cmp(&other.flow))
            .then_with(|| self.suppressed.cmp(&other.suppressed))
    }
}

/// The finding extension of a correlated finding: every [`Source`] that
/// went into it.
///
/// Each ingested finding starts with one source; merging duplicates unions
/// them, so a correlated finding lists every tool, check id and location
/// that reported the issue. Sources are kept sorted by kind, tool, check id
/// and fingerprint (then the other members), without duplicates.
///
/// With the `serde` feature it serializes (inside `Finding<Provenance>`) as
/// a `sources` member next to the finding's own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Provenance {
    /// The original reports.
    #[cfg_attr(feature = "serde", serde(default))]
    pub sources: Vec<Source>,
}

impl Provenance {
    /// Provenance with one source.
    #[must_use]
    pub fn new(source: Source) -> Self {
        Self {
            sources: vec![source],
        }
    }

    /// The distinct tools, sorted.
    #[must_use]
    pub fn tools(&self) -> BTreeSet<&str> {
        self.sources
            .iter()
            .map(|source| source.tool.as_str())
            .collect()
    }

    /// The distinct kinds, sorted.
    #[must_use]
    pub fn kinds(&self) -> BTreeSet<Kind> {
        self.sources.iter().map(|source| source.kind).collect()
    }

    /// Whether a source of `kind` is present.
    #[must_use]
    pub fn has_kind(&self, kind: Kind) -> bool {
        self.sources.iter().any(|source| source.kind == kind)
    }

    /// Add the sources of `other`, keeping the list sorted and free of
    /// duplicates.
    pub fn absorb(&mut self, other: Self) {
        self.sources.extend(other.sources);
        self.normalize();
    }

    /// Sort the sources and drop repeats.
    pub(crate) fn normalize(&mut self) {
        self.sources.sort_by(Source::order);
        self.sources.dedup();
    }
}

/// The sorted, distinct CWE numbers of a taxonomy list.
fn cwes_of(taxonomy: &[TaxonomyRef]) -> Vec<u32> {
    let mut cwes: Vec<u32> = taxonomy
        .iter()
        .filter(|entry| entry.framework == Taxonomy::Cwe)
        .filter_map(TaxonomyRef::cwe_number)
        .collect();
    cwes.sort_unstable();
    cwes.dedup();
    cwes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(location: Location) -> Finding {
        Finding::<()>::new("c", "t", Severity::High, Confidence::Firm, location)
            .push_taxonomy(TaxonomyRef::cwe(89))
            .push_taxonomy(TaxonomyRef::cwe(20))
            .push_taxonomy(TaxonomyRef::cwe(89))
    }

    #[test]
    fn kinds_infer_from_location() {
        assert_eq!(Kind::infer(&Location::network("a.test", 443)), Kind::Dast);
        assert_eq!(Kind::infer(&Location::artifact("bin", None)), Kind::Sca);
        assert_eq!(
            Kind::infer(&Location::cluster_object("ns", "Ingress", "web")),
            Kind::Iac
        );
        for kind in [
            Kind::Sast,
            Kind::Dast,
            Kind::Sca,
            Kind::Secrets,
            Kind::Iac,
            Kind::Other,
        ] {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    #[test]
    fn source_of_finding() {
        let f = finding(Location::file("a.py"));
        let source = Source::of("semgrep", &f);
        assert_eq!(source.kind, Kind::Sast);
        assert_eq!(source.cwes, [20, 89]);
        assert_eq!(source.fingerprint, f.fingerprint());
        let source = source
            .with_kind(Kind::Secrets)
            .with_flow(vec![Location::file("b.py")]);
        assert_eq!(source.kind, Kind::Secrets);
        assert_eq!(source.locations().count(), 2);
    }

    #[test]
    fn absorb_sorts_and_dedupes() {
        let sast = Source::of("semgrep", &finding(Location::file("a.py")));
        let dast = Source::of("dast-scanner", &finding(Location::url("https://a.test/")));
        let mut provenance = Provenance::new(dast.clone());
        provenance.absorb(Provenance::new(sast.clone()));
        provenance.absorb(Provenance::new(sast.clone()));
        assert_eq!(provenance.sources, [sast, dast]);
        assert!(provenance.has_kind(Kind::Dast));
        assert!(!provenance.has_kind(Kind::Sca));
        assert_eq!(
            provenance.tools().into_iter().collect::<Vec<_>>(),
            ["dast-scanner", "semgrep"]
        );
        assert_eq!(provenance.kinds().len(), 2);
    }

    // Sources that sort alike but differ (here, in title) used to keep a
    // repeated one apart from its twin.
    #[test]
    fn absorb_drops_repeats_among_alike_sources() {
        let at = |title: &str| {
            let finding = Finding::<()>::new(
                "c",
                title,
                Severity::High,
                Confidence::Firm,
                Location::file("a.py"),
            );
            Source::of("semgrep", &finding)
        };
        let mut provenance = Provenance::new(at("one"));
        provenance.absorb(Provenance::new(at("two")));
        provenance.absorb(Provenance::new(at("one")));
        assert_eq!(provenance.sources.len(), 2);
    }
}
