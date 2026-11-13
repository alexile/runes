//! Merging duplicate findings into one, and [`Options`].

use std::collections::{HashMap, HashSet};

use rune_finding::{Finding, Taxonomy};

use crate::Correlate;

/// Settings for merging duplicates.
///
/// # Examples
///
/// ```
/// use rune_finding_dedupe::Options;
///
/// let options = Options::default().with_max_evidence(8);
/// assert_eq!(options.max_evidence, 8);
/// assert_eq!(options.max_taxonomy, 64);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[non_exhaustive]
pub struct Options {
    /// The most evidence items a merged finding keeps. Evidence of the
    /// kept finding comes first; duplicates only add items up to this
    /// bound. Default 32.
    pub max_evidence: usize,
    /// The most taxonomy references a merged finding keeps, in the same
    /// way as [`max_evidence`](Self::max_evidence). Default 64.
    pub max_taxonomy: usize,
    /// The most remediation reference URLs a merged finding keeps, in the
    /// same way as [`max_evidence`](Self::max_evidence). Default 32.
    pub max_remediation_refs: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_evidence: 32,
            max_taxonomy: 64,
            max_remediation_refs: 32,
        }
    }
}

impl Options {
    /// Set [`max_evidence`](Self::max_evidence).
    #[must_use]
    pub const fn with_max_evidence(mut self, max_evidence: usize) -> Self {
        self.max_evidence = max_evidence;
        self
    }

    /// Set [`max_taxonomy`](Self::max_taxonomy).
    #[must_use]
    pub const fn with_max_taxonomy(mut self, max_taxonomy: usize) -> Self {
        self.max_taxonomy = max_taxonomy;
        self
    }

    /// Set [`max_remediation_refs`](Self::max_remediation_refs).
    #[must_use]
    pub const fn with_max_remediation_refs(mut self, max_remediation_refs: usize) -> Self {
        self.max_remediation_refs = max_remediation_refs;
        self
    }
}

/// Merge the duplicate `from` into `into`.
///
/// The finding that ranks higher, by severity and then confidence, keeps its
/// check id, title, location, severity, confidence and extension; on a tie
/// `into` wins, so the first-seen finding stays the representative. The
/// other one contributes:
///
/// - evidence, taxonomy references and remediation reference URLs it has
///   that the kept one lacks, up to [`Options::max_evidence`],
///   [`Options::max_taxonomy`] and [`Options::max_remediation_refs`] (the
///   kept one's own are never dropped). A taxonomy reference the kept one
///   already has gives it its name when the kept one has none;
/// - its remediation, when the kept one has none;
/// - its CVSS score, when it is higher or the kept one has none;
/// - its extension, through [`Correlate::merge_ext`].
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Evidence, Finding, Location, Severity, TaxonomyRef};
/// use rune_finding_dedupe::{merge, Options, Strategy};
///
/// let loc = Location::file("app.py").with_lines(9, 9);
/// let mut a = Finding::<()>::new("r1", "low", Severity::Low, Confidence::Firm, loc.clone())
///     .push_taxonomy(TaxonomyRef::cwe(79));
/// let b = Finding::<()>::new("r2", "high", Severity::High, Confidence::Firm, loc)
///     .push_evidence(Evidence::new("sink", "innerHTML"));
///
/// merge(&mut a, b, &Strategy::Fingerprint, &Options::default());
/// assert_eq!(a.title, "high");
/// assert_eq!(a.taxonomy, [TaxonomyRef::cwe(79)]);
/// assert_eq!(a.evidence.len(), 1);
/// ```
pub fn merge<X, C: Correlate<X> + ?Sized>(
    into: &mut Finding<X>,
    mut from: Finding<X>,
    correlate: &C,
    options: &Options,
) {
    if (from.severity, from.confidence) > (into.severity, into.confidence) {
        core::mem::swap(into, &mut from);
    }

    let room = options.max_evidence.saturating_sub(into.evidence.len());
    let mut added = 0;
    for evidence in from.evidence {
        if added >= room {
            break;
        }
        if !into.evidence.contains(&evidence) {
            into.evidence.push(evidence);
            added += 1;
        }
    }

    if !from.taxonomy.is_empty() {
        let mut index: HashMap<(Taxonomy, String), usize> = into
            .taxonomy
            .iter()
            .enumerate()
            .map(|(at, kept)| ((kept.framework.clone(), kept.id.clone()), at))
            .collect();
        for entry in from.taxonomy {
            let key = (entry.framework.clone(), entry.id.clone());
            if let Some(&at) = index.get(&key) {
                if let Some(kept) = into.taxonomy.get_mut(at)
                    && kept.name.is_none()
                {
                    kept.name = entry.name;
                }
            } else if into.taxonomy.len() < options.max_taxonomy {
                index.insert(key, into.taxonomy.len());
                into.taxonomy.push(entry);
            }
        }
    }

    if into.remediation_refs.len() < options.max_remediation_refs
        && !from.remediation_refs.is_empty()
    {
        let mut seen: HashSet<String> = into.remediation_refs.iter().cloned().collect();
        for url in from.remediation_refs {
            if into.remediation_refs.len() >= options.max_remediation_refs {
                break;
            }
            if seen.insert(url.clone()) {
                into.remediation_refs.push(url);
            }
        }
    }

    if into.remediation.is_none() {
        into.remediation = from.remediation;
    }

    match (&into.cvss, from.cvss) {
        (None, cvss @ Some(_)) => into.cvss = cvss,
        (Some(kept), Some(other)) if other.base_score > kept.base_score => {
            into.cvss = Some(other);
        }
        _ => {}
    }

    correlate.merge_ext(&mut into.ext, from.ext);
}

#[cfg(test)]
mod tests {
    use rune_finding::{
        Confidence, Cvss, Evidence, Location, Remediation, Severity, Taxonomy, TaxonomyRef,
    };

    use super::*;
    use crate::Strategy;

    fn finding(title: &str, severity: Severity, confidence: Confidence) -> Finding {
        Finding::new("c", title, severity, confidence, Location::file("f"))
    }

    #[test]
    fn higher_rank_wins_and_tie_keeps_first() {
        let mut a = finding("a", Severity::Medium, Confidence::Certain);
        merge(
            &mut a,
            finding("b", Severity::Medium, Confidence::Certain),
            &Strategy::Fingerprint,
            &Options::default(),
        );
        assert_eq!(a.title, "a");
        merge(
            &mut a,
            finding("c", Severity::Medium, Confidence::Tentative),
            &Strategy::Fingerprint,
            &Options::default(),
        );
        assert_eq!(a.title, "a");
        merge(
            &mut a,
            finding("d", Severity::High, Confidence::Tentative),
            &Strategy::Fingerprint,
            &Options::default(),
        );
        assert_eq!(a.title, "d");
        assert_eq!(a.severity, Severity::High);
    }

    #[test]
    fn unions_detail_without_duplicates() {
        let mut a = finding("a", Severity::High, Confidence::Firm)
            .push_evidence(Evidence::new("x", "1"))
            .push_taxonomy(TaxonomyRef::new(Taxonomy::Cwe, "CWE-79"))
            .push_remediation_ref("https://a.test/");
        let b = finding("b", Severity::Low, Confidence::Firm)
            .push_evidence(Evidence::new("x", "1"))
            .push_evidence(Evidence::new("y", "2"))
            .push_taxonomy(TaxonomyRef::cwe(79).with_name("XSS"))
            .push_taxonomy(TaxonomyRef::owasp("A03:2021"))
            .push_remediation_ref("https://a.test/")
            .push_remediation_ref("https://b.test/")
            .with_remediation(Remediation::new("encode"))
            .with_cvss(Cvss::new("v", 6.1));
        merge(&mut a, b, &Strategy::Fingerprint, &Options::default());
        assert_eq!(a.evidence.len(), 2);
        assert_eq!(a.taxonomy.len(), 2);
        assert_eq!(a.taxonomy[0].name.as_deref(), Some("XSS"));
        assert_eq!(a.remediation_refs.len(), 2);
        assert_eq!(a.remediation, Some(Remediation::new("encode")));
        assert_eq!(a.cvss.as_ref().map(|c| c.base_score), Some(6.1));

        let c = finding("c", Severity::Low, Confidence::Firm)
            .with_remediation(Remediation::new("other"))
            .with_cvss(Cvss::new("w", 5.0));
        merge(&mut a, c, &Strategy::Fingerprint, &Options::default());
        assert_eq!(a.remediation, Some(Remediation::new("encode")));
        assert_eq!(a.cvss.as_ref().map(|c| c.base_score), Some(6.1));
        let d = finding("d", Severity::Low, Confidence::Firm).with_cvss(Cvss::new("z", 9.8));
        merge(&mut a, d, &Strategy::Fingerprint, &Options::default());
        assert_eq!(a.cvss.as_ref().map(|c| c.base_score), Some(9.8));
    }

    #[test]
    fn evidence_is_bounded() {
        let options = Options::default().with_max_evidence(2);
        let mut a =
            finding("a", Severity::High, Confidence::Firm).push_evidence(Evidence::new("a", "1"));
        let b = finding("b", Severity::Low, Confidence::Firm)
            .push_evidence(Evidence::new("b", "1"))
            .push_evidence(Evidence::new("c", "1"));
        merge(&mut a, b, &Strategy::Fingerprint, &options);
        assert_eq!(a.evidence.len(), 2);

        // A kept finding already over the bound is not trimmed.
        let mut big = finding("a", Severity::High, Confidence::Firm)
            .push_evidence(Evidence::new("a", "1"))
            .push_evidence(Evidence::new("b", "1"))
            .push_evidence(Evidence::new("c", "1"));
        merge(
            &mut big,
            finding("b", Severity::Low, Confidence::Firm).push_evidence(Evidence::new("d", "1")),
            &Strategy::Fingerprint,
            &options,
        );
        assert_eq!(big.evidence.len(), 3);
    }

    // Merging many duplicates used to grow the lists without bound and
    // scan them once per entry added.
    #[test]
    fn many_duplicates_merge_in_bounded_lists() {
        let mut kept = finding("a", Severity::High, Confidence::Firm);
        let start = std::time::Instant::now();
        for i in 0..20_000_u32 {
            let duplicate = finding("b", Severity::Low, Confidence::Firm)
                .push_taxonomy(TaxonomyRef::cwe(i))
                .push_taxonomy(TaxonomyRef::cwe(i))
                .with_remediation_refs(vec![format!("https://x.test/{i}")]);
            merge(
                &mut kept,
                duplicate,
                &Strategy::Fingerprint,
                &Options::default(),
            );
        }
        let elapsed = start.elapsed();
        assert_eq!(kept.taxonomy.len(), Options::default().max_taxonomy);
        assert_eq!(
            kept.remediation_refs.len(),
            Options::default().max_remediation_refs
        );
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn known_taxonomy_still_gets_its_name_at_the_bound() {
        let options = Options::default().with_max_taxonomy(1);
        let mut a =
            finding("a", Severity::High, Confidence::Firm).push_taxonomy(TaxonomyRef::cwe(79));
        let b = finding("b", Severity::Low, Confidence::Firm)
            .push_taxonomy(TaxonomyRef::cwe(89))
            .push_taxonomy(TaxonomyRef::cwe(79).with_name("XSS"));
        merge(&mut a, b, &Strategy::Fingerprint, &options);
        assert_eq!(a.taxonomy, [TaxonomyRef::cwe(79).with_name("XSS")]);
    }

    #[test]
    fn merges_extensions_through_correlate() {
        struct Sum;
        impl Correlate<u32> for Sum {
            fn keys(&self, _: &Finding<u32>) -> Vec<crate::Key> {
                Vec::new()
            }
            fn merge_ext(&self, into: &mut u32, from: u32) {
                *into += from;
            }
        }
        let mut a = finding("a", Severity::Low, Confidence::Firm).with_ext(1_u32);
        let b = finding("b", Severity::High, Confidence::Firm).with_ext(10_u32);
        merge(&mut a, b, &Sum, &Options::default());
        assert_eq!(a.ext, 11);
        assert_eq!(a.title, "b");
    }
}
