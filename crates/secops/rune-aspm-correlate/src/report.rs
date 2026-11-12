//! [`correlate`] and the risk view it returns: [`Report`], [`RiskIssue`],
//! [`Corroboration`].

use std::collections::{BTreeMap, BTreeSet};

use rune_finding::Finding;
use rune_finding_dedupe::{Correlate, Group, Key, dedupe, merge};

use crate::{Correlator, Kind, Link, Options, Provenance};

/// How well an issue is backed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Corroboration {
    /// One tool reported it.
    Single,
    /// Several tools reported it.
    MultiTool,
    /// A SAST and a DAST tool both reported it: the code has the weakness
    /// and a running instance is exploitable through it.
    Confirmed,
}

/// One issue of the risk view: the merged finding and how it was built.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RiskIssue {
    /// The merged finding. Its extension lists every original report.
    pub finding: Finding<Provenance>,
    /// Every correlation key of every report in it.
    pub keys: BTreeSet<Key>,
    /// The distinct fingerprints of the reports in it.
    pub fingerprints: BTreeSet<String>,
    /// How many findings were merged, duplicates included.
    pub count: usize,
    /// The route links that tie its SAST and DAST reports together.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeSet::is_empty")
    )]
    pub links: BTreeSet<Link>,
    /// How well it is backed up.
    pub corroboration: Corroboration,
}

impl RiskIssue {
    fn from_group(group: Group<Provenance>) -> Self {
        let Group {
            finding,
            keys,
            fingerprints,
            count,
            ..
        } = group;
        Self {
            finding,
            keys,
            fingerprints,
            count,
            links: BTreeSet::new(),
            corroboration: Corroboration::Single,
        }
    }

    fn absorb(&mut self, other: Self, correlator: Correlator<'_>) {
        merge(
            &mut self.finding,
            other.finding,
            &correlator,
            &correlator.options().merge,
        );
        self.keys.extend(other.keys);
        self.fingerprints.extend(other.fingerprints);
        self.count += other.count;
    }

    /// Whether a SAST and a DAST tool both reported it.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.corroboration == Corroboration::Confirmed
    }

    /// The distinct tools that reported it.
    #[must_use]
    pub fn tools(&self) -> BTreeSet<&str> {
        self.finding.ext.tools()
    }

    /// The distinct kinds of testing that reported it.
    #[must_use]
    pub fn kinds(&self) -> BTreeSet<Kind> {
        self.finding.ext.kinds()
    }

    /// Ranking: severity, corroboration, confidence, then report count.
    const fn rank(
        &self,
    ) -> (
        rune_finding::Severity,
        Corroboration,
        rune_finding::Confidence,
        usize,
    ) {
        (
            self.finding.severity,
            self.corroboration,
            self.finding.confidence,
            self.count,
        )
    }
}

/// The risk view: every issue once, most urgent first.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Report {
    /// The issues, by severity, then corroboration, then confidence, then
    /// report count, all descending; ties keep input order.
    pub issues: Vec<RiskIssue>,
    /// How many findings came in, suppressed ones included.
    pub inputs: usize,
    /// How many suppressed findings were dropped
    /// ([`Options::keep_suppressed`]).
    pub suppressed: usize,
}

impl Report {
    /// The issues a SAST and a DAST tool both reported.
    pub fn confirmed(&self) -> impl Iterator<Item = &RiskIssue> {
        self.issues.iter().filter(|issue| issue.is_confirmed())
    }

    /// The merged findings, most urgent first, e.g. to feed a
    /// `rune_finding_dedupe::Tracker` with a [`Correlator`].
    pub fn findings(&self) -> impl Iterator<Item = &Finding<Provenance>> {
        self.issues.iter().map(|issue| &issue.finding)
    }

    /// The merged findings, most urgent first.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding<Provenance>> {
        self.issues.into_iter().map(|issue| issue.finding).collect()
    }
}

/// Correlate findings from every tool into one risk view.
///
/// 1. Suppressed SARIF results are dropped, unless
///    [`Options::keep_suppressed`].
/// 2. Duplicates merge by the [`Correlator`]'s keys: same fingerprint, same
///    SARIF partial fingerprint from the same tool and check, and (with
///    [`Options::same_location_cwe`]) same CWE at the same location.
/// 3. SAST and DAST issues meet on [routes](crate::Route): every issue
///    with a SAST report and every issue with a DAST report that share a
///    [`Link`] (route and CWE class) merge. Two SAST issues on one route
///    never merge unless a DAST report ties them, and likewise two DAST
///    issues.
///
/// Merging keeps the highest severity and confidence and unions evidence
/// and taxonomy (rune-finding-dedupe's `merge`); every original report
/// stays in the finding's [`Provenance`].
///
/// # Examples
///
/// ```
/// use rune_aspm_correlate::{Batch, Corroboration, Options, Route, correlate};
/// use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
///
/// let sast = Finding::<()>::new("py.sqli", "SQL built from input", Severity::High,
///     Confidence::Firm, Location::file("src/users.py").with_lines(18, 18))
///     .push_taxonomy(TaxonomyRef::cwe(89));
/// let dast = Finding::<()>::new("sqli.error", "SQL injection", Severity::Critical,
///     Confidence::Certain, Location::url("https://shop.test/users/42").with_parameter("id"))
///     .push_taxonomy(TaxonomyRef::cwe(89));
///
/// let mut batch = Batch::new();
/// batch.add_findings("sast-tool", [sast]);
/// batch.add_findings("dast-scanner", [dast]);
/// let options = Options::default().with_route(Route::new("/users/{id}", "src/users.py")?);
///
/// let report = correlate(batch.into_findings(), &options);
/// assert_eq!(report.issues.len(), 1);
/// let issue = &report.issues[0];
/// assert_eq!(issue.corroboration, Corroboration::Confirmed);
/// assert_eq!(issue.finding.severity, Severity::Critical);
/// assert_eq!(issue.finding.ext.sources.len(), 2, "both reports kept");
/// # Ok::<(), rune_aspm_correlate::Error>(())
/// ```
#[must_use]
pub fn correlate(
    findings: impl IntoIterator<Item = Finding<Provenance>>,
    options: &Options,
) -> Report {
    let correlator = Correlator::new(options);
    let mut inputs = 0;
    let mut suppressed = 0;
    let kept = findings.into_iter().filter(|finding| {
        inputs += 1;
        let drop = !options.keep_suppressed
            && !finding.ext.sources.is_empty()
            && finding.ext.sources.iter().all(|source| source.suppressed);
        suppressed += usize::from(drop);
        !drop
    });
    let groups = dedupe(kept, &correlator, &options.merge);

    // Union SAST and DAST groups that share a link candidate.
    let mut parent: Vec<usize> = (0..groups.len()).collect();
    let mut sides: BTreeMap<Link, (Vec<usize>, Vec<usize>)> = BTreeMap::new();
    for (index, group) in groups.iter().enumerate() {
        for source in &group.finding.ext.sources {
            for link in correlator.candidates(source) {
                let side = sides.entry(link).or_default();
                let list = if source.kind == Kind::Dast {
                    &mut side.0
                } else {
                    &mut side.1
                };
                if list.last() != Some(&index) {
                    list.push(index);
                }
            }
        }
    }
    for (dast, sast) in sides.values() {
        if dast.is_empty() || sast.is_empty() {
            continue;
        }
        let mut members = dast.iter().chain(sast);
        if let Some(&first) = members.next() {
            for &other in members {
                union(&mut parent, first, other);
            }
        }
    }

    let mut merged: BTreeMap<usize, RiskIssue> = BTreeMap::new();
    for (index, group) in groups.into_iter().enumerate() {
        let issue = RiskIssue::from_group(group);
        match merged.entry(find(&mut parent, index)) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(issue);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                slot.get_mut().absorb(issue, correlator);
            }
        }
    }

    let mut issues: Vec<RiskIssue> = merged
        .into_values()
        .map(|mut issue| {
            issue.links = correlator.links(&issue.finding.ext);
            issue.keys.extend(correlator.keys(&issue.finding));
            let provenance = &issue.finding.ext;
            issue.corroboration =
                if provenance.has_kind(Kind::Sast) && provenance.has_kind(Kind::Dast) {
                    Corroboration::Confirmed
                } else if provenance.tools().len() > 1 {
                    Corroboration::MultiTool
                } else {
                    Corroboration::Single
                };
            issue
        })
        .collect();
    issues.sort_by_key(|issue| core::cmp::Reverse(issue.rank()));

    Report {
        issues,
        inputs,
        suppressed,
    }
}

fn find(parent: &mut [usize], mut index: usize) -> usize {
    while let Some(&up) = parent.get(index) {
        if up == index {
            break;
        }
        let grand = parent.get(up).copied().unwrap_or(up);
        if let Some(slot) = parent.get_mut(index) {
            *slot = grand;
        }
        index = up;
    }
    index
}

/// Join the sets of `a` and `b`; the smaller index stays the root, so the
/// merged issue sits where its first report was.
fn union(parent: &mut [usize], a: usize, b: usize) {
    let (a, b) = (find(parent, a), find(parent, b));
    let (root, child) = (a.min(b), a.max(b));
    if let Some(slot) = parent.get_mut(child) {
        *slot = root;
    }
}

#[cfg(test)]
mod tests {
    use rune_finding::{Confidence, Location, Severity, TaxonomyRef};

    use super::*;
    use crate::{Batch, Route};

    fn finding(check: &str, severity: Severity, location: Location, cwe: u32) -> Finding {
        Finding::<()>::new(check, check, severity, Confidence::Firm, location)
            .push_taxonomy(TaxonomyRef::cwe(cwe))
    }

    fn options() -> Options {
        Options::default()
            .with_route(Route::new("/users/{id}", "src/users.py").unwrap())
            .with_route(Route::new("/search", "src/search.py").unwrap())
    }

    #[test]
    fn sast_pairs_merge_only_through_dast() {
        let s1 = finding(
            "sqli",
            Severity::High,
            Location::file("src/users.py").with_lines(5, 5),
            89,
        );
        let s2 = finding(
            "sqli",
            Severity::Medium,
            Location::file("src/users.py").with_lines(9, 9),
            89,
        );
        let mut batch = Batch::new();
        batch.add_findings("semgrep", [s1, s2]);
        let report = batch.clone().correlate(&options());
        assert_eq!(report.issues.len(), 2, "no DAST: two SAST issues");
        assert_eq!(report.confirmed().count(), 0);

        let d = finding(
            "dast.sqli",
            Severity::High,
            Location::url("https://a.test/users/3"),
            564,
        );
        batch.add_findings("dast-scanner", [d]);
        let report = batch.correlate(&options());
        assert_eq!(report.issues.len(), 1);
        let issue = &report.issues[0];
        assert!(issue.is_confirmed());
        assert_eq!(issue.count, 3);
        assert_eq!(issue.fingerprints.len(), 3);
        assert_eq!(issue.finding.ext.sources.len(), 3);
        assert_eq!(issue.kinds().len(), 2);
        assert_eq!(issue.tools().len(), 2);
        assert_eq!(issue.links.len(), 1);
        assert!(issue.keys.iter().any(|key| key.scheme() == Link::SCHEME));
    }

    #[test]
    fn dast_pairs_do_not_merge_through_a_route_alone() {
        let d = |param: &str| {
            finding(
                "xss",
                Severity::High,
                Location::url("https://a.test/search").with_parameter(param),
                79,
            )
        };
        let mut batch = Batch::new();
        batch.add_findings("dast-scanner", [d("q"), d("page")]);
        assert_eq!(batch.correlate(&options()).issues.len(), 2);
    }

    #[test]
    fn different_weakness_or_route_stays_apart() {
        let mut batch = Batch::new();
        batch.add_findings(
            "semgrep",
            [finding(
                "xss",
                Severity::High,
                Location::file("src/users.py"),
                79,
            )],
        );
        batch.add_findings(
            "dast-scanner",
            [
                finding(
                    "sqli",
                    Severity::High,
                    Location::url("https://a.test/users/1"),
                    89,
                ),
                finding(
                    "xss",
                    Severity::High,
                    Location::url("https://a.test/search"),
                    79,
                ),
            ],
        );
        let report = batch.correlate(&options());
        assert_eq!(report.issues.len(), 3);
        assert!(
            report
                .issues
                .iter()
                .all(|i| i.corroboration == Corroboration::Single)
        );
    }

    #[test]
    fn ranking_and_multi_tool() {
        let at = |line: u32, severity| {
            finding(
                "r",
                severity,
                Location::file("lib.py").with_lines(line, line),
                20,
            )
        };
        let mut batch = Batch::new();
        batch.add_findings("a", [at(1, Severity::Low), at(2, Severity::High)]);
        batch.add_findings("b", [at(1, Severity::Low)]);
        let report = batch.correlate(&options());
        let order: Vec<_> = report
            .issues
            .iter()
            .map(|i| (i.finding.severity, i.corroboration))
            .collect();
        assert_eq!(
            order,
            [
                (Severity::High, Corroboration::Single),
                (Severity::Low, Corroboration::MultiTool)
            ]
        );
        assert_eq!(report.inputs, 3);
        assert_eq!(report.findings().count(), 2);
        assert_eq!(report.into_findings().len(), 2);
    }

    #[test]
    fn suppressed_reports_are_dropped_by_default() {
        let mut batch = Batch::new();
        batch.add_findings("a", [finding("r", Severity::Low, Location::file("x"), 1)]);
        let mut hidden = Batch::new();
        hidden.add_findings("a", [finding("q", Severity::Low, Location::file("z"), 1)]);
        let mut hidden = hidden.into_findings();
        for finding in &mut hidden {
            finding.ext.sources[0].suppressed = true;
        }
        batch.extend(hidden);
        batch.push(
            finding("r", Severity::Low, Location::file("y"), 1).with_ext(Provenance::default()),
        );
        let report = batch.clone().correlate(&options());
        assert_eq!(
            (report.inputs, report.suppressed, report.issues.len()),
            (3, 1, 2)
        );
        let report = batch.correlate(&options().with_keep_suppressed(true));
        assert_eq!((report.suppressed, report.issues.len()), (0, 3));
    }

    #[test]
    fn union_find() {
        let mut parent: Vec<usize> = (0..5).collect();
        union(&mut parent, 3, 4);
        union(&mut parent, 4, 1);
        union(&mut parent, 1, 1);
        assert_eq!(find(&mut parent, 4), 1);
        assert_eq!(find(&mut parent, 3), 1);
        assert_eq!(find(&mut parent, 0), 0);
        assert_eq!(find(&mut parent, 9), 9);
    }
}
