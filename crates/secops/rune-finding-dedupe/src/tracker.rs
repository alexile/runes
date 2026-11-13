//! Issue identity over time: [`Tracker`], [`Scan`], [`Issue`] and
//! [`ScanReport`].

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use rune_finding::Finding;

#[cfg(any(feature = "serde", test))]
use crate::Error;
use crate::{Correlate, Group, Key, Options, dedupe};

/// The stable identity of a tracked issue: the [`Finding::fingerprint`] of
/// the finding that first reported it.
///
/// It never changes while the issue lives. When two issues turn out to be
/// one, the younger id becomes an alias of the older:
/// [`Tracker::resolve`] follows it.
///
/// With the `serde` feature an id serializes as its string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct IssueId(String);

impl IssueId {
    /// An id from a fingerprint, as stored elsewhere.
    pub fn new(fingerprint: impl Into<String>) -> Self {
        Self(fingerprint.into())
    }

    /// The id as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One run of one tool, as [`Tracker::observe`] sees it.
///
/// # Examples
///
/// ```
/// use rune_finding_dedupe::Scan;
///
/// let nightly = Scan::new("semgrep", 1_700_000_000_000);
/// assert!(nightly.complete);
/// // A scan of a subset (one changed file, one URL) cannot prove fixes.
/// assert!(!Scan::new("semgrep", 1_700_000_000_000).partial().complete);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Scan {
    /// The tool that ran, e.g. `codeql`. An issue is fixed once every tool
    /// that reported it has run a complete scan without it.
    pub tool: String,
    /// When the scan ran, Unix epoch milliseconds.
    pub at_unix_ms: u64,
    /// Whether the scan covered everything the tool covers. Only a complete
    /// scan marks the issues it did not report as fixed. Default `true`.
    pub complete: bool,
}

impl Scan {
    /// A complete scan by `tool` at `at_unix_ms`.
    pub fn new(tool: impl Into<String>, at_unix_ms: u64) -> Self {
        Self {
            tool: tool.into(),
            at_unix_ms,
            complete: true,
        }
    }

    /// Mark the scan partial: it reports what it sees, and fixes nothing.
    #[must_use]
    pub const fn partial(mut self) -> Self {
        self.complete = false;
        self
    }
}

/// Whether an issue is still there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Status {
    /// Reported by the latest scan of at least one tool that saw it.
    Open,
    /// Every tool that reported it has since run a complete scan without it.
    Fixed,
}

/// One issue the [`Tracker`] follows across scans.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Issue<X = ()> {
    /// The stable id.
    pub id: IssueId,
    /// The latest observation, merged across the tools in that scan.
    pub finding: Finding<X>,
    /// Every key the issue has been seen under. A finding with any of them
    /// is this issue.
    pub keys: BTreeSet<Key>,
    /// Ids of issues that were merged into this one.
    pub aliases: BTreeSet<IssueId>,
    /// Open or fixed.
    pub status: Status,
    /// Tools whose latest complete scan still reports the issue, or that
    /// reported it in a partial scan since.
    pub reporters: BTreeSet<String>,
    /// Every tool that ever reported the issue.
    pub tools: BTreeSet<String>,
    /// Earliest scan time that reported it, Unix epoch milliseconds.
    pub first_seen_unix_ms: u64,
    /// Latest scan time that reported it, Unix epoch milliseconds.
    pub last_seen_unix_ms: u64,
    /// When it was last marked fixed, while [`Status::Fixed`].
    pub fixed_unix_ms: Option<u64>,
    /// Sequence number of the first scan that reported it.
    pub first_scan: u64,
    /// Sequence number of the latest scan that reported it.
    pub last_scan: u64,
    /// How many scans reported it.
    pub times_seen: u64,
    /// How many times it came back after being fixed.
    pub reopened: u64,
}

/// What one [`Tracker::observe`] call changed. Every list is sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ScanReport {
    /// The scan's sequence number, counting from 1.
    pub scan: u64,
    /// Issues seen for the first time.
    pub new: Vec<IssueId>,
    /// Open issues seen again.
    pub recurring: Vec<IssueId>,
    /// Fixed issues seen again, now open.
    pub reopened: Vec<IssueId>,
    /// Issues this scan marked fixed.
    pub fixed: Vec<IssueId>,
    /// Issues found to be one: `(absorbed, survivor)`. The absorbed id is
    /// now an alias of the survivor.
    pub merged: Vec<(IssueId, IssueId)>,
}

/// Follows issues across scans, so each keeps one identity over time.
///
/// Feed it each scan's findings with [`observe`](Self::observe). Findings
/// are deduplicated within the scan ([`dedupe`]), then matched to known
/// issues by [`Key`]: a finding with any key of an issue is that issue.
/// The tracker reports what is new, recurring, reopened and fixed.
///
/// An issue is fixed once every tool that reported it has run a complete
/// scan without it, so one tool's scan does not close another tool's
/// issue. If a finding links two known issues, they merge into the older
/// one and the other id becomes its alias.
///
/// The tracker is plain data with no clock or I/O: scan times come in with
/// [`Scan`]. With the `serde` feature it serializes, so identity persists
/// between runs; deserializing checks the state is consistent.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity};
/// use rune_finding_dedupe::{Options, Scan, Status, Strategy, Tracker};
///
/// let xss = |url: &str| -> Finding {
///     Finding::<()>::new("xss.reflected", "XSS", Severity::High, Confidence::Firm,
///         Location::url(url).with_parameter("q"))
/// };
/// let mut tracker = Tracker::new(Options::default());
///
/// let first = tracker.observe(&Scan::new("dast", 1_000), [xss("https://a.test/s?q=1")], &Strategy::Fingerprint);
/// assert_eq!(first.new.len(), 1);
/// let id = first.new[0].clone();
///
/// // Same issue, different query value: same identity.
/// let second = tracker.observe(&Scan::new("dast", 2_000), [xss("https://a.test/s?q=2")], &Strategy::Fingerprint);
/// assert_eq!(second.recurring, [id.clone()]);
///
/// // Gone from a complete scan: fixed. Back again: reopened, same id.
/// let third = tracker.observe(&Scan::new("dast", 3_000), [], &Strategy::Fingerprint);
/// assert_eq!(third.fixed, [id.clone()]);
/// assert_eq!(tracker.issue(&id).map(|i| i.status), Some(Status::Fixed));
/// let fourth = tracker.observe(&Scan::new("dast", 4_000), [xss("https://a.test/s?q=3")], &Strategy::Fingerprint);
/// assert_eq!(fourth.reopened, [id]);
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        try_from = "Snapshot<X>",
        bound(deserialize = "X: serde::Deserialize<'de>")
    )
)]
pub struct Tracker<X = ()> {
    options: Options,
    scans: u64,
    issues: BTreeMap<IssueId, Issue<X>>,
    redirects: BTreeMap<IssueId, IssueId>,
    #[cfg_attr(feature = "serde", serde(skip))]
    index: BTreeMap<Key, IssueId>,
}

impl<X> Default for Tracker<X> {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

impl<X> Tracker<X> {
    /// An empty tracker.
    #[must_use]
    pub const fn new(options: Options) -> Self {
        Self {
            options,
            scans: 0,
            issues: BTreeMap::new(),
            redirects: BTreeMap::new(),
            index: BTreeMap::new(),
        }
    }

    /// The merge options.
    #[must_use]
    pub const fn options(&self) -> &Options {
        &self.options
    }

    /// How many scans were observed.
    #[must_use]
    pub const fn scans(&self) -> u64 {
        self.scans
    }

    /// Every issue, open and fixed, by id.
    pub fn issues(&self) -> impl Iterator<Item = &Issue<X>> {
        self.issues.values()
    }

    /// The open issues, by id.
    pub fn open_issues(&self) -> impl Iterator<Item = &Issue<X>> {
        self.issues().filter(|issue| issue.status == Status::Open)
    }

    /// The issue with this id, following aliases of merged issues.
    #[must_use]
    pub fn issue(&self, id: &IssueId) -> Option<&Issue<X>> {
        self.issues.get(&self.resolve(id))
    }

    /// The current id of `id`: itself, or the issue it was merged into.
    #[must_use]
    pub fn resolve(&self, id: &IssueId) -> IssueId {
        self.redirects.get(id).unwrap_or(id).clone()
    }

    /// The issue a finding with this key belongs to.
    #[must_use]
    pub fn issue_for_key(&self, key: &Key) -> Option<&Issue<X>> {
        self.index.get(key).and_then(|id| self.issues.get(id))
    }

    /// The issue `finding` belongs to, if it is known, without recording
    /// anything.
    pub fn issue_for<C: Correlate<X> + ?Sized>(
        &self,
        finding: &Finding<X>,
        correlate: &C,
    ) -> Option<&Issue<X>> {
        let (_, keys) = crate::keys_of(finding, correlate);
        keys.iter().find_map(|key| self.issue_for_key(key))
    }

    /// Record one scan's findings and report what changed.
    ///
    /// Findings are deduplicated first, so a tool reporting the same issue
    /// twice in one scan counts once. Each group then becomes a new issue,
    /// or updates the issue it matches: its finding becomes the latest
    /// observation, its keys grow, and a fixed issue reopens. Last, if the
    /// scan is complete, open issues this tool reported but did not report
    /// now lose it as a reporter, and those with no reporter left are fixed.
    pub fn observe<C: Correlate<X> + ?Sized>(
        &mut self,
        scan: &Scan,
        findings: impl IntoIterator<Item = Finding<X>>,
        correlate: &C,
    ) -> ScanReport {
        self.scans = self.scans.saturating_add(1);
        let mut report = ScanReport {
            scan: self.scans,
            ..ScanReport::default()
        };
        let mut seen = BTreeSet::new();

        for group in dedupe(findings, correlate, &self.options) {
            let id = self.record(scan, group, &mut report);
            seen.insert(id);
        }

        if scan.complete {
            for issue in self.issues.values_mut() {
                if issue.status == Status::Open
                    && !seen.contains(&issue.id)
                    && issue.reporters.remove(&scan.tool)
                    && issue.reporters.is_empty()
                {
                    issue.status = Status::Fixed;
                    issue.fixed_unix_ms = Some(scan.at_unix_ms);
                    report.fixed.push(issue.id.clone());
                }
            }
        }

        // An issue merged away later in the scan is reported by its survivor.
        for list in [&mut report.new, &mut report.recurring, &mut report.reopened] {
            for id in list.iter_mut() {
                *id = self.redirects.get(id).unwrap_or(id).clone();
            }
            list.sort();
            list.dedup();
        }
        let reopened: BTreeSet<_> = report.reopened.iter().cloned().collect();
        let new: BTreeSet<_> = report.new.iter().cloned().collect();
        report
            .recurring
            .retain(|id| !reopened.contains(id) && !new.contains(id));
        report.reopened.retain(|id| !new.contains(id));
        report.fixed.sort();
        report
    }

    /// Fold one deduplicated group into the issues. Returns its issue id.
    fn record(&mut self, scan: &Scan, group: Group<X>, report: &mut ScanReport) -> IssueId {
        let mut matched: Vec<IssueId> = group
            .keys
            .iter()
            .filter_map(|key| self.index.get(key))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        matched.sort_by_key(|id| {
            self.issues.get(id).map_or((u64::MAX, u64::MAX), |issue| {
                (issue.first_scan, issue.first_seen_unix_ms)
            })
        });

        let Some(survivor) = matched.first().cloned() else {
            return self.create(scan, group, report);
        };
        for absorbed in matched.iter().skip(1) {
            self.absorb(absorbed, &survivor);
            report.merged.push((absorbed.clone(), survivor.clone()));
        }

        for key in &group.keys {
            self.index.insert(key.clone(), survivor.clone());
        }
        if let Some(issue) = self.issues.get_mut(&survivor) {
            if issue.status == Status::Fixed {
                issue.status = Status::Open;
                issue.fixed_unix_ms = None;
                issue.reopened = issue.reopened.saturating_add(1);
                report.reopened.push(survivor.clone());
            } else if issue.last_scan != self.scans {
                report.recurring.push(survivor.clone());
            }
            issue.finding = group.finding;
            issue.keys.extend(group.keys);
            issue.reporters.insert(scan.tool.clone());
            issue.tools.insert(scan.tool.clone());
            issue.first_seen_unix_ms = issue.first_seen_unix_ms.min(scan.at_unix_ms);
            issue.last_seen_unix_ms = issue.last_seen_unix_ms.max(scan.at_unix_ms);
            if issue.last_scan != self.scans {
                issue.times_seen = issue.times_seen.saturating_add(1);
                issue.last_scan = self.scans;
            }
        }
        survivor
    }

    fn create(&mut self, scan: &Scan, group: Group<X>, report: &mut ScanReport) -> IssueId {
        let id = IssueId(group.finding.fingerprint());
        for key in &group.keys {
            self.index.insert(key.clone(), id.clone());
        }
        let issue = Issue {
            id: id.clone(),
            finding: group.finding,
            keys: group.keys,
            aliases: BTreeSet::new(),
            status: Status::Open,
            reporters: BTreeSet::from([scan.tool.clone()]),
            tools: BTreeSet::from([scan.tool.clone()]),
            first_seen_unix_ms: scan.at_unix_ms,
            last_seen_unix_ms: scan.at_unix_ms,
            fixed_unix_ms: None,
            first_scan: self.scans,
            last_scan: self.scans,
            times_seen: 1,
            reopened: 0,
        };
        self.issues.insert(id.clone(), issue);
        report.new.push(id.clone());
        id
    }

    /// Merge issue `absorbed` into `survivor`, keeping the survivor's
    /// finding and id.
    fn absorb(&mut self, absorbed: &IssueId, survivor: &IssueId) {
        let Some(gone) = self.issues.remove(absorbed) else {
            return;
        };
        for key in &gone.keys {
            self.index.insert(key.clone(), survivor.clone());
        }
        // The ids redirected to the absorbed issue are its aliases.
        for alias in &gone.aliases {
            if let Some(target) = self.redirects.get_mut(alias) {
                target.clone_from(survivor);
            }
        }
        self.redirects.insert(absorbed.clone(), survivor.clone());
        if let Some(issue) = self.issues.get_mut(survivor) {
            issue.keys.extend(gone.keys);
            issue.aliases.extend(gone.aliases);
            issue.aliases.insert(gone.id);
            issue.reporters.extend(gone.reporters);
            issue.tools.extend(gone.tools);
            issue.first_seen_unix_ms = issue.first_seen_unix_ms.min(gone.first_seen_unix_ms);
            issue.last_seen_unix_ms = issue.last_seen_unix_ms.max(gone.last_seen_unix_ms);
            issue.first_scan = issue.first_scan.min(gone.first_scan);
            issue.last_scan = issue.last_scan.max(gone.last_scan);
            issue.times_seen = issue.times_seen.max(gone.times_seen);
            issue.reopened = issue.reopened.max(gone.reopened);
            if gone.status == Status::Open {
                issue.status = Status::Open;
                issue.fixed_unix_ms = None;
            }
        }
    }
}

/// The serialized form of a [`Tracker`], checked on the way in.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct Snapshot<X> {
    options: Options,
    scans: u64,
    issues: BTreeMap<IssueId, Issue<X>>,
    redirects: BTreeMap<IssueId, IssueId>,
}

#[cfg(feature = "serde")]
impl<X> TryFrom<Snapshot<X>> for Tracker<X> {
    type Error = Error;

    fn try_from(snapshot: Snapshot<X>) -> Result<Self, Error> {
        Self::from_parts(
            snapshot.options,
            snapshot.scans,
            snapshot.issues,
            snapshot.redirects,
        )
    }
}

#[cfg(any(feature = "serde", test))]
impl<X> Tracker<X> {
    /// Rebuild a tracker from its parts, checking that they agree: each
    /// issue is filed under its own id and has its id's fingerprint key, no
    /// key belongs to two issues, and each alias points at a live issue.
    fn from_parts(
        options: Options,
        scans: u64,
        issues: BTreeMap<IssueId, Issue<X>>,
        redirects: BTreeMap<IssueId, IssueId>,
    ) -> Result<Self, Error> {
        let mut index = BTreeMap::new();
        for (id, issue) in &issues {
            if *id != issue.id {
                return Err(Error::IdMismatch(id.to_string()));
            }
            let own = Key::fingerprint(id.as_str());
            for key in issue.keys.iter().chain([&own]) {
                if let Some(other) = index.insert(key.clone(), id.clone())
                    && other != *id
                {
                    return Err(Error::SharedKey(key.to_string()));
                }
            }
        }
        for (from, to) in &redirects {
            let listed = issues
                .get(to)
                .is_some_and(|issue| issue.aliases.contains(from));
            if issues.contains_key(from) || !listed {
                return Err(Error::BadAlias(from.to_string()));
            }
        }
        Ok(Self {
            options,
            scans,
            issues,
            redirects,
            index,
        })
    }
}

#[cfg(test)]
mod tests {
    use rune_finding::{Confidence, Location, Severity, TaxonomyRef};

    use super::*;
    use crate::Strategy;

    fn sqli(check: &str, line: u32) -> Finding {
        Finding::<()>::new(
            check,
            "SQLi",
            Severity::High,
            Confidence::Firm,
            Location::file("app.py").with_lines(line, line),
        )
        .push_taxonomy(TaxonomyRef::cwe(89))
    }

    #[test]
    fn same_issue_across_scans_keeps_identity() {
        let mut tracker = Tracker::default();
        let s = Strategy::Fingerprint;
        let r1 = tracker.observe(&Scan::new("t", 10), [sqli("a", 1), sqli("a", 2)], &s);
        assert_eq!(r1.scan, 1);
        assert_eq!(r1.new.len(), 2);
        let r2 = tracker.observe(&Scan::new("t", 20), [sqli("a", 1), sqli("a", 1)], &s);
        assert_eq!(r2.new.len(), 0);
        assert_eq!(r2.recurring, [IssueId(sqli("a", 1).fingerprint())]);
        assert_eq!(r2.fixed, [IssueId(sqli("a", 2).fingerprint())]);
        let issue = tracker.issue(&r2.recurring[0]).cloned();
        let issue = issue.as_ref();
        assert_eq!(issue.map(|i| i.times_seen), Some(2));
        assert_eq!(
            issue.map(|i| (i.first_seen_unix_ms, i.last_seen_unix_ms)),
            Some((10, 20))
        );
        assert_eq!(tracker.open_issues().count(), 1);
        assert_eq!(tracker.scans(), 2);
    }

    #[test]
    fn one_tool_does_not_fix_another_tools_issue() {
        let mut tracker = Tracker::default();
        let s = Strategy::FingerprintOrCwe;
        let r1 = tracker.observe(&Scan::new("codeql", 1), [sqli("codeql/sqli", 5)], &s);
        let id = r1.new[0].clone();
        let r2 = tracker.observe(&Scan::new("semgrep", 2), [sqli("semgrep/sqli", 5)], &s);
        assert_eq!(r2.recurring, std::slice::from_ref(&id), "cross-tool match");
        let issue = tracker.issue(&id).map(|i| i.reporters.len());
        assert_eq!(issue, Some(2));

        let r3 = tracker.observe(&Scan::new("codeql", 3), [], &s);
        assert!(r3.fixed.is_empty(), "semgrep still reports it");
        let r4 = tracker.observe(&Scan::new("semgrep", 4).partial(), [], &s);
        assert!(r4.fixed.is_empty(), "partial scans prove nothing");
        let r5 = tracker.observe(&Scan::new("semgrep", 5), [], &s);
        assert_eq!(r5.fixed, std::slice::from_ref(&id));
        assert_eq!(tracker.issue(&id).and_then(|i| i.fixed_unix_ms), Some(5));

        let r6 = tracker.observe(&Scan::new("codeql", 6), [sqli("codeql/sqli", 5)], &s);
        assert_eq!(r6.reopened, std::slice::from_ref(&id));
        assert_eq!(r6.recurring.len(), 0);
        let issue = tracker.issue(&id).cloned();
        assert_eq!(issue.as_ref().map(|i| i.reopened), Some(1));
        assert_eq!(issue.as_ref().map(|i| i.status), Some(Status::Open));
        assert_eq!(issue.map(|i| i.fixed_unix_ms), Some(None));
    }

    // Merging an issue used to scan every redirect the tracker had made.
    #[test]
    fn one_finding_linking_many_issues_merges_in_linear_time() {
        const N: u32 = 10_000;
        let mut tracker = Tracker::default();
        let s = Strategy::FingerprintOrCwe;
        let at = |check: String| {
            Finding::<()>::new(
                check,
                "x",
                Severity::Low,
                Confidence::Firm,
                Location::file("f"),
            )
        };
        let first = (0..N).map(|cwe| at(format!("c{cwe}")).push_taxonomy(TaxonomyRef::cwe(cwe)));
        assert_eq!(
            tracker.observe(&Scan::new("t", 1), first, &s).new.len(),
            10_000
        );
        let link = at("link".to_owned()).with_taxonomy((0..N).map(TaxonomyRef::cwe).collect());
        let start = std::time::Instant::now();
        let r = tracker.observe(&Scan::new("t", 2), [link], &s);
        let elapsed = start.elapsed();
        assert_eq!(r.merged.len(), 9_999);
        assert_eq!(tracker.issues().count(), 1);
        let (gone, kept) = &r.merged[0];
        assert_eq!(&tracker.resolve(gone), kept);
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
    }

    #[test]
    fn linking_finding_merges_issues_into_the_older() {
        let mut tracker = Tracker::default();
        let s = Strategy::FingerprintOrCwe;
        let a = Finding::<()>::new(
            "a",
            "x",
            Severity::Low,
            Confidence::Firm,
            Location::file("f"),
        )
        .push_taxonomy(TaxonomyRef::cwe(1));
        let b = Finding::<()>::new(
            "b",
            "x",
            Severity::Low,
            Confidence::Firm,
            Location::file("f"),
        )
        .push_taxonomy(TaxonomyRef::cwe(2));
        let link = Finding::<()>::new(
            "c",
            "x",
            Severity::Low,
            Confidence::Firm,
            Location::file("f"),
        )
        .push_taxonomy(TaxonomyRef::cwe(1))
        .push_taxonomy(TaxonomyRef::cwe(2));
        let older = tracker.observe(&Scan::new("t", 1), [a], &s).new[0].clone();
        let younger = tracker.observe(&Scan::new("u", 2), [b.clone()], &s).new[0].clone();
        let r = tracker.observe(&Scan::new("v", 3), [link], &s);
        assert_eq!(r.merged, [(younger.clone(), older.clone())]);
        assert_eq!(r.recurring, std::slice::from_ref(&older));
        assert_eq!(tracker.resolve(&younger), older);
        assert_eq!(tracker.issues().count(), 1);
        let issue = tracker.issue(&younger).cloned();
        assert_eq!(issue.as_ref().map(|i| i.id.clone()), Some(older.clone()));
        assert_eq!(issue.as_ref().map(|i| i.tools.len()), Some(3));
        assert!(issue.is_some_and(|i| i.aliases.contains(&younger)));
        // The absorbed issue's own findings keep matching the survivor.
        assert_eq!(tracker.issue_for(&b, &s).map(|i| i.id.clone()), Some(older));
    }

    #[test]
    fn rejects_inconsistent_parts() {
        let mut tracker = Tracker::default();
        tracker.observe(
            &Scan::new("t", 1),
            [sqli("a", 1), sqli("a", 2)],
            &Strategy::Fingerprint,
        );
        let rebuilt = Tracker::from_parts(
            tracker.options.clone(),
            tracker.scans,
            tracker.issues.clone(),
            tracker.redirects.clone(),
        );
        assert_eq!(rebuilt.as_ref().map(|t| &t.index), Ok(&tracker.index));

        let mut issues = tracker.issues.clone();
        let stolen = issues.values().nth(1).and_then(|i| i.keys.first().cloned());
        if let (Some(issue), Some(key)) = (issues.values_mut().next(), stolen) {
            issue.keys.insert(key);
        }
        assert!(matches!(
            Tracker::from_parts(Options::default(), 1, issues, BTreeMap::new()),
            Err(Error::SharedKey(_))
        ));

        let id = tracker
            .issues
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| IssueId::new(""));
        let redirects = BTreeMap::from([(IssueId::new("x"), IssueId::new("missing"))]);
        assert!(matches!(
            Tracker::from_parts(Options::default(), 1, tracker.issues.clone(), redirects),
            Err(Error::BadAlias(_))
        ));
        let unlisted = BTreeMap::from([(IssueId::new("x"), id.clone())]);
        assert!(matches!(
            Tracker::from_parts(Options::default(), 1, tracker.issues.clone(), unlisted),
            Err(Error::BadAlias(_))
        ));
        let mut issues = tracker.issues.clone();
        if let Some(issue) = issues.remove(&id) {
            issues.insert(IssueId::new("other"), issue);
        }
        assert!(matches!(
            Tracker::from_parts(Options::default(), 1, issues, BTreeMap::new()),
            Err(Error::IdMismatch(_))
        ));
    }
}
