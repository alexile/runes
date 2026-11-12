//! Deduplicating one batch of findings: [`dedupe`] and [`Group`].

use std::collections::{BTreeMap, BTreeSet};

use rune_finding::Finding;

use crate::{Correlate, Key, Options, merge};

/// One issue after deduplication: the merged finding and what went into it.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Group<X = ()> {
    /// The duplicates merged into one finding, as [`merge`] does.
    pub finding: Finding<X>,
    /// Every key of every member, fingerprint keys included.
    pub keys: BTreeSet<Key>,
    /// The distinct [`Finding::fingerprint`]s of the members.
    pub fingerprints: BTreeSet<String>,
    /// How many findings were merged, duplicates included.
    pub count: usize,
}

impl<X> Group<X> {
    fn absorb<C: Correlate<X> + ?Sized>(&mut self, other: Self, correlate: &C, options: &Options) {
        merge(&mut self.finding, other.finding, correlate, options);
        self.keys.extend(other.keys);
        self.fingerprints.extend(other.fingerprints);
        self.count += other.count;
    }
}

/// The keys of `finding` under `correlate`: its fingerprint key and the
/// extra ones. Returns the fingerprint as well.
pub fn keys_of<X, C: Correlate<X> + ?Sized>(
    finding: &Finding<X>,
    correlate: &C,
) -> (String, BTreeSet<Key>) {
    let fingerprint = finding.fingerprint();
    let mut keys: BTreeSet<Key> = correlate.keys(finding).into_iter().collect();
    keys.insert(Key::fingerprint(&fingerprint));
    (fingerprint, keys)
}

/// Merge the duplicates in one batch of findings, from one scan or from
/// several tools.
///
/// Two findings are duplicates when they share a [`Key`]: the same
/// [`Finding::fingerprint`] always, plus whatever `correlate` adds. Sharing
/// is transitive, so if A and B share one key and B and C another, all three
/// are one group. Each group's finding is merged with [`merge`].
///
/// Groups come back in the order of their first member, so the result is
/// deterministic for a given input order.
///
/// # Examples
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
/// use rune_finding_dedupe::{dedupe, Options, Strategy};
///
/// let at = |check: &str, line: u32| {
///     Finding::<()>::new(check, "SQLi", Severity::High, Confidence::Firm,
///         Location::file("app.py").with_lines(line, line))
///     .push_taxonomy(TaxonomyRef::cwe(89))
/// };
/// let batch = [at("codeql/py/sqli", 7), at("semgrep/sqli", 7), at("semgrep/sqli", 7), at("semgrep/sqli", 30)];
///
/// // By fingerprint, the two tools stay apart.
/// assert_eq!(dedupe(batch.clone(), &Strategy::Fingerprint, &Options::default()).len(), 3);
///
/// // By CWE at location, line 7 is one issue reported three times.
/// let groups = dedupe(batch, &Strategy::FingerprintOrCwe, &Options::default());
/// assert_eq!(groups.len(), 2);
/// assert_eq!(groups[0].count, 3);
/// assert_eq!(groups[0].fingerprints.len(), 2);
/// ```
pub fn dedupe<X, C: Correlate<X> + ?Sized>(
    findings: impl IntoIterator<Item = Finding<X>>,
    correlate: &C,
    options: &Options,
) -> Vec<Group<X>> {
    let mut groups: Vec<Option<Group<X>>> = Vec::new();
    let mut index: BTreeMap<Key, usize> = BTreeMap::new();

    for finding in findings {
        let (fingerprint, keys) = keys_of(&finding, correlate);
        let hits: BTreeSet<usize> = keys
            .iter()
            .filter_map(|key| index.get(key))
            .copied()
            .collect();
        let group = Group {
            finding,
            keys,
            fingerprints: BTreeSet::from([fingerprint]),
            count: 1,
        };

        let mut hits = hits.into_iter();
        let target = hits.next().unwrap_or_else(|| {
            groups.push(None);
            groups.len() - 1
        });

        // Fold every later group this finding links into the earliest one.
        let mut merged = groups.get_mut(target).and_then(Option::take);
        for other in hits {
            if let Some(other) = groups.get_mut(other).and_then(Option::take) {
                for key in &other.keys {
                    index.insert(key.clone(), target);
                }
                if let Some(kept) = merged.as_mut() {
                    kept.absorb(other, correlate, options);
                }
            }
        }
        let merged = match merged {
            Some(mut kept) => {
                kept.absorb(group, correlate, options);
                kept
            }
            None => group,
        };
        for key in &merged.keys {
            index.insert(key.clone(), target);
        }
        if let Some(slot) = groups.get_mut(target) {
            *slot = Some(merged);
        }
    }

    groups.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use rune_finding::{Confidence, Location, Severity, TaxonomyRef};

    use super::*;
    use crate::Strategy;

    fn at(check: &str, line: u32, cwe: Option<u32>) -> Finding {
        let finding = Finding::<()>::new(
            check,
            check,
            Severity::Medium,
            Confidence::Firm,
            Location::file("a.rs").with_lines(line, line),
        );
        match cwe {
            Some(cwe) => finding.push_taxonomy(TaxonomyRef::cwe(cwe)),
            None => finding,
        }
    }

    #[test]
    fn same_issue_merges_distinct_issues_stay_apart() {
        let groups = dedupe(
            [
                at("a", 1, None),
                at("a", 1, None),
                at("a", 2, None),
                at("b", 1, None),
            ],
            &Strategy::Fingerprint,
            &Options::default(),
        );
        let counts: Vec<_> = groups
            .iter()
            .map(|g| (g.finding.check_id.as_str(), g.count))
            .collect();
        assert_eq!(counts, [("a", 2), ("a", 1), ("b", 1)]);
    }

    #[test]
    fn transitive_links_join_earlier_groups() {
        // A (cwe 1) and B (cwe 2) are separate until C carries both CWEs.
        let mut c = at("c", 1, Some(1));
        c = c.push_taxonomy(TaxonomyRef::cwe(2));
        let groups = dedupe(
            [
                at("a", 1, Some(1)),
                at("b", 1, Some(2)),
                at("z", 9, None),
                c,
            ],
            &Strategy::FingerprintOrCwe,
            &Options::default(),
        );
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].finding.check_id, "a");
        assert_eq!(groups[0].count, 3);
        assert_eq!(groups[0].fingerprints.len(), 3);
        assert_eq!(groups[1].finding.check_id, "z");

        // Later findings that only match the absorbed group still land in
        // the survivor.
        let groups = dedupe(
            [
                at("a", 1, Some(1)),
                at("b", 1, Some(2)),
                at("c", 1, Some(1)).push_taxonomy(TaxonomyRef::cwe(2)),
                at("b", 1, Some(2)),
            ],
            &Strategy::FingerprintOrCwe,
            &Options::default(),
        );
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 4);
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            dedupe(
                Vec::<Finding>::new(),
                &Strategy::Fingerprint,
                &Options::default()
            )
            .len(),
            0
        );
    }
}
