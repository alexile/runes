//! [`Options`]: routes, CWE classes and merge settings.

use std::collections::{BTreeMap, BTreeSet};

use crate::Route;

/// CWE groups that SAST and DAST tools commonly use interchangeably for one
/// weakness. Each is one class in [`Options::default`].
pub const COMMON_CWE_CLASSES: &[&[u32]] = &[
    // Cross-site scripting.
    &[79, 80, 83, 87],
    // SQL injection.
    &[89, 564],
    // OS command injection.
    &[77, 78],
    // Path traversal.
    &[22, 23, 36],
    // Code injection.
    &[94, 95],
];

/// How findings are correlated.
///
/// # Examples
///
/// ```
/// use rune_aspm_correlate::{Options, Route};
///
/// let options = Options::default()
///     .with_route(Route::new("/users/{id}", "src/users.py")?)
///     .with_cwe_class([352, 1275]);
/// assert_eq!(options.cwe_class(1275), 352);
/// assert_eq!(options.cwe_class(80), 79, "built-in XSS class");
/// assert_eq!(options.cwe_class(918), 918, "unclassified CWEs stand alone");
/// # Ok::<(), rune_aspm_correlate::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[non_exhaustive]
pub struct Options {
    /// The application's routes, linking URLs to source files. Without
    /// routes, SAST and DAST results cannot meet.
    pub routes: Vec<Route>,
    /// CWE number to the class it belongs to (the smallest number of the
    /// class). CWEs not listed are their own class. Classes apply to route
    /// links. Default: [`COMMON_CWE_CLASSES`].
    pub cwe_classes: BTreeMap<u32, u32>,
    /// Also merge results with the same CWE at the same location, across
    /// check ids (rune-finding-dedupe's `Strategy::FingerprintOrCwe`).
    /// Default `true`.
    pub same_location_cwe: bool,
    /// Ingest SARIF results that carry an accepted suppression. Default
    /// `false`: they are counted and dropped.
    pub keep_suppressed: bool,
    /// How duplicates merge.
    pub merge: rune_finding_dedupe::Options,
}

impl Default for Options {
    fn default() -> Self {
        let options = Self {
            routes: Vec::new(),
            cwe_classes: BTreeMap::new(),
            same_location_cwe: true,
            keep_suppressed: false,
            merge: rune_finding_dedupe::Options::default(),
        };
        COMMON_CWE_CLASSES.iter().fold(options, |options, class| {
            options.with_cwe_class(class.iter().copied())
        })
    }
}

impl Options {
    /// Add a route.
    #[must_use]
    pub fn with_route(mut self, route: Route) -> Self {
        self.routes.push(route);
        self
    }

    /// Add routes.
    #[must_use]
    pub fn with_routes(mut self, routes: impl IntoIterator<Item = Route>) -> Self {
        self.routes.extend(routes);
        self
    }

    /// Treat these CWEs as one weakness for route links. A class that
    /// overlaps existing ones joins them.
    #[must_use]
    pub fn with_cwe_class(mut self, cwes: impl IntoIterator<Item = u32>) -> Self {
        let mut members: BTreeSet<u32> = cwes.into_iter().collect();
        let joined: BTreeSet<u32> = members
            .iter()
            .filter_map(|cwe| self.cwe_classes.get(cwe))
            .copied()
            .collect();
        for (cwe, class) in &self.cwe_classes {
            if joined.contains(class) {
                members.insert(*cwe);
            }
        }
        if let Some(&canonical) = members.first() {
            for cwe in members {
                self.cwe_classes.insert(cwe, canonical);
            }
        }
        self
    }

    /// Forget every CWE class, including the built-in ones.
    #[must_use]
    pub fn without_cwe_classes(mut self) -> Self {
        self.cwe_classes.clear();
        self
    }

    /// Set [`same_location_cwe`](Self::same_location_cwe).
    #[must_use]
    pub const fn with_same_location_cwe(mut self, enabled: bool) -> Self {
        self.same_location_cwe = enabled;
        self
    }

    /// Set [`keep_suppressed`](Self::keep_suppressed).
    #[must_use]
    pub const fn with_keep_suppressed(mut self, keep: bool) -> Self {
        self.keep_suppressed = keep;
        self
    }

    /// Set the [`merge`](Self::merge) options.
    #[must_use]
    pub const fn with_merge(mut self, merge: rune_finding_dedupe::Options) -> Self {
        self.merge = merge;
        self
    }

    /// The class of `cwe`: the smallest CWE of its class, or itself.
    #[must_use]
    pub fn cwe_class(&self, cwe: u32) -> u32 {
        self.cwe_classes.get(&cwe).copied().unwrap_or(cwe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_join_when_they_overlap() {
        let options = Options::default()
            .without_cwe_classes()
            .with_cwe_class([5, 7])
            .with_cwe_class([9, 8])
            .with_cwe_class([7, 9, 3])
            .with_cwe_class([]);
        for cwe in [3, 5, 7, 8, 9] {
            assert_eq!(options.cwe_class(cwe), 3);
        }
        assert_eq!(options.cwe_class(4), 4);
    }

    #[test]
    fn builders() {
        let options = Options::default()
            .with_routes([crate::Route::new("/", "a.py").unwrap()])
            .with_same_location_cwe(false)
            .with_keep_suppressed(true)
            .with_merge(rune_finding_dedupe::Options::default().with_max_evidence(1));
        assert_eq!(options.routes.len(), 1);
        assert!(!options.same_location_cwe);
        assert!(options.keep_suppressed);
        assert_eq!(options.merge.max_evidence, 1);
        assert_eq!(Options::default().cwe_class(564), 89);
        assert_eq!(Options::default().without_cwe_classes().cwe_class(564), 564);
    }
}
