//! [`Correlator`]: the [`Correlate`] implementation for correlated
//! findings, and route [`Link`]s.

use std::collections::BTreeSet;

use rune_finding::{Finding, TaxonomyRef};
use rune_finding_dedupe::{Correlate, Key, Strategy};
use sha2::{Digest, Sha256};

use crate::{Kind, Options, Provenance, Source};

/// Domain-separation prefix of SARIF partial-fingerprint keys, version 1.
const PARTIAL_PREFIX_V1: &[u8] = b"rune-aspm-correlate/sarif-partial/v1";

/// A SAST and a DAST report of one weakness meeting on one route: the
/// reason a correlated finding is [confirmed](crate::Corroboration::Confirmed).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Link {
    /// The [route name](crate::Route::name).
    pub route: String,
    /// The CWE class both reports share
    /// ([`Options::cwe_class`]).
    pub cwe: u32,
}

impl Link {
    /// Scheme of route-link keys.
    pub const SCHEME: &'static str = "route";

    /// The correlation key of the link: `route:<name>#CWE-<class>`.
    #[must_use]
    pub fn key(&self) -> Key {
        Key::new(Self::SCHEME, format!("{}#CWE-{}", self.route, self.cwe))
    }
}

/// The [`Correlate`] implementation for `Finding<Provenance>`, configured
/// by [`Options`].
///
/// Use it with rune-finding-dedupe's `dedupe` or `Tracker` directly, e.g.
/// to track the issues of [`Report::findings`](crate::Report::findings)
/// across runs. For each [`Source`] of a finding the keys are:
///
/// - its fingerprint, so a merged issue is found again by any report in it;
/// - its SARIF `partialFingerprints` (other than rune-sarif's own copy of
///   the fingerprint), scoped by tool and check id, so a result whose line
///   moved but whose tool-computed fingerprint did not stays one issue;
/// - with [`Options::same_location_cwe`], the same CWE at the same
///   location;
///
/// plus one key per route [`Link`] when the finding already holds both a
/// SAST and a DAST source of it. Links are made by
/// [`correlate`](crate::correlate), not by sharing keys, because two SAST
/// results on one route are not one issue unless a DAST result ties them.
///
/// Merging unions the [`Provenance`].
#[derive(Debug, Clone, Copy)]
pub struct Correlator<'a> {
    options: &'a Options,
}

impl<'a> Correlator<'a> {
    /// A correlator with `options`.
    #[must_use]
    pub const fn new(options: &'a Options) -> Self {
        Self { options }
    }

    /// The options.
    #[must_use]
    pub const fn options(&self) -> &'a Options {
        self.options
    }

    /// The route links `source` could take part in: each route its
    /// location (for SAST also a flow location) is on, with each CWE class
    /// of the source. Only SAST and DAST sources have any.
    #[must_use]
    pub fn candidates(&self, source: &Source) -> BTreeSet<Link> {
        let mut out = BTreeSet::new();
        if source.cwes.is_empty() {
            return out;
        }
        for route in &self.options.routes {
            let on_route = match source.kind {
                Kind::Sast => source.locations().any(|loc| route.matches_location(loc)),
                Kind::Dast => route.matches_location(&source.location),
                _ => false,
            };
            if on_route {
                for &cwe in &source.cwes {
                    out.insert(Link {
                        route: route.name().to_owned(),
                        cwe: self.options.cwe_class(cwe),
                    });
                }
            }
        }
        out
    }

    /// The links `provenance` holds: candidates of one of its SAST sources
    /// that are also candidates of one of its DAST sources.
    #[must_use]
    pub fn links(&self, provenance: &Provenance) -> BTreeSet<Link> {
        let of_kind = |kind: Kind| -> BTreeSet<Link> {
            provenance
                .sources
                .iter()
                .filter(|source| source.kind == kind)
                .flat_map(|source| self.candidates(source))
                .collect()
        };
        let dast = of_kind(Kind::Dast);
        if dast.is_empty() {
            return BTreeSet::new();
        }
        of_kind(Kind::Sast).intersection(&dast).cloned().collect()
    }
}

impl Correlate<Provenance> for Correlator<'_> {
    fn keys(&self, finding: &Finding<Provenance>) -> Vec<Key> {
        let mut keys = Vec::new();
        for source in &finding.ext.sources {
            keys.push(Key::fingerprint(&source.fingerprint));
            for (name, value) in &source.partial_fingerprints {
                if name != rune_sarif::keys::FINGERPRINT {
                    keys.push(partial_key(source, name, value));
                }
            }
            if self.options.same_location_cwe && !source.cwes.is_empty() {
                let probe = Finding::<()>::new(
                    source.check_id.as_str(),
                    "",
                    source.severity,
                    source.confidence,
                    source.location.clone(),
                )
                .with_taxonomy(
                    source
                        .cwes
                        .iter()
                        .map(|&cwe| TaxonomyRef::cwe(cwe))
                        .collect(),
                );
                keys.extend(Strategy::FingerprintOrCwe.keys(&probe));
            }
        }
        keys.extend(self.links(&finding.ext).iter().map(Link::key));
        keys
    }

    fn merge_ext(&self, into: &mut Provenance, from: Provenance) {
        into.absorb(from);
    }
}

/// `sarif:` + lowercase hex SHA-256 of
/// `"rune-aspm-correlate/sarif-partial/v1" US tool US check_id US name US value`.
fn partial_key(source: &Source, name: &str, value: &str) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(PARTIAL_PREFIX_V1);
    for part in [&source.tool, &source.check_id, name, value] {
        hasher.update([0x1F]);
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0F)]));
    }
    Key::new("sarif", hex)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rune_finding::{Confidence, Location, Severity};

    use super::*;
    use crate::Route;

    fn source(tool: &str, location: Location, cwe: u32) -> Source {
        let finding = Finding::<()>::new("c", "t", Severity::High, Confidence::Firm, location)
            .push_taxonomy(TaxonomyRef::cwe(cwe));
        Source::of(tool, &finding)
    }

    fn options() -> Options {
        Options::default().with_route(
            Route::new("/users/{id}", "src/users.py")
                .unwrap()
                .with_name("users"),
        )
    }

    #[test]
    fn candidates_by_kind_and_class() {
        let options = options();
        let c = Correlator::new(&options);
        let dast = source("dast-scanner", Location::url("https://a.test/users/1"), 564);
        assert_eq!(
            c.candidates(&dast).into_iter().collect::<Vec<_>>(),
            [Link {
                route: "users".into(),
                cwe: 89
            }]
        );
        // A SAST sink elsewhere, reached from the handler.
        let sast = source("semgrep", Location::file("src/db.py"), 89);
        assert!(c.candidates(&sast).is_empty());
        let sast = sast.with_flow(vec![Location::file("src/users.py")]);
        assert_eq!(c.candidates(&sast).len(), 1);
        // No CWE, or a kind that does not link: nothing.
        let mut plain = dast.clone();
        plain.cwes.clear();
        assert!(c.candidates(&plain).is_empty());
        assert!(c.candidates(&dast.clone().with_kind(Kind::Sca)).is_empty());

        let mut both = Provenance::new(dast);
        assert!(c.links(&both).is_empty());
        both.absorb(Provenance::new(sast));
        assert_eq!(c.links(&both).len(), 1);
    }

    #[test]
    fn keys_cover_every_source() {
        let options = options();
        let c = Correlator::new(&options);
        let sast = source(
            "semgrep",
            Location::file("src/users.py").with_lines(3, 3),
            89,
        )
        .with_partial_fingerprints(BTreeMap::from([
            ("primaryLocationLineHash".to_owned(), "abc:1".to_owned()),
            (rune_sarif::keys::FINGERPRINT.to_owned(), "x".to_owned()),
        ]));
        let finding = Finding::<()>::new(
            "c",
            "t",
            Severity::High,
            Confidence::Firm,
            sast.location.clone(),
        )
        .with_ext(Provenance::new(sast.clone()));
        let keys = c.keys(&finding);
        let schemes: Vec<_> = keys.iter().map(Key::scheme).collect();
        assert_eq!(schemes, ["fp", "sarif", "cwe"]);

        let mut other_tool = sast;
        other_tool.tool = "codeql".into();
        let other = finding.clone().with_ext(Provenance::new(other_tool));
        assert_ne!(c.keys(&other)[1], keys[1], "partial keys are per tool");

        let no_cwe = options.clone().with_same_location_cwe(false);
        assert_eq!(Correlator::new(&no_cwe).keys(&finding).len(), 2);
        assert_eq!(Correlator::new(&no_cwe).options().routes.len(), 1);

        let mut ext = finding.ext.clone();
        ext.absorb(Provenance::new(source(
            "dast-scanner",
            Location::url("https://a.test/users/2"),
            89,
        )));
        let linked = finding.with_ext(ext);
        let keys = c.keys(&linked);
        assert!(keys.contains(&Key::new("route", "users#CWE-89")));
    }
}
