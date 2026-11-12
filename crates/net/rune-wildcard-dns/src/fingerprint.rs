//! Answer fingerprints and how a candidate's answer compares to a
//! wildcard's.

use std::collections::BTreeSet;
use std::net::IpAddr;

use rune_dns_wire::{Name, RData};

use crate::Response;

/// The data a set of DNS answers resolved to: addresses and first-hop CNAME
/// targets.
///
/// For a wildcard this is the union over every probe, so a wildcard that
/// rotates through a pool of addresses (or CNAME targets) accumulates the
/// pool as more probes are made. Names are kept lowercased.
///
/// ```
/// use std::net::Ipv4Addr;
/// use rune_dns_wire::{Name, RData, Record};
/// use rune_wildcard_dns::{Fingerprint, Match, Response};
///
/// let probe: Name = "x7q2k9.example.com".parse()?;
/// let wildcard = Fingerprint::from_response(&probe, &Response::answer(vec![
///     Record::new(probe.clone(), 60, RData::A(Ipv4Addr::new(192, 0, 2, 1))),
/// ]));
///
/// let www: Name = "www.example.com".parse()?;
/// let candidate = Fingerprint::from_response(&www, &Response::answer(vec![
///     Record::new(www.clone(), 60, RData::A(Ipv4Addr::new(192, 0, 2, 1))),
/// ]));
/// assert_eq!(wildcard.compare(&candidate), Match::Covered);
/// # Ok::<(), rune_dns_wire::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    addresses: BTreeSet<IpAddr>,
    targets: BTreeSet<Name>,
}

/// How a candidate's answer relates to a wildcard's [`Fingerprint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Match {
    /// Everything the candidate resolved to is something the wildcard
    /// resolves to: the answer is (indistinguishable from) the wildcard.
    Covered,
    /// The answers overlap but the candidate has data the wildcard has not
    /// shown yet. Typical of a rotating wildcard probed too few times.
    Partial,
    /// Nothing in common, or the candidate has no data.
    Disjoint,
}

impl Fingerprint {
    /// The fingerprint of `response`, an answer for `qname`.
    ///
    /// Collects every `A` and `AAAA` address in the answer section, and the
    /// target of the `CNAME` owned by `qname` (the first hop of the chain).
    /// Owner names are compared ignoring ASCII case.
    #[must_use]
    pub fn from_response(qname: &Name, response: &Response) -> Self {
        let mut fingerprint = Self::default();
        for record in &response.answers {
            match &record.data {
                RData::A(addr) => {
                    fingerprint.addresses.insert(IpAddr::V4(*addr));
                }
                RData::Aaaa(addr) => {
                    fingerprint.addresses.insert(IpAddr::V6(*addr));
                }
                RData::Cname(target) if record.name.eq_ignore_ascii_case(qname) => {
                    fingerprint.targets.insert(target.to_ascii_lowercase());
                }
                _ => {}
            }
        }
        fingerprint
    }

    /// A fingerprint from explicit addresses and CNAME targets, for example
    /// one persisted from an earlier run.
    #[must_use]
    pub fn from_parts(
        addresses: impl IntoIterator<Item = IpAddr>,
        targets: impl IntoIterator<Item = Name>,
    ) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
            targets: targets
                .into_iter()
                .map(|t| t.to_ascii_lowercase())
                .collect(),
        }
    }

    /// The addresses seen, in order.
    pub fn addresses(&self) -> impl ExactSizeIterator<Item = &IpAddr> {
        self.addresses.iter()
    }

    /// The first-hop CNAME targets seen, lowercased, in order.
    pub fn cname_targets(&self) -> impl ExactSizeIterator<Item = &Name> {
        self.targets.iter()
    }

    /// Whether no address and no CNAME target was seen.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty() && self.targets.is_empty()
    }

    /// Adds everything in `other`. Returns whether anything was new.
    pub fn merge(&mut self, other: &Self) -> bool {
        let before = (self.addresses.len(), self.targets.len());
        self.addresses.extend(other.addresses.iter().copied());
        self.targets.extend(other.targets.iter().cloned());
        before != (self.addresses.len(), self.targets.len())
    }

    /// Compares a candidate's fingerprint against this wildcard one.
    ///
    /// - A candidate whose CNAME target the wildcard also returned is
    ///   [`Match::Covered`]: wildcard CNAMEs are compared by target, so a
    ///   CDN behind them may rotate addresses freely.
    /// - Otherwise its addresses decide: all known is [`Match::Covered`],
    ///   some is [`Match::Partial`], none is [`Match::Disjoint`].
    /// - A candidate with only an unknown CNAME target is
    ///   [`Match::Partial`] when the wildcard itself has shown more than one
    ///   target (it rotates), [`Match::Disjoint`] otherwise.
    #[must_use]
    pub fn compare(&self, candidate: &Self) -> Match {
        if !candidate.targets.is_empty() && candidate.targets.is_subset(&self.targets) {
            return Match::Covered;
        }
        if !candidate.addresses.is_empty() {
            if candidate.addresses.is_subset(&self.addresses) {
                return Match::Covered;
            }
            if !candidate.addresses.is_disjoint(&self.addresses) {
                return Match::Partial;
            }
        }
        if !candidate.targets.is_empty() && self.targets.len() > 1 {
            return Match::Partial;
        }
        Match::Disjoint
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    #[test]
    fn address_subset_overlap_and_disjoint() {
        let wildcard = Fingerprint::from_parts([v4(1), v4(2)], []);
        let covered = Fingerprint::from_parts([v4(2)], []);
        let partial = Fingerprint::from_parts([v4(2), v4(3)], []);
        let disjoint = Fingerprint::from_parts([v4(9)], []);
        assert_eq!(wildcard.compare(&covered), Match::Covered);
        assert_eq!(wildcard.compare(&partial), Match::Partial);
        assert_eq!(wildcard.compare(&disjoint), Match::Disjoint);
        assert_eq!(wildcard.compare(&Fingerprint::default()), Match::Disjoint);
    }

    #[test]
    fn cname_target_match_ignores_addresses() {
        let wildcard = Fingerprint::from_parts([v4(1)], [name("LB.cdn.example.net")]);
        let candidate = Fingerprint::from_parts([v4(77)], [name("lb.cdn.example.net")]);
        assert_eq!(wildcard.compare(&candidate), Match::Covered);
        let other = Fingerprint::from_parts([], [name("other.example.net")]);
        assert_eq!(wildcard.compare(&other), Match::Disjoint);
    }

    #[test]
    fn unknown_target_against_rotating_targets_is_partial() {
        let wildcard = Fingerprint::from_parts([], [name("a.cdn.test"), name("b.cdn.test")]);
        let candidate = Fingerprint::from_parts([], [name("c.cdn.test")]);
        assert_eq!(wildcard.compare(&candidate), Match::Partial);
    }

    #[test]
    fn from_response_takes_first_hop_only() {
        let q = name("Foo.example.com");
        let response = Response::answer(vec![
            rune_dns_wire::Record::new(name("foo.EXAMPLE.com"), 60, RData::Cname(name("a.test"))),
            rune_dns_wire::Record::new(name("a.test"), 60, RData::Cname(name("b.test"))),
            rune_dns_wire::Record::new(name("b.test"), 60, RData::A(Ipv4Addr::new(192, 0, 2, 5))),
        ]);
        let fp = Fingerprint::from_response(&q, &response);
        assert_eq!(fp.cname_targets().collect::<Vec<_>>(), [&name("a.test")]);
        assert_eq!(fp.addresses().collect::<Vec<_>>(), [&v4(5)]);
    }

    #[test]
    fn merge_reports_growth() {
        let mut fp = Fingerprint::from_parts([v4(1)], []);
        assert!(!fp.merge(&Fingerprint::from_parts([v4(1)], [])));
        assert!(fp.merge(&Fingerprint::from_parts([v4(2)], [])));
        assert_eq!(fp.addresses().len(), 2);
    }
}
