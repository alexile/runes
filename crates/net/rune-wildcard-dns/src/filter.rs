//! Wildcard detection by random-label probing, and the per-name filter.

use std::collections::HashMap;
use std::fmt;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rune_dns_wire::{Name, Rcode, RecordType};

use crate::resolver::{Blocking, block_on};
use crate::{AsyncResolver, Error, Fingerprint, Match, Resolver, Response};

/// Characters a probe label is drawn from. The first one is always a
/// letter.
const LABEL_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const LETTERS: usize = 26;

/// Tuning for [`WildcardFilter`].
///
/// ```
/// use rune_wildcard_dns::Options;
///
/// let options = Options::default().with_probes(4).with_max_probes(16).with_seed(7);
/// assert_eq!(options.probes, 4);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Random labels probed when a level is first learned (at least 1).
    /// Default 3.
    pub probes: usize,
    /// Upper bound on probes per level, including the extra ones made when
    /// a wildcard keeps showing new addresses (rotation) or a candidate
    /// partly overlaps it. Default 12.
    pub max_probes: usize,
    /// Record types queried for every probe and candidate. Default `A` and
    /// `AAAA`. CNAMEs are seen through the chain in either answer.
    pub record_types: Vec<RecordType>,
    /// Length of the random probe labels, clamped to 1..=63. Default 16.
    pub label_len: usize,
    /// How many levels below the domain [`WildcardFilter::detect`] probes:
    /// 1 probes `<r>.domain`, 2 also `<r>.<r>.domain`, and so on. Default 2.
    pub depth: usize,
    /// Never probe under a public suffix (by the embedded Public Suffix
    /// List): a candidate such as `example.co.uk` is judged genuine without
    /// probing `co.uk`. Default `true`.
    pub skip_public_suffixes: bool,
    /// Seed for the probe-label generator, for reproducible runs. `None`
    /// (the default) seeds from the operating system.
    pub seed: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            probes: 3,
            max_probes: 12,
            record_types: vec![RecordType::A, RecordType::AAAA],
            label_len: 16,
            depth: 2,
            skip_public_suffixes: true,
            seed: None,
        }
    }
}

impl Options {
    /// Sets [`Options::probes`].
    #[must_use]
    pub const fn with_probes(mut self, probes: usize) -> Self {
        self.probes = probes;
        self
    }

    /// Sets [`Options::max_probes`].
    #[must_use]
    pub const fn with_max_probes(mut self, max_probes: usize) -> Self {
        self.max_probes = max_probes;
        self
    }

    /// Sets [`Options::record_types`].
    #[must_use]
    pub fn with_record_types(mut self, types: impl IntoIterator<Item = RecordType>) -> Self {
        self.record_types = types.into_iter().collect();
        self
    }

    /// Sets [`Options::label_len`].
    #[must_use]
    pub const fn with_label_len(mut self, len: usize) -> Self {
        self.label_len = len;
        self
    }

    /// Sets [`Options::depth`].
    #[must_use]
    pub const fn with_depth(mut self, depth: usize) -> Self {
        self.depth = depth;
        self
    }

    /// Sets [`Options::skip_public_suffixes`].
    #[must_use]
    pub const fn with_skip_public_suffixes(mut self, skip: bool) -> Self {
        self.skip_public_suffixes = skip;
        self
    }

    /// Sets [`Options::seed`].
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    fn initial_probes(&self) -> usize {
        self.probes.max(1)
    }

    fn probe_budget(&self) -> usize {
        self.max_probes.max(self.initial_probes())
    }
}

/// What probing a parent name found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Level {
    /// Random children do not resolve: no wildcard here.
    Clean,
    /// Random children resolve, to this data.
    Wildcard(Fingerprint),
}

impl Level {
    /// The wildcard's fingerprint, if this level has one.
    #[must_use]
    pub const fn fingerprint(&self) -> Option<&Fingerprint> {
        match self {
            Self::Clean => None,
            Self::Wildcard(fingerprint) => Some(fingerprint),
        }
    }

    /// Whether this level has a wildcard.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard(_))
    }
}

/// The filter's judgement on one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verdict {
    /// The name resolves to something its parent's wildcard does not:
    /// report it.
    Genuine,
    /// The name's answer is (indistinguishable from) its parent's
    /// wildcard: drop it.
    Wildcard,
    /// The name has no data (`NXDOMAIN`, `NODATA` or a failure): nothing to
    /// report either way.
    Unresolved,
}

impl Verdict {
    /// Whether the answer is the wildcard's.
    #[must_use]
    pub const fn is_wildcard(self) -> bool {
        matches!(self, Self::Wildcard)
    }

    /// Whether the name should be reported as live.
    #[must_use]
    pub const fn is_genuine(self) -> bool {
        matches!(self, Self::Genuine)
    }
}

/// One level probed by [`WildcardFilter::detect`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LevelReport {
    /// How many labels below the domain the probes were: 1 for
    /// `<r>.domain`, 2 for `<r>.<r>.domain`.
    pub depth: usize,
    /// The parent whose random children were probed.
    pub parent: Name,
    /// What the probes found.
    pub level: Level,
}

/// The result of [`WildcardFilter::detect`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The domain, in ASCII (A-label) form.
    pub domain: Name,
    /// One entry per depth, shallowest first.
    pub levels: Vec<LevelReport>,
}

impl Report {
    /// Whether any probed depth has a wildcard.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.levels.iter().any(|l| l.level.is_wildcard())
    }

    /// The wildcard fingerprint directly under the domain (`*.domain`), if
    /// any.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        self.levels
            .iter()
            .find(|l| l.depth == 1)
            .and_then(|l| l.level.fingerprint())
    }
}

/// Probe bookkeeping for one parent name.
#[derive(Debug, Clone, Default)]
struct Probing {
    fingerprint: Fingerprint,
    probes: usize,
    answered: bool,
    negative: bool,
}

impl Probing {
    fn level(&self, parent: &Name) -> Result<Level, Error> {
        if self.answered {
            Ok(Level::Wildcard(self.fingerprint.clone()))
        } else if self.negative {
            Ok(Level::Clean)
        } else {
            Err(Error::Inconclusive {
                level: parent.clone(),
            })
        }
    }
}

/// Detects wildcard DNS by probing random labels, and filters answers that
/// are just the wildcard.
///
/// The filter caches what it learns per parent name, so filtering many
/// candidates under the same parent costs one round of probes. To judge
/// `a.b.example.com` it probes random siblings, `<r>.b.example.com`: by
/// DNS wildcard rules (RFC 4592) such a sibling is answered by exactly the
/// wildcard that would answer the candidate, whether that is `*.b.example.com`
/// or, when `b.example.com` does not exist, `*.example.com`. That makes
/// multi-level wildcards come out right.
///
/// Rotating wildcards (a pool of addresses, a few per answer) are handled
/// twice over: learning keeps probing while probes still show new data, up
/// to [`Options::max_probes`], and a candidate that only partly overlaps the
/// wildcard triggers more probes before it is judged.
///
/// A host that really exists but answers exactly what the wildcard answers
/// cannot be told apart from it, and is filtered as [`Verdict::Wildcard`].
///
/// Each method comes in a blocking form over a [`Resolver`] and an `_async`
/// form over an [`AsyncResolver`].
pub struct WildcardFilter {
    options: Options,
    levels: HashMap<Name, Probing>,
    rng: StdRng,
}

impl fmt::Debug for WildcardFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WildcardFilter")
            .field("options", &self.options)
            .field("levels", &self.levels.len())
            .finish_non_exhaustive()
    }
}

impl Default for WildcardFilter {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

impl WildcardFilter {
    /// A filter with the given options and an empty cache.
    #[must_use]
    pub fn new(options: Options) -> Self {
        let rng = options
            .seed
            .map_or_else(|| StdRng::from_rng(&mut rand::rng()), StdRng::seed_from_u64);
        Self {
            options,
            levels: HashMap::new(),
            rng,
        }
    }

    /// The options in use.
    #[must_use]
    pub const fn options(&self) -> &Options {
        &self.options
    }

    /// What is known about `parent`, if it has been probed (or seeded with
    /// [`WildcardFilter::insert_level`]).
    #[must_use]
    pub fn level(&self, parent: &Name) -> Option<Level> {
        let key = parent.to_ascii_lowercase();
        self.levels.get(&key).and_then(|p| p.level(&key).ok())
    }

    /// Records what is known about `parent` without probing, for example
    /// from an earlier run. A seeded wildcard still grows if candidates
    /// partly overlap it.
    pub fn insert_level(&mut self, parent: &Name, level: Level) {
        let probing = match level {
            Level::Clean => Probing {
                probes: self.options.initial_probes(),
                negative: true,
                ..Probing::default()
            },
            Level::Wildcard(fingerprint) => Probing {
                fingerprint,
                probes: self.options.initial_probes(),
                answered: true,
                negative: false,
            },
        };
        self.levels.insert(parent.to_ascii_lowercase(), probing);
    }

    /// Forgets everything learned.
    pub fn clear(&mut self) {
        self.levels.clear();
    }

    /// A fresh random name directly under `parent`.
    ///
    /// # Errors
    ///
    /// [`Error::Name`] if the result would exceed 255 octets.
    pub fn probe_name(&mut self, parent: &Name) -> Result<Name, Error> {
        let label = self.random_label();
        let name = Name::from_labels(core::iter::once(&label[..]).chain(parent.labels()))?;
        Ok(name)
    }

    /// The sans-I/O predicate: judges `name`'s `response` from the cache
    /// alone. `None` when the parent has not been probed yet, so the answer
    /// needs [`WildcardFilter::classify`].
    #[must_use]
    pub fn cached_verdict(&self, name: &Name, response: &Response) -> Option<Verdict> {
        let candidate = Fingerprint::from_response(name, response);
        if candidate.is_empty() {
            return Some(Verdict::Unresolved);
        }
        let Some(parent) = self.probe_parent(name) else {
            return Some(Verdict::Genuine);
        };
        let level = self.levels.get(&parent)?.level(&parent).ok()?;
        Some(match level {
            Level::Clean => Verdict::Genuine,
            Level::Wildcard(fingerprint) => match fingerprint.compare(&candidate) {
                Match::Covered => Verdict::Wildcard,
                Match::Partial | Match::Disjoint => Verdict::Genuine,
            },
        })
    }

    // ----- blocking API -----

    /// Probes `domain` (text, Unicode allowed) at each depth up to
    /// [`Options::depth`] and reports which have wildcards. The depth-1
    /// result is cached for later filtering.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidDomain`], [`Error::Resolver`], or
    /// [`Error::Inconclusive`] when every probe at some depth failed.
    pub fn detect<R: Resolver>(&mut self, resolver: &mut R, domain: &str) -> Result<Report, Error> {
        block_on(self.detect_async(&mut Blocking(resolver), domain))
    }

    /// Learns whether `parent` has a wildcard (probing only if not cached).
    ///
    /// # Errors
    ///
    /// [`Error::Resolver`], [`Error::Inconclusive`], [`Error::Name`].
    pub fn learn<R: Resolver>(&mut self, resolver: &mut R, parent: &Name) -> Result<Level, Error> {
        block_on(self.learn_async(&mut Blocking(resolver), parent))
    }

    /// Resolves `name` with [`Options::record_types`] and judges it.
    ///
    /// # Errors
    ///
    /// As [`WildcardFilter::classify`].
    pub fn check<R: Resolver>(&mut self, resolver: &mut R, name: &Name) -> Result<Verdict, Error> {
        block_on(self.check_async(&mut Blocking(resolver), name))
    }

    /// Judges `name` given the `response` already obtained for it, probing
    /// its parent if needed.
    ///
    /// # Errors
    ///
    /// [`Error::Resolver`], [`Error::Inconclusive`], [`Error::Name`].
    pub fn classify<R: Resolver>(
        &mut self,
        resolver: &mut R,
        name: &Name,
        response: &Response,
    ) -> Result<Verdict, Error> {
        block_on(self.classify_async(&mut Blocking(resolver), name, response))
    }

    // ----- async API -----

    /// Async form of [`WildcardFilter::detect`].
    ///
    /// # Errors
    ///
    /// As [`WildcardFilter::detect`].
    pub async fn detect_async<R: AsyncResolver>(
        &mut self,
        resolver: &mut R,
        domain: &str,
    ) -> Result<Report, Error> {
        let domain = parse_domain(domain)?;
        let mut levels = Vec::new();
        let mut parent = domain.clone();
        for depth in 1..=self.options.depth.max(1) {
            let level = if depth == 1 {
                self.learn_async(resolver, &parent).await?
            } else {
                // A random parent: learnt but not cached, it is never seen
                // again.
                let probing = self
                    .probe_level(resolver, &parent, Probing::default())
                    .await?;
                probing.level(&parent)?
            };
            levels.push(LevelReport {
                depth,
                parent: parent.clone(),
                level,
            });
            parent = self.probe_name(&parent)?;
        }
        Ok(Report { domain, levels })
    }

    /// Async form of [`WildcardFilter::learn`].
    ///
    /// # Errors
    ///
    /// As [`WildcardFilter::learn`].
    pub async fn learn_async<R: AsyncResolver>(
        &mut self,
        resolver: &mut R,
        parent: &Name,
    ) -> Result<Level, Error> {
        let key = parent.to_ascii_lowercase();
        if let Some(probing) = self.levels.get(&key) {
            return probing.level(&key);
        }
        let probing = self.probe_level(resolver, &key, Probing::default()).await?;
        let level = probing.level(&key)?;
        self.levels.insert(key, probing);
        Ok(level)
    }

    /// Async form of [`WildcardFilter::check`].
    ///
    /// # Errors
    ///
    /// As [`WildcardFilter::check`].
    pub async fn check_async<R: AsyncResolver>(
        &mut self,
        resolver: &mut R,
        name: &Name,
    ) -> Result<Verdict, Error> {
        let response = self.resolve_all(resolver, name).await?;
        self.classify_async(resolver, name, &response).await
    }

    /// Async form of [`WildcardFilter::classify`].
    ///
    /// # Errors
    ///
    /// As [`WildcardFilter::classify`].
    pub async fn classify_async<R: AsyncResolver>(
        &mut self,
        resolver: &mut R,
        name: &Name,
        response: &Response,
    ) -> Result<Verdict, Error> {
        let candidate = Fingerprint::from_response(name, response);
        if candidate.is_empty() {
            return Ok(Verdict::Unresolved);
        }
        let Some(parent) = self.probe_parent(name) else {
            return Ok(Verdict::Genuine);
        };
        let Level::Wildcard(fingerprint) = self.learn_async(resolver, &parent).await? else {
            return Ok(Verdict::Genuine);
        };
        match fingerprint.compare(&candidate) {
            Match::Covered => return Ok(Verdict::Wildcard),
            Match::Disjoint => return Ok(Verdict::Genuine),
            Match::Partial => {}
        }

        // Partial overlap: the wildcard may rotate through more data than
        // probed so far. Probe on until the candidate is covered or the
        // budget runs out.
        let mut probing = self.levels.remove(&parent).unwrap_or_default();
        let mut covered = false;
        while probing.probes < self.options.probe_budget() {
            match self.probe_once(resolver, &parent, &mut probing).await {
                Ok(_) => {}
                Err(error) => {
                    self.levels.insert(parent.clone(), probing);
                    return Err(error);
                }
            }
            if probing.fingerprint.compare(&candidate) == Match::Covered {
                covered = true;
                break;
            }
        }
        self.levels.insert(parent, probing);
        Ok(if covered {
            Verdict::Wildcard
        } else {
            Verdict::Genuine
        })
    }

    // ----- internals -----

    /// The lowercased parent to probe for `name`, or `None` when there is
    /// nothing to probe (the root, a TLD, or a public suffix).
    fn probe_parent(&self, name: &Name) -> Option<Name> {
        let parent = name.parent()?.to_ascii_lowercase();
        if parent.is_root() {
            return None;
        }
        if self.options.skip_public_suffixes && rune_psl::is_public_suffix(&parent.to_string()) {
            return None;
        }
        Some(parent)
    }

    /// Runs the initial probes for `parent`, then keeps going while a
    /// wildcard still shows new data.
    async fn probe_level<R: AsyncResolver>(
        &mut self,
        resolver: &mut R,
        parent: &Name,
        mut probing: Probing,
    ) -> Result<Probing, Error> {
        let mut grew = false;
        while probing.probes < self.options.initial_probes() {
            grew = self.probe_once(resolver, parent, &mut probing).await?;
        }
        while probing.answered && grew && probing.probes < self.options.probe_budget() {
            grew = self.probe_once(resolver, parent, &mut probing).await?;
        }
        Ok(probing)
    }

    /// One random child of `parent`, queried for every record type. Returns
    /// whether the fingerprint grew.
    async fn probe_once<R: AsyncResolver>(
        &mut self,
        resolver: &mut R,
        parent: &Name,
        probing: &mut Probing,
    ) -> Result<bool, Error> {
        let name = self.probe_name(parent)?;
        let response = self.resolve_all(resolver, &name).await?;
        probing.probes += 1;
        if !response.is_answer() {
            return Ok(false);
        }
        let fingerprint = Fingerprint::from_response(&name, &response);
        if response.rcode == Rcode::NOERROR && !fingerprint.is_empty() {
            probing.answered = true;
            Ok(probing.fingerprint.merge(&fingerprint))
        } else {
            probing.negative = true;
            Ok(false)
        }
    }

    /// Resolves `name` for every configured record type and merges the
    /// answers.
    async fn resolve_all<R: AsyncResolver>(
        &self,
        resolver: &mut R,
        name: &Name,
    ) -> Result<Response, Error> {
        let mut merged: Option<Response> = None;
        for &rtype in &self.options.record_types {
            let response =
                resolver
                    .resolve(name, rtype)
                    .await
                    .map_err(|source| Error::Resolver {
                        name: name.clone(),
                        rtype,
                        source: Box::new(source),
                    })?;
            match &mut merged {
                Some(merged) => merged.merge(response),
                None => merged = Some(response),
            }
        }
        // No record types configured: nothing resolves.
        Ok(merged.unwrap_or_else(Response::nxdomain))
    }

    fn random_label(&mut self) -> Vec<u8> {
        let len = self
            .options
            .label_len
            .clamp(1, rune_dns_wire::MAX_LABEL_LEN);
        let mut label = Vec::with_capacity(len);
        for i in 0..len {
            let bound = if i == 0 {
                LETTERS
            } else {
                LABEL_ALPHABET.len()
            };
            let index = self.rng.random_range(0..bound);
            label.push(LABEL_ALPHABET.get(index).copied().unwrap_or(b'x'));
        }
        label
    }
}

/// Parses a domain given as text, Unicode or ASCII, into its lowercased
/// A-label [`Name`].
///
/// # Errors
///
/// [`Error::InvalidDomain`] if IDNA processing rejects it, [`Error::Name`]
/// if the result is not a valid DNS name.
///
/// ```
/// let name = rune_wildcard_dns::parse_domain("Bücher.Example")?;
/// assert_eq!(name.to_string(), "xn--bcher-kva.example");
/// # Ok::<(), rune_wildcard_dns::Error>(())
/// ```
pub fn parse_domain(domain: &str) -> Result<Name, Error> {
    let ascii = rune_idna::to_ascii(domain, &rune_idna::Options::default()).map_err(|source| {
        Error::InvalidDomain {
            domain: domain.to_owned(),
            source,
        }
    })?;
    Ok(Name::from_ascii(&ascii)?.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_names_are_fresh_and_well_formed() {
        let mut filter = WildcardFilter::new(Options::default().with_seed(1).with_label_len(10));
        let parent: Name = "example.com".parse().unwrap();
        let a = filter.probe_name(&parent).unwrap();
        let b = filter.probe_name(&parent).unwrap();
        assert_ne!(a, b);
        assert!(a.is_subdomain_of(&parent));
        let label = a.labels().next().unwrap();
        assert_eq!(label.len(), 10);
        assert!(label[0].is_ascii_lowercase());
        assert!(
            label
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn seeded_filters_agree() {
        let parent: Name = "example.com".parse().unwrap();
        let mut a = WildcardFilter::new(Options::default().with_seed(42));
        let mut b = WildcardFilter::new(Options::default().with_seed(42));
        assert_eq!(
            a.probe_name(&parent).unwrap(),
            b.probe_name(&parent).unwrap()
        );
    }

    #[test]
    fn label_len_is_clamped() {
        let parent: Name = "example.com".parse().unwrap();
        let mut filter = WildcardFilter::new(Options::default().with_label_len(500));
        let name = filter.probe_name(&parent).unwrap();
        assert_eq!(name.labels().next().unwrap().len(), 63);
        let mut filter = WildcardFilter::new(Options::default().with_label_len(0));
        let name = filter.probe_name(&parent).unwrap();
        assert_eq!(name.labels().next().unwrap().len(), 1);
    }

    #[test]
    fn public_suffix_parents_are_skipped() {
        let filter = WildcardFilter::default();
        let name: Name = "example.co.uk".parse().unwrap();
        assert_eq!(filter.probe_parent(&name), None);
        let name: Name = "www.Example.co.uk".parse().unwrap();
        assert_eq!(
            filter.probe_parent(&name),
            Some("example.co.uk".parse().unwrap())
        );
        let filter = WildcardFilter::new(Options::default().with_skip_public_suffixes(false));
        let name: Name = "example.co.uk".parse().unwrap();
        assert_eq!(filter.probe_parent(&name), Some("co.uk".parse().unwrap()));
    }

    #[test]
    fn invalid_domain_is_rejected() {
        assert!(matches!(
            parse_domain("exa mple.com"),
            Err(Error::InvalidDomain { .. })
        ));
    }
}
