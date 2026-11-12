//! The generator: seeds × patterns × payloads, plus number mutation.

use std::collections::{HashSet, VecDeque};

use rune_dns_wire::Name;

use crate::pattern::Token;
use crate::{DEFAULT_PATTERNS, Error, Pattern, Payloads, Seed};

/// Longest host name in text form (RFC 1035 §2.3.4, without the root dot).
const MAX_HOST_LEN: usize = 253;
/// Longest label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Generation settings.
///
/// ```
/// use rune_subdomain_permute::Options;
///
/// let options = Options::default().with_limit(10_000).with_enrich(true).with_number_delta(3);
/// assert_eq!(options.limit, Some(10_000));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Stop after this many candidates. `None` (the default) is unbounded.
    pub limit: Option<usize>,
    /// Number mutation: a label with a number in it (`api2`, `db-07`) also
    /// yields that number ± 1 … ± `number_delta`, keeping zero padding.
    /// `0` turns it off. Default 1.
    pub number_delta: u32,
    /// Add tokens seen in the seeds (whole labels and their `-`-separated
    /// parts, without trailing digits) to the `word` payload, after its
    /// own values. Default `false`.
    pub enrich: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            limit: None,
            number_delta: 1,
            enrich: false,
        }
    }
}

impl Options {
    /// Sets [`Options::limit`].
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Sets [`Options::number_delta`].
    #[must_use]
    pub const fn with_number_delta(mut self, delta: u32) -> Self {
        self.number_delta = delta;
        self
    }

    /// Sets [`Options::enrich`].
    #[must_use]
    pub const fn with_enrich(mut self, enrich: bool) -> Self {
        self.enrich = enrich;
        self
    }
}

/// A configured permutation generator.
///
/// Output is a deterministic function of the seeds, patterns, payloads and
/// options: seeds in the order given (duplicates dropped), then for each
/// seed every pattern in order, each expanded over its payload values
/// (last variable fastest), then that seed's number mutations. Candidates
/// are lowercase, valid host names (LDH labels of 1–63 octets, at most 253
/// octets), never one of the seeds, and never repeated.
///
/// ```
/// use rune_subdomain_permute::{Options, Payloads, Permutator, Seed};
///
/// let mut payloads = Payloads::new();
/// payloads.insert("word", ["dev", "prod"])?;
/// let permutator = Permutator::new(
///     ["{{word}}-{{sub}}.{{suffix}}", "{{sub}}{{number}}.{{suffix}}"],
///     payloads,
///     Options::default(),
/// )?;
/// let seeds = [Seed::parse("api.example.com")?, Seed::parse("db2.example.com")?];
/// let names: Vec<String> = permutator.permute(&seeds).collect();
/// assert_eq!(names, [
///     "dev-api.example.com", "prod-api.example.com",
///     "dev-db2.example.com", "prod-db2.example.com",
///     "db1.example.com", "db3.example.com", // number mutation
/// ]);
/// # Ok::<(), rune_subdomain_permute::Error>(())
/// ```
///
/// `{{sub}}{{number}}` yields nothing here because these payloads have no
/// `number` list; `db1` and `db3` come from number mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permutator {
    patterns: Vec<Pattern>,
    payloads: Payloads,
    options: Options,
}

impl Default for Permutator {
    /// [`DEFAULT_PATTERNS`] over [`Payloads::builtin`].
    fn default() -> Self {
        let patterns = DEFAULT_PATTERNS
            .iter()
            .filter_map(|p| Pattern::parse(p).ok())
            .collect();
        Self {
            patterns,
            payloads: Payloads::builtin(),
            options: Options::default(),
        }
    }
}

impl Permutator {
    /// A generator over `patterns` and `payloads`.
    ///
    /// A pattern variable that is neither built in nor a payload is an
    /// error, except for the conventional names `word`, `number`, `region`
    /// and `env`, which may be left without a list (the pattern then
    /// produces nothing), so the default patterns work with partial
    /// payloads.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPattern`] for a malformed pattern,
    /// [`Error::UnknownVariable`] for an unknown variable.
    pub fn new<I, P>(patterns: I, payloads: Payloads, options: Options) -> Result<Self, Error>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let patterns = patterns
            .into_iter()
            .map(|p| Pattern::parse(p.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        for pattern in &patterns {
            for var in pattern.payload_vars() {
                let conventional = matches!(var, "word" | "number" | "region" | "env");
                if !conventional && payloads.get(var).is_none() {
                    return Err(Error::UnknownVariable {
                        pattern: pattern.as_str().to_owned(),
                        name: var.to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            patterns,
            payloads,
            options,
        })
    }

    /// [`DEFAULT_PATTERNS`] over [`Payloads::builtin`] with `options`.
    #[must_use]
    pub fn with_options(options: Options) -> Self {
        Self {
            options,
            ..Self::default()
        }
    }

    /// The patterns, in order.
    #[must_use]
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// The payloads.
    #[must_use]
    pub const fn payloads(&self) -> &Payloads {
        &self.payloads
    }

    /// The options.
    #[must_use]
    pub const fn options(&self) -> &Options {
        &self.options
    }

    /// Generates candidates for `seeds`, lazily.
    #[must_use]
    pub fn permute<'s>(&self, seeds: impl IntoIterator<Item = &'s Seed>) -> Permutations<'_> {
        let mut seen = HashSet::new();
        let seeds: Vec<Seed> = seeds
            .into_iter()
            .filter(|s| seen.insert(s.name().to_owned()))
            .cloned()
            .collect();
        let payloads = if self.options.enrich {
            enrich(&self.payloads, &seeds)
        } else {
            self.payloads.clone()
        };
        Permutations {
            permutator: self,
            payloads,
            seeds,
            seed: 0,
            pattern: 0,
            odometer: None,
            numbers: None,
            seen,
            emitted: 0,
        }
    }

    /// An upper bound on how many candidates [`Permutator::permute`] yields
    /// for `seeds`, before deduplication and validity filtering and
    /// ignoring [`Options::limit`]. Saturates at `u64::MAX`.
    #[must_use]
    pub fn estimate<'s>(&self, seeds: impl IntoIterator<Item = &'s Seed>) -> u64 {
        let seeds: Vec<&Seed> = seeds.into_iter().collect();
        let owned: Vec<Seed> = seeds.iter().map(|s| (*s).clone()).collect();
        let payloads = if self.options.enrich {
            enrich(&self.payloads, &owned)
        } else {
            self.payloads.clone()
        };
        let mut total: u64 = 0;
        for seed in &seeds {
            for pattern in &self.patterns {
                if applicable(pattern, seed) {
                    total = total.saturating_add(combinations(pattern, &payloads));
                }
            }
            let numbers = number_mutations(seed, self.options.number_delta).len();
            total = total.saturating_add(u64::try_from(numbers).unwrap_or(u64::MAX));
        }
        total
    }
}

/// The lazy candidate stream returned by [`Permutator::permute`].
///
/// Memory is bounded by the set of names already emitted (for
/// deduplication), so pair large inputs with [`Options::limit`].
#[derive(Debug)]
pub struct Permutations<'a> {
    permutator: &'a Permutator,
    payloads: Payloads,
    seeds: Vec<Seed>,
    seed: usize,
    pattern: usize,
    /// Current payload indices for the pattern being expanded.
    odometer: Option<Vec<usize>>,
    /// Number mutations of the current seed, once patterns are done.
    numbers: Option<VecDeque<String>>,
    seen: HashSet<String>,
    emitted: usize,
}

impl Permutations<'_> {
    /// The candidates as DNS names, ready for a resolver or
    /// `rune-wildcard-dns`.
    pub fn names(self) -> impl Iterator<Item = Name> {
        self.filter_map(|candidate| Name::from_ascii(&candidate).ok())
    }

    /// The next raw candidate, before validation and deduplication.
    fn next_raw(&mut self) -> Option<String> {
        let patterns = self.permutator.patterns.as_slice();
        loop {
            let seed = self.seeds.get(self.seed)?;
            let Some(pattern) = patterns.get(self.pattern) else {
                let numbers = self.numbers.get_or_insert_with(|| {
                    number_mutations(seed, self.permutator.options.number_delta).into()
                });
                if let Some(candidate) = numbers.pop_front() {
                    return Some(candidate);
                }
                self.seed += 1;
                self.pattern = 0;
                self.numbers = None;
                continue;
            };
            if self.odometer.is_none() {
                if !applicable(pattern, seed) || combinations(pattern, &self.payloads) == 0 {
                    self.pattern += 1;
                    continue;
                }
                self.odometer = Some(vec![0; pattern.payload_vars().len()]);
            }
            let Some(odometer) = self.odometer.as_mut() else {
                continue;
            };
            let candidate = render(pattern, seed, &self.payloads, odometer);
            if !advance(pattern, &self.payloads, odometer) {
                self.odometer = None;
                self.pattern += 1;
            }
            if let Some(candidate) = candidate {
                return Some(candidate);
            }
        }
    }
}

impl Iterator for Permutations<'_> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self
            .permutator
            .options
            .limit
            .is_some_and(|limit| self.emitted >= limit)
        {
            return None;
        }
        loop {
            let candidate = self.next_raw()?;
            if is_valid_host(&candidate) && self.seen.insert(candidate.clone()) {
                self.emitted += 1;
                return Some(candidate);
            }
        }
    }
}

/// Whether every built-in variable in `pattern` has a value for `seed`.
fn applicable(pattern: &Pattern, seed: &Seed) -> bool {
    pattern.tokens().iter().all(|token| match token {
        Token::Var(name) => pattern.payload_index(name).is_some() || seed.var(name).is_some(),
        Token::Literal(_) => true,
    })
}

/// Number of payload combinations `pattern` expands to.
fn combinations(pattern: &Pattern, payloads: &Payloads) -> u64 {
    pattern.payload_vars().fold(1u64, |acc, var| {
        let len = payloads.get(var).map_or(0, <[String]>::len);
        acc.saturating_mul(u64::try_from(len).unwrap_or(u64::MAX))
    })
}

fn render(
    pattern: &Pattern,
    seed: &Seed,
    payloads: &Payloads,
    odometer: &[usize],
) -> Option<String> {
    let mut out = String::new();
    for token in pattern.tokens() {
        match token {
            Token::Literal(text) => out.push_str(text),
            Token::Var(name) => {
                let value = match pattern.payload_index(name) {
                    Some(i) => payloads.get(name)?.get(*odometer.get(i)?)?.as_str(),
                    None => seed.var(name)?,
                };
                out.push_str(value);
            }
        }
    }
    Some(out)
}

/// Steps the odometer, last variable fastest. `false` once it wraps.
fn advance(pattern: &Pattern, payloads: &Payloads, odometer: &mut [usize]) -> bool {
    let vars: Vec<&str> = pattern.payload_vars().collect();
    for (i, var) in vars.iter().enumerate().rev() {
        let len = payloads.get(var).map_or(0, <[String]>::len);
        let Some(slot) = odometer.get_mut(i) else {
            return false;
        };
        *slot += 1;
        if *slot < len {
            return true;
        }
        *slot = 0;
    }
    false
}

/// Variants of `seed` with each number in a sub label moved by ±1 … ±delta.
fn number_mutations(seed: &Seed, delta: u32) -> Vec<String> {
    let mut out = Vec::new();
    if delta == 0 {
        return out;
    }
    let labels = seed.sub_labels();
    for (index, label) in labels.iter().enumerate() {
        for (start, end) in digit_runs(label) {
            let digits = label.get(start..end).unwrap_or_default();
            let Ok(value) = digits.parse::<u64>() else {
                continue;
            };
            let width = if digits.len() > 1 && digits.starts_with('0') {
                digits.len()
            } else {
                0
            };
            for step in 1..=u64::from(delta) {
                for next in [value.checked_sub(step), value.checked_add(step)]
                    .into_iter()
                    .flatten()
                {
                    let number = format!("{next:0width$}");
                    let mutated = format!(
                        "{}{number}{}",
                        label.get(..start).unwrap_or_default(),
                        label.get(end..).unwrap_or_default()
                    );
                    let mut parts: Vec<&str> = labels.iter().map(String::as_str).collect();
                    if let Some(slot) = parts.get_mut(index) {
                        *slot = &mutated;
                    }
                    parts.push(seed.root());
                    out.push(parts.join("."));
                }
            }
        }
    }
    out
}

/// Byte ranges of maximal ASCII digit runs in `label`.
fn digit_runs(label: &str) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut start = None;
    for (i, b) in label.bytes().enumerate() {
        match (b.is_ascii_digit(), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                runs.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        runs.push((s, label.len()));
    }
    runs
}

/// `payloads` with tokens from the seeds appended to `word`.
fn enrich(payloads: &Payloads, seeds: &[Seed]) -> Payloads {
    let mut tokens = Vec::new();
    for seed in seeds {
        for label in seed.sub_labels() {
            let parts = label
                .split('-')
                .flat_map(|part| [part, part.trim_end_matches(|c: char| c.is_ascii_digit())]);
            for token in core::iter::once(label.as_str()).chain(parts) {
                if token.len() >= 2 && !token.bytes().all(|b| b.is_ascii_digit()) {
                    tokens.push(token.to_owned());
                }
            }
        }
    }
    let mut enriched = payloads.clone();
    // `word` is a valid payload name, so this cannot fail.
    let _ = enriched.extend("word", tokens);
    enriched
}

/// Whether `host` is a lowercase LDH host name of valid length.
fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(host: &str) -> Seed {
        Seed::parse(host).unwrap()
    }

    #[test]
    fn host_validity() {
        assert!(is_valid_host("a-b.example.com"));
        assert!(!is_valid_host("-a.example.com"));
        assert!(!is_valid_host("a-.example.com"));
        assert!(!is_valid_host("a..example.com"));
        assert!(!is_valid_host("a_b.example.com"));
        assert!(!is_valid_host(&format!("{}.com", "a".repeat(64))));
        assert!(!is_valid_host(&format!("{}com", "abcdefghi.".repeat(26))));
    }

    #[test]
    fn digit_runs_found() {
        assert_eq!(digit_runs("db01-x2"), [(2, 4), (6, 7)]);
        assert_eq!(digit_runs("abc"), []);
        assert_eq!(digit_runs("42"), [(0, 2)]);
    }

    #[test]
    fn numbers_mutate_with_padding() {
        let got = number_mutations(&seed("db07.eu.example.com"), 2);
        assert_eq!(
            got,
            [
                "db06.eu.example.com",
                "db08.eu.example.com",
                "db05.eu.example.com",
                "db09.eu.example.com"
            ]
        );
        let got = number_mutations(&seed("node0.example.com"), 1);
        assert_eq!(got, ["node1.example.com"]);
        assert_eq!(
            number_mutations(&seed("api.example.com"), 3),
            Vec::<String>::new()
        );
        assert_eq!(
            number_mutations(&seed("db1.example.com"), 0),
            Vec::<String>::new()
        );
    }

    #[test]
    fn enrichment_extracts_tokens() {
        let enriched = enrich(
            &Payloads::new(),
            &[seed("api2-prod.example.com"), seed("x.example.com")],
        );
        assert_eq!(
            enriched.get("word").unwrap(),
            ["api2-prod", "api2", "api", "prod"]
        );
    }

    #[test]
    fn odometer_covers_cartesian_product() {
        let mut payloads = Payloads::new();
        payloads.insert("a", ["1", "2"]).unwrap();
        payloads.insert("b", ["x", "y", "z"]).unwrap();
        let p = Permutator::new(["{{a}}-{{b}}.{{root}}"], payloads, Options::default()).unwrap();
        let got: Vec<String> = p.permute(&[seed("example.com")]).collect();
        assert_eq!(
            got,
            [
                "1-x.example.com",
                "1-y.example.com",
                "1-z.example.com",
                "2-x.example.com",
                "2-y.example.com",
                "2-z.example.com"
            ]
        );
        assert_eq!(p.estimate(&[seed("example.com")]), 6);
    }
}
