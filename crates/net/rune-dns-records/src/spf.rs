//! Sender Policy Framework records ([RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)).

use core::fmt;
use core::str::FromStr;
use std::net::{Ipv4Addr, Ipv6Addr};

use rune_finding::Severity;

use crate::error::{Error, RecordKind};
use crate::issue::{Issue, IssueKind, sorted};

/// Most DNS-querying terms one SPF evaluation may use (RFC 7208 §4.6.4).
pub const MAX_DNS_LOOKUPS: usize = 10;

/// Most lookups returning no records ("void lookups") one SPF evaluation
/// should allow (RFC 7208 §4.6.4).
pub const MAX_VOID_LOOKUPS: usize = 2;

const R: RecordKind = RecordKind::Spf;

/// The result a matching directive produces (RFC 7208 §4.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Qualifier {
    /// `+`, the default: the host is authorized.
    Pass,
    /// `-`: the host is not authorized.
    Fail,
    /// `~`: probably not authorized.
    SoftFail,
    /// `?`: no assertion.
    Neutral,
}

impl Qualifier {
    /// The qualifier character.
    #[must_use]
    pub const fn symbol(self) -> char {
        match self {
            Self::Pass => '+',
            Self::Fail => '-',
            Self::SoftFail => '~',
            Self::Neutral => '?',
        }
    }

    const fn from_symbol(c: u8) -> Option<Self> {
        match c {
            b'+' => Some(Self::Pass),
            b'-' => Some(Self::Fail),
            b'~' => Some(Self::SoftFail),
            b'?' => Some(Self::Neutral),
            _ => None,
        }
    }
}

/// The optional `/<ip4-cidr>` and `//<ip6-cidr>` of `a` and `mx`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct DualCidr {
    /// IPv4 prefix length, 0 to 32.
    pub v4: Option<u8>,
    /// IPv6 prefix length, 0 to 128.
    pub v6: Option<u8>,
}

/// An SPF mechanism (RFC 7208 §5). Domain specifications are kept as
/// written, including any macros (§7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mechanism {
    /// `all`: always matches.
    All,
    /// `include:<domain-spec>`: matches if the included record passes.
    Include(String),
    /// `a[:<domain-spec>][<dual-cidr>]`: the domain's addresses.
    A {
        /// Domain to look up; the current domain when `None`.
        domain: Option<String>,
        /// Prefix lengths applied to the addresses.
        cidr: DualCidr,
    },
    /// `mx[:<domain-spec>][<dual-cidr>]`: the domain's mail exchangers.
    Mx {
        /// Domain to look up; the current domain when `None`.
        domain: Option<String>,
        /// Prefix lengths applied to the addresses.
        cidr: DualCidr,
    },
    /// `ptr[:<domain-spec>]` (deprecated, §5.5).
    Ptr(Option<String>),
    /// `ip4:<address>[/<prefix>]`.
    Ip4 {
        /// The network address.
        addr: Ipv4Addr,
        /// Prefix length; 32 when `None`.
        prefix: Option<u8>,
    },
    /// `ip6:<address>[/<prefix>]`.
    Ip6 {
        /// The network address.
        addr: Ipv6Addr,
        /// Prefix length; 128 when `None`.
        prefix: Option<u8>,
    },
    /// `exists:<domain-spec>`: matches if the name has an `A` record.
    Exists(String),
}

impl Mechanism {
    /// The mechanism name, e.g. `include`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Include(_) => "include",
            Self::A { .. } => "a",
            Self::Mx { .. } => "mx",
            Self::Ptr(_) => "ptr",
            Self::Ip4 { .. } => "ip4",
            Self::Ip6 { .. } => "ip6",
            Self::Exists(_) => "exists",
        }
    }

    /// Whether evaluating the mechanism costs a DNS lookup that counts
    /// towards [`MAX_DNS_LOOKUPS`].
    #[must_use]
    pub const fn needs_lookup(&self) -> bool {
        matches!(
            self,
            Self::Include(_) | Self::A { .. } | Self::Mx { .. } | Self::Ptr(_) | Self::Exists(_)
        )
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        match self {
            Self::All => Ok(()),
            Self::Include(domain) | Self::Exists(domain) => write!(f, ":{domain}"),
            Self::A { domain, cidr } | Self::Mx { domain, cidr } => {
                if let Some(domain) = domain {
                    write!(f, ":{domain}")?;
                }
                if let Some(v4) = cidr.v4 {
                    write!(f, "/{v4}")?;
                }
                if let Some(v6) = cidr.v6 {
                    write!(f, "//{v6}")?;
                }
                Ok(())
            }
            Self::Ptr(domain) => domain.as_ref().map_or(Ok(()), |d| write!(f, ":{d}")),
            Self::Ip4 { addr, prefix } => {
                write!(f, ":{addr}")?;
                prefix.map_or(Ok(()), |p| write!(f, "/{p}"))
            }
            Self::Ip6 { addr, prefix } => {
                write!(f, ":{addr}")?;
                prefix.map_or(Ok(()), |p| write!(f, "/{p}"))
            }
        }
    }
}

/// A qualified mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Directive {
    /// The result if the mechanism matches.
    pub qualifier: Qualifier,
    /// The mechanism.
    pub mechanism: Mechanism,
}

impl fmt::Display for Directive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.qualifier != Qualifier::Pass {
            write!(f, "{}", self.qualifier.symbol())?;
        }
        write!(f, "{}", self.mechanism)
    }
}

/// An SPF modifier (RFC 7208 §6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Modifier {
    /// `redirect=<domain-spec>`: use another domain's record when nothing
    /// matched.
    Redirect(String),
    /// `exp=<domain-spec>`: where to find the explanation for a fail.
    Exp(String),
    /// Any other modifier, which evaluation ignores.
    Unknown {
        /// The modifier name, as written.
        name: String,
        /// Its value (a macro string, possibly empty).
        value: String,
    },
}

impl fmt::Display for Modifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redirect(domain) => write!(f, "redirect={domain}"),
            Self::Exp(domain) => write!(f, "exp={domain}"),
            Self::Unknown { name, value } => write!(f, "{name}={value}"),
        }
    }
}

/// One term of an SPF record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Term {
    /// A qualified mechanism.
    Directive(Directive),
    /// A modifier.
    Modifier(Modifier),
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directive(d) => d.fmt(f),
            Self::Modifier(m) => m.fmt(f),
        }
    }
}

/// A parsed SPF record.
///
/// `Display` writes the canonical form: lowercase mechanism names, no `+`
/// qualifiers, single spaces. Parsing it gives back an equal record.
///
/// ```
/// use rune_dns_records::spf::{Qualifier, Spf};
///
/// let spf: Spf = "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net ~all".parse()?;
/// assert_eq!(spf.all(), Some(Qualifier::SoftFail));
/// assert_eq!(spf.lookup_count(), 1);
/// assert!(!spf.is_permissive());
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Spf {
    /// The terms after `v=spf1`, in order.
    pub terms: Vec<Term>,
}

/// Whether `text` is an SPF record: it starts with `v=spf1` (any case),
/// followed by a space or the end (RFC 7208 §4.5).
#[must_use]
pub fn is_spf(text: &str) -> bool {
    let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
    text.get(..6)
        .is_some_and(|v| v.eq_ignore_ascii_case("v=spf1"))
        && matches!(text.as_bytes().get(6), None | Some(b' '))
}

impl Spf {
    /// Parses one SPF record.
    ///
    /// # Errors
    ///
    /// [`Error::NotThisRecord`] if it does not start with `v=spf1`,
    /// [`Error::Syntax`] for a malformed term (unknown mechanism, bad
    /// address, prefix or macro), [`Error::DuplicateTag`] for a second
    /// `redirect=` or `exp=`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
        if !is_spf(text) {
            return Err(Error::NotThisRecord {
                record: R,
                reason: "does not start with v=spf1",
            });
        }
        let mut terms = Vec::new();
        let (mut redirect, mut exp) = (false, false);
        for token in text[6..].split(' ').filter(|t| !t.is_empty()) {
            let term = parse_term(token)?;
            if let Term::Modifier(m) = &term {
                let seen = match m {
                    Modifier::Redirect(_) => Some((&mut redirect, "redirect")),
                    Modifier::Exp(_) => Some((&mut exp, "exp")),
                    Modifier::Unknown { .. } => None,
                };
                if let Some((seen, tag)) = seen {
                    if *seen {
                        return Err(Error::DuplicateTag {
                            record: R,
                            tag: tag.to_owned(),
                        });
                    }
                    *seen = true;
                }
            }
            terms.push(term);
        }
        Ok(Self { terms })
    }

    /// Selects and parses the SPF record among a domain's `TXT` records
    /// (each one already joined from its strings, see
    /// [`txt_to_string`](crate::txt_to_string)).
    ///
    /// Returns `Ok(None)` when no record starts with `v=spf1`.
    ///
    /// # Errors
    ///
    /// [`Error::MultipleRecords`] if more than one does (RFC 7208 §4.5),
    /// otherwise any error of [`Spf::parse`].
    pub fn find<I, S>(txts: I) -> Result<Option<Self>, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut found = None;
        let mut count = 0;
        for txt in txts {
            if is_spf(txt.as_ref()) {
                count += 1;
                if found.is_none() {
                    found = Some(txt);
                }
            }
        }
        match (found, count) {
            (None, _) => Ok(None),
            (Some(txt), 1) => Self::parse(txt.as_ref()).map(Some),
            (Some(_), count) => Err(Error::MultipleRecords { record: R, count }),
        }
    }

    /// The directives, in order.
    pub fn directives(&self) -> impl Iterator<Item = &Directive> {
        self.terms.iter().filter_map(|t| match t {
            Term::Directive(d) => Some(d),
            Term::Modifier(_) => None,
        })
    }

    /// The modifiers, in order.
    pub fn modifiers(&self) -> impl Iterator<Item = &Modifier> {
        self.terms.iter().filter_map(|t| match t {
            Term::Modifier(m) => Some(m),
            Term::Directive(_) => None,
        })
    }

    /// The qualifier of the first `all` mechanism, if any.
    #[must_use]
    pub fn all(&self) -> Option<Qualifier> {
        self.directives()
            .find(|d| d.mechanism == Mechanism::All)
            .map(|d| d.qualifier)
    }

    /// The `redirect=` target, if any.
    #[must_use]
    pub fn redirect(&self) -> Option<&str> {
        self.modifiers().find_map(|m| match m {
            Modifier::Redirect(d) => Some(d.as_str()),
            _ => None,
        })
    }

    /// The `exp=` target, if any.
    #[must_use]
    pub fn exp(&self) -> Option<&str> {
        self.modifiers().find_map(|m| match m {
            Modifier::Exp(d) => Some(d.as_str()),
            _ => None,
        })
    }

    /// Directives that evaluation can reach: those up to and including the
    /// first `all`.
    fn reachable(&self) -> impl Iterator<Item = &Directive> {
        let mut done = false;
        self.directives().take_while(move |d| {
            let take = !done;
            done |= d.mechanism == Mechanism::All;
            take
        })
    }

    /// The `redirect=` target evaluation would follow: none when the record
    /// has an `all` mechanism (RFC 7208 §6.1).
    fn effective_redirect(&self) -> Option<&str> {
        if self.all().is_some() {
            None
        } else {
            self.redirect()
        }
    }

    /// DNS-querying terms in this record alone (`include`, `a`, `mx`,
    /// `ptr`, `exists` and an effective `redirect`). Terms after `all` are
    /// not counted, since evaluation never reaches them. See
    /// [`Spf::count_lookups`] for the total across included records.
    #[must_use]
    pub fn lookup_count(&self) -> usize {
        self.reachable()
            .filter(|d| d.mechanism.needs_lookup())
            .count()
            + usize::from(self.effective_redirect().is_some())
    }

    /// Whether the record authorizes any host: it has a `+all` (or bare
    /// `all`) mechanism.
    #[must_use]
    pub fn is_permissive(&self) -> bool {
        self.all() == Some(Qualifier::Pass)
    }

    /// Checks this record on its own: the `all` mechanism, deprecated and
    /// overly broad terms, unreachable terms and the lookup count of this
    /// record. Most severe first.
    #[must_use]
    pub fn issues(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let record = self.to_string();
        let ev = |issue: Issue| issue.with_evidence(record.clone());
        match self.all() {
            Some(Qualifier::Pass) => issues.push(ev(Issue::new(
                IssueKind::SpfPermissiveAll,
                "SPF record uses a permissive +all",
            ))),
            Some(Qualifier::Neutral) => issues.push(ev(Issue::new(
                IssueKind::SpfNeutralAll,
                "SPF record ends in ?all, which gives unlisted senders a neutral result",
            ))),
            Some(_) => {
                if self.redirect().is_some() {
                    issues.push(ev(Issue::new(
                        IssueKind::SpfRedirectIgnored,
                        "redirect= is ignored because the record has an all mechanism",
                    )));
                }
            }
            None if self.redirect().is_none() => issues.push(ev(Issue::new(
                IssueKind::SpfNoAll,
                "SPF record has neither an all mechanism nor a redirect",
            ))),
            None => {}
        }
        let reachable = self.reachable().count();
        if let Some(after) = self.directives().nth(reachable) {
            issues.push(
                Issue::new(
                    IssueKind::SpfTermsAfterAll,
                    format!("`{after}` follows the all mechanism and is never evaluated"),
                )
                .with_evidence(after.to_string()),
            );
        }
        for directive in self.directives() {
            match &directive.mechanism {
                Mechanism::Ptr(_) => issues.push(
                    Issue::new(
                        IssueKind::SpfPtrMechanism,
                        "SPF record uses the deprecated ptr mechanism",
                    )
                    .with_evidence(directive.to_string()),
                ),
                Mechanism::Ip4 {
                    prefix: Some(p), ..
                } if directive.qualifier == Qualifier::Pass && *p < 12 => {
                    issues.push(broad_range(directive, *p));
                }
                Mechanism::Ip6 {
                    prefix: Some(p), ..
                } if directive.qualifier == Qualifier::Pass && *p < 24 => {
                    issues.push(broad_range(directive, *p));
                }
                _ => {}
            }
        }
        let lookups = self.lookup_count();
        if lookups > MAX_DNS_LOOKUPS {
            issues.push(ev(Issue::new(
                IssueKind::SpfTooManyLookups,
                format!("SPF record needs {lookups} DNS lookups, more than the limit of {MAX_DNS_LOOKUPS}"),
            )));
        }
        sorted(issues)
    }

    /// Walks the `include:` and `redirect=` chain from this record, which is
    /// `domain`'s, and counts DNS lookups across it, as an evaluator would
    /// (RFC 7208 §4.6.4).
    ///
    /// `fetch` returns the SPF record text published at a domain, or `None`
    /// if there is none; it is the only source of data, so this stays
    /// sans-I/O. Use [`Spf::find`] on the domain's `TXT` records to
    /// implement it. Targets with macros cannot be followed and are listed
    /// in [`LookupReport::unexpanded`].
    ///
    /// The walk stops fetching once the limit is exceeded, so `fetch` is
    /// called at most [`MAX_DNS_LOOKUPS`] + 1 times, and
    /// [`LookupReport::lookups`] is then a lower bound.
    ///
    /// ```
    /// use rune_dns_records::spf::Spf;
    ///
    /// let spf: Spf = "v=spf1 include:a.example include:b.example -all".parse()?;
    /// let report = spf.count_lookups("example.com", |domain| match domain {
    ///     "a.example" => Some("v=spf1 a mx -all".to_owned()),
    ///     "b.example" => Some("v=spf1 include:a.example -all".to_owned()),
    ///     _ => None,
    /// });
    /// // 2 in the root, 2 in a.example, 1 in b.example, and a.example again.
    /// assert_eq!(report.lookups, 7);
    /// assert!(!report.exceeded());
    /// # Ok::<(), rune_dns_records::Error>(())
    /// ```
    pub fn count_lookups<F>(&self, domain: &str, mut fetch: F) -> LookupReport
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut report = LookupReport::default();
        let mut stack = vec![normalize(domain)];
        walk(self, &mut stack, &mut fetch, &mut report);
        report
    }
}

fn broad_range(directive: &Directive, prefix: u8) -> Issue {
    let issue = Issue::new(
        IssueKind::SpfBroadIpRange,
        format!("`{directive}` authorizes a /{prefix} range"),
    )
    .with_evidence(directive.to_string());
    if prefix == 0 {
        issue.with_severity(Severity::High)
    } else {
        issue
    }
}

fn normalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn walk<F>(spf: &Spf, stack: &mut Vec<String>, fetch: &mut F, report: &mut LookupReport)
where
    F: FnMut(&str) -> Option<String>,
{
    let includes = spf.reachable().map(|d| {
        report.lookups += usize::from(d.mechanism.needs_lookup());
        match &d.mechanism {
            Mechanism::Include(target) => Some(target.clone()),
            _ => None,
        }
    });
    let mut targets: Vec<String> = includes.flatten().collect();
    if let Some(target) = spf.effective_redirect() {
        report.lookups += 1;
        targets.push(target.to_owned());
    }
    // Counting the whole record first matches evaluation order closely
    // enough: every reachable term may be evaluated before a later include
    // is fetched, and the limit is a total.
    for target in targets {
        if report.exceeded() {
            return;
        }
        if target.contains('%') {
            report.unexpanded.push(target);
            continue;
        }
        let key = normalize(&target);
        if stack.contains(&key) {
            report.loops.push(target);
            continue;
        }
        match fetch(&key) {
            None => {
                report.void_lookups += 1;
                report.missing.push(target);
            }
            Some(text) => match Spf::parse(&text) {
                Err(error) => report.errors.push((target, error)),
                Ok(child) => {
                    stack.push(key);
                    walk(&child, stack, fetch, report);
                    stack.pop();
                }
            },
        }
    }
}

/// The result of [`Spf::count_lookups`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LookupReport {
    /// DNS-querying terms counted across the chain.
    pub lookups: usize,
    /// `include`/`redirect` targets that returned no SPF record.
    pub void_lookups: usize,
    /// `include`/`redirect` targets without an SPF record (a permerror).
    pub missing: Vec<String>,
    /// Targets already being evaluated higher up the chain.
    pub loops: Vec<String>,
    /// Targets whose record does not parse.
    pub errors: Vec<(String, Error)>,
    /// Targets containing macros, which cannot be followed statically.
    pub unexpanded: Vec<String>,
}

impl LookupReport {
    /// Whether the chain needs more than [`MAX_DNS_LOOKUPS`] lookups.
    #[must_use]
    pub const fn exceeded(&self) -> bool {
        self.lookups > MAX_DNS_LOOKUPS
    }

    /// Whether more than [`MAX_VOID_LOOKUPS`] targets returned nothing.
    #[must_use]
    pub const fn void_exceeded(&self) -> bool {
        self.void_lookups > MAX_VOID_LOOKUPS
    }

    /// The weaknesses this walk shows. Most severe first.
    #[must_use]
    pub fn issues(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        if self.exceeded() {
            issues.push(Issue::new(
                IssueKind::SpfTooManyLookups,
                format!(
                    "SPF evaluation needs at least {} DNS lookups, more than the limit of {MAX_DNS_LOOKUPS}",
                    self.lookups
                ),
            ));
        }
        if self.void_exceeded() {
            issues.push(Issue::new(
                IssueKind::SpfTooManyVoidLookups,
                format!(
                    "{} SPF include/redirect targets return no record, more than the limit of {MAX_VOID_LOOKUPS}",
                    self.void_lookups
                ),
            ));
        }
        for target in &self.missing {
            issues.push(
                Issue::new(
                    IssueKind::SpfIncludeMissing,
                    format!("SPF include/redirect target {target} publishes no SPF record"),
                )
                .with_evidence(target.clone()),
            );
        }
        for target in &self.loops {
            issues.push(
                Issue::new(
                    IssueKind::SpfIncludeLoop,
                    format!("SPF include/redirect loop through {target}"),
                )
                .with_evidence(target.clone()),
            );
        }
        for (target, error) in &self.errors {
            issues.push(
                Issue::new(
                    IssueKind::SpfInvalid,
                    format!("SPF record of {target}: {error}"),
                )
                .with_evidence(target.clone()),
            );
        }
        sorted(issues)
    }
}

impl FromStr for Spf {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl fmt::Display for Spf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("v=spf1")?;
        for term in &self.terms {
            write!(f, " {term}")?;
        }
        Ok(())
    }
}

fn parse_term(token: &str) -> Result<Term, Error> {
    if !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(Error::syntax(
            R,
            token,
            "non-printable or non-ASCII character",
        ));
    }
    let name_len = token
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
        .unwrap_or(token.len());
    let name = &token[..name_len];
    if token.as_bytes().get(name_len) == Some(&b'=')
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
    {
        let value = &token[name_len + 1..];
        let modifier = if name.eq_ignore_ascii_case("redirect") {
            Modifier::Redirect(domain_spec(value, token)?)
        } else if name.eq_ignore_ascii_case("exp") {
            Modifier::Exp(domain_spec(value, token)?)
        } else {
            macro_string(value, false).map_err(|reason| Error::syntax(R, token, reason))?;
            Modifier::Unknown {
                name: name.to_owned(),
                value: value.to_owned(),
            }
        };
        return Ok(Term::Modifier(modifier));
    }

    let (qualifier, rest) = token
        .bytes()
        .next()
        .and_then(Qualifier::from_symbol)
        .map_or((Qualifier::Pass, token), |q| (q, &token[1..]));
    let name_len = rest.find([':', '/']).unwrap_or(rest.len());
    let (name, arg) = rest.split_at(name_len);
    let mechanism = match name.to_ascii_lowercase().as_str() {
        "all" if arg.is_empty() => Mechanism::All,
        "include" => Mechanism::Include(required_spec(arg, token)?),
        "exists" => Mechanism::Exists(required_spec(arg, token)?),
        "ptr" => Mechanism::Ptr(optional_spec(arg, token)?),
        "a" | "mx" => {
            let (spec, cidr) = dual_cidr(arg, token)?;
            let domain = optional_spec(spec, token)?;
            if name.eq_ignore_ascii_case("a") {
                Mechanism::A { domain, cidr }
            } else {
                Mechanism::Mx { domain, cidr }
            }
        }
        "ip4" => {
            let (addr, prefix) = network(arg, token, 32)?;
            let addr = addr
                .parse()
                .map_err(|_| Error::syntax(R, token, "invalid IPv4 address"))?;
            Mechanism::Ip4 { addr, prefix }
        }
        "ip6" => {
            let (addr, prefix) = network(arg, token, 128)?;
            let addr = addr
                .parse()
                .map_err(|_| Error::syntax(R, token, "invalid IPv6 address"))?;
            Mechanism::Ip6 { addr, prefix }
        }
        "all" => return Err(Error::syntax(R, token, "all takes no argument")),
        _ => return Err(Error::syntax(R, token, "unknown mechanism")),
    };
    Ok(Term::Directive(Directive {
        qualifier,
        mechanism,
    }))
}

fn required_spec(arg: &str, token: &str) -> Result<String, Error> {
    optional_spec(arg, token)?.ok_or_else(|| Error::syntax(R, token, "missing domain"))
}

fn optional_spec(arg: &str, token: &str) -> Result<Option<String>, Error> {
    if arg.is_empty() {
        return Ok(None);
    }
    let Some(spec) = arg.strip_prefix(':') else {
        return Err(Error::syntax(
            R,
            token,
            "expected `:` after the mechanism name",
        ));
    };
    domain_spec(spec, token).map(Some)
}

/// Splits `ip4:`/`ip6:` arguments into address text and prefix.
fn network<'a>(arg: &'a str, token: &str, max: u8) -> Result<(&'a str, Option<u8>), Error> {
    let Some(arg) = arg.strip_prefix(':') else {
        return Err(Error::syntax(R, token, "missing address"));
    };
    match arg.split_once('/') {
        None => Ok((arg, None)),
        Some((addr, prefix)) => Ok((addr, Some(cidr(prefix, max, token)?))),
    }
}

/// Splits `[:domain][/v4][//v6]` into the domain part and the prefixes.
fn dual_cidr<'a>(arg: &'a str, token: &str) -> Result<(&'a str, DualCidr), Error> {
    let mut rest = arg;
    let mut out = DualCidr::default();
    if let Some(i) = rest.rfind("//")
        && is_digits(&rest[i + 2..])
    {
        out.v6 = Some(cidr(&rest[i + 2..], 128, token)?);
        rest = &rest[..i];
    }
    if let Some(i) = rest.rfind('/')
        && is_digits(&rest[i + 1..])
    {
        out.v4 = Some(cidr(&rest[i + 1..], 32, token)?);
        rest = &rest[..i];
    }
    Ok((rest, out))
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A prefix length: decimal without leading zeros, at most `max`.
fn cidr(text: &str, max: u8, token: &str) -> Result<u8, Error> {
    let bad = || Error::syntax(R, token, "invalid prefix length");
    if !is_digits(text) || text.len() > 3 || (text.len() > 1 && text.starts_with('0')) {
        return Err(bad());
    }
    match text.parse::<u8>() {
        Ok(n) if n <= max => Ok(n),
        _ => Err(bad()),
    }
}

/// Validates a `domain-spec`: a macro string ending in a macro or in
/// `.<toplabel>` with an optional trailing dot.
fn domain_spec(spec: &str, token: &str) -> Result<String, Error> {
    let ends_in_macro =
        macro_string(spec, false).map_err(|reason| Error::syntax(R, token, reason))?;
    if spec.is_empty() {
        return Err(Error::syntax(R, token, "missing domain"));
    }
    if !ends_in_macro {
        let name = spec.strip_suffix('.').unwrap_or(spec);
        let Some((_, top)) = name.rsplit_once('.') else {
            return Err(Error::syntax(R, token, "domain has a single label"));
        };
        if !is_toplabel(top) {
            return Err(Error::syntax(R, token, "invalid top-level label"));
        }
    }
    Ok(spec.to_owned())
}

/// `toplabel` (RFC 7208 §7.1): letters and digits with at least one letter,
/// or with inner hyphens.
fn is_toplabel(label: &str) -> bool {
    let bytes = label.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    {
        return false;
    }
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return false;
    }
    bytes.iter().any(|b| b.is_ascii_alphabetic() || *b == b'-')
}

/// Validates a `macro-string` (RFC 7208 §7.1) and returns whether it ends
/// in a macro expansion. `exp` allows the `c`, `r` and `t` letters, which
/// only explanation strings may use.
pub(crate) fn macro_string(text: &str, exp: bool) -> Result<bool, &'static str> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut ends_in_macro = false;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'%' => {
                match bytes.get(i + 1) {
                    Some(b'%' | b'_' | b'-') => i += 2,
                    Some(b'{') => {
                        let Some(len) = bytes[i + 2..].iter().position(|&b| b == b'}') else {
                            return Err("unterminated macro");
                        };
                        macro_body(&bytes[i + 2..i + 2 + len], exp)?;
                        i += len + 3;
                    }
                    _ => return Err("invalid macro escape"),
                }
                ends_in_macro = true;
            }
            0x21..=0x7e => {
                ends_in_macro = false;
                i += 1;
            }
            _ => return Err("invalid character"),
        }
    }
    Ok(ends_in_macro)
}

/// `macro-letter transformers *delimiter`.
fn macro_body(body: &[u8], exp: bool) -> Result<(), &'static str> {
    let Some((&letter, rest)) = body.split_first() else {
        return Err("empty macro");
    };
    let letter = letter.to_ascii_lowercase();
    let known = b"slodiphv".contains(&letter) || (exp && b"crt".contains(&letter));
    if !known {
        return Err("unknown macro letter");
    }
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let mut rest = &rest[digits..];
    if let Some(r) = rest.strip_prefix(b"r").or_else(|| rest.strip_prefix(b"R")) {
        rest = r;
    }
    if rest.iter().all(|b| b".-+,/_=".contains(b)) {
        Ok(())
    } else {
        Err("invalid macro transformer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spf(text: &str) -> Spf {
        text.parse().unwrap()
    }

    #[test]
    fn rfc_7208_appendix_a_records_parse() {
        // RFC 7208 Appendix A.
        for record in [
            "v=spf1 +all",
            "v=spf1 a -all",
            "v=spf1 a:example.org -all",
            "v=spf1 mx -all",
            "v=spf1 mx:example.org -all",
            "v=spf1 mx mx:example.org -all",
            "v=spf1 mx/30 mx:example.org/30 -all",
            "v=spf1 ptr -all",
            "v=spf1 ip4:192.0.2.128/28 -all",
            "v=spf1 mx -all exp=explain._spf.%{d}",
            "v=spf1 -include:ip4._spf.%{d} -include:ptr._spf.%{d} +all",
            "v=spf1 -ip4:192.0.2.0/24 +all",
            "v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all",
            "v=spf1 mx -all exp=%{ir}.%{v}._spf.%{d2}",
            "v=spf1 a:mail.example.com//64 redirect=_spf.example.com",
            "v=spf1 ip6:2001:db8::/32 ip6:2001:db8::1 ~all",
        ] {
            let parsed = spf(record);
            assert_eq!(spf(&parsed.to_string()), parsed, "{record}");
        }
    }

    #[test]
    fn parses_terms() {
        let parsed = spf(
            "v=spf1 +a:example.org/24//64 -ip4:192.0.2.1 ?mx ~exists:%{i}.x.example foo=bar redirect=_spf.example.com",
        );
        assert_eq!(
            parsed.terms[0],
            Term::Directive(Directive {
                qualifier: Qualifier::Pass,
                mechanism: Mechanism::A {
                    domain: Some("example.org".into()),
                    cidr: DualCidr {
                        v4: Some(24),
                        v6: Some(64)
                    },
                },
            })
        );
        assert_eq!(
            parsed.terms[1],
            Term::Directive(Directive {
                qualifier: Qualifier::Fail,
                mechanism: Mechanism::Ip4 {
                    addr: Ipv4Addr::new(192, 0, 2, 1),
                    prefix: None
                },
            })
        );
        assert_eq!(
            parsed.terms[4],
            Term::Modifier(Modifier::Unknown {
                name: "foo".into(),
                value: "bar".into()
            })
        );
        assert_eq!(parsed.redirect(), Some("_spf.example.com"));
        assert_eq!(parsed.all(), None);
        // a, mx, exists, redirect.
        assert_eq!(parsed.lookup_count(), 4);
        assert_eq!(
            parsed.to_string(),
            "v=spf1 a:example.org/24//64 -ip4:192.0.2.1 ?mx ~exists:%{i}.x.example foo=bar redirect=_spf.example.com"
        );
    }

    #[test]
    fn case_insensitive_names_and_version() {
        let parsed = spf("V=SPF1 MX INCLUDE:Example.COM -ALL");
        assert_eq!(parsed.all(), Some(Qualifier::Fail));
        assert_eq!(parsed.to_string(), "v=spf1 mx include:Example.COM -all");
    }

    #[test]
    fn rejects_malformed_records() {
        for (record, expected) in [
            ("v=spf10 -all", "not"),
            ("spf1 -all", "not"),
            ("v=spf1 foo -all", "unknown mechanism"),
            ("v=spf1 ip4:192.0.2.0/33", "prefix"),
            ("v=spf1 ip4:192.0.2.0/024", "prefix"),
            ("v=spf1 ip4:300.0.2.0", "IPv4"),
            ("v=spf1 ip6:2001:db8::/129", "prefix"),
            ("v=spf1 ip6:zz::", "IPv6"),
            ("v=spf1 include:", "domain"),
            ("v=spf1 include", "domain"),
            ("v=spf1 include:localhost", "single label"),
            ("v=spf1 include:example.123", "top-level"),
            ("v=spf1 exists:%{z}.example.com", "macro letter"),
            ("v=spf1 exists:%{i.example.com", "unterminated"),
            ("v=spf1 exists:%x.example.com", "escape"),
            ("v=spf1 all:example.com", "argument"),
            (
                "v=spf1 redirect=a.example redirect=b.example",
                "more than once",
            ),
            ("v=spf1 a:ex\u{e4}mple.com", "ASCII"),
        ] {
            let error = Spf::parse(record).unwrap_err();
            assert!(error.to_string().contains(expected), "{record}: {error}");
            assert_eq!(error.record(), RecordKind::Spf);
        }
    }

    #[test]
    fn exp_only_macro_letters_need_exp_context() {
        assert!(macro_string("%{c}", true).is_ok());
        assert!(macro_string("%{c}", false).is_err());
        assert_eq!(macro_string("%{d2r.-}", false), Ok(true));
        assert_eq!(macro_string("%{d}.example", false), Ok(false));
        assert_eq!(macro_string("a%%b%_%-", false), Ok(true));
    }

    #[test]
    fn find_selects_one_record() {
        let txts = ["google-site-verification=abc", "v=spf1 -all", "v=spf1x"];
        assert_eq!(Spf::find(txts).unwrap(), Some(spf("v=spf1 -all")));
        assert_eq!(Spf::find(["hello"]).unwrap(), None);
        assert_eq!(
            Spf::find(["v=spf1 -all", "v=spf1 ~all"]),
            Err(Error::MultipleRecords {
                record: RecordKind::Spf,
                count: 2
            })
        );
        assert!(is_spf("v=spf1"));
        assert!(!is_spf("v=spf1-all"));
    }

    fn kinds(issues: &[Issue]) -> Vec<IssueKind> {
        issues.iter().map(|i| i.kind).collect()
    }

    #[test]
    fn issues_for_weak_records() {
        assert_eq!(
            kinds(&spf("v=spf1 mx +all").issues()),
            [IssueKind::SpfPermissiveAll]
        );
        assert_eq!(
            kinds(&spf("v=spf1 mx all").issues()),
            [IssueKind::SpfPermissiveAll]
        );
        assert_eq!(
            kinds(&spf("v=spf1 mx ?all").issues()),
            [IssueKind::SpfNeutralAll]
        );
        assert_eq!(kinds(&spf("v=spf1 mx").issues()), [IssueKind::SpfNoAll]);
        assert_eq!(spf("v=spf1 mx -all").issues().len(), 0);
        assert_eq!(spf("v=spf1 mx ~all").issues().len(), 0);
        assert_eq!(spf("v=spf1 redirect=_spf.example.com").issues().len(), 0);
        assert_eq!(
            kinds(&spf("v=spf1 -all redirect=_spf.example.com").issues()),
            [IssueKind::SpfRedirectIgnored]
        );
        assert_eq!(
            kinds(&spf("v=spf1 ~all mx").issues()),
            [IssueKind::SpfTermsAfterAll]
        );
        assert_eq!(
            kinds(&spf("v=spf1 ptr -all").issues()),
            [IssueKind::SpfPtrMechanism]
        );
        let broad =
            spf("v=spf1 ip4:0.0.0.0/0 ip6:2001:db8::/16 ip4:40.92.0.0/15 -ip4:10.0.0.0/8 -all")
                .issues();
        assert_eq!(
            kinds(&broad),
            [IssueKind::SpfBroadIpRange, IssueKind::SpfBroadIpRange]
        );
        assert_eq!(broad[0].severity, Severity::High);
        let many = "v=spf1 a mx ptr exists:x.example include:a.example include:b.example \
                    include:c.example include:d.example include:e.example include:f.example \
                    include:g.example -all";
        assert!(kinds(&spf(many).issues()).contains(&IssueKind::SpfTooManyLookups));
    }

    #[test]
    fn permissive_matches_auditor_semantics() {
        assert!(spf("v=spf1 +all").is_permissive());
        assert!(spf("v=spf1 all").is_permissive());
        assert!(!spf("v=spf1 -all").is_permissive());
        assert!(!spf("v=spf1 -all +all").is_permissive());
    }

    #[test]
    fn counts_lookups_across_includes() {
        let records = std::collections::HashMap::from([
            (
                "a.example",
                "v=spf1 include:b.example include:missing.example -all",
            ),
            (
                "b.example",
                "v=spf1 a mx include:a.example redirect=ignored.example ~all",
            ),
            ("bad.example", "v=spf1 bogus"),
        ]);
        let root =
            spf("v=spf1 include:a.example include:bad.example include:%{d}.mac.example -all");
        let report = root.count_lookups("example.com", |d| records.get(d).map(|s| (*s).to_owned()));
        // root 3 + a.example 2 + b.example 3 (redirect ignored next to all).
        assert_eq!(report.lookups, 8);
        assert_eq!(report.void_lookups, 1);
        assert_eq!(report.missing, ["missing.example"]);
        assert_eq!(report.loops, ["a.example"]);
        assert_eq!(report.unexpanded, ["%{d}.mac.example"]);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(
            kinds(&report.issues()),
            [
                IssueKind::SpfIncludeMissing,
                IssueKind::SpfIncludeLoop,
                IssueKind::SpfInvalid
            ]
        );
    }

    #[test]
    fn lookup_walk_stops_after_the_limit() {
        // Every domain includes two more: unbounded without the limit.
        let mut fetches = 0;
        let root = spf("v=spf1 include:d0.example -all");
        let report = root.count_lookups("example.com", |d| {
            fetches += 1;
            Some(format!(
                "v=spf1 include:x{fetches}.{d} include:y{fetches}.{d} -all"
            ))
        });
        assert!(report.exceeded());
        assert!(fetches <= MAX_DNS_LOOKUPS + 1, "{fetches} fetches");
        assert_eq!(kinds(&report.issues()), [IssueKind::SpfTooManyLookups]);
    }

    #[test]
    fn self_include_is_a_loop() {
        let root = spf("v=spf1 include:Example.com. -all");
        let report = root.count_lookups("example.com", |_| None);
        assert_eq!(report.loops, ["Example.com."]);
    }
}
