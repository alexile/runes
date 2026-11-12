//! robots.txt parsing and matching ([RFC 9309](https://www.rfc-editor.org/rfc/rfc9309)).

use std::borrow::Cow;
use std::time::Duration;

/// How many bytes of a robots.txt file are parsed; the rest is ignored.
///
/// RFC 9309 §2.5 requires crawlers to parse at least 500 KiB, and Google
/// stops there.
pub const MAX_ROBOTS_LEN: usize = 500 * 1024;

/// The path that is always allowed (RFC 9309 §2.2.2).
pub const ROBOTS_PATH: &str = "/robots.txt";

/// Whether a rule allows or disallows the paths it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RuleKind {
    /// `Allow:` — matching paths may be crawled.
    Allow,
    /// `Disallow:` — matching paths must not be crawled.
    Disallow,
}

/// One `Allow` or `Disallow` rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Rule {
    /// Allow or disallow.
    pub kind: RuleKind,
    /// The path pattern, normalised: bytes outside printable ASCII are
    /// percent-encoded and existing `%xx` escapes use uppercase hex. `*`
    /// matches any sequence of bytes and a trailing `$` anchors the end.
    pub pattern: String,
    /// 1-based line number in the source file.
    pub line: usize,
}

impl Rule {
    /// Creates a rule, normalising `pattern` the way the parser does.
    #[must_use]
    pub fn new(kind: RuleKind, pattern: &str) -> Self {
        Self {
            kind,
            pattern: escape(pattern.as_bytes()).into_owned(),
            line: 0,
        }
    }

    /// Whether the rule matches `path` (a path with optional query, as
    /// returned by [`robots_path`]).
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        pattern_matches(escape(path.as_bytes()).as_bytes(), self.pattern.as_bytes())
    }

    /// Match priority: the length of the pattern in bytes (RFC 9309 §2.2.2,
    /// "the most specific match").
    #[must_use]
    pub const fn priority(&self) -> usize {
        self.pattern.len()
    }
}

/// A group: one or more `User-agent` lines and the rules that follow them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Group {
    /// The `User-agent` values as written (trimmed).
    pub user_agents: Vec<String>,
    /// The `Allow` / `Disallow` rules, in file order. Rules with an empty
    /// pattern match nothing and are dropped.
    pub rules: Vec<Rule>,
    /// The first valid `Crawl-delay` of the group (a non-standard but
    /// widely used extension).
    pub crawl_delay: Option<Duration>,
}

impl Group {
    /// Whether the group applies to every crawler (`User-agent: *`).
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.user_agents
            .iter()
            .any(|agent| is_wildcard_agent(agent))
    }

    /// Whether the group names `product_token` explicitly (case-insensitive,
    /// comparing product tokens: `Googlebot/2.1` names `googlebot`).
    #[must_use]
    pub fn names(&self, product_token: &str) -> bool {
        !product_token.is_empty()
            && self
                .user_agents
                .iter()
                .any(|agent| agent_token(agent).eq_ignore_ascii_case(product_token))
    }
}

/// The outcome of checking a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verdict<'a> {
    /// Whether the path may be crawled.
    pub allowed: bool,
    /// The rule that decided, or `None` when no rule matched (or the path is
    /// [`ROBOTS_PATH`]).
    pub rule: Option<&'a Rule>,
}

/// A parsed robots.txt file.
///
/// Parsing never fails: lines that are not understood are ignored, as RFC
/// 9309 requires. An empty `Robots` (the [`Default`]) allows everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Robots {
    /// The groups, in file order.
    pub groups: Vec<Group>,
    /// `Sitemap:` URLs, in file order. They are global, not part of a group.
    pub sitemaps: Vec<String>,
}

impl Robots {
    /// Parses robots.txt text. See [`Robots::parse_bytes`].
    #[must_use]
    pub fn parse(text: &str) -> Self {
        Self::parse_bytes(text.as_bytes())
    }

    /// Parses a robots.txt body.
    ///
    /// Accepts LF, CR and CRLF line endings and a UTF-8 byte-order mark,
    /// ignores everything past [`MAX_ROBOTS_LEN`], and tolerates the
    /// directive misspellings Google's parser accepts (`disalow`,
    /// `useragent`, `site-map`, …) and a missing colon (`Disallow /x`).
    #[must_use]
    pub fn parse_bytes(body: &[u8]) -> Self {
        let body = body.get(..MAX_ROBOTS_LEN).unwrap_or(body);
        let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body);
        let mut robots = Self::default();
        let mut current: Option<Group> = None;
        // True while consecutive `User-agent` lines are building one group.
        let mut collecting_agents = false;
        for (index, line) in lines(body).enumerate() {
            let Some((key, value)) = split_key_value(line) else {
                continue;
            };
            match Directive::from_key(key) {
                Directive::UserAgent => {
                    if !collecting_agents {
                        robots.groups.extend(current.take());
                        current = Some(Group::default());
                        collecting_agents = true;
                    }
                    if let Some(group) = current.as_mut() {
                        group
                            .user_agents
                            .push(String::from_utf8_lossy(value).into_owned());
                    }
                }
                directive @ (Directive::Allow | Directive::Disallow) => {
                    collecting_agents = false;
                    // Rules outside any group are ignored (RFC 9309 §2.1).
                    if let (Some(group), false) = (current.as_mut(), value.is_empty()) {
                        group.rules.push(Rule {
                            kind: if directive == Directive::Allow {
                                RuleKind::Allow
                            } else {
                                RuleKind::Disallow
                            },
                            pattern: escape(value).into_owned(),
                            line: index + 1,
                        });
                    }
                }
                Directive::CrawlDelay => {
                    collecting_agents = false;
                    if let Some(group) = current.as_mut().filter(|g| g.crawl_delay.is_none()) {
                        group.crawl_delay = parse_delay(value);
                    }
                }
                Directive::Sitemap => {
                    if !value.is_empty() {
                        robots
                            .sitemaps
                            .push(String::from_utf8_lossy(value).into_owned());
                    }
                }
                Directive::Other => {}
            }
        }
        robots.groups.extend(current);
        robots
    }

    /// A robots.txt that allows everything (what an unavailable file means).
    #[must_use]
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// A robots.txt that disallows everything (what an unreachable file
    /// means).
    #[must_use]
    pub fn disallow_all() -> Self {
        Self {
            groups: vec![Group {
                user_agents: vec!["*".to_owned()],
                rules: vec![Rule::new(RuleKind::Disallow, "/")],
                crawl_delay: None,
            }],
            sitemaps: Vec::new(),
        }
    }

    /// Interprets a fetch of `/robots.txt` by its HTTP status (RFC 9309
    /// §2.3.1).
    ///
    /// - 2xx: the body is parsed.
    /// - 3xx (redirects the caller did not or could not resolve) and 4xx:
    ///   the file is *unavailable*, so everything is allowed. 429 Too Many
    ///   Requests is the exception and is treated like 5xx, as Google does.
    /// - 5xx and any other status: the server is *unreachable*, so
    ///   everything is disallowed.
    #[must_use]
    pub fn from_response(status: u16, body: &[u8]) -> Self {
        match status {
            200..=299 => Self::parse_bytes(body),
            429 => Self::disallow_all(),
            300..=499 => Self::allow_all(),
            _ => Self::disallow_all(),
        }
    }

    /// The groups that apply to `user_agent`.
    ///
    /// `user_agent` is the crawler's product token (`Googlebot`); a full
    /// `User-Agent` value starting with the token (`Googlebot/2.1 (+…)`) works
    /// too. Every group naming the token applies, merged (RFC 9309 §2.2.1);
    /// otherwise every `*` group; otherwise none.
    pub fn groups_for<'a>(&'a self, user_agent: &str) -> impl Iterator<Item = &'a Group> + 'a {
        let token = agent_token(user_agent).to_owned();
        let specific = self.groups.iter().any(|group| group.names(&token));
        self.groups.iter().filter(move |group| {
            if specific {
                group.names(&token)
            } else {
                group.is_wildcard()
            }
        })
    }

    /// Checks `path` for `user_agent` and reports the deciding rule.
    ///
    /// `path` is the URL path with optional query (`/a/b?x=1`); a full URL
    /// is reduced with [`robots_path`] first. The longest matching pattern
    /// wins; on a tie `Allow` wins. [`ROBOTS_PATH`] is always allowed.
    #[must_use]
    pub fn verdict(&self, user_agent: &str, path: &str) -> Verdict<'_> {
        let path = robots_path(path);
        if path == ROBOTS_PATH {
            return Verdict {
                allowed: true,
                rule: None,
            };
        }
        let escaped = escape(path.as_bytes());
        let mut best: Option<&Rule> = None;
        for rule in self.groups_for(user_agent).flat_map(|group| &group.rules) {
            let better = best.is_none_or(|current| {
                rule.priority() > current.priority()
                    || (rule.priority() == current.priority()
                        && rule.kind == RuleKind::Allow
                        && current.kind == RuleKind::Disallow)
            });
            if better && pattern_matches(escaped.as_bytes(), rule.pattern.as_bytes()) {
                best = Some(rule);
            }
        }
        Verdict {
            allowed: best.is_none_or(|rule| rule.kind == RuleKind::Allow),
            rule: best,
        }
    }

    /// Whether `user_agent` may crawl `path` (a path or a full URL).
    #[must_use]
    pub fn is_allowed(&self, user_agent: &str, path: &str) -> bool {
        self.verdict(user_agent, path).allowed
    }

    /// The crawl delay for `user_agent`: the first `Crawl-delay` among the
    /// groups that apply to it.
    #[must_use]
    pub fn crawl_delay(&self, user_agent: &str) -> Option<Duration> {
        self.groups_for(user_agent)
            .find_map(|group| group.crawl_delay)
    }
}

/// Reduces a URL to the part robots.txt rules match: the path plus query,
/// without the fragment.
///
/// A value starting with `/` is taken as a path already. An absolute URL
/// (`scheme://authority/...`) loses its scheme and authority. An empty path
/// becomes `/`.
///
/// ```
/// use rune_robots::robots_path;
///
/// assert_eq!(robots_path("https://example.com/a/b?x=1#top"), "/a/b?x=1");
/// assert_eq!(robots_path("https://example.com"), "/");
/// assert_eq!(robots_path("https://example.com?q"), "/?q");
/// assert_eq!(robots_path("/p#f"), "/p");
/// ```
#[must_use]
pub fn robots_path(url: &str) -> Cow<'_, str> {
    let url = url.split_once('#').map_or(url, |(before, _)| before);
    let rest = match url.split_once("://") {
        Some((scheme, rest))
            if !scheme.is_empty()
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) =>
        {
            rest.find(['/', '?']).map_or("", |at| &rest[at..])
        }
        _ => url,
    };
    if rest.starts_with('/') {
        Cow::Borrowed(rest)
    } else {
        Cow::Owned(format!("/{rest}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Directive {
    UserAgent,
    Allow,
    Disallow,
    CrawlDelay,
    Sitemap,
    Other,
}

impl Directive {
    fn from_key(key: &[u8]) -> Self {
        const USER_AGENT: &[&[u8]] = &[b"user-agent", b"useragent", b"user agent"];
        const DISALLOW: &[&[u8]] = &[
            b"disallow",
            b"dissallow",
            b"dissalow",
            b"disalow",
            b"diasllow",
            b"disallaw",
        ];
        const CRAWL_DELAY: &[&[u8]] = &[b"crawl-delay", b"crawldelay", b"crawl delay"];
        const SITEMAP: &[&[u8]] = &[b"sitemap", b"site-map"];
        let is = |names: &[&[u8]]| names.iter().any(|name| key.eq_ignore_ascii_case(name));
        if is(USER_AGENT) {
            Self::UserAgent
        } else if key.eq_ignore_ascii_case(b"allow") {
            Self::Allow
        } else if is(DISALLOW) {
            Self::Disallow
        } else if is(CRAWL_DELAY) {
            Self::CrawlDelay
        } else if is(SITEMAP) {
            Self::Sitemap
        } else {
            Self::Other
        }
    }
}

/// Splits on LF, CR and CRLF.
fn lines(body: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(body);
    std::iter::from_fn(move || {
        let current = rest?;
        let Some(at) = current.iter().position(|&b| b == b'\n' || b == b'\r') else {
            rest = None;
            return Some(current);
        };
        let skip = if current.get(at..at + 2) == Some(b"\r\n") {
            2
        } else {
            1
        };
        rest = current.get(at + skip..);
        current.get(..at)
    })
}

/// `key: value` (or `key value` with exactly two words), comments removed
/// and both sides trimmed.
fn split_key_value(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let line = line
        .iter()
        .position(|&b| b == b'#')
        .map_or(line, |at| &line[..at])
        .trim_ascii();
    let (key, value) = if let Some(at) = line.iter().position(|&b| b == b':') {
        (&line[..at], &line[at + 1..])
    } else {
        let at = line.iter().position(u8::is_ascii_whitespace)?;
        let value = line[at..].trim_ascii();
        if value.iter().any(u8::is_ascii_whitespace) {
            return None;
        }
        (&line[..at], value)
    };
    let key = key.trim_ascii();
    (!key.is_empty()).then(|| (key, value.trim_ascii()))
}

fn parse_delay(value: &[u8]) -> Option<Duration> {
    let seconds: f64 = std::str::from_utf8(value).ok()?.parse().ok()?;
    Duration::try_from_secs_f64(seconds).ok()
}

/// The product token of a user-agent value: the leading run of
/// `[A-Za-z_-]` (RFC 9309 §2.2.1).
fn agent_token(agent: &str) -> &str {
    let agent = agent.trim_start();
    let end = agent
        .find(|c: char| !(c.is_ascii_alphabetic() || c == '_' || c == '-'))
        .unwrap_or(agent.len());
    &agent[..end]
}

fn is_wildcard_agent(agent: &str) -> bool {
    agent
        .trim()
        .strip_prefix('*')
        .is_some_and(|rest| rest.trim_start().is_empty())
}

/// Percent-encodes bytes outside printable ASCII and uppercases the hex of
/// existing `%xx` escapes, so patterns and paths compare consistently.
fn escape(bytes: &[u8]) -> Cow<'_, str> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let needs_escape = |b: u8| !(0x21..0x7F).contains(&b);
    let clean = bytes.iter().enumerate().all(|(i, &b)| {
        !needs_escape(b)
            && (b != b'%'
                || !matches!(
                    bytes.get(i + 1..i + 3),
                    Some([h, l]) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit()
                        && (h.is_ascii_lowercase() || l.is_ascii_lowercase())
                ))
    });
    if clean {
        // All bytes are printable ASCII here.
        return String::from_utf8_lossy(bytes);
    }
    let mut out = String::with_capacity(bytes.len() + 8);
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match bytes.get(i + 1..i + 3) {
            Some(&[h, l]) if b == b'%' && h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
                out.push('%');
                out.push(char::from(h.to_ascii_uppercase()));
                out.push(char::from(l.to_ascii_uppercase()));
                i += 3;
                continue;
            }
            _ => {}
        }
        if needs_escape(b) {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0F)]));
        } else {
            out.push(char::from(b));
        }
        i += 1;
    }
    Cow::Owned(out)
}

/// RFC 9309 pattern matching: `*` matches any byte sequence, a trailing `$`
/// anchors the end, and an unanchored pattern matches as a prefix.
///
/// Tracks the set of path offsets reachable after each pattern byte, so it
/// runs in `O(pattern × path)` with no backtracking.
fn pattern_matches(path: &[u8], pattern: &[u8]) -> bool {
    let (pattern, anchored) = pattern
        .strip_suffix(b"$")
        .map_or((pattern, false), |p| (p, true));
    // Sorted, distinct offsets into `path`.
    let mut offsets: Vec<usize> = vec![0];
    let mut previous_star = false;
    for &c in pattern {
        if c == b'*' {
            if !previous_star {
                let start = offsets.first().copied().unwrap_or(0);
                offsets = (start..=path.len()).collect();
            }
            previous_star = true;
            continue;
        }
        previous_star = false;
        offsets.retain(|&at| path.get(at) == Some(&c));
        if offsets.is_empty() {
            return false;
        }
        for at in &mut offsets {
            *at += 1;
        }
    }
    !anchored || offsets.last() == Some(&path.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        let m = |path: &str, pattern: &str| pattern_matches(path.as_bytes(), pattern.as_bytes());
        assert!(m("/fish", "/fish"));
        assert!(m("/fish.html", "/fish"));
        assert!(m("/fish/salmon.html", "/fish"));
        assert!(m("/fishheads", "/fish"));
        assert!(!m("/Fish.asp", "/fish"));
        assert!(!m("/catfish", "/fish"));
        assert!(m("/fish/", "/fish/"));
        assert!(!m("/fish", "/fish/"));
        assert!(m("/filename.php", "/*.php"));
        assert!(m("/folder/filename.php?parameters", "/*.php"));
        assert!(!m("/windows.PHP", "/*.php"));
        assert!(m("/filename.php", "/*.php$"));
        assert!(!m("/filename.php?parameters", "/*.php$"));
        assert!(!m("/filename.php5", "/*.php$"));
        assert!(m("/fish.php", "/fish*.php"));
        assert!(m("/fishheads/catfish.php?parameters", "/fish*.php"));
        assert!(!m("/Fish.PHP", "/fish*.php"));
        assert!(m("/", "/$"));
        assert!(!m("/a", "/$"));
        assert!(m("/a$b", "/a$b"));
        assert!(m("/anything", "*"));
        assert!(m("/x", "/**x$"));
    }

    #[test]
    fn escaping() {
        assert_eq!(escape(b"/foo/bar"), "/foo/bar");
        assert_eq!(escape("/ä".as_bytes()), "/%C3%A4");
        assert_eq!(escape(b"/%c3%a4"), "/%C3%A4");
        assert_eq!(escape(b"/%zz"), "/%zz");
        assert_eq!(escape(b"/a b"), "/a%20b");
    }

    #[test]
    fn key_values() {
        assert_eq!(
            split_key_value(b"  Disallow : /x # comment"),
            Some((&b"Disallow"[..], &b"/x"[..]))
        );
        assert_eq!(
            split_key_value(b"Disallow /x"),
            Some((&b"Disallow"[..], &b"/x"[..]))
        );
        assert_eq!(split_key_value(b"Disallow /x /y"), None);
        assert_eq!(split_key_value(b"# only a comment"), None);
        assert_eq!(split_key_value(b": value"), None);
    }

    #[test]
    fn line_endings() {
        let split: Vec<_> = lines(b"a\r\nb\rc\nd").collect();
        assert_eq!(split, [&b"a"[..], b"b", b"c", b"d"]);
    }

    #[test]
    fn tokens() {
        assert_eq!(
            agent_token("Googlebot/2.1 (+http://www.google.com/bot.html)"),
            "Googlebot"
        );
        assert_eq!(agent_token("  foo_bar-baz"), "foo_bar-baz");
        assert!(is_wildcard_agent("*"));
        assert!(is_wildcard_agent(" * "));
        assert!(!is_wildcard_agent("*bot"));
    }
}
