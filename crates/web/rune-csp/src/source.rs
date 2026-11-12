//! Source expressions (CSP3 §2.3.1, `source-expression`).

use std::fmt;

/// A quoted keyword source such as `'self'` or `'unsafe-inline'`.
///
/// Keywords are matched ASCII case-insensitively and serialize in
/// lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Keyword {
    /// `'self'`: the document's own origin.
    SelfOrigin,
    /// `'unsafe-inline'`: inline scripts, styles and event handlers.
    UnsafeInline,
    /// `'unsafe-eval'`: `eval()` and similar string-to-code sinks.
    UnsafeEval,
    /// `'unsafe-hashes'`: hashes also match event handlers and `style`
    /// attributes.
    UnsafeHashes,
    /// `'strict-dynamic'`: trust propagates from nonced or hashed scripts
    /// to the scripts they load; allowlists are ignored.
    StrictDynamic,
    /// `'report-sample'`: include a sample of the violating code in reports.
    ReportSample,
    /// `'unsafe-allow-redirects'`.
    UnsafeAllowRedirects,
    /// `'wasm-unsafe-eval'`: WebAssembly compilation, without JS `eval`.
    WasmUnsafeEval,
    /// `'inline-speculation-rules'`.
    InlineSpeculationRules,
}

impl Keyword {
    /// Every keyword, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::SelfOrigin,
        Self::UnsafeInline,
        Self::UnsafeEval,
        Self::UnsafeHashes,
        Self::StrictDynamic,
        Self::ReportSample,
        Self::UnsafeAllowRedirects,
        Self::WasmUnsafeEval,
        Self::InlineSpeculationRules,
    ];

    /// The keyword without quotes, in lowercase (e.g. `unsafe-inline`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SelfOrigin => "self",
            Self::UnsafeInline => "unsafe-inline",
            Self::UnsafeEval => "unsafe-eval",
            Self::UnsafeHashes => "unsafe-hashes",
            Self::StrictDynamic => "strict-dynamic",
            Self::ReportSample => "report-sample",
            Self::UnsafeAllowRedirects => "unsafe-allow-redirects",
            Self::WasmUnsafeEval => "wasm-unsafe-eval",
            Self::InlineSpeculationRules => "inline-speculation-rules",
        }
    }

    /// Looks up a keyword by its unquoted name, ASCII case-insensitively.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.name().eq_ignore_ascii_case(name))
    }
}

/// The digest algorithm of a hash source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Every algorithm.
    pub const ALL: [Self; 3] = [Self::Sha256, Self::Sha384, Self::Sha512];

    /// The lowercase name used in a hash source (e.g. `sha256`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// Length of the digest in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// The port of a [`HostSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Port {
    /// An explicit port number.
    Number(u16),
    /// `*`: any port.
    Wildcard,
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::Wildcard => f.write_str("*"),
        }
    }
}

/// A host source: `[scheme://]host[:port][/path]`.
///
/// The scheme and host are stored in lowercase; the path is kept as written.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HostSource {
    /// The scheme, when the source names one (`https` in
    /// `https://example.com`).
    pub scheme: Option<String>,
    /// The host: `*`, `*.example.com` or `example.com`.
    pub host: String,
    /// The port, when the source names one.
    pub port: Option<Port>,
    /// The path, starting with `/`, when the source names one.
    pub path: Option<String>,
}

impl HostSource {
    /// `true` when the host is the bare wildcard `*`.
    #[must_use]
    pub fn is_any_host(&self) -> bool {
        self.host == "*"
    }

    /// `true` when the host is a wildcard over a single label, such as
    /// `*.com`, which matches every site under a top-level domain.
    #[must_use]
    pub fn is_tld_wildcard(&self) -> bool {
        self.host
            .strip_prefix("*.")
            .map(|rest| rest.trim_end_matches('.'))
            .is_some_and(|rest| !rest.contains('.'))
    }
}

impl fmt::Display for HostSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scheme) = &self.scheme {
            write!(f, "{scheme}://")?;
        }
        f.write_str(&self.host)?;
        if let Some(port) = &self.port {
            write!(f, ":{port}")?;
        }
        if let Some(path) = &self.path {
            f.write_str(path)?;
        }
        Ok(())
    }
}

/// One source expression of a source list.
///
/// Parsing never fails: a token that matches no production of the CSP
/// grammar becomes [`Source::Invalid`], which browsers ignore.
///
/// ```
/// use rune_csp::{HashAlgorithm, Keyword, Source};
///
/// assert_eq!(Source::parse("'SELF'"), Source::Keyword(Keyword::SelfOrigin));
/// assert_eq!(Source::parse("https:"), Source::Scheme("https".into()));
/// assert!(matches!(
///     Source::parse("'sha256-abc='"),
///     Source::Hash { algorithm: HashAlgorithm::Sha256, .. }
/// ));
/// assert_eq!(Source::parse("HTTPS://Example.COM:443").to_string(), "https://example.com:443");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// `'none'`: matches nothing.
    None,
    /// A quoted keyword such as `'self'`.
    Keyword(Keyword),
    /// `'nonce-<value>'`, holding the base64 value.
    Nonce(String),
    /// `'<algorithm>-<value>'`, holding the base64 digest.
    Hash {
        /// The digest algorithm.
        algorithm: HashAlgorithm,
        /// The base64 digest as written.
        value: String,
    },
    /// A scheme source such as `https:` (stored without the colon, in
    /// lowercase).
    Scheme(String),
    /// A host source.
    Host(HostSource),
    /// A token that is not a valid source expression, kept verbatim.
    Invalid(String),
}

impl Source {
    /// Parses one whitespace-free token.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        parse_token(token).unwrap_or_else(|| Self::Invalid(token.to_owned()))
    }

    /// `true` for a nonce or hash source.
    #[must_use]
    pub const fn is_nonce_or_hash(&self) -> bool {
        matches!(self, Self::Nonce(_) | Self::Hash { .. })
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("'none'"),
            Self::Keyword(k) => write!(f, "'{}'", k.name()),
            Self::Nonce(v) => write!(f, "'nonce-{v}'"),
            Self::Hash { algorithm, value } => write!(f, "'{}-{value}'", algorithm.name()),
            Self::Scheme(s) => write!(f, "{s}:"),
            Self::Host(h) => h.fmt(f),
            Self::Invalid(t) => f.write_str(t),
        }
    }
}

fn parse_token(token: &str) -> Option<Source> {
    if let Some(inner) = token.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')) {
        return parse_quoted(inner);
    }
    if !token.bytes().all(|b| b.is_ascii_graphic()) || token.contains('\'') {
        return None;
    }
    if let Some(scheme) = token.strip_suffix(':') {
        return is_scheme(scheme).then(|| Source::Scheme(scheme.to_ascii_lowercase()));
    }
    parse_host_source(token).map(Source::Host)
}

fn parse_quoted(inner: &str) -> Option<Source> {
    if inner.eq_ignore_ascii_case("none") {
        return Some(Source::None);
    }
    if let Some(keyword) = Keyword::from_name(inner) {
        return Some(Source::Keyword(keyword));
    }
    let (prefix, value) = inner.split_once('-')?;
    if !is_base64_value(value) {
        return None;
    }
    if prefix.eq_ignore_ascii_case("nonce") {
        return Some(Source::Nonce(value.to_owned()));
    }
    let algorithm = HashAlgorithm::ALL
        .into_iter()
        .find(|a| a.name().eq_ignore_ascii_case(prefix))?;
    Some(Source::Hash {
        algorithm,
        value: value.to_owned(),
    })
}

/// `base64-value = 1*( ALPHA / DIGIT / "+" / "/" / "-" / "_" ) *2( "=" )`
fn is_base64_value(value: &str) -> bool {
    let body = value.trim_end_matches('=');
    let padding = value.len() - body.len();
    !body.is_empty()
        && padding <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_'))
}

/// `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986).
fn is_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

/// `host-part = "*" / [ "*." ] 1*host-char *( "." 1*host-char ) [ "." ]`
fn is_host(host: &str) -> bool {
    if host == "*" {
        return true;
    }
    let rest = host.strip_prefix("*.").unwrap_or(host);
    let rest = rest.strip_suffix('.').unwrap_or(rest);
    !rest.is_empty()
        && rest.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn parse_host_source(token: &str) -> Option<HostSource> {
    let (scheme, rest) = match token.split_once("://") {
        Some((scheme, rest)) => {
            if !is_scheme(scheme) {
                return None;
            }
            (Some(scheme.to_ascii_lowercase()), rest)
        }
        None => (None, token),
    };
    let host_end = rest.find([':', '/']).unwrap_or(rest.len());
    let (host, mut rest) = rest.split_at(host_end);
    if !is_host(host) {
        return None;
    }
    let mut port = None;
    if let Some(after) = rest.strip_prefix(':') {
        let port_end = after.find('/').unwrap_or(after.len());
        let (text, remaining) = after.split_at(port_end);
        port = Some(if text == "*" {
            Port::Wildcard
        } else if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
            Port::Number(text.parse().ok()?)
        } else {
            return None;
        });
        rest = remaining;
    }
    let path = if rest.is_empty() {
        None
    } else {
        Some(rest.to_owned())
    };
    Some(HostSource {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(scheme: Option<&str>, host: &str, port: Option<Port>, path: Option<&str>) -> Source {
        Source::Host(HostSource {
            scheme: scheme.map(str::to_owned),
            host: host.to_owned(),
            port,
            path: path.map(str::to_owned),
        })
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert_eq!(Source::parse("'none'"), Source::None);
        assert_eq!(Source::parse("'NoNe'"), Source::None);
        for k in Keyword::ALL {
            let upper = format!("'{}'", k.name().to_ascii_uppercase());
            assert_eq!(Source::parse(&upper), Source::Keyword(k));
            assert_eq!(Source::Keyword(k).to_string(), format!("'{}'", k.name()));
        }
    }

    #[test]
    fn nonces_and_hashes() {
        assert_eq!(
            Source::parse("'nonce-r4nd0m+/_-=='"),
            Source::Nonce("r4nd0m+/_-==".into())
        );
        assert_eq!(
            Source::parse("'SHA384-AbC='"),
            Source::Hash {
                algorithm: HashAlgorithm::Sha384,
                value: "AbC=".into()
            }
        );
        assert_eq!(Source::parse("'SHA384-AbC='").to_string(), "'sha384-AbC='");
        for bad in [
            "'nonce-'",
            "'nonce-a==='",
            "'nonce-a b'",
            "'md5-abc'",
            "'sha256-'",
        ] {
            assert_eq!(Source::parse(bad), Source::Invalid(bad.into()), "{bad}");
        }
    }

    #[test]
    fn schemes() {
        assert_eq!(Source::parse("HTTPS:"), Source::Scheme("https".into()));
        assert_eq!(Source::parse("data:"), Source::Scheme("data".into()));
        assert_eq!(Source::parse("1http:"), Source::Invalid("1http:".into()));
        assert_eq!(Source::parse(":"), Source::Invalid(":".into()));
    }

    #[test]
    fn hosts() {
        assert_eq!(Source::parse("*"), host(None, "*", None, None));
        assert_eq!(
            Source::parse("https://*.Example.com:*/a/B"),
            host(
                Some("https"),
                "*.example.com",
                Some(Port::Wildcard),
                Some("/a/B")
            )
        );
        assert_eq!(
            Source::parse("localhost:8080"),
            host(None, "localhost", Some(Port::Number(8080)), None)
        );
        assert_eq!(
            Source::parse("example.com."),
            host(None, "example.com.", None, None)
        );
        assert_eq!(
            Source::parse("cdn.example/x.js"),
            host(None, "cdn.example", None, Some("/x.js"))
        );
        for bad in [
            "https://",
            "exa_mple.com",
            "a..b",
            "*example.com",
            "example.com:65536",
            "example.com:8x",
            "[::1]",
            "self'",
            "caf\u{e9}.fr",
            "ftp+://",
        ] {
            assert_eq!(Source::parse(bad), Source::Invalid(bad.into()), "{bad}");
        }
    }

    #[test]
    fn tld_wildcards() {
        let Source::Host(h) = Source::parse("*.com") else {
            panic!("host")
        };
        assert!(h.is_tld_wildcard());
        let Source::Host(h) = Source::parse("*.example.com") else {
            panic!("host")
        };
        assert!(!h.is_tld_wildcard());
        assert!(!h.is_any_host());
    }
}
