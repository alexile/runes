//! Dedup keys: one string per resource, for crawl frontiers and site maps.

use std::fmt;

use url::Url;

use crate::Error;
use crate::canon::{Options, canonicalize_url};
use crate::query::QueryParams;

/// How the query contributes to a [`DedupKey`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum QueryKey {
    /// The query as canonicalized, parameter order included.
    Exact,
    /// Parameters sorted by name (stable: repeated names keep their order),
    /// empty pieces dropped.
    #[default]
    Sorted,
    /// Only the sorted, de-duplicated parameter names: `?id=1` and `?id=2`
    /// share a key. Useful to test each endpoint and parameter set once.
    Names,
    /// The query is ignored.
    Ignore,
}

/// Settings for [`dedup_key`].
///
/// The defaults treat as one resource the URLs that differ only in what
/// [`Options::crawler`] normalizes and in query parameter order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent key switches, set through builders"
)]
pub struct KeyOptions {
    /// Canonicalization applied before the key is built.
    pub canonical: Options,
    /// Leave the scheme out, so `http://h/` and `https://h/` share a key.
    pub ignore_scheme: bool,
    /// Leave a leading `www.` out of the host.
    pub ignore_www: bool,
    /// Treat `/a/` and `/a` as one path.
    pub ignore_trailing_slash: bool,
    /// Compare paths ASCII case-insensitively (IIS and other
    /// case-insensitive servers).
    pub case_insensitive_path: bool,
    /// How the query contributes.
    pub query: QueryKey,
    /// Keep the fragment in the key (single-page apps that route on it).
    pub include_fragment: bool,
    /// Keep the user name and password in the key.
    pub include_userinfo: bool,
}

impl Default for KeyOptions {
    fn default() -> Self {
        Self {
            canonical: Options::crawler(),
            ignore_scheme: false,
            ignore_www: false,
            ignore_trailing_slash: false,
            case_insensitive_path: false,
            query: QueryKey::Sorted,
            include_fragment: false,
            include_userinfo: false,
        }
    }
}

impl KeyOptions {
    /// Sets [`KeyOptions::canonical`].
    #[must_use]
    pub fn with_canonical(mut self, options: Options) -> Self {
        self.canonical = options;
        self
    }

    /// Sets [`KeyOptions::ignore_scheme`].
    #[must_use]
    pub const fn with_ignore_scheme(mut self, yes: bool) -> Self {
        self.ignore_scheme = yes;
        self
    }

    /// Sets [`KeyOptions::ignore_www`].
    #[must_use]
    pub const fn with_ignore_www(mut self, yes: bool) -> Self {
        self.ignore_www = yes;
        self
    }

    /// Sets [`KeyOptions::ignore_trailing_slash`].
    #[must_use]
    pub const fn with_ignore_trailing_slash(mut self, yes: bool) -> Self {
        self.ignore_trailing_slash = yes;
        self
    }

    /// Sets [`KeyOptions::case_insensitive_path`].
    #[must_use]
    pub const fn with_case_insensitive_path(mut self, yes: bool) -> Self {
        self.case_insensitive_path = yes;
        self
    }

    /// Sets [`KeyOptions::query`].
    #[must_use]
    pub const fn with_query(mut self, query: QueryKey) -> Self {
        self.query = query;
        self
    }

    /// Sets [`KeyOptions::include_fragment`].
    #[must_use]
    pub const fn with_include_fragment(mut self, yes: bool) -> Self {
        self.include_fragment = yes;
        self
    }

    /// Sets [`KeyOptions::include_userinfo`].
    #[must_use]
    pub const fn with_include_userinfo(mut self, yes: bool) -> Self {
        self.include_userinfo = yes;
        self
    }

    /// The key of `url`; see [`dedup_key`].
    #[must_use]
    pub fn key(&self, url: &Url) -> DedupKey {
        dedup_key_url(url, self)
    }
}

/// A string that is equal for two URLs exactly when [`KeyOptions`] treats
/// them as the same resource.
///
/// It looks like a URL (`//host/path` when the
/// scheme is ignored) but is meant for comparing and hashing, not fetching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DedupKey(String);

impl DedupKey {
    /// The key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The key text, owned.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for DedupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for DedupKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Parses `input` and builds its dedup key.
///
/// ```
/// use rune_url::{KeyOptions, dedup_key};
///
/// let options = KeyOptions::default();
/// let a = dedup_key("https://Example.com/a?b=2&a=1&utm_source=x#top", &options)?;
/// let b = dedup_key("https://example.com:443/a/../a?a=1&b=2", &options)?;
/// assert_eq!(a, b);
/// assert_eq!(a.as_str(), "https://example.com/a?a=1&b=2");
/// # Ok::<(), rune_url::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Parse`] if `input` is not a valid absolute URL.
pub fn dedup_key(input: &str, options: &KeyOptions) -> Result<DedupKey, Error> {
    let url = Url::parse(input)?;
    Ok(dedup_key_url(&url, options))
}

/// Builds the dedup key of an already parsed URL.
#[must_use]
pub fn dedup_key_url(url: &Url, options: &KeyOptions) -> DedupKey {
    let url = canonicalize_url(url, &options.canonical);
    if url.cannot_be_a_base() {
        return DedupKey(opaque_key(&url, options));
    }
    let mut key = String::with_capacity(url.as_str().len());
    if !options.ignore_scheme {
        key.push_str(url.scheme());
        key.push(':');
    }
    if url.has_host() || url.scheme() == "file" {
        key.push_str("//");
        if options.include_userinfo && (!url.username().is_empty() || url.password().is_some()) {
            key.push_str(url.username());
            if let Some(password) = url.password() {
                key.push(':');
                key.push_str(password);
            }
            key.push('@');
        }
        if let Some(host) = url.host_str() {
            let host = if options.ignore_www {
                host.strip_prefix("www.")
                    .filter(|rest| rest.contains('.'))
                    .unwrap_or(host)
            } else {
                host
            };
            key.push_str(host);
        }
        if let Some(port) = url.port() {
            key.push(':');
            key.push_str(&port.to_string());
        }
    }
    let mut path = url.path();
    if options.ignore_trailing_slash && path.len() > 1 {
        path = path.trim_end_matches('/');
        if path.is_empty() {
            path = "/";
        }
    }
    if options.case_insensitive_path {
        key.push_str(&path.to_ascii_lowercase());
    } else {
        key.push_str(path);
    }
    push_query(&mut key, &url, options.query);
    if options.include_fragment
        && let Some(fragment) = url.fragment()
    {
        key.push('#');
        key.push_str(fragment);
    }
    DedupKey(key)
}

fn opaque_key(url: &Url, options: &KeyOptions) -> String {
    let mut key = String::new();
    if !options.ignore_scheme {
        key.push_str(url.scheme());
        key.push(':');
    }
    key.push_str(url.path());
    push_query(&mut key, url, options.query);
    if options.include_fragment
        && let Some(fragment) = url.fragment()
    {
        key.push('#');
        key.push_str(fragment);
    }
    key
}

fn push_query(key: &mut String, url: &Url, mode: QueryKey) {
    let Some(query) = url.query() else {
        return;
    };
    let text = match mode {
        QueryKey::Exact => query.to_owned(),
        QueryKey::Sorted => {
            let mut params = QueryParams::parse(query);
            params.remove_empty();
            params.sort_by_name();
            params.to_string()
        }
        QueryKey::Names => {
            let params = QueryParams::parse(query);
            let mut names: Vec<&str> = params
                .iter()
                .filter(|param| !param.is_empty())
                .map(crate::QueryParam::raw_name)
                .collect();
            names.sort_unstable();
            names.dedup();
            names.join("&")
        }
        QueryKey::Ignore => return,
    };
    push_text(key, &text);
}

fn push_text(key: &mut String, query: &str) {
    if !query.is_empty() {
        key.push('?');
        key.push_str(query);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(input: &str, options: &KeyOptions) -> String {
        dedup_key(input, options).unwrap().into_string()
    }

    #[test]
    fn default_key() {
        let options = KeyOptions::default();
        assert_eq!(key("HTTP://H:80/a?b&a=1#f", &options), "http://h/a?a=1&b");
        assert_eq!(key("http://u:p@h:8080/", &options), "http://h:8080/");
        assert_eq!(key("http://h/?", &options), "http://h/");
        assert_eq!(
            key("mailto:a@b?subject=x#y", &options),
            "mailto:a@b?subject=x"
        );
        assert_eq!(key("file:///etc/passwd", &options), "file:///etc/passwd");
    }

    #[test]
    fn options_change_the_key() {
        let loose = KeyOptions::default()
            .with_ignore_scheme(true)
            .with_ignore_www(true)
            .with_ignore_trailing_slash(true)
            .with_case_insensitive_path(true);
        assert_eq!(key("https://www.h.com/A/B/", &loose), "//h.com/a/b");
        assert_eq!(key("http://h.com/a/b", &loose), "//h.com/a/b");
        assert_eq!(key("http://www.com/", &loose), "//www.com/");
        assert_eq!(key("http://h.com//", &loose), "//h.com/");

        let names = KeyOptions::default().with_query(QueryKey::Names);
        assert_eq!(key("http://h/?id=2&b=1&id=3", &names), "http://h/?b&id");
        let ignore = KeyOptions::default().with_query(QueryKey::Ignore);
        assert_eq!(key("http://h/p?id=2", &ignore), "http://h/p");
        let exact = KeyOptions::default().with_query(QueryKey::Exact);
        assert_eq!(key("http://h/p?b&a", &exact), "http://h/p?b&a");

        let full = KeyOptions::default()
            .with_include_fragment(true)
            .with_include_userinfo(true)
            .with_canonical(Options::default());
        assert_eq!(key("http://u:p@h/#f", &full), "http://u:p@h/#f");
    }

    #[test]
    fn key_method_matches_function() {
        let options = KeyOptions::default();
        let url = Url::parse("http://h/x").unwrap();
        assert_eq!(options.key(&url), dedup_key_url(&url, &options));
        assert_eq!(options.key(&url).to_string(), "http://h/x");
        assert_eq!(options.key(&url).as_ref(), "http://h/x");
    }
}
