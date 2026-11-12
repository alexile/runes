//! Query strings as ordered parameter lists, and parameter filters.

use std::fmt;

use url::Url;

/// One `name[=value]` piece of a query string, kept in its encoded form.
///
/// `a` (no value) and `a=` (empty value) are different pieces, and an empty
/// piece (between `&&`) has an empty name and no value, so splitting and
/// joining a query reproduces it byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryParam {
    name: String,
    value: Option<String>,
}

impl QueryParam {
    /// A parameter from its encoded parts, taken as they are.
    #[must_use]
    pub fn from_raw(name: impl Into<String>, value: Option<String>) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }

    /// A parameter from decoded text, percent-encoding everything outside
    /// the RFC 3986 unreserved set.
    ///
    /// ```
    /// use rune_url::QueryParam;
    ///
    /// let param = QueryParam::new("q", Some("a b&c"));
    /// assert_eq!(param.to_string(), "q=a%20b%26c");
    /// assert_eq!(param.value().as_deref(), Some("a b&c"));
    /// ```
    #[must_use]
    pub fn new(name: &str, value: Option<&str>) -> Self {
        Self {
            name: rune_url_encode::encode(name),
            value: value.map(rune_url_encode::encode),
        }
    }

    /// The encoded name.
    #[must_use]
    pub fn raw_name(&self) -> &str {
        &self.name
    }

    /// The encoded value, `None` when the piece has no `=`.
    #[must_use]
    pub fn raw_value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// The decoded name (`application/x-www-form-urlencoded` rules: `+` is
    /// a space). Invalid UTF-8 is replaced with U+FFFD.
    #[must_use]
    pub fn name(&self) -> String {
        form_decode(&self.name)
    }

    /// The decoded value, `None` when the piece has no `=`.
    #[must_use]
    pub fn value(&self) -> Option<String> {
        self.value.as_deref().map(form_decode)
    }

    /// Whether this is an empty piece (as between `&&`).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name.is_empty() && self.value.is_none()
    }

    fn parse(piece: &str) -> Self {
        match piece.split_once('=') {
            Some((name, value)) => Self::from_raw(name, Some(value.to_owned())),
            None => Self::from_raw(piece, None),
        }
    }
}

impl fmt::Display for QueryParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if let Some(value) = &self.value {
            write!(f, "={value}")?;
        }
        Ok(())
    }
}

fn form_decode(raw: &str) -> String {
    rune_url_encode::decode_bytes(raw.as_bytes()).map_or_else(
        |_| rune_url_encode::decode_lossy(raw),
        |bytes| String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// A query string split on `&`, in order.
///
/// Splitting and joining are exact inverses: `split_query(q).to_string() == q`.
///
/// ```
/// use rune_url::split_query;
///
/// let mut params = split_query("b=2&a=1&utm_source=x&a=0");
/// params.remove("utm_source");
/// params.sort_by_name();
/// assert_eq!(params.to_string(), "a=1&a=0&b=2");
/// assert_eq!(params.get("b").and_then(|p| p.value()).as_deref(), Some("2"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct QueryParams {
    params: Vec<QueryParam>,
}

/// Splits a query string (without the leading `?`) into its parameters.
#[must_use]
pub fn split_query(query: &str) -> QueryParams {
    QueryParams::parse(query)
}

/// Joins parameters back into a query string (without a leading `?`).
#[must_use]
pub fn join_query<'a>(params: impl IntoIterator<Item = &'a QueryParam>) -> String {
    let mut out = String::new();
    for (index, param) in params.into_iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(&param.name);
        if let Some(value) = &param.value {
            out.push('=');
            out.push_str(value);
        }
    }
    out
}

impl QueryParams {
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self { params: Vec::new() }
    }

    /// Splits a query string (without the leading `?`). The empty string
    /// gives an empty list.
    #[must_use]
    pub fn parse(query: &str) -> Self {
        if query.is_empty() {
            return Self::new();
        }
        Self {
            params: query.split('&').map(QueryParam::parse).collect(),
        }
    }

    /// The parameters of `url`'s query; empty when it has none.
    #[must_use]
    pub fn from_url(url: &Url) -> Self {
        url.query().map(Self::parse).unwrap_or_default()
    }

    /// Replaces `url`'s query with these parameters, removing the `?`
    /// altogether when the list is empty.
    pub fn apply_to(&self, url: &mut Url) {
        if self.params.is_empty() {
            url.set_query(None);
        } else {
            url.set_query(Some(&self.to_string()));
        }
    }

    /// Number of parameters, empty pieces included.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.params.len()
    }

    /// Whether there are no parameters.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// The parameters, in order.
    pub fn iter(&self) -> std::slice::Iter<'_, QueryParam> {
        self.params.iter()
    }

    /// The parameters as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[QueryParam] {
        &self.params
    }

    /// The first parameter whose decoded name is `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&QueryParam> {
        self.params.iter().find(|param| param.name() == name)
    }

    /// Every parameter whose decoded name is `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a QueryParam> + 'a {
        self.params.iter().filter(move |param| param.name() == name)
    }

    /// Appends a parameter.
    pub fn push(&mut self, param: QueryParam) {
        self.params.push(param);
    }

    /// Appends a parameter from decoded text; see [`QueryParam::new`].
    pub fn append(&mut self, name: &str, value: Option<&str>) {
        self.params.push(QueryParam::new(name, value));
    }

    /// Removes every parameter whose decoded name is `name`, returning how
    /// many were removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.params.len();
        self.params.retain(|param| param.name() != name);
        before - self.params.len()
    }

    /// Keeps only the parameters for which `keep` returns `true`.
    pub fn retain(&mut self, keep: impl FnMut(&QueryParam) -> bool) {
        self.params.retain(keep);
    }

    /// Removes the parameters `filter` matches, returning how many were
    /// removed.
    pub fn remove_matching(&mut self, filter: &ParamFilter) -> usize {
        let before = self.params.len();
        self.params.retain(|param| !filter.matches(&param.name()));
        before - self.params.len()
    }

    /// Removes empty pieces (`a=1&&b=2` → `a=1&b=2`).
    pub fn remove_empty(&mut self) {
        self.params.retain(|param| !param.is_empty());
    }

    /// Sorts by encoded name. The sort is stable, so repeated names keep
    /// their relative order (`a=2&a=1` stays as it is): servers often give
    /// that order meaning.
    pub fn sort_by_name(&mut self) {
        self.params.sort_by(|a, b| a.name.cmp(&b.name));
    }
}

impl fmt::Display for QueryParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&join_query(&self.params))
    }
}

impl FromIterator<QueryParam> for QueryParams {
    fn from_iter<I: IntoIterator<Item = QueryParam>>(iter: I) -> Self {
        Self {
            params: iter.into_iter().collect(),
        }
    }
}

impl Extend<QueryParam> for QueryParams {
    fn extend<I: IntoIterator<Item = QueryParam>>(&mut self, iter: I) {
        self.params.extend(iter);
    }
}

impl IntoIterator for QueryParams {
    type Item = QueryParam;
    type IntoIter = std::vec::IntoIter<QueryParam>;

    fn into_iter(self) -> Self::IntoIter {
        self.params.into_iter()
    }
}

impl<'a> IntoIterator for &'a QueryParams {
    type Item = &'a QueryParam;
    type IntoIter = std::slice::Iter<'a, QueryParam>;

    fn into_iter(self) -> Self::IntoIter {
        self.params.iter()
    }
}

/// Click-tracking and analytics parameters dropped by
/// [`ParamFilter::tracking`]: exact names.
const TRACKING_NAMES: &[&str] = &[
    "_ga",
    "_gl",
    "_hsenc",
    "_hsmi",
    "dclid",
    "fbclid",
    "gbraid",
    "gclid",
    "gclsrc",
    "igshid",
    "li_fat_id",
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "msclkid",
    "oly_anon_id",
    "oly_enc_id",
    "rb_clickid",
    "s_cid",
    "ttclid",
    "twclid",
    "vero_id",
    "wbraid",
    "yclid",
];

/// Prefixes dropped by [`ParamFilter::tracking`].
const TRACKING_PREFIXES: &[&str] = &["utm_", "pk_", "mtm_"];

/// Session identifiers dropped by [`ParamFilter::session_ids`].
const SESSION_NAMES: &[&str] = &[
    "cfid",
    "cftoken",
    "jsessionid",
    "phpsessid",
    "session_id",
    "sessionid",
    "sid",
];

/// Session prefixes dropped by [`ParamFilter::session_ids`]
/// (`ASPSESSIONIDQASCTSRA` and friends).
const SESSION_PREFIXES: &[&str] = &["aspsessionid"];

/// A set of parameter names to drop: exact names and name prefixes,
/// compared ASCII case-insensitively against the decoded name.
///
/// ```
/// use rune_url::ParamFilter;
///
/// let filter = ParamFilter::tracking().with_name("ref");
/// assert!(filter.matches("utm_source"));
/// assert!(filter.matches("FBCLID"));
/// assert!(filter.matches("ref"));
/// assert!(!filter.matches("id"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ParamFilter {
    names: Vec<String>,
    prefixes: Vec<String>,
}

impl ParamFilter {
    /// A filter that matches nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            names: Vec::new(),
            prefixes: Vec::new(),
        }
    }

    /// Common click-tracking and analytics parameters: `utm_*`, `pk_*`,
    /// `mtm_*`, `gclid`, `fbclid`, `msclkid`, `_ga`, `mc_cid` and similar.
    /// None of them changes what a server returns.
    #[must_use]
    pub fn tracking() -> Self {
        Self::from_lists(TRACKING_NAMES, TRACKING_PREFIXES)
    }

    /// Common session-identifier parameters: `jsessionid`, `phpsessid`,
    /// `aspsessionid*`, `sid`, `sessionid`, `cfid`, `cftoken`. Dropping them
    /// stops a crawler seeing one page per session.
    #[must_use]
    pub fn session_ids() -> Self {
        Self::from_lists(SESSION_NAMES, SESSION_PREFIXES)
    }

    fn from_lists(names: &[&str], prefixes: &[&str]) -> Self {
        Self {
            names: names.iter().map(|name| (*name).to_owned()).collect(),
            prefixes: prefixes.iter().map(|prefix| (*prefix).to_owned()).collect(),
        }
    }

    /// Adds an exact name.
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.names.push(name.to_ascii_lowercase());
        self
    }

    /// Adds a name prefix.
    #[must_use]
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefixes.push(prefix.to_ascii_lowercase());
        self
    }

    /// Adds every name and prefix of `other`.
    #[must_use]
    pub fn union(mut self, other: &Self) -> Self {
        self.names.extend(other.names.iter().cloned());
        self.prefixes.extend(other.prefixes.iter().cloned());
        self
    }

    /// Whether the filter has no names and no prefixes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.names.is_empty() && self.prefixes.is_empty()
    }

    /// Whether the decoded parameter name `name` is matched.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.names.contains(&lower)
            || self
                .prefixes
                .iter()
                .any(|prefix| lower.starts_with(prefix.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_join_round_trip() {
        for query in ["", "a", "a=", "a=1", "a=1&&b", "&", "a=1=2&b=%20+", "=x"] {
            assert_eq!(split_query(query).to_string(), query, "{query:?}");
        }
    }

    #[test]
    fn distinguishes_missing_and_empty_values() {
        let params = split_query("a&b=");
        assert_eq!(params.as_slice()[0].raw_value(), None);
        assert_eq!(params.as_slice()[1].raw_value(), Some(""));
    }

    #[test]
    fn decodes_form_encoding() {
        let params = split_query("q=a+b%20c&n%61me=%E2%9C%93&bad=%zz&bin=%FF");
        assert_eq!(
            params.get("q").and_then(QueryParam::value).as_deref(),
            Some("a b c")
        );
        assert_eq!(
            params.get("name").and_then(QueryParam::value).as_deref(),
            Some("✓")
        );
        assert_eq!(
            params.get("bad").and_then(QueryParam::value).as_deref(),
            Some("%zz")
        );
        assert_eq!(
            params.get("bin").and_then(QueryParam::value).as_deref(),
            Some("\u{FFFD}")
        );
    }

    #[test]
    fn remove_and_get_all() {
        let mut params = split_query("a=1&b=2&a=3");
        let values: Vec<_> = params.get_all("a").filter_map(QueryParam::value).collect();
        assert_eq!(values, ["1", "3"]);
        assert_eq!(params.remove("a"), 2);
        assert_eq!(params.to_string(), "b=2");
    }

    #[test]
    fn stable_sort_keeps_repeated_order() {
        let mut params = split_query("b=1&a=2&a=1&c&a=0");
        params.sort_by_name();
        assert_eq!(params.to_string(), "a=2&a=1&a=0&b=1&c");
    }

    #[test]
    fn apply_to_url() {
        let mut url = Url::parse("http://h/?x=1").unwrap();
        QueryParams::new().apply_to(&mut url);
        assert_eq!(url.as_str(), "http://h/");
        let mut params = QueryParams::new();
        params.append("k", Some("v w"));
        params.apply_to(&mut url);
        assert_eq!(url.as_str(), "http://h/?k=v%20w");
        assert_eq!(QueryParams::from_url(&url), params);
    }

    #[test]
    fn filters() {
        let mut params = split_query("utm_source=a&UTM_Medium=b&id=1&gclid=x&PHPSESSID=y");
        assert_eq!(params.remove_matching(&ParamFilter::tracking()), 3);
        assert_eq!(params.remove_matching(&ParamFilter::session_ids()), 1);
        assert_eq!(params.to_string(), "id=1");
        assert!(ParamFilter::new().is_empty());
        let both = ParamFilter::new()
            .with_prefix("X_")
            .union(&ParamFilter::session_ids());
        assert!(both.matches("x_trace"));
        assert!(both.matches("ASPSESSIONIDQASCTSRA"));
    }
}
