//! [`Route`]: the link between a URL a DAST tool tested and the source code
//! that serves it.

use rune_finding::Location;

use crate::Error;

/// One segment of a route pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Segment {
    /// Matches exactly this segment.
    Literal(String),
    /// `{name}` or `:name`: matches any one segment.
    Param,
    /// `*` or `{*name}`, last only: matches the rest, possibly nothing.
    Rest,
}

/// A route of the application: the URL path pattern a DAST tool reaches and
/// the source file (optionally a line range of it) that handles it.
///
/// SAST results know files, DAST results know URLs; routes are what lets
/// the two meet. A SAST result whose location (or a step of its code flow)
/// is in the route's file and a DAST result whose URL matches the pattern,
/// both with the same CWE class, are one issue.
///
/// Patterns are URL paths whose segments are literals, `{name}` or `:name`
/// (any one segment), or a final `*` or `{*name}` (the rest of the path,
/// possibly empty). Empty segments are ignored, so a trailing slash does
/// not matter. Literals compare exactly, as they appear in the URL.
///
/// Files match by path components from the end, either way round:
/// `src/app.py` matches `/ci/repo/src/app.py`, and `repo/src/app.py`
/// matches `src/app.py`. Backslashes count as slashes.
///
/// With the `serde` feature a route serializes as
/// `{"name":…,"pattern":"/users/{id}","host":…,"file":"src/users.py","lines":[10,40]}`,
/// where `name`, `host` and `lines` are optional.
///
/// # Examples
///
/// ```
/// use rune_aspm_correlate::Route;
/// use rune_finding::Location;
///
/// let route = Route::new("/users/{id}", "src/users.py")?.with_lines(10, 40);
/// assert!(route.matches_url("https://shop.test/users/42?tab=1"));
/// assert!(!route.matches_url("https://shop.test/users/42/orders"));
/// assert!(route.matches_location(&Location::file("/ci/repo/src/users.py").with_lines(12, 12)));
/// assert!(!route.matches_location(&Location::file("src/users.py").with_lines(50, 50)));
/// # Ok::<(), rune_aspm_correlate::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "RouteSpec", into = "RouteSpec")
)]
pub struct Route {
    name: String,
    pattern: String,
    segments: Vec<Segment>,
    host: Option<String>,
    file: String,
    file_parts: Vec<String>,
    lines: Option<(u32, u32)>,
}

impl Route {
    /// A route from a URL path `pattern` to the source `file` that handles
    /// it. Its name is the pattern.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRoute`] when the pattern does not start with `/`,
    /// has an unbalanced brace or an empty parameter name, or has a rest
    /// segment that is not last, or when the file path is empty.
    pub fn new(pattern: impl Into<String>, file: impl Into<String>) -> Result<Self, Error> {
        let pattern = pattern.into();
        let file = file.into();
        let segments = parse_pattern(&pattern).map_err(|reason| Error::InvalidRoute {
            pattern: pattern.clone(),
            reason,
        })?;
        let file_parts = path_parts(&file);
        if file_parts.is_empty() {
            return Err(Error::InvalidRoute {
                pattern,
                reason: "the file path is empty",
            });
        }
        Ok(Self {
            name: pattern.clone(),
            pattern,
            segments,
            host: None,
            file,
            file_parts,
            lines: None,
        })
    }

    /// Set the name. Routes with the same name are one route for
    /// correlation, e.g. one endpoint served by two files.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Only match URLs on this host (compared case-insensitively).
    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into().to_ascii_lowercase());
        self
    }

    /// Only match results within these lines of the file, inclusive. The
    /// bounds may come in either order.
    #[must_use]
    pub fn with_lines(mut self, start: u32, end: u32) -> Self {
        self.lines = Some((start.min(end), start.max(end)));
        self
    }

    /// The name, by default the pattern.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The URL path pattern.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// The host restriction, lowercase.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// The source file, as given.
    #[must_use]
    pub fn file(&self) -> &str {
        &self.file
    }

    /// The line range, inclusive.
    #[must_use]
    pub const fn lines(&self) -> Option<(u32, u32)> {
        self.lines
    }

    /// Whether `url` (absolute, or a path starting with `/`) is on this
    /// route. Query and fragment do not count.
    #[must_use]
    pub fn matches_url(&self, url: &str) -> bool {
        let (host, path) = match url::Url::parse(url) {
            Ok(parsed) => (
                parsed.host_str().map(str::to_ascii_lowercase),
                parsed.path().to_owned(),
            ),
            Err(_) if url.starts_with('/') => {
                let end = url.find(['?', '#']).unwrap_or(url.len());
                (None, url.get(..end).unwrap_or(url).to_owned())
            }
            Err(_) => return false,
        };
        if let Some(wanted) = &self.host
            && host.as_deref() != Some(wanted.as_str())
        {
            return false;
        }
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        self.matches_path(&parts)
    }

    fn matches_path(&self, parts: &[&str]) -> bool {
        let mut parts = parts.iter();
        for segment in &self.segments {
            match segment {
                Segment::Rest => return true,
                Segment::Param => {
                    if parts.next().is_none() {
                        return false;
                    }
                }
                Segment::Literal(literal) => {
                    if parts.next() != Some(&literal.as_str()) {
                        return false;
                    }
                }
            }
        }
        parts.next().is_none()
    }

    /// Whether `location` is on this route: a URL matching the pattern, or
    /// a file region in the route's file (and line range, when it has one;
    /// a location without a line then does not match).
    #[must_use]
    pub fn matches_location(&self, location: &Location) -> bool {
        match location {
            Location::Url { url, .. } => self.matches_url(url),
            Location::File {
                path, start_line, ..
            } => {
                let parts = path_parts(path);
                let n = parts.len().min(self.file_parts.len());
                if n == 0
                    || parts.get(parts.len() - n..)
                        != self.file_parts.get(self.file_parts.len() - n..)
                {
                    return false;
                }
                match (self.lines, start_line) {
                    (None, _) => true,
                    (Some((start, end)), Some(line)) => (start..=end).contains(line),
                    (Some(_), None) => false,
                }
            }
            _ => false,
        }
    }
}

/// The non-empty, non-`.` components of a path, with `\` as a separator.
fn path_parts(path: &str) -> Vec<String> {
    path.split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_owned)
        .collect()
}

fn parse_pattern(pattern: &str) -> Result<Vec<Segment>, &'static str> {
    if !pattern.starts_with('/') {
        return Err("the pattern must start with `/`");
    }
    let raw: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();
    let mut segments = Vec::with_capacity(raw.len());
    for (index, part) in raw.iter().enumerate() {
        let segment = if *part == "*" {
            Segment::Rest
        } else if let Some(inner) = part.strip_prefix('{') {
            let name = inner.strip_suffix('}').ok_or("unbalanced `{`")?;
            if name.contains(['{', '}']) {
                return Err("unbalanced `{`");
            }
            match name.strip_prefix('*') {
                Some(rest) if !rest.is_empty() => Segment::Rest,
                Some(_) => return Err("empty rest parameter name"),
                None if name.is_empty() => return Err("empty parameter name"),
                None => Segment::Param,
            }
        } else if let Some(name) = part.strip_prefix(':') {
            if name.is_empty() {
                return Err("empty parameter name");
            }
            Segment::Param
        } else if part.contains(['{', '}']) {
            return Err("unbalanced `{`");
        } else {
            Segment::Literal((*part).to_owned())
        };
        if segment == Segment::Rest && index + 1 != raw.len() {
            return Err("a rest segment must be last");
        }
        segments.push(segment);
    }
    Ok(segments)
}

/// The serialized form of a [`Route`].
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lines: Option<[u32; 2]>,
}

#[cfg(feature = "serde")]
impl TryFrom<RouteSpec> for Route {
    type Error = Error;

    fn try_from(spec: RouteSpec) -> Result<Self, Error> {
        let mut route = Self::new(spec.pattern, spec.file)?;
        if let Some(name) = spec.name {
            route = route.with_name(name);
        }
        if let Some(host) = spec.host {
            route = route.with_host(host);
        }
        if let Some([start, end]) = spec.lines {
            route = route.with_lines(start, end);
        }
        Ok(route)
    }
}

#[cfg(feature = "serde")]
impl From<Route> for RouteSpec {
    fn from(route: Route) -> Self {
        Self {
            name: (route.name != route.pattern).then_some(route.name),
            pattern: route.pattern,
            host: route.host,
            file: route.file,
            lines: route.lines.map(<[u32; 2]>::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(pattern: &str) -> Route {
        Route::new(pattern, "src/app.py").unwrap()
    }

    #[test]
    fn patterns_match_paths() {
        let users = route("/api/users/{id}");
        assert!(users.matches_url("https://a.test/api/users/7"));
        assert!(users.matches_url("https://a.test/api/users/7/"));
        assert!(users.matches_url("/api/users/7?x=1#f"));
        assert!(!users.matches_url("https://a.test/api/users"));
        assert!(!users.matches_url("https://a.test/api/users/7/x"));
        assert!(!users.matches_url("https://a.test/api/groups/7"));
        assert!(!users.matches_url("not a url"));

        let colon = route("/api/:kind/list");
        assert!(colon.matches_url("https://a.test/api/x/list"));

        let rest = route("/static/{*path}");
        assert!(rest.matches_url("https://a.test/static"));
        assert!(rest.matches_url("https://a.test/static/a/b/c.js"));
        assert!(route("/*").matches_url("https://a.test/anything/at/all"));
        assert!(route("/").matches_url("https://a.test"));
        assert!(!route("/").matches_url("https://a.test/x"));
    }

    #[test]
    fn host_restriction() {
        let api = route("/x").with_host("API.test");
        assert_eq!(api.host(), Some("api.test"));
        assert!(api.matches_url("https://api.test/x"));
        assert!(!api.matches_url("https://www.test/x"));
        assert!(!api.matches_url("/x"));
    }

    #[test]
    fn files_match_by_suffix_and_lines() {
        let r = Route::new("/x", "./src\\app.py").unwrap();
        assert!(r.matches_location(&Location::file("src/app.py")));
        assert!(r.matches_location(&Location::file("/ci/repo/src/app.py")));
        assert!(r.matches_location(&Location::file("app.py")));
        assert!(!r.matches_location(&Location::file("lib/app.py")));
        assert!(!r.matches_location(&Location::file("src/app.pyc")));
        assert!(!r.matches_location(&Location::file("")));
        assert!(!r.matches_location(&Location::network("a", 1)));

        let ranged = r.with_lines(20, 10);
        assert_eq!(ranged.lines(), Some((10, 20)));
        assert!(ranged.matches_location(&Location::file("src/app.py").with_lines(10, 11)));
        assert!(ranged.matches_location(&Location::file("src/app.py").with_lines(20, 30)));
        assert!(!ranged.matches_location(&Location::file("src/app.py").with_lines(21, 21)));
        assert!(!ranged.matches_location(&Location::file("src/app.py")));
        assert!(ranged.matches_location(&Location::url("https://a.test/x")));
    }

    #[test]
    fn bad_patterns_are_rejected() {
        for bad in [
            "users",
            "/{id",
            "/id}",
            "/{}",
            "/:",
            "/{*}",
            "/*/x",
            "/{*rest}/x",
            "/a{b}",
            "/{{a}}",
        ] {
            assert!(
                matches!(Route::new(bad, "a.py"), Err(Error::InvalidRoute { .. })),
                "{bad}"
            );
        }
        assert!(Route::new("/x", "./").is_err());
    }

    #[test]
    fn accessors() {
        let r = route("/x").with_name("x-endpoint");
        assert_eq!(r.name(), "x-endpoint");
        assert_eq!(r.pattern(), "/x");
        assert_eq!(r.file(), "src/app.py");
        assert_eq!(route("/y").name(), "/y");
    }
}
