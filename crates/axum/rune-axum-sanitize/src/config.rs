//! Middleware configuration: what to clean, limits and per-route rules.

use crate::{Mode, Sanitizer};

/// Default cap on buffered bodies, matching axum's `DefaultBodyLimit`.
pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Default JSON nesting limit, matching `serde_json`'s recursion limit.
pub const DEFAULT_MAX_JSON_DEPTH: usize = 128;

/// What the middleware does with a body it does not clean: anything that is
/// not JSON, a URL-encoded form or `text/*` (multipart, binary, missing
/// `Content-Type`).
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::{OtherBodies, SanitizeConfig};
///
/// let config = SanitizeConfig::new().other_bodies(OtherBodies::Reject);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtherBodies {
    /// Forward untouched and unbuffered. File uploads and binary payloads
    /// are not corrupted, and are not sanitized either.
    #[default]
    Passthrough,
    /// Answer `415 Unsupported Media Type` for any non-empty body of another
    /// type. Use it on routes that should only ever take JSON or forms, so
    /// a handler reading raw bytes can't be reached with an odd
    /// `Content-Type`.
    Reject,
}

/// A route matcher: an exact path, `/prefix/*` for a path and everything
/// below it, or `*` for every path.
#[derive(Clone, Debug)]
pub struct RoutePattern {
    path: String,
    prefix: bool,
}

impl RoutePattern {
    fn parse(pattern: &str) -> Self {
        let prefix = pattern
            .strip_suffix("/*")
            .or_else(|| pattern.strip_suffix('*'));
        Self {
            path: prefix.unwrap_or(pattern).to_owned(),
            prefix: prefix.is_some(),
        }
    }

    pub fn matches(&self, path: &str) -> bool {
        if !self.prefix {
            return path == self.path;
        }
        path.strip_prefix(self.path.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/') || self.path.is_empty())
    }
}

/// A field matcher: a JSON Pointer (`/post/body`, `/items/*/html`) or, for
/// query and form fields, a bare name. `*` matches any one key or index, and
/// a pattern also covers everything nested below what it matches.
#[derive(Clone, Debug)]
pub struct FieldPattern {
    segments: Vec<String>,
}

impl FieldPattern {
    fn parse(pattern: &str) -> Self {
        let segments = match pattern.strip_prefix('/') {
            None if pattern.is_empty() => Vec::new(),
            None => vec![pattern.to_owned()],
            Some("") => Vec::new(),
            Some(pointer) => pointer
                .split('/')
                .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
                .collect(),
        };
        Self { segments }
    }

    pub fn matches(&self, path: &[String]) -> bool {
        self.segments.len() <= path.len()
            && self
                .segments
                .iter()
                .zip(path)
                .all(|(pattern, segment)| pattern == "*" || pattern == segment)
    }
}

#[derive(Clone, Debug)]
pub enum FieldAction {
    Skip,
    Mode(Mode),
}

#[derive(Clone, Debug)]
pub struct FieldRule {
    pub route: RoutePattern,
    pub field: FieldPattern,
    pub action: FieldAction,
}

/// Configuration for [`SanitizeLayer`](crate::SanitizeLayer).
///
/// Defaults: strip tags and control characters from query values, JSON
/// strings, URL-encoded form fields and `text/*` bodies; pass other bodies
/// through; buffer at most 2 MiB (413 above that); JSON nesting up to 128.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::{Mode, Normalization, OtherBodies, SanitizeConfig, Sanitizer};
///
/// let config = SanitizeConfig::new()
///     .sanitizer(
///         Sanitizer::new()
///             .normalization(Some(Normalization::Nfc))
///             .strip_invisible(true),
///     )
///     .max_body_bytes(256 * 1024)
///     .other_bodies(OtherBodies::Reject)
///     .exempt_route("/webhooks/*")
///     .exempt_field("/posts/*", "/body");
/// ```
#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent on/off switches, set through builder methods"
)]
pub struct SanitizeConfig {
    pub(crate) sanitizer: Sanitizer,
    pub(crate) query: bool,
    pub(crate) json: bool,
    pub(crate) form: bool,
    pub(crate) text: bool,
    pub(crate) other_bodies: OtherBodies,
    pub(crate) max_body_bytes: usize,
    pub(crate) max_json_depth: usize,
    pub(crate) exempt_routes: Vec<RoutePattern>,
    pub(crate) field_rules: Vec<FieldRule>,
}

impl Default for SanitizeConfig {
    fn default() -> Self {
        Self {
            sanitizer: Sanitizer::default(),
            query: true,
            json: true,
            form: true,
            text: true,
            other_bodies: OtherBodies::Passthrough,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_json_depth: DEFAULT_MAX_JSON_DEPTH,
            exempt_routes: Vec::new(),
            field_rules: Vec::new(),
        }
    }
}

impl SanitizeConfig {
    /// The default configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the string pipeline used for every field.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{Mode, SanitizeConfig, Sanitizer};
    ///
    /// let config = SanitizeConfig::new().sanitizer(Sanitizer::new().mode(Mode::Escape));
    /// ```
    #[must_use]
    #[cfg_attr(
        not(feature = "allowlist"),
        expect(
            clippy::missing_const_for_fn,
            reason = "not const once `Mode` can hold an allowlist"
        )
    )]
    pub fn sanitizer(mut self, sanitizer: Sanitizer) -> Self {
        self.sanitizer = sanitizer;
        self
    }

    /// Shorthand for changing only the sanitizer's [`Mode`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{Mode, SanitizeConfig};
    ///
    /// let config = SanitizeConfig::new().mode(Mode::Escape);
    /// ```
    #[must_use]
    pub fn mode(mut self, mode: Mode) -> Self {
        self.sanitizer = self.sanitizer.mode(mode);
        self
    }

    /// Whether to clean query string names and values. Default `true`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().sanitize_query(false);
    /// ```
    #[must_use]
    pub const fn sanitize_query(mut self, enabled: bool) -> Self {
        self.query = enabled;
        self
    }

    /// Whether to clean `application/json` and `application/*+json` bodies.
    /// Default `true`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().sanitize_json(false);
    /// ```
    #[must_use]
    pub const fn sanitize_json(mut self, enabled: bool) -> Self {
        self.json = enabled;
        self
    }

    /// Whether to clean `application/x-www-form-urlencoded` bodies. Default
    /// `true`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().sanitize_form(false);
    /// ```
    #[must_use]
    pub const fn sanitize_form(mut self, enabled: bool) -> Self {
        self.form = enabled;
        self
    }

    /// Whether to clean `text/*` bodies as one string. Default `true`. Such
    /// bodies must be UTF-8 (400 otherwise).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().sanitize_text(false);
    /// ```
    #[must_use]
    pub const fn sanitize_text(mut self, enabled: bool) -> Self {
        self.text = enabled;
        self
    }

    /// What to do with bodies of any other type. Default
    /// [`OtherBodies::Passthrough`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{OtherBodies, SanitizeConfig};
    ///
    /// let config = SanitizeConfig::new().other_bodies(OtherBodies::Reject);
    /// ```
    #[must_use]
    pub const fn other_bodies(mut self, other_bodies: OtherBodies) -> Self {
        self.other_bodies = other_bodies;
        self
    }

    /// Largest body the middleware buffers for cleaning; bigger ones get
    /// `413 Payload Too Large`. Default 2 MiB. Bodies that are passed
    /// through are not buffered and not limited here.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().max_body_bytes(64 * 1024);
    /// ```
    #[must_use]
    pub const fn max_body_bytes(mut self, limit: usize) -> Self {
        self.max_body_bytes = limit;
        self
    }

    /// Deepest JSON nesting accepted; deeper bodies get `400 Bad Request`.
    /// Default 128.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().max_json_depth(32);
    /// ```
    #[must_use]
    pub const fn max_json_depth(mut self, depth: usize) -> Self {
        self.max_json_depth = depth;
        self
    }

    /// Skips the middleware entirely for matching paths.
    ///
    /// `route` is an exact path, `/prefix/*` for a path and everything below
    /// it, or `*` for all paths. It is matched against the path the layer
    /// sees, which inside a nested router excludes the nest prefix.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new().exempt_route("/webhooks/*");
    /// ```
    #[must_use]
    pub fn exempt_route(mut self, route: &str) -> Self {
        self.exempt_routes.push(RoutePattern::parse(route));
        self
    }

    /// Leaves one field (and anything nested in it) untouched on matching
    /// routes.
    ///
    /// `field` is a JSON Pointer such as `/post/body` or `/items/*/html`
    /// (`*` matches any key or array index), or a bare name such as `body`
    /// for query and form fields. `/body` matches the query or form field
    /// `body` as well. Rules are checked in the order added; the first match
    /// wins.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeConfig;
    ///
    /// let config = SanitizeConfig::new()
    ///     .exempt_field("/posts", "/content/html")
    ///     .exempt_field("*", "password");
    /// ```
    #[must_use]
    pub fn exempt_field(mut self, route: &str, field: &str) -> Self {
        self.field_rules.push(FieldRule {
            route: RoutePattern::parse(route),
            field: FieldPattern::parse(field),
            action: FieldAction::Skip,
        });
        self
    }

    /// Cleans one field's values with a different [`Mode`] on matching
    /// routes, typically [`Mode::Allowlist`] for rich text. Matching works as
    /// in [`exempt_field`](Self::exempt_field). Object keys inside the field
    /// still get the default mode.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{Mode, SanitizeConfig};
    ///
    /// let config = SanitizeConfig::new().field_mode("/comments", "/text", Mode::Escape);
    /// ```
    #[must_use]
    pub fn field_mode(mut self, route: &str, field: &str, mode: Mode) -> Self {
        self.field_rules.push(FieldRule {
            route: RoutePattern::parse(route),
            field: FieldPattern::parse(field),
            action: FieldAction::Mode(mode),
        });
        self
    }

    pub(crate) fn is_exempt(&self, path: &str) -> bool {
        self.exempt_routes.iter().any(|route| route.matches(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(segments: &[&str]) -> Vec<String> {
        segments
            .iter()
            .map(|segment| (*segment).to_owned())
            .collect()
    }

    #[test]
    fn route_patterns() {
        let exact = RoutePattern::parse("/a");
        assert!(exact.matches("/a"));
        assert!(!exact.matches("/a/b"));
        let prefix = RoutePattern::parse("/a/*");
        assert!(prefix.matches("/a"));
        assert!(prefix.matches("/a/b/c"));
        assert!(!prefix.matches("/ab"));
        let all = RoutePattern::parse("*");
        assert!(all.matches("/anything"));
    }

    #[test]
    fn field_patterns() {
        let pointer = FieldPattern::parse("/items/*/html");
        assert!(pointer.matches(&path(&["items", "3", "html"])));
        assert!(pointer.matches(&path(&["items", "3", "html", "x"])));
        assert!(!pointer.matches(&path(&["items", "3", "text"])));
        assert!(!pointer.matches(&path(&["items"])));
        assert!(FieldPattern::parse("body").matches(&path(&["body"])));
        assert!(FieldPattern::parse("/a~1b~0").matches(&path(&["a/b~"])));
        assert!(FieldPattern::parse("").matches(&path(&[])));
    }
}
