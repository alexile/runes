//! Conditional request evaluation ([RFC 9110 §13.2.2]).
//!
//! [RFC 9110 §13.2.2]: https://www.rfc-editor.org/rfc/rfc9110#section-13.2.2

use http::header::{
    ETAG, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_UNMODIFIED_SINCE, LAST_MODIFIED,
};
use http::{HeaderMap, HeaderName, Method, StatusCode};

use crate::{EntityTag, EntityTagList, HttpDate};

/// The outcome of evaluating a request's preconditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Precondition {
    /// No precondition failed: perform the request normally.
    Proceed,
    /// A `GET`/`HEAD` whose cached copy is still current: answer
    /// `304 Not Modified`.
    NotModified,
    /// A precondition failed: answer `412 Precondition Failed` without
    /// performing the request.
    Failed,
}

impl Precondition {
    /// The status code to answer with, or `None` for [`Precondition::Proceed`].
    #[must_use]
    pub const fn status(self) -> Option<StatusCode> {
        match self {
            Self::Proceed => None,
            Self::NotModified => Some(StatusCode::NOT_MODIFIED),
            Self::Failed => Some(StatusCode::PRECONDITION_FAILED),
        }
    }
}

/// The validators of a resource's current representation: its entity tag
/// and last-modification date.
///
/// Handlers use it to set `ETag` / `Last-Modified` and to answer
/// conditional requests before doing expensive or state-changing work.
///
/// # Examples
///
/// ```rust
/// use http::{HeaderMap, Method, header};
/// use rune_axum_cache::{EntityTag, HttpDate, Precondition, Validators};
///
/// let validators = Validators::new()
///     .with_etag(EntityTag::strong("v2")?)
///     .with_last_modified(HttpDate::parse("Sun, 06 Nov 1994 08:49:37 GMT")?);
///
/// let mut request = HeaderMap::new();
/// request.insert(header::IF_NONE_MATCH, r#"W/"v2""#.parse().unwrap());
/// assert_eq!(validators.evaluate(&Method::GET, &request), Precondition::NotModified);
///
/// // A stale `If-Match` on a write must not go through.
/// let mut write = HeaderMap::new();
/// write.insert(header::IF_MATCH, r#""v1""#.parse().unwrap());
/// assert_eq!(validators.evaluate(&Method::PUT, &write), Precondition::Failed);
///
/// let mut response = HeaderMap::new();
/// validators.apply_to(&mut response);
/// assert_eq!(response[header::ETAG], r#""v2""#);
/// # Ok::<(), rune_axum_cache::Error>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Validators {
    etag: Option<EntityTag>,
    last_modified: Option<HttpDate>,
}

impl Validators {
    /// Validators with neither an entity tag nor a date.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the entity tag.
    #[must_use]
    pub fn with_etag(mut self, etag: EntityTag) -> Self {
        self.etag = Some(etag);
        self
    }

    /// Sets the last-modification date.
    #[must_use]
    pub const fn with_last_modified(mut self, date: HttpDate) -> Self {
        self.last_modified = Some(date);
        self
    }

    /// Reads `ETag` and `Last-Modified` from response headers. Missing or
    /// invalid fields are left unset.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let text = |name| headers.get(name).and_then(|v| v.to_str().ok());
        Self {
            etag: text(ETAG).and_then(|t| EntityTag::parse(t).ok()),
            last_modified: text(LAST_MODIFIED).and_then(|t| HttpDate::parse(t).ok()),
        }
    }

    /// The entity tag, if any.
    #[must_use]
    pub const fn etag(&self) -> Option<&EntityTag> {
        self.etag.as_ref()
    }

    /// The last-modification date, if any.
    #[must_use]
    pub const fn last_modified(&self) -> Option<HttpDate> {
        self.last_modified
    }

    /// Writes `ETag` and `Last-Modified` into `headers`, replacing any
    /// existing values. Unset validators are left alone.
    pub fn apply_to(&self, headers: &mut HeaderMap) {
        if let Some(etag) = &self.etag {
            headers.insert(ETAG, etag.to_header_value());
        }
        if let Some(date) = self.last_modified {
            headers.insert(LAST_MODIFIED, date.to_header_value());
        }
    }

    /// Evaluates the request's preconditions against these validators,
    /// for a resource that currently exists. See [`evaluate`].
    #[must_use]
    pub fn evaluate(&self, method: &Method, request: &HeaderMap) -> Precondition {
        evaluate(method, request, Some(self))
    }
}

/// Evaluates `If-Match`, `If-Unmodified-Since`, `If-None-Match` and
/// `If-Modified-Since` in the order RFC 9110 §13.2.2 prescribes.
///
/// `current` describes the selected representation, or is `None` when the
/// target resource has none (so `If-Match: *` fails and
/// `If-None-Match: *` passes, the create-only-if-absent idiom).
///
/// Malformed fields are handled conservatively: an unparseable `If-Match`
/// fails the request, while an unparseable `If-None-Match` and invalid or
/// repeated dates are ignored, so the full response is sent.
///
/// The result is only meaningful when the request would otherwise succeed
/// with a 2xx status; evaluate it after authorization and routing.
#[must_use]
pub fn evaluate(
    method: &Method,
    request: &HeaderMap,
    current: Option<&Validators>,
) -> Precondition {
    let safe = method == Method::GET || method == Method::HEAD;
    let etag = current.and_then(|v| v.etag.as_ref());
    let last_modified = current.and_then(|v| v.last_modified);

    // Step 1 and 2: If-Match, else If-Unmodified-Since.
    if request.contains_key(IF_MATCH) {
        let passes = EntityTagList::from_header_values(request.get_all(IF_MATCH)).is_ok_and(
            |list| match list {
                EntityTagList::Any => current.is_some(),
                list => etag.is_some_and(|t| list.matches_strong(t)),
            },
        );
        if !passes {
            return Precondition::Failed;
        }
    } else if let (Some(since), Some(modified)) =
        (single_date(request, &IF_UNMODIFIED_SINCE), last_modified)
        && modified > since
    {
        return Precondition::Failed;
    }

    // Step 3 and 4: If-None-Match, else If-Modified-Since.
    let none_match = request
        .contains_key(IF_NONE_MATCH)
        .then(|| EntityTagList::from_header_values(request.get_all(IF_NONE_MATCH)).ok())
        .flatten();
    if let Some(list) = none_match {
        let matched = match list {
            EntityTagList::Any => current.is_some(),
            list => etag.is_some_and(|t| list.matches_weak(t)),
        };
        if matched {
            return if safe {
                Precondition::NotModified
            } else {
                Precondition::Failed
            };
        }
    } else if safe
        && let (Some(since), Some(modified)) =
            (single_date(request, &IF_MODIFIED_SINCE), last_modified)
        && modified <= since
    {
        return Precondition::NotModified;
    }
    Precondition::Proceed
}

/// The field's date when it has exactly one valid value.
fn single_date(headers: &HeaderMap, name: &HeaderName) -> Option<HttpDate> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    HttpDate::parse(first.to_str().ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    const T0: &str = "Sun, 06 Nov 1994 08:49:37 GMT";
    const T_EARLIER: &str = "Sat, 05 Nov 1994 08:49:37 GMT";
    const T_LATER: &str = "Mon, 07 Nov 1994 08:49:37 GMT";

    fn current() -> Validators {
        Validators::new()
            .with_etag(EntityTag::strong("v1").unwrap())
            .with_last_modified(HttpDate::parse(T0).unwrap())
    }

    fn headers(pairs: &[(HeaderName, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(name.clone(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn eval(method: &Method, pairs: &[(HeaderName, &str)]) -> Precondition {
        evaluate(method, &headers(pairs), Some(&current()))
    }

    #[test]
    fn no_preconditions_proceed() {
        assert_eq!(eval(&Method::GET, &[]), Precondition::Proceed);
        assert_eq!(
            evaluate(&Method::GET, &HeaderMap::new(), None),
            Precondition::Proceed
        );
    }

    #[test]
    fn if_none_match() {
        let get = &Method::GET;
        assert_eq!(
            eval(get, &[(IF_NONE_MATCH, r#""v1""#)]),
            Precondition::NotModified
        );
        assert_eq!(
            eval(get, &[(IF_NONE_MATCH, r#"W/"v1""#)]),
            Precondition::NotModified
        );
        assert_eq!(
            eval(&Method::HEAD, &[(IF_NONE_MATCH, "*")]),
            Precondition::NotModified
        );
        assert_eq!(
            eval(get, &[(IF_NONE_MATCH, r#""v0", "v2""#)]),
            Precondition::Proceed
        );
        assert_eq!(
            eval(
                get,
                &[(IF_NONE_MATCH, r#""v0""#), (IF_NONE_MATCH, r#""v1""#)]
            ),
            Precondition::NotModified
        );
        // Unsafe methods fail instead of 304.
        assert_eq!(
            eval(&Method::PUT, &[(IF_NONE_MATCH, "*")]),
            Precondition::Failed
        );
        // Create-if-absent passes when nothing exists.
        let h = headers(&[(IF_NONE_MATCH, "*")]);
        assert_eq!(evaluate(&Method::PUT, &h, None), Precondition::Proceed);
        // Malformed: ignored.
        assert_eq!(eval(get, &[(IF_NONE_MATCH, "v1")]), Precondition::Proceed);
    }

    #[test]
    fn if_none_match_takes_precedence_over_if_modified_since() {
        let pairs = [(IF_NONE_MATCH, r#""other""#), (IF_MODIFIED_SINCE, T0)];
        assert_eq!(eval(&Method::GET, &pairs), Precondition::Proceed);
        // A malformed If-None-Match is ignored, so IMS applies.
        let pairs = [(IF_NONE_MATCH, "garbage"), (IF_MODIFIED_SINCE, T0)];
        assert_eq!(eval(&Method::GET, &pairs), Precondition::NotModified);
    }

    #[test]
    fn if_modified_since() {
        let get = &Method::GET;
        assert_eq!(
            eval(get, &[(IF_MODIFIED_SINCE, T0)]),
            Precondition::NotModified
        );
        assert_eq!(
            eval(get, &[(IF_MODIFIED_SINCE, T_LATER)]),
            Precondition::NotModified
        );
        assert_eq!(
            eval(get, &[(IF_MODIFIED_SINCE, T_EARLIER)]),
            Precondition::Proceed
        );
        assert_eq!(
            eval(get, &[(IF_MODIFIED_SINCE, "yesterday")]),
            Precondition::Proceed
        );
        assert_eq!(
            eval(get, &[(IF_MODIFIED_SINCE, T0), (IF_MODIFIED_SINCE, T0)]),
            Precondition::Proceed
        );
        // Only for GET and HEAD.
        assert_eq!(
            eval(&Method::POST, &[(IF_MODIFIED_SINCE, T0)]),
            Precondition::Proceed
        );
        // Without a Last-Modified there is nothing to compare.
        let only_tag = Validators::new().with_etag(EntityTag::strong("v1").unwrap());
        let h = headers(&[(IF_MODIFIED_SINCE, T_LATER)]);
        assert_eq!(only_tag.evaluate(get, &h), Precondition::Proceed);
    }

    #[test]
    fn if_match() {
        let put = &Method::PUT;
        assert_eq!(eval(put, &[(IF_MATCH, r#""v1""#)]), Precondition::Proceed);
        assert_eq!(
            eval(put, &[(IF_MATCH, r#""v0", "v1""#)]),
            Precondition::Proceed
        );
        assert_eq!(eval(put, &[(IF_MATCH, "*")]), Precondition::Proceed);
        // Strong comparison: a weak tag never matches.
        assert_eq!(eval(put, &[(IF_MATCH, r#"W/"v1""#)]), Precondition::Failed);
        assert_eq!(eval(put, &[(IF_MATCH, r#""v0""#)]), Precondition::Failed);
        assert_eq!(eval(put, &[(IF_MATCH, "garbage")]), Precondition::Failed);
        let h = headers(&[(IF_MATCH, "*")]);
        assert_eq!(evaluate(put, &h, None), Precondition::Failed);
        let weak_current = Validators::new().with_etag(EntityTag::weak("v1").unwrap());
        let h = headers(&[(IF_MATCH, r#""v1""#)]);
        assert_eq!(weak_current.evaluate(put, &h), Precondition::Failed);
    }

    #[test]
    fn if_unmodified_since() {
        let put = &Method::PUT;
        assert_eq!(
            eval(put, &[(IF_UNMODIFIED_SINCE, T0)]),
            Precondition::Proceed
        );
        assert_eq!(
            eval(put, &[(IF_UNMODIFIED_SINCE, T_EARLIER)]),
            Precondition::Failed
        );
        assert_eq!(
            eval(put, &[(IF_UNMODIFIED_SINCE, "nope")]),
            Precondition::Proceed
        );
        // Ignored when If-Match is present.
        let pairs = [(IF_MATCH, r#""v1""#), (IF_UNMODIFIED_SINCE, T_EARLIER)];
        assert_eq!(eval(put, &pairs), Precondition::Proceed);
    }

    #[test]
    fn if_match_is_evaluated_before_if_none_match() {
        let pairs = [(IF_MATCH, r#""v0""#), (IF_NONE_MATCH, r#""v1""#)];
        assert_eq!(eval(&Method::GET, &pairs), Precondition::Failed);
    }

    #[test]
    fn statuses() {
        assert_eq!(Precondition::Proceed.status(), None);
        assert_eq!(
            Precondition::NotModified.status(),
            Some(StatusCode::NOT_MODIFIED)
        );
        assert_eq!(
            Precondition::Failed.status(),
            Some(StatusCode::PRECONDITION_FAILED)
        );
    }

    #[test]
    fn validators_round_trip_through_headers() {
        let mut h = HeaderMap::new();
        current().apply_to(&mut h);
        assert_eq!(h[LAST_MODIFIED], T0);
        assert_eq!(Validators::from_headers(&h), current());
        h.insert(ETAG, HeaderValue::from_static("not-quoted"));
        assert_eq!(Validators::from_headers(&h).etag(), None);
    }
}
