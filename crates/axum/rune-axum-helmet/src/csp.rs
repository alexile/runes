//! `Content-Security-Policy` builder and per-request nonces.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use http::HeaderValue;
use rand::RngCore;
use rune_csp::{Keyword, Policy, Source};

use crate::Error;

/// Header name used in errors for the enforced policy.
pub const CSP: &str = "Content-Security-Policy";
/// Header name used in errors for the report-only policy.
pub const CSP_REPORT_ONLY: &str = "Content-Security-Policy-Report-Only";

/// A stand-in nonce used when checking a policy that has nonce slots.
const PLACEHOLDER_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

/// One token of a directive value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    /// Written as given.
    Lit(String),
    /// Replaced with `'nonce-<value>'` for every request.
    Nonce,
}

/// Builder for a `Content-Security-Policy` value.
///
/// Each directive method replaces any earlier value of that directive, so
/// a builder never holds duplicates. Sources may be passed one per slice
/// element or space-separated. Nothing is checked until the policy is
/// handed to [`Helmet`](crate::Helmet) and built (or
/// [`CspBuilder::validate`] is called): then unknown directives, malformed
/// sources, fixed nonces and a `'strict-dynamic'` without a nonce or hash
/// are all errors.
///
/// [`CspBuilder::script_nonce`] and [`CspBuilder::style_nonce`] add a nonce
/// slot that the layer fills with a fresh random value on every request;
/// handlers read it through the [`CspNonce`] request extension.
///
/// # Examples
///
/// ```rust
/// use rune_axum_helmet::CspBuilder;
///
/// let csp = CspBuilder::new()
///     .default_src(&["'self'"])
///     .img_src(&["'self'", "data:"])
///     .script_src(&["'self'"])
///     .script_nonce()
///     .strict_dynamic()
///     .upgrade_insecure_requests();
///
/// assert!(csp.validate().is_ok());
/// assert_eq!(
///     csp.render(Some("abc123")),
///     "default-src 'self'; img-src 'self' data:; \
///      script-src 'self' 'nonce-abc123' 'strict-dynamic'; upgrade-insecure-requests"
/// );
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CspBuilder {
    directives: Vec<(String, Vec<Token>)>,
}

impl CspBuilder {
    /// An empty policy. Add at least one directive before using it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The policy [`Helmet::new`](crate::Helmet::new) sends by default:
    /// same-origin everything, no plugins, no framing, no inline script
    /// attributes, and HTTPS upgrades.
    ///
    /// ```text
    /// default-src 'self'; base-uri 'self'; font-src 'self' https: data:;
    /// form-action 'self'; frame-ancestors 'none'; img-src 'self' data:;
    /// object-src 'none'; script-src 'self'; script-src-attr 'none';
    /// style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests
    /// ```
    ///
    /// Inline styles stay allowed, as in Helmet.js, because many pages and
    /// component libraries still rely on them. Start from this and adjust,
    /// e.g. `CspBuilder::recommended().script_nonce()`.
    #[must_use]
    pub fn recommended() -> Self {
        Self::new()
            .default_src(&["'self'"])
            .base_uri(&["'self'"])
            .font_src(&["'self'", "https:", "data:"])
            .form_action(&["'self'"])
            .frame_ancestors(&["'none'"])
            .img_src(&["'self'", "data:"])
            .object_src(&["'none'"])
            .script_src(&["'self'"])
            .script_src_attr(&["'none'"])
            .style_src(&["'self'", "https:", "'unsafe-inline'"])
            .upgrade_insecure_requests()
    }

    /// A nonce-based "strict CSP": scripts run only when they carry the
    /// per-request nonce, or are loaded by one that does.
    ///
    /// ```text
    /// script-src 'nonce-…' 'strict-dynamic' https: 'unsafe-inline';
    /// object-src 'none'; base-uri 'none'; frame-ancestors 'none'
    /// ```
    ///
    /// `https:` and `'unsafe-inline'` are fallbacks for browsers without
    /// CSP 3; browsers that understand nonces and `'strict-dynamic'` ignore
    /// them. Every `<script>` the server renders needs
    /// `nonce="{CspNonce}"`.
    #[must_use]
    pub fn strict() -> Self {
        Self::new()
            .script_src(&[])
            .script_nonce()
            .strict_dynamic()
            .add_sources("script-src", &["https:", "'unsafe-inline'"])
            .object_src(&["'none'"])
            .base_uri(&["'none'"])
            .frame_ancestors(&["'none'"])
    }

    /// Reads an existing policy, e.g. one kept in configuration.
    ///
    /// # Errors
    ///
    /// [`Error::Csp`] when the text is not a single valid policy.
    ///
    /// ```rust
    /// use rune_axum_helmet::CspBuilder;
    ///
    /// let csp = CspBuilder::parse("default-src 'self'; img-src *")?
    ///     .script_nonce();
    /// assert_eq!(
    ///     csp.render(Some("n")),
    ///     "default-src 'self'; img-src *; script-src 'self' 'nonce-n'"
    /// );
    /// # Ok::<(), rune_axum_helmet::Error>(())
    /// ```
    pub fn parse(policy: &str) -> Result<Self, Error> {
        Self::parse_for(policy, CSP)
    }

    pub(crate) fn parse_for(policy: &str, header: &'static str) -> Result<Self, Error> {
        let parsed = Policy::from_str(policy).map_err(|source| Error::Csp { header, source })?;
        let directives = parsed
            .directives()
            .iter()
            .map(|d| {
                let tokens = d.tokens().iter().cloned().map(Token::Lit).collect();
                (d.name().to_owned(), tokens)
            })
            .collect();
        Ok(Self { directives })
    }

    /// Sets any directive by name, replacing an earlier value. Use it for
    /// directives without a dedicated method.
    #[must_use]
    pub fn directive(mut self, name: &str, values: &[&str]) -> Self {
        let name = name.trim().to_ascii_lowercase();
        let tokens = split(values).map(Token::Lit).collect();
        if let Some(slot) = self.directives.iter_mut().find(|(n, _)| *n == name) {
            slot.1 = tokens;
        } else {
            self.directives.push((name, tokens));
        }
        self
    }

    /// Removes a directive.
    #[must_use]
    pub fn remove(mut self, name: &str) -> Self {
        let name = name.trim().to_ascii_lowercase();
        self.directives.retain(|(n, _)| *n != name);
        self
    }

    /// Sets `default-src`.
    #[must_use]
    pub fn default_src(self, sources: &[&str]) -> Self {
        self.directive("default-src", sources)
    }

    /// Sets `script-src`.
    #[must_use]
    pub fn script_src(self, sources: &[&str]) -> Self {
        self.directive("script-src", sources)
    }

    /// Sets `script-src-elem` (`<script>` elements only).
    #[must_use]
    pub fn script_src_elem(self, sources: &[&str]) -> Self {
        self.directive("script-src-elem", sources)
    }

    /// Sets `script-src-attr` (inline event handlers such as `onclick`).
    #[must_use]
    pub fn script_src_attr(self, sources: &[&str]) -> Self {
        self.directive("script-src-attr", sources)
    }

    /// Sets `style-src`.
    #[must_use]
    pub fn style_src(self, sources: &[&str]) -> Self {
        self.directive("style-src", sources)
    }

    /// Sets `style-src-elem` (`<style>` and `<link rel=stylesheet>`).
    #[must_use]
    pub fn style_src_elem(self, sources: &[&str]) -> Self {
        self.directive("style-src-elem", sources)
    }

    /// Sets `style-src-attr` (`style="..."` attributes).
    #[must_use]
    pub fn style_src_attr(self, sources: &[&str]) -> Self {
        self.directive("style-src-attr", sources)
    }

    /// Sets `img-src`.
    #[must_use]
    pub fn img_src(self, sources: &[&str]) -> Self {
        self.directive("img-src", sources)
    }

    /// Sets `connect-src`.
    #[must_use]
    pub fn connect_src(self, sources: &[&str]) -> Self {
        self.directive("connect-src", sources)
    }

    /// Sets `font-src`.
    #[must_use]
    pub fn font_src(self, sources: &[&str]) -> Self {
        self.directive("font-src", sources)
    }

    /// Sets `media-src`.
    #[must_use]
    pub fn media_src(self, sources: &[&str]) -> Self {
        self.directive("media-src", sources)
    }

    /// Sets `object-src`. Keep it `'none'` unless you really embed plugins.
    #[must_use]
    pub fn object_src(self, sources: &[&str]) -> Self {
        self.directive("object-src", sources)
    }

    /// Sets `frame-src`.
    #[must_use]
    pub fn frame_src(self, sources: &[&str]) -> Self {
        self.directive("frame-src", sources)
    }

    /// Sets `frame-ancestors`, the modern replacement for
    /// `X-Frame-Options`. `'none'` matches `DENY`, `'self'` matches
    /// `SAMEORIGIN`.
    #[must_use]
    pub fn frame_ancestors(self, sources: &[&str]) -> Self {
        self.directive("frame-ancestors", sources)
    }

    /// Sets `child-src`.
    #[must_use]
    pub fn child_src(self, sources: &[&str]) -> Self {
        self.directive("child-src", sources)
    }

    /// Sets `worker-src`.
    #[must_use]
    pub fn worker_src(self, sources: &[&str]) -> Self {
        self.directive("worker-src", sources)
    }

    /// Sets `manifest-src`.
    #[must_use]
    pub fn manifest_src(self, sources: &[&str]) -> Self {
        self.directive("manifest-src", sources)
    }

    /// Sets `form-action`.
    #[must_use]
    pub fn form_action(self, sources: &[&str]) -> Self {
        self.directive("form-action", sources)
    }

    /// Sets `base-uri`.
    #[must_use]
    pub fn base_uri(self, sources: &[&str]) -> Self {
        self.directive("base-uri", sources)
    }

    /// Sets `sandbox` with the given `allow-*` flags (none for the most
    /// restrictive sandbox).
    #[must_use]
    pub fn sandbox(self, flags: &[&str]) -> Self {
        self.directive("sandbox", flags)
    }

    /// Adds `require-trusted-types-for 'script'`.
    #[must_use]
    pub fn require_trusted_types_for_script(self) -> Self {
        self.directive("require-trusted-types-for", &["'script'"])
    }

    /// Sets `trusted-types` with the allowed policy names.
    #[must_use]
    pub fn trusted_types(self, policies: &[&str]) -> Self {
        self.directive("trusted-types", policies)
    }

    /// Adds `upgrade-insecure-requests`.
    #[must_use]
    pub fn upgrade_insecure_requests(self) -> Self {
        self.directive("upgrade-insecure-requests", &[])
    }

    /// Adds `block-all-mixed-content`.
    ///
    /// Deprecated by browsers in favour of
    /// [`CspBuilder::upgrade_insecure_requests`]; kept for older clients.
    #[must_use]
    pub fn block_all_mixed_content(self) -> Self {
        self.directive("block-all-mixed-content", &[])
    }

    /// Sets `report-uri`. Deprecated in CSP 3 but still the only reporting
    /// mechanism Firefox supports; send it together with
    /// [`CspBuilder::report_to`].
    #[must_use]
    pub fn report_uri(self, uri: &str) -> Self {
        self.directive("report-uri", &[uri])
    }

    /// Sets `report-to`, naming an endpoint declared with
    /// [`Helmet::reporting_endpoint`](crate::Helmet::reporting_endpoint).
    #[must_use]
    pub fn report_to(self, endpoint: &str) -> Self {
        self.directive("report-to", &[endpoint])
    }

    /// Adds a per-request nonce to `script-src`.
    ///
    /// When `script-src` is not set yet it starts as a copy of
    /// `default-src`, because a new `script-src` stops scripts from falling
    /// back to `default-src`.
    #[must_use]
    pub fn script_nonce(self) -> Self {
        self.add_nonce("script-src")
    }

    /// Adds a per-request nonce to `style-src`, copying `default-src` first
    /// when `style-src` is not set yet.
    #[must_use]
    pub fn style_nonce(self) -> Self {
        self.add_nonce("style-src")
    }

    /// Adds `'strict-dynamic'` to `script-src`, so scripts loaded by a
    /// nonced script are trusted too and host allowlists are ignored.
    /// Needs a nonce (see [`CspBuilder::script_nonce`]) or a hash in
    /// `script-src`, which [`CspBuilder::validate`] checks.
    #[must_use]
    pub fn strict_dynamic(self) -> Self {
        self.add_sources("script-src", &["'strict-dynamic'"])
    }

    /// `true` when the policy has a nonce slot.
    #[must_use]
    pub fn uses_nonce(&self) -> bool {
        self.directives
            .iter()
            .any(|(_, tokens)| tokens.contains(&Token::Nonce))
    }

    /// The policy as a header value. Nonce slots become `'nonce-<nonce>'`,
    /// or are left out when `nonce` is `None`.
    #[must_use]
    pub fn render(&self, nonce: Option<&str>) -> String {
        let mut out = String::new();
        for (name, tokens) in &self.directives {
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(name);
            for token in tokens {
                match (token, nonce) {
                    (Token::Lit(t), _) => {
                        out.push(' ');
                        out.push_str(t);
                    }
                    (Token::Nonce, Some(n)) => {
                        out.push_str(" 'nonce-");
                        out.push_str(n);
                        out.push('\'');
                    }
                    (Token::Nonce, None) => {}
                }
            }
        }
        out
    }

    /// Checks the policy the way [`Helmet`](crate::Helmet) does at build
    /// time.
    ///
    /// # Errors
    ///
    /// - [`Error::Csp`] for an empty policy, a malformed source, or a
    ///   directive name or value containing `;`.
    /// - [`Error::UnknownCspDirective`] for a directive no spec defines.
    /// - [`Error::StaticCspNonce`] for a hard-coded `'nonce-...'`.
    /// - [`Error::StrictDynamicWithoutNonce`] for a `'strict-dynamic'`
    ///   that would block every script.
    /// - [`Error::InvalidHeaderValue`] for characters a header cannot hold.
    ///
    /// ```rust
    /// use rune_axum_helmet::{CspBuilder, Error};
    ///
    /// let typo = CspBuilder::new().directive("scirpt-src", &["'self'"]);
    /// assert!(matches!(typo.validate(), Err(Error::UnknownCspDirective { .. })));
    ///
    /// let blocked = CspBuilder::new().script_src(&["'self'"]).strict_dynamic();
    /// assert!(matches!(
    ///     blocked.validate(),
    ///     Err(Error::StrictDynamicWithoutNonce { .. })
    /// ));
    /// ```
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_for(CSP)
    }

    pub(crate) fn validate_for(&self, header: &'static str) -> Result<(), Error> {
        // A `;` inside a name or value would end the directive early and
        // start another one the caller never asked for.
        let csp = |source| Error::Csp { header, source };
        for (name, tokens) in &self.directives {
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(csp(rune_csp::Error::InvalidDirectiveName {
                    name: name.clone(),
                }));
            }
            if let Some(Token::Lit(token)) = tokens
                .iter()
                .find(|t| matches!(t, Token::Lit(l) if l.contains(';')))
            {
                return Err(csp(rune_csp::Error::InvalidSource {
                    directive: name.clone(),
                    token: token.clone(),
                }));
            }
        }
        let rendered = self.render(Some(PLACEHOLDER_NONCE));
        if HeaderValue::from_str(&rendered).is_err() {
            return Err(Error::InvalidHeaderValue { header });
        }
        let policy = Policy::from_str(&rendered).map_err(csp)?;
        for directive in policy.directives() {
            if !directive.is_known() {
                return Err(Error::UnknownCspDirective {
                    header,
                    name: directive.name().to_owned(),
                });
            }
        }
        for (name, tokens) in &self.directives {
            let fixed_nonce = tokens.iter().any(
                |t| matches!(t, Token::Lit(t) if matches!(Source::parse(t), Source::Nonce(_))),
            );
            if fixed_nonce {
                return Err(Error::StaticCspNonce {
                    header,
                    directive: name.clone(),
                });
            }
        }
        for name in ["script-src", "script-src-elem", "default-src"] {
            if name == "default-src" && policy.directive("script-src").is_some() {
                continue;
            }
            let Some(directive) = policy.directive(name) else {
                continue;
            };
            let sources = directive.sources();
            let strict_dynamic = sources.contains(&Source::Keyword(Keyword::StrictDynamic));
            if strict_dynamic && !sources.iter().any(Source::is_nonce_or_hash) {
                return Err(Error::StrictDynamicWithoutNonce {
                    header,
                    directive: name.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// The endpoint named by `report-to`, if any.
    pub(crate) fn report_to_endpoint(&self) -> Option<&str> {
        self.directives
            .iter()
            .find(|(n, _)| n == "report-to")
            .and_then(|(_, tokens)| tokens.first())
            .and_then(|t| match t {
                Token::Lit(t) => Some(t.as_str()),
                Token::Nonce => None,
            })
    }

    fn add_nonce(mut self, name: &str) -> Self {
        let slot = self.slot(name);
        if !slot.contains(&Token::Nonce) {
            slot.push(Token::Nonce);
        }
        self
    }

    fn add_sources(mut self, name: &str, sources: &[&str]) -> Self {
        let slot = self.slot(name);
        for source in split(sources) {
            let token = Token::Lit(source);
            if !slot.contains(&token) {
                slot.push(token);
            }
        }
        self
    }

    /// The token list of `name`, created from `default-src` when missing.
    fn slot(&mut self, name: &str) -> &mut Vec<Token> {
        let index = if let Some(i) = self.directives.iter().position(|(n, _)| n == name) {
            i
        } else {
            let inherited = self
                .directives
                .iter()
                .find(|(n, _)| n == "default-src")
                .map(|(_, tokens)| tokens.clone())
                .unwrap_or_default();
            self.directives.push((name.to_owned(), inherited));
            self.directives.len() - 1
        };
        let tokens = &mut self.directives[index].1;
        // `'none'` cannot be combined with other sources.
        tokens.retain(|t| !matches!(t, Token::Lit(l) if l.eq_ignore_ascii_case("'none'")));
        tokens
    }
}

impl fmt::Display for CspBuilder {
    /// Writes the policy with nonce slots shown as `'nonce-…'`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(Some("…")))
    }
}

fn split<'a>(values: &'a [&'a str]) -> impl Iterator<Item = String> + 'a {
    values
        .iter()
        .flat_map(|v| v.split_ascii_whitespace())
        .map(str::to_owned)
}

/// The nonce of the current request's `Content-Security-Policy`.
///
/// When the configured policy has a nonce slot, the layer generates 128
/// random bits per request, puts them in the header, and inserts this
/// value into the request extensions before the handler runs. Write it
/// into every inline `<script>` / `<style>` tag the page should run.
///
/// # Examples
///
/// ```rust
/// use axum::{Extension, response::Html};
/// use rune_axum_helmet::CspNonce;
///
/// async fn page(Extension(nonce): Extension<CspNonce>) -> Html<String> {
///     Html(format!(r#"<script nonce="{nonce}">console.log("hi")</script>"#))
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CspNonce(Arc<str>);

impl CspNonce {
    /// A fresh nonce: 16 bytes from a cryptographically secure generator,
    /// base64-encoded (24 characters).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        Self(base64(&bytes).into())
    }

    /// The base64 value, as it appears after `nonce-` in the header.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CspNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> shift) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A policy ready to be sent: fixed, or rendered per request.
#[derive(Clone, Debug)]
pub enum CompiledCsp {
    Static(HeaderValue),
    Nonce(CspBuilder),
}

impl CompiledCsp {
    pub fn new(builder: CspBuilder, header: &'static str) -> Result<Self, Error> {
        builder.validate_for(header)?;
        if builder.uses_nonce() {
            Ok(Self::Nonce(builder))
        } else {
            HeaderValue::from_str(&builder.render(None))
                .map(Self::Static)
                .map_err(|_| Error::InvalidHeaderValue { header })
        }
    }

    pub const fn uses_nonce(&self) -> bool {
        matches!(self, Self::Nonce(_))
    }

    /// The header value; `None` only for a nonce policy without a nonce.
    pub fn value(&self, nonce: Option<&CspNonce>) -> Option<HeaderValue> {
        match self {
            Self::Static(v) => Some(v.clone()),
            Self::Nonce(b) => HeaderValue::from_str(&b.render(Some(nonce?.as_str()))).ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn base64_known_values() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(&[0xff; 16]), "/////////////////////w==");
    }

    #[test]
    fn nonces_are_24_chars_and_distinct() {
        let a = CspNonce::generate();
        let b = CspNonce::generate();
        assert_eq!(a.as_str().len(), 24);
        assert_ne!(a, b);
        assert!(matches!(
            Source::parse(&format!("'nonce-{a}'")),
            Source::Nonce(_)
        ));
    }

    #[test]
    fn recommended_policy_is_valid_and_stable() {
        let csp = CspBuilder::recommended();
        csp.validate().unwrap();
        assert_eq!(
            csp.render(None),
            "default-src 'self'; base-uri 'self'; font-src 'self' https: data:; \
             form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; \
             object-src 'none'; script-src 'self'; script-src-attr 'none'; \
             style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests"
        );
    }

    #[test]
    fn strict_policy_is_valid() {
        let csp = CspBuilder::strict();
        csp.validate().unwrap();
        assert!(csp.uses_nonce());
        assert_eq!(
            csp.render(Some("n")),
            "script-src 'nonce-n' 'strict-dynamic' https: 'unsafe-inline'; \
             object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        );
    }

    #[test]
    fn directive_replaces_instead_of_duplicating() {
        let csp = CspBuilder::new()
            .script_src(&["'self'"])
            .script_src(&["https://cdn.example"]);
        assert_eq!(csp.render(None), "script-src https://cdn.example");
    }

    #[test]
    fn space_separated_sources_are_split() {
        let csp = CspBuilder::new().img_src(&["'self'  data:"]);
        assert_eq!(csp.render(None), "img-src 'self' data:");
    }

    #[test]
    fn nonce_copies_default_src_and_drops_none() {
        let csp = CspBuilder::new().default_src(&["'self'"]).script_nonce();
        assert_eq!(
            csp.render(Some("n")),
            "default-src 'self'; script-src 'self' 'nonce-n'"
        );
        let csp = CspBuilder::new().script_src(&["'none'"]).script_nonce();
        assert_eq!(csp.render(Some("n")), "script-src 'nonce-n'");
    }

    #[test]
    fn nonce_slot_is_not_duplicated() {
        let csp = CspBuilder::new().script_nonce().script_nonce();
        assert_eq!(csp.render(Some("n")), "script-src 'nonce-n'");
    }

    #[test]
    fn rejects_unknown_directive() {
        let err = CspBuilder::new()
            .directive("img-scr", &["'self'"])
            .validate()
            .unwrap_err();
        assert_eq!(
            err,
            Error::UnknownCspDirective {
                header: CSP,
                name: "img-scr".into()
            }
        );
    }

    #[test]
    fn rejects_bad_source_and_empty_policy() {
        assert!(matches!(
            CspBuilder::new()
                .script_src(&["'unsafe-everything'"])
                .validate(),
            Err(Error::Csp { .. })
        ));
        assert!(matches!(
            CspBuilder::new().validate(),
            Err(Error::Csp {
                source: rune_csp::Error::Empty,
                ..
            })
        ));
    }

    #[test]
    fn rejects_fixed_nonce() {
        let err = CspBuilder::parse("script-src 'nonce-abc'")
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(matches!(err, Error::StaticCspNonce { .. }));
    }

    #[test]
    fn strict_dynamic_needs_nonce_or_hash() {
        let bare = CspBuilder::new().script_src(&["'self'"]).strict_dynamic();
        assert!(matches!(
            bare.validate(),
            Err(Error::StrictDynamicWithoutNonce { .. })
        ));
        bare.clone().script_nonce().validate().unwrap();
        bare.script_src(&[
            "'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8='",
            "'strict-dynamic'",
        ])
        .validate()
        .unwrap();
        let via_default = CspBuilder::parse("default-src 'self' 'strict-dynamic'").unwrap();
        assert!(matches!(
            via_default.validate(),
            Err(Error::StrictDynamicWithoutNonce { .. })
        ));
    }

    #[test]
    fn rejects_control_characters() {
        let err = CspBuilder::new()
            .report_uri("/csp\u{7f}")
            .validate()
            .unwrap_err();
        assert_eq!(err, Error::InvalidHeaderValue { header: CSP });
    }

    #[test]
    fn values_cannot_inject_directives() {
        let injected = [
            CspBuilder::new()
                .default_src(&["'self'"])
                .img_src(&["https://cdn.example; script-src *"]),
            CspBuilder::new()
                .default_src(&["'self'"])
                .report_uri("/csp;script-src *"),
            CspBuilder::new()
                .default_src(&["'self'"])
                .directive("img-src https://cdn.example; script-src", &["*"]),
            CspBuilder::new()
                .default_src(&["'self'"])
                .directive("sandbox", &["allow-forms;", "script-src", "*"]),
        ];
        for builder in injected {
            assert!(
                matches!(
                    builder.validate(),
                    Err(Error::Csp {
                        source: rune_csp::Error::InvalidSource { .. }
                            | rune_csp::Error::InvalidDirectiveName { .. },
                        ..
                    })
                ),
                "{builder}"
            );
        }
        // Line breaks only ever split sources, never the header.
        let split = CspBuilder::new().img_src(&["'self'\r\nhttps://a.example"]);
        assert_eq!(split.render(None), "img-src 'self' https://a.example");
        split.validate().unwrap();
    }

    #[test]
    fn parse_rejects_several_policies() {
        assert!(matches!(
            CspBuilder::parse("default-src 'self', img-src *"),
            Err(Error::Csp {
                source: rune_csp::Error::MultiplePolicies,
                ..
            })
        ));
    }

    proptest! {
        #[test]
        fn base64_has_expected_length(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let encoded = base64(&bytes);
            prop_assert_eq!(encoded.len(), bytes.len().div_ceil(3) * 4);
            prop_assert!(encoded.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)));
        }

        #[test]
        fn rendered_nonce_round_trips(n in "[A-Za-z0-9+/]{22}==") {
            let csp = CspBuilder::recommended().script_nonce();
            let rendered = csp.render(Some(&n));
            let policy = Policy::from_str(&rendered).unwrap();
            let sources = policy.directive("script-src").unwrap().sources();
            prop_assert!(sources.contains(&Source::Nonce(n)));
        }
    }
}
