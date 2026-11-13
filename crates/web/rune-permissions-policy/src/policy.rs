//! The policy model, both header syntaxes, and canonical serialization.

use std::collections::HashMap;
use std::fmt;

use crate::Error;
use crate::sf::{self, BareItem};

/// Which header a policy was written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Syntax {
    /// `Permissions-Policy`: an RFC 8941 dictionary,
    /// `camera=(), geolocation=(self "https://maps.example")`.
    #[default]
    PermissionsPolicy,
    /// The legacy `Feature-Policy` header,
    /// `camera 'none'; geolocation 'self' https://maps.example`.
    FeaturePolicy,
}

/// One entry of an allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Member {
    /// `*`: every origin.
    All,
    /// `self` (`'self'` in `Feature-Policy`): the document's own origin.
    SelfOrigin,
    /// `src` (`'src'`): the origin of the iframe's `src`. Only meaningful in
    /// an iframe `allow` attribute.
    Src,
    /// An origin, as written (`https://maps.example`, possibly with a
    /// `*.` subdomain wildcard). Must be printable ASCII to serialize.
    Origin(String),
    /// A member browsers ignore — a string that is not an origin, an
    /// unknown token, a number. Holds its serialization as written in the
    /// policy's syntax.
    Other(String),
}

impl Member {
    /// An `http://` origin: the grant also covers plain-HTTP frames.
    #[must_use]
    pub fn is_insecure_origin(&self) -> bool {
        matches!(self, Self::Origin(o) if o.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("http://")))
    }

    fn write(&self, f: &mut fmt::Formatter<'_>, syntax: Syntax) -> fmt::Result {
        match (self, syntax) {
            (Self::All, _) => f.write_str("*"),
            (Self::SelfOrigin, Syntax::PermissionsPolicy) => f.write_str("self"),
            (Self::SelfOrigin, Syntax::FeaturePolicy) => f.write_str("'self'"),
            (Self::Src, Syntax::PermissionsPolicy) => f.write_str("src"),
            (Self::Src, Syntax::FeaturePolicy) => f.write_str("'src'"),
            (Self::Origin(o), Syntax::PermissionsPolicy) => sf::write_string(f, o),
            (Self::Origin(o) | Self::Other(o), _) => f.write_str(o),
        }
    }
}

/// The origins a feature is allowed in. Empty means no origin (`()`,
/// `'none'`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct Allowlist {
    /// The members, in the order written.
    pub members: Vec<Member>,
}

impl Allowlist {
    /// An allowlist with these members.
    #[must_use]
    pub fn new(members: impl IntoIterator<Item = Member>) -> Self {
        Self {
            members: members.into_iter().collect(),
        }
    }

    /// No origin is allowed (ignored members do not count).
    #[must_use]
    pub fn is_none(&self) -> bool {
        self.members.iter().all(|m| matches!(m, Member::Other(_)))
    }

    /// Every origin is allowed (`*`).
    #[must_use]
    pub fn allows_all(&self) -> bool {
        self.members.contains(&Member::All)
    }

    /// The document's own origin is allowed (`self` or `*`).
    #[must_use]
    pub fn allows_self(&self) -> bool {
        self.members
            .iter()
            .any(|m| matches!(m, Member::All | Member::SelfOrigin))
    }

    /// The explicitly listed origins.
    pub fn origins(&self) -> impl Iterator<Item = &str> {
        self.members.iter().filter_map(|m| match m {
            Member::Origin(o) => Some(o.as_str()),
            _ => None,
        })
    }
}

/// One `feature=allowlist` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Directive {
    /// The feature name (`camera`, `geolocation`). Lowercase in
    /// `Permissions-Policy`.
    pub feature: String,
    /// Where the feature is allowed.
    pub allowlist: Allowlist,
    /// The `report-to` parameter: the reporting endpoint for violations.
    pub report_to: Option<String>,
}

impl Directive {
    /// A directive with no `report-to`.
    #[must_use]
    pub fn new(feature: impl Into<String>, allowlist: Allowlist) -> Self {
        Self {
            feature: feature.into(),
            allowlist,
            report_to: None,
        }
    }

    /// Sets [`Directive::report_to`].
    #[must_use]
    pub fn with_report_to(mut self, endpoint: impl Into<String>) -> Self {
        self.report_to = Some(endpoint.into());
        self
    }
}

/// A parsed `Permissions-Policy` or `Feature-Policy` header.
///
/// Directives keep their order and repeats; [`PermissionsPolicy::get`]
/// applies each syntax's rule for repeated features.
/// [`Display`](fmt::Display) writes the canonical form for the policy's
/// [`Syntax`], which parses back to an equal policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct PermissionsPolicy {
    /// The header syntax the policy was read from (and is written in).
    pub syntax: Syntax,
    /// The directives, in the order written.
    pub directives: Vec<Directive>,
}

impl PermissionsPolicy {
    /// An empty policy in the given syntax.
    #[must_use]
    pub const fn new(syntax: Syntax) -> Self {
        Self {
            syntax,
            directives: Vec::new(),
        }
    }

    /// Appends a directive.
    #[must_use]
    pub fn with_directive(mut self, directive: Directive) -> Self {
        self.directives.push(directive);
        self
    }

    /// Parses a `Permissions-Policy` header value, strictly: a value that is
    /// not a valid RFC 8941 dictionary is an [`Error`], since browsers then
    /// ignore the whole header.
    ///
    /// Members browsers ignore are kept as [`Member::Other`]; a feature
    /// given a bare item that is not an allowlist (`camera`, `camera=?1`)
    /// gets an allowlist holding only that [`Member::Other`]. Parameters
    /// other than `report-to` are dropped.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedChar`], [`Error::UnterminatedString`] or
    /// [`Error::NumberOutOfRange`] for a syntax error.
    pub fn parse(header: &str) -> Result<Self, Error> {
        let members = sf::parse_dictionary(header)?;
        let directives = members
            .into_iter()
            .map(|m| {
                let allowlist = match m.value {
                    sf::Value::InnerList(items) => {
                        Allowlist::new(items.into_iter().map(|i| member_from_item(i.bare)))
                    }
                    sf::Value::Item(bare) => Allowlist::new([member_from_item(bare)]),
                };
                let report_to = m.params.into_iter().find_map(|(k, v)| match v {
                    BareItem::Token(s) | BareItem::String(s) if k == "report-to" => Some(s),
                    _ => None,
                });
                Directive {
                    feature: m.key,
                    allowlist,
                    report_to,
                }
            })
            .collect();
        Ok(Self {
            syntax: Syntax::PermissionsPolicy,
            directives,
        })
    }

    /// Parses a legacy `Feature-Policy` header value:
    /// `feature allowlist; feature allowlist`, with `*`, `'self'`, `'src'`,
    /// `'none'` and origins separated by whitespace.
    ///
    /// `'none'` contributes nothing, so `camera 'none'` and a bare `camera`
    /// both have an empty allowlist. Unrecognised members are kept as
    /// [`Member::Other`]. Feature names keep their case.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFeatureName`] for a name with characters outside the
    /// HTTP token set.
    pub fn parse_feature_policy(header: &str) -> Result<Self, Error> {
        let mut directives = Vec::new();
        for decl in header.split(';') {
            let mut words = decl.split_ascii_whitespace();
            let Some(name) = words.next() else {
                continue;
            };
            if !name.bytes().all(sf::is_tchar) {
                return Err(Error::InvalidFeatureName {
                    name: name.to_owned(),
                });
            }
            let members = words.filter_map(|w| match w.to_ascii_lowercase().as_str() {
                "*" => Some(Member::All),
                "'self'" => Some(Member::SelfOrigin),
                "'src'" => Some(Member::Src),
                "'none'" => None,
                _ if is_origin(w) => Some(Member::Origin(w.to_owned())),
                _ => Some(Member::Other(w.to_owned())),
            });
            directives.push(Directive::new(name, Allowlist::new(members)));
        }
        Ok(Self {
            syntax: Syntax::FeaturePolicy,
            directives,
        })
    }

    /// The effective allowlist for `feature`: the last declaration in
    /// `Permissions-Policy` (RFC 8941 dictionaries keep the last value), the
    /// first in `Feature-Policy`.
    #[must_use]
    pub fn get(&self, feature: &str) -> Option<&Directive> {
        let mut matching = self.directives.iter().filter(|d| d.feature == feature);
        match self.syntax {
            Syntax::PermissionsPolicy => matching.next_back(),
            Syntax::FeaturePolicy => matching.next(),
        }
    }

    /// The effective directive of every feature, once each, in first-seen
    /// order.
    pub fn effective(&self) -> impl Iterator<Item = &Directive> {
        // feature -> (index of its first declaration, index of the one that counts)
        let mut slots: HashMap<&str, (usize, usize)> = HashMap::new();
        for (i, d) in self.directives.iter().enumerate() {
            let slot = slots.entry(d.feature.as_str()).or_insert((i, i));
            if self.syntax == Syntax::PermissionsPolicy {
                slot.1 = i;
            }
        }
        self.directives
            .iter()
            .enumerate()
            .filter_map(move |(i, d)| match slots.get(d.feature.as_str()) {
                Some(&(first, winner)) if first == i => self.directives.get(winner),
                _ => None,
            })
    }

    /// Converts the effective policy to `Permissions-Policy` syntax, for
    /// migrating off `Feature-Policy`: names are lowercased, and names that
    /// are not valid dictionary keys and ignored members are dropped.
    #[must_use]
    pub fn to_permissions_policy(&self) -> Self {
        let directives = self
            .effective()
            .filter_map(|d| {
                let feature = d.feature.to_ascii_lowercase();
                if !sf::is_key(&feature) {
                    return None;
                }
                let members = d
                    .allowlist
                    .members
                    .iter()
                    .filter(|m| match m {
                        Member::Other(_) => false,
                        Member::Origin(o) => o.bytes().all(|b| (0x20..=0x7e).contains(&b)),
                        _ => true,
                    })
                    .cloned();
                Some(Directive {
                    feature,
                    allowlist: Allowlist::new(members),
                    report_to: d.report_to.clone(),
                })
            })
            .collect();
        Self {
            syntax: Syntax::PermissionsPolicy,
            directives,
        }
    }
}

impl std::str::FromStr for PermissionsPolicy {
    type Err = Error;

    /// [`PermissionsPolicy::parse`].
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::parse(s)
    }
}

fn member_from_item(bare: BareItem) -> Member {
    match bare {
        BareItem::Token(t) if t == "*" => Member::All,
        BareItem::Token(t) if t == "self" => Member::SelfOrigin,
        BareItem::Token(t) if t == "src" => Member::Src,
        BareItem::String(s) if is_origin(&s) => Member::Origin(s),
        other => Member::Other(other.to_string()),
    }
}

/// Whether `s` is an `http(s)` URL with a host, i.e. one with a tuple
/// origin. A leading `*.` wildcard label is allowed; a path is allowed
/// (only the origin counts).
#[must_use]
pub fn is_origin(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once("://") else {
        return false;
    };
    if !(scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")) {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return false;
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let Some((addr, after)) = v6.split_once(']') else {
            return false;
        };
        if addr.is_empty()
            || !addr
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return false;
        }
        match after.strip_prefix(':') {
            Some(p) => ("v6", Some(p)),
            None if after.is_empty() => ("v6", None),
            None => return false,
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if let Some(p) = port
        && (p.is_empty() || p.len() > 5 || p.parse::<u16>().is_err())
    {
        return false;
    }
    let host = host.strip_prefix("*.").unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

impl fmt::Display for Directive {
    /// `Permissions-Policy` form; see [`PermissionsPolicy`] for the
    /// policy's own syntax.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_directive(self, f, Syntax::PermissionsPolicy)
    }
}

fn write_directive(d: &Directive, f: &mut fmt::Formatter<'_>, syntax: Syntax) -> fmt::Result {
    f.write_str(&d.feature)?;
    let members = &d.allowlist.members;
    match syntax {
        Syntax::PermissionsPolicy => {
            f.write_str("=")?;
            if members == &[Member::All] {
                f.write_str("*")?;
            } else {
                f.write_str("(")?;
                for (i, m) in members.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" ")?;
                    }
                    m.write(f, syntax)?;
                }
                f.write_str(")")?;
            }
            if let Some(ep) = &d.report_to {
                f.write_str(";report-to=")?;
                if sf::is_token(ep) {
                    f.write_str(ep)?;
                } else {
                    sf::write_string(f, ep)?;
                }
            }
        }
        Syntax::FeaturePolicy => {
            if members.is_empty() {
                f.write_str(" 'none'")?;
            }
            for m in members {
                f.write_str(" ")?;
                m.write(f, syntax)?;
            }
        }
    }
    Ok(())
}

impl fmt::Display for PermissionsPolicy {
    /// The canonical header value in the policy's [`Syntax`]:
    /// `camera=(), geolocation=(self "https://a.example")` or
    /// `camera 'none'; geolocation 'self' https://a.example`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sep = match self.syntax {
            Syntax::PermissionsPolicy => ", ",
            Syntax::FeaturePolicy => "; ",
        };
        for (i, d) in self.directives.iter().enumerate() {
            if i > 0 {
                f.write_str(sep)?;
            }
            write_directive(d, f, self.syntax)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        PermissionsPolicy::parse(s).unwrap().to_string()
    }

    #[test]
    fn parses_permissions_policy() {
        let p = PermissionsPolicy::parse(
            "camera=(), geolocation=(self \"https://maps.example\"), fullscreen=*, \
             payment=self;report-to=ep, usb=src",
        )
        .unwrap();
        assert_eq!(p.directives.len(), 5);
        assert!(p.get("camera").unwrap().allowlist.is_none());
        let geo = &p.get("geolocation").unwrap().allowlist;
        assert!(geo.allows_self() && !geo.allows_all());
        assert_eq!(geo.origins().collect::<Vec<_>>(), ["https://maps.example"]);
        assert!(p.get("fullscreen").unwrap().allowlist.allows_all());
        assert_eq!(p.get("payment").unwrap().report_to.as_deref(), Some("ep"));
        assert_eq!(p.get("usb").unwrap().allowlist.members, [Member::Src]);
    }

    #[test]
    fn canonical_form() {
        assert_eq!(
            canon("camera=(),geolocation=self,  fullscreen=( * ) ,payment=*"),
            "camera=(), geolocation=(self), fullscreen=*, payment=*"
        );
        assert_eq!(
            canon("a=\"x\";report-to=\"e p\""),
            "a=(\"x\");report-to=\"e p\""
        );
        assert_eq!(
            canon("a, b=?1, c=1.50, d=none"),
            "a=(?1), b=(?1), c=(1.5), d=(none)"
        );
        assert_eq!(canon(""), "");
    }

    #[test]
    fn ignored_members() {
        let p = PermissionsPolicy::parse("a=(\"self\" none 3 \"https://ok.example/x\")").unwrap();
        assert_eq!(
            p.directives[0].allowlist.members,
            [
                Member::Other("\"self\"".into()),
                Member::Other("none".into()),
                Member::Other("3".into()),
                Member::Origin("https://ok.example/x".into()),
            ]
        );
        assert!(
            PermissionsPolicy::parse("a=()").unwrap().directives[0]
                .allowlist
                .is_none()
        );
    }

    #[test]
    fn duplicates_follow_syntax() {
        let p = PermissionsPolicy::parse("camera=*, camera=()").unwrap();
        assert!(p.get("camera").unwrap().allowlist.is_none());
        assert_eq!(p.effective().count(), 1);
        let p = PermissionsPolicy::parse_feature_policy("camera *; camera 'none'").unwrap();
        assert!(p.get("camera").unwrap().allowlist.allows_all());
    }

    #[test]
    fn feature_policy() {
        let p = PermissionsPolicy::parse_feature_policy(
            "camera 'none'; geolocation 'self' https://maps.example ; ;fullscreen *; usb 'SRC' bogus",
        )
        .unwrap();
        assert_eq!(
            p.to_string(),
            "camera 'none'; geolocation 'self' https://maps.example; fullscreen *; usb 'src' bogus"
        );
        assert_eq!(
            p.to_permissions_policy().to_string(),
            "camera=(), geolocation=(self \"https://maps.example\"), fullscreen=*, usb=(src)"
        );
        assert!(PermissionsPolicy::parse_feature_policy("cam(era) *").is_err());
        assert_eq!(
            PermissionsPolicy::parse_feature_policy("  ")
                .unwrap()
                .directives,
            []
        );
    }

    #[test]
    fn origins() {
        for ok in [
            "https://a.example",
            "http://a.example:8080/",
            "https://*.a.example",
            "https://[::1]:443",
            "HTTPS://A.EXAMPLE/path?q",
        ] {
            assert!(is_origin(ok), "{ok}");
        }
        for bad in [
            "self",
            "a.example",
            "data:text/html,x",
            "https://",
            "https://a..b",
            "https://u@a.example",
            "https://a.example:99999",
            "https://a.example:",
            "ftp://a.example",
            "https://a b",
        ] {
            assert!(!is_origin(bad), "{bad}");
        }
        assert!(Member::Origin("http://a".into()).is_insecure_origin());
        assert!(!Member::Origin("https://a".into()).is_insecure_origin());
    }
}
