//! The well-known resource catalogue, the sans-I/O response type and the
//! dispatching parser.

use std::fmt;

use rune_securitytxt::SecurityTxt;

use crate::{AppleAppSiteAssociation, AssetLinks, Error, MtaStsPolicy, OpenIdConfiguration};

/// Bodies larger than this are rejected by [`parse`] (1 MiB).
pub const MAX_BODY_LEN: usize = 1 << 20;

/// The path whose status code tells whether a server answers unknown
/// well-known paths reliably ([Change Password URL §5](https://w3c.github.io/webappsec-change-password-url/#detecting-the-reliability-of-http-status-codes)).
pub const STATUS_PROBE_PATH: &str =
    "/.well-known/resource-that-should-not-exist-whose-status-code-should-not-be-200";

/// A well-known resource this crate parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WellKnown {
    /// `security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)).
    SecurityTxt,
    /// `change-password` ([W3C](https://w3c.github.io/webappsec-change-password-url/)).
    ChangePassword,
    /// `mta-sts.txt` ([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)),
    /// served on the `mta-sts.` subdomain of the mail domain.
    MtaSts,
    /// `openid-configuration` (OIDC Discovery 1.0).
    OpenIdConfiguration,
    /// `assetlinks.json` (Digital Asset Links).
    AssetLinks,
    /// `apple-app-site-association` (Apple associated domains).
    AppleAppSiteAssociation,
}

impl WellKnown {
    /// Every resource, in catalogue order.
    pub const ALL: [Self; 6] = [
        Self::SecurityTxt,
        Self::ChangePassword,
        Self::MtaSts,
        Self::OpenIdConfiguration,
        Self::AssetLinks,
        Self::AppleAppSiteAssociation,
    ];

    /// The registered name, the last path segment.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SecurityTxt => "security.txt",
            Self::ChangePassword => "change-password",
            Self::MtaSts => "mta-sts.txt",
            Self::OpenIdConfiguration => "openid-configuration",
            Self::AssetLinks => "assetlinks.json",
            Self::AppleAppSiteAssociation => "apple-app-site-association",
        }
    }

    /// The path, `/.well-known/<name>`.
    #[must_use]
    pub fn path(self) -> String {
        format!("/.well-known/{}", self.name())
    }

    /// The resource at `path`: `/.well-known/<name>`, `<name>`, or
    /// `/apple-app-site-association` (the legacy root location). A query
    /// or fragment is ignored.
    #[must_use]
    pub fn from_path(path: &str) -> Option<Self> {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let name = path
            .strip_prefix("/.well-known/")
            .or_else(|| {
                path.strip_prefix('/')
                    .filter(|p| *p == "apple-app-site-association")
            })
            .unwrap_or(path);
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

impl fmt::Display for WellKnown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An HTTP response, as the caller received it. The crate never performs
/// I/O itself; fill this from any client (or use the `fetch` feature).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Header fields, in order, as `(name, value)`.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with a status and body and no headers.
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Adds a header field.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The first value of a header, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The media type of `Content-Type`, lowercased, without parameters.
    #[must_use]
    pub fn media_type(&self) -> Option<String> {
        self.header("content-type").map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
    }

    fn text(&self) -> Result<&str, Error> {
        if self.body.len() > MAX_BODY_LEN {
            return Err(Error::TooLarge {
                limit: MAX_BODY_LEN,
            });
        }
        std::str::from_utf8(&self.body).map_err(|e| Error::NotUtf8 {
            offset: e.valid_up_to(),
        })
    }
}

/// How a site answers its change-password URL.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangePassword {
    /// It redirects (as it should, with 302, 303 or 307) to the page where
    /// users change their password.
    Redirect {
        /// The status code.
        status: u16,
        /// The `Location` header, as sent (possibly relative).
        location: String,
    },
    /// It serves a page directly (2xx) instead of redirecting.
    Page {
        /// The status code.
        status: u16,
    },
    /// No change-password URL: any other status, or a redirect without a
    /// `Location`.
    Unsupported {
        /// The status code.
        status: u16,
    },
}

impl ChangePassword {
    /// Classifies a response to `GET /.well-known/change-password` (made
    /// without following redirects).
    #[must_use]
    pub fn from_response(response: &Response) -> Self {
        let status = response.status;
        match (status, response.header("location")) {
            (300..=399, Some(location)) if !location.trim().is_empty() => Self::Redirect {
                status,
                location: location.trim().to_owned(),
            },
            (200..=299, _) => Self::Page { status },
            _ => Self::Unsupported { status },
        }
    }

    /// Whether the site supports the change-password URL (redirect or page).
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }
}

/// Whether a response to [`STATUS_PROBE_PATH`] shows the server reports
/// missing resources with an error status, so that a 2xx elsewhere under
/// `/.well-known/` can be believed.
#[must_use]
pub const fn status_codes_reliable(probe: &Response) -> bool {
    !matches!(probe.status, 200..=299)
}

/// A resource this crate does not parse, or chose not to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RawResource {
    /// The path it was requested at.
    pub path: String,
    /// The response status.
    pub status: u16,
    /// The media type, if any.
    pub media_type: Option<String>,
    /// The body, unchanged.
    pub body: Vec<u8>,
}

/// A parsed well-known resource.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resource {
    /// `security.txt`. Validate it with [`rune_securitytxt::run`].
    SecurityTxt(Box<SecurityTxt>),
    /// `change-password`.
    ChangePassword(ChangePassword),
    /// `mta-sts.txt`.
    MtaSts(MtaStsPolicy),
    /// `openid-configuration`.
    OpenIdConfiguration(Box<OpenIdConfiguration>),
    /// `assetlinks.json`.
    AssetLinks(AssetLinks),
    /// `apple-app-site-association`.
    AppleAppSiteAssociation(Box<AppleAppSiteAssociation>),
    /// Any other path, returned raw.
    Unknown(RawResource),
}

impl Resource {
    /// Which resource this is, `None` for [`Resource::Unknown`].
    #[must_use]
    pub const fn kind(&self) -> Option<WellKnown> {
        Some(match self {
            Self::SecurityTxt(_) => WellKnown::SecurityTxt,
            Self::ChangePassword(_) => WellKnown::ChangePassword,
            Self::MtaSts(_) => WellKnown::MtaSts,
            Self::OpenIdConfiguration(_) => WellKnown::OpenIdConfiguration,
            Self::AssetLinks(_) => WellKnown::AssetLinks,
            Self::AppleAppSiteAssociation(_) => WellKnown::AppleAppSiteAssociation,
            Self::Unknown(_) => return None,
        })
    }
}

/// Parses the response to a request for `path`.
///
/// Known resources ([`WellKnown::from_path`]) need a 2xx status (any status
/// for `change-password`, which is classified instead) and a UTF-8 body of
/// at most [`MAX_BODY_LEN`] bytes. Unknown paths come back as
/// [`Resource::Unknown`] whatever the status.
pub fn parse(path: &str, response: &Response) -> Result<Resource, Error> {
    let Some(kind) = WellKnown::from_path(path) else {
        return Ok(Resource::Unknown(RawResource {
            path: path.to_owned(),
            status: response.status,
            media_type: response.media_type(),
            body: response.body.clone(),
        }));
    };
    if kind == WellKnown::ChangePassword {
        return Ok(Resource::ChangePassword(ChangePassword::from_response(
            response,
        )));
    }
    if !(200..=299).contains(&response.status) {
        return Err(Error::Status {
            status: response.status,
        });
    }
    if kind == WellKnown::AppleAppSiteAssociation && response.body.first() == Some(&0x30) {
        return Err(Error::SignedAasa);
    }
    parse_body(kind, response.text()?)
}

/// Parses the body of a known resource.
pub fn parse_body(kind: WellKnown, text: &str) -> Result<Resource, Error> {
    Ok(match kind {
        WellKnown::SecurityTxt => Resource::SecurityTxt(Box::new(SecurityTxt::parse(text)?)),
        WellKnown::ChangePassword => {
            // A body alone says nothing about a redirect.
            Resource::ChangePassword(ChangePassword::Page { status: 200 })
        }
        WellKnown::MtaSts => Resource::MtaSts(MtaStsPolicy::parse(text)?),
        WellKnown::OpenIdConfiguration => {
            Resource::OpenIdConfiguration(Box::new(OpenIdConfiguration::parse(text)?))
        }
        WellKnown::AssetLinks => Resource::AssetLinks(AssetLinks::parse(text)?),
        WellKnown::AppleAppSiteAssociation => {
            Resource::AppleAppSiteAssociation(Box::new(AppleAppSiteAssociation::parse(text)?))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        for k in WellKnown::ALL {
            assert_eq!(WellKnown::from_path(&k.path()), Some(k));
            assert_eq!(WellKnown::from_path(k.name()), Some(k));
        }
        assert_eq!(
            WellKnown::from_path("/apple-app-site-association"),
            Some(WellKnown::AppleAppSiteAssociation)
        );
        assert_eq!(
            WellKnown::from_path("/.well-known/security.txt?x=1"),
            Some(WellKnown::SecurityTxt)
        );
        assert_eq!(WellKnown::from_path("/security.txt"), None);
        assert_eq!(WellKnown::from_path("/.well-known/nodeinfo"), None);
    }

    #[test]
    fn change_password() {
        let r = Response::new(302, "").with_header("Location", "/account/password");
        assert_eq!(
            ChangePassword::from_response(&r),
            ChangePassword::Redirect {
                status: 302,
                location: "/account/password".to_owned()
            }
        );
        assert!(ChangePassword::from_response(&Response::new(200, "")).is_supported());
        assert!(!ChangePassword::from_response(&Response::new(404, "")).is_supported());
        assert!(!ChangePassword::from_response(&Response::new(301, "")).is_supported());
        assert!(status_codes_reliable(&Response::new(404, "")));
        assert!(!status_codes_reliable(&Response::new(200, "")));
    }

    #[test]
    fn dispatch_errors_and_raw() {
        let path = "/.well-known/security.txt";
        assert_eq!(
            parse(path, &Response::new(404, "")),
            Err(Error::Status { status: 404 })
        );
        assert_eq!(
            parse(path, &Response::new(200, vec![b'a', 0xff])),
            Err(Error::NotUtf8 { offset: 1 })
        );
        assert!(matches!(
            parse(path, &Response::new(200, vec![b'#'; MAX_BODY_LEN + 1])),
            Err(Error::TooLarge { .. })
        ));
        assert_eq!(
            parse(
                "/.well-known/apple-app-site-association",
                &Response::new(200, vec![0x30, 0x82, 0x01])
            ),
            Err(Error::SignedAasa)
        );
        let raw = parse(
            "/.well-known/nodeinfo",
            &Response::new(200, "{}")
                .with_header("Content-Type", "application/json; charset=utf-8"),
        )
        .unwrap();
        let Resource::Unknown(raw) = raw else {
            panic!("{raw:?}")
        };
        assert_eq!(raw.media_type.as_deref(), Some("application/json"));
        assert_eq!(raw.body, b"{}");
    }
}
