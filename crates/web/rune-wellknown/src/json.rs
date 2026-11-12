//! JSON resources: OIDC discovery, Digital Asset Links and Apple
//! App Site Association.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::Error;

fn from_json<'a, T: Deserialize<'a>>(text: &'a str) -> Result<T, Error> {
    serde_json::from_str(text).map_err(|e| Error::Json {
        message: e.to_string(),
    })
}

/// An OIDC provider configuration
/// ([OpenID Connect Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)),
/// served at `/.well-known/openid-configuration`.
///
/// Every field is optional so a partial document still parses;
/// [`OpenIdConfiguration::missing_required`] lists what the specification
/// requires and is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct OpenIdConfiguration {
    /// The issuer identifier.
    pub issuer: Option<String>,
    /// The authorization endpoint.
    pub authorization_endpoint: Option<String>,
    /// The token endpoint.
    pub token_endpoint: Option<String>,
    /// The `UserInfo` endpoint.
    pub userinfo_endpoint: Option<String>,
    /// The JSON Web Key Set document.
    pub jwks_uri: Option<String>,
    /// The dynamic client registration endpoint.
    pub registration_endpoint: Option<String>,
    /// The RP-initiated logout endpoint.
    pub end_session_endpoint: Option<String>,
    /// Token revocation endpoint (RFC 7009).
    pub revocation_endpoint: Option<String>,
    /// Token introspection endpoint (RFC 7662).
    pub introspection_endpoint: Option<String>,
    /// Supported scopes.
    pub scopes_supported: Option<Vec<String>>,
    /// Supported `response_type` values.
    pub response_types_supported: Option<Vec<String>>,
    /// Supported grant types.
    pub grant_types_supported: Option<Vec<String>>,
    /// Supported subject identifier types.
    pub subject_types_supported: Option<Vec<String>>,
    /// Supported ID token signing algorithms.
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported client authentication methods at the token endpoint.
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported PKCE methods (RFC 7636).
    pub code_challenge_methods_supported: Option<Vec<String>>,
    /// Supported claims.
    pub claims_supported: Option<Vec<String>>,
    /// Every other member, as JSON.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

impl OpenIdConfiguration {
    /// Parses the JSON document.
    pub fn parse(text: &str) -> Result<Self, Error> {
        from_json(text)
    }

    /// Names of members Discovery §3 requires that are absent.
    /// `authorization_endpoint` and `token_endpoint` are required unless
    /// the provider only supports the implicit flow (`token_endpoint`).
    #[must_use]
    pub fn missing_required(&self) -> Vec<&'static str> {
        let implicit_only = self
            .grant_types_supported
            .as_ref()
            .is_some_and(|g| !g.is_empty() && g.iter().all(|t| t == "implicit"));
        [
            ("issuer", self.issuer.is_some()),
            (
                "authorization_endpoint",
                self.authorization_endpoint.is_some(),
            ),
            (
                "token_endpoint",
                implicit_only || self.token_endpoint.is_some(),
            ),
            ("jwks_uri", self.jwks_uri.is_some()),
            (
                "response_types_supported",
                self.response_types_supported.is_some(),
            ),
            (
                "subject_types_supported",
                self.subject_types_supported.is_some(),
            ),
            (
                "id_token_signing_alg_values_supported",
                self.id_token_signing_alg_values_supported.is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(name, present)| (!present).then_some(name))
        .collect()
    }

    /// Whether `issuer` is exactly `expected` — the URL the configuration
    /// was requested for, without `/.well-known/openid-configuration`
    /// (Discovery §4.3).
    #[must_use]
    pub fn issuer_matches(&self, expected: &str) -> bool {
        self.issuer.as_deref() == Some(expected)
    }

    /// Endpoint members whose value is not an `https://` URL, as
    /// `(member, value)`.
    #[must_use]
    pub fn insecure_endpoints(&self) -> Vec<(&'static str, &str)> {
        [
            ("issuer", &self.issuer),
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("userinfo_endpoint", &self.userinfo_endpoint),
            ("jwks_uri", &self.jwks_uri),
            ("registration_endpoint", &self.registration_endpoint),
            ("end_session_endpoint", &self.end_session_endpoint),
            ("revocation_endpoint", &self.revocation_endpoint),
            ("introspection_endpoint", &self.introspection_endpoint),
        ]
        .into_iter()
        .filter_map(|(name, v)| {
            v.as_deref()
                .filter(|v| {
                    !v.get(..8)
                        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
                })
                .map(|v| (name, v))
        })
        .collect()
    }
}

/// The target of a Digital Asset Links statement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssetTarget {
    /// An Android app, identified by package name and signing certificate
    /// SHA-256 fingerprints (`AA:BB:…`).
    AndroidApp {
        /// The application ID.
        package_name: String,
        /// Signing certificate fingerprints.
        sha256_cert_fingerprints: Vec<String>,
    },
    /// A web site (`https://example.com`).
    Web {
        /// The site origin.
        site: String,
    },
    /// Another namespace, with its members as JSON.
    Other {
        /// The `namespace` value.
        namespace: String,
        /// The other members of `target`.
        fields: BTreeMap<String, Value>,
    },
}

/// One Digital Asset Links statement
/// ([format](https://developers.google.com/digital-asset-links/v1/statements)),
/// as served in `/.well-known/assetlinks.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AssetStatement {
    /// Relations, e.g. `delegate_permission/common.handle_all_urls`.
    pub relation: Vec<String>,
    /// What the relation is granted to.
    pub target: AssetTarget,
}

/// The relation that lets an Android app open the site's links.
pub const HANDLE_ALL_URLS: &str = "delegate_permission/common.handle_all_urls";
/// The relation that shares the site's credentials with an app.
pub const GET_LOGIN_CREDS: &str = "delegate_permission/common.get_login_creds";

#[derive(Deserialize)]
struct RawStatement {
    relation: Vec<String>,
    target: RawTarget,
}

#[derive(Deserialize)]
struct RawTarget {
    namespace: String,
    #[serde(flatten)]
    rest: BTreeMap<String, Value>,
}

/// A parsed `assetlinks.json`: a list of statements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AssetLinks {
    /// The statements, in order.
    pub statements: Vec<AssetStatement>,
}

impl AssetLinks {
    /// Parses the JSON array of statements.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let raw: Vec<RawStatement> = from_json(text)?;
        let invalid = |m: &str| Error::Json {
            message: m.to_owned(),
        };
        let mut statements = Vec::with_capacity(raw.len());
        for s in raw {
            let RawTarget {
                namespace,
                mut rest,
            } = s.target;
            let target = match namespace.as_str() {
                "android_app" => {
                    let Some(Value::String(package_name)) = rest.remove("package_name") else {
                        return Err(invalid("android_app target without package_name"));
                    };
                    let sha256_cert_fingerprints = match rest.remove("sha256_cert_fingerprints") {
                        Some(Value::Array(a)) => a
                            .into_iter()
                            .map(|v| match v {
                                Value::String(s) => Ok(s),
                                _ => Err(invalid("fingerprint is not a string")),
                            })
                            .collect::<Result<_, _>>()?,
                        None => Vec::new(),
                        Some(_) => return Err(invalid("sha256_cert_fingerprints is not an array")),
                    };
                    AssetTarget::AndroidApp {
                        package_name,
                        sha256_cert_fingerprints,
                    }
                }
                "web" => match rest.remove("site") {
                    Some(Value::String(site)) => AssetTarget::Web { site },
                    _ => return Err(invalid("web target without site")),
                },
                _ => AssetTarget::Other {
                    namespace,
                    fields: rest,
                },
            };
            statements.push(AssetStatement {
                relation: s.relation,
                target,
            });
        }
        Ok(Self { statements })
    }

    /// Android package names granted `relation`, with their fingerprints.
    #[must_use]
    pub fn android_apps(&self, relation: &str) -> Vec<(&str, &[String])> {
        self.statements
            .iter()
            .filter(|s| s.relation.iter().any(|r| r == relation))
            .filter_map(|s| match &s.target {
                AssetTarget::AndroidApp {
                    package_name,
                    sha256_cert_fingerprints,
                } => Some((package_name.as_str(), sha256_cert_fingerprints.as_slice())),
                _ => None,
            })
            .collect()
    }
}

/// A path pattern of an `applinks` detail (iOS 13+ `components` form).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct AppLinkComponent {
    /// URL path pattern (`/`).
    #[serde(rename = "/")]
    pub path: Option<String>,
    /// Query pattern (`?`): a string or an object of item patterns.
    #[serde(rename = "?")]
    pub query: Option<Value>,
    /// Fragment pattern (`#`).
    #[serde(rename = "#")]
    pub fragment: Option<String>,
    /// URLs matching this component are excluded.
    #[serde(default)]
    pub exclude: bool,
    /// Free-text comment.
    pub comment: Option<String>,
}

/// One `applinks.details` entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct AppLinkDetail {
    /// App identifiers (`TEAMID.bundle.id`), from `appIDs`.
    #[serde(rename = "appIDs", default)]
    pub app_ids: Vec<String>,
    /// The single app identifier of the legacy `appID` form.
    #[serde(rename = "appID")]
    pub app_id: Option<String>,
    /// Legacy path patterns (`NOT ` prefix excludes).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Path components (iOS 13+).
    #[serde(default)]
    pub components: Vec<AppLinkComponent>,
}

/// The `applinks` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct AppLinks {
    /// Legacy `apps` array (must be empty when present).
    #[serde(default)]
    pub apps: Vec<String>,
    /// Per-app rules.
    #[serde(default)]
    pub details: Vec<AppLinkDetail>,
}

/// A section that is only a list of apps (`webcredentials`, `appclips`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct AppList {
    /// App identifiers.
    #[serde(default)]
    pub apps: Vec<String>,
}

/// A parsed `apple-app-site-association` file
/// ([Apple docs](https://developer.apple.com/documentation/xcode/supporting-associated-domains)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct AppleAppSiteAssociation {
    /// Universal links.
    pub applinks: Option<AppLinks>,
    /// Shared web credentials (password autofill).
    pub webcredentials: Option<AppList>,
    /// App Clips.
    pub appclips: Option<AppList>,
    /// Handoff (`activitycontinuation`).
    pub activitycontinuation: Option<AppList>,
    /// Every other member, as JSON.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

impl AppleAppSiteAssociation {
    /// Parses the JSON document. (A legacy PKCS #7-signed file is binary;
    /// [`parse`](crate::parse) reports it as [`Error::SignedAasa`].)
    pub fn parse(text: &str) -> Result<Self, Error> {
        from_json(text)
    }

    /// Every app identifier the file names, in order, without duplicates.
    #[must_use]
    pub fn app_ids(&self) -> Vec<&str> {
        let details = self
            .applinks
            .iter()
            .flat_map(|l| &l.details)
            .flat_map(|d| d.app_id.iter().chain(&d.app_ids));
        let lists = [
            &self.webcredentials,
            &self.appclips,
            &self.activitycontinuation,
        ]
        .into_iter()
        .flatten()
        .flat_map(|l| &l.apps);
        let mut out: Vec<&str> = Vec::new();
        for id in details.chain(lists) {
            if !out.contains(&id.as_str()) {
                out.push(id);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openid_configuration() {
        let c = OpenIdConfiguration::parse(
            r#"{"issuer":"https://server.example.com",
                "authorization_endpoint":"https://server.example.com/connect/authorize",
                "token_endpoint":"https://server.example.com/connect/token",
                "jwks_uri":"https://server.example.com/jwks.json",
                "userinfo_endpoint":"http://server.example.com/connect/userinfo",
                "response_types_supported":["code","id_token"],
                "subject_types_supported":["public"],
                "id_token_signing_alg_values_supported":["RS256"],
                "frontchannel_logout_supported":true}"#,
        )
        .unwrap();
        assert_eq!(c.missing_required(), Vec::<&str>::new());
        assert!(c.issuer_matches("https://server.example.com"));
        assert_eq!(
            c.insecure_endpoints(),
            [(
                "userinfo_endpoint",
                "http://server.example.com/connect/userinfo"
            )]
        );
        assert_eq!(
            c.other.get("frontchannel_logout_supported"),
            Some(&Value::Bool(true))
        );
        let partial = OpenIdConfiguration::parse(r#"{"issuer":"https://a"}"#).unwrap();
        assert_eq!(partial.missing_required().len(), 6);
        assert!(OpenIdConfiguration::parse("[]").is_err());
        assert!(OpenIdConfiguration::parse(r#"{"issuer":1}"#).is_err());
    }

    #[test]
    fn asset_links() {
        let a = AssetLinks::parse(
            r#"[{"relation":["delegate_permission/common.handle_all_urls"],
                 "target":{"namespace":"android_app","package_name":"com.example.app",
                           "sha256_cert_fingerprints":["14:6D:E9:83"]}},
                {"relation":["delegate_permission/common.get_login_creds"],
                 "target":{"namespace":"web","site":"https://example.com"}},
                {"relation":["x"],"target":{"namespace":"ios_app","appid":"T.b"}}]"#,
        )
        .unwrap();
        assert_eq!(a.statements.len(), 3);
        let apps = a.android_apps(HANDLE_ALL_URLS);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].0, "com.example.app");
        assert_eq!(a.android_apps(GET_LOGIN_CREDS), []);
        assert!(matches!(a.statements[2].target, AssetTarget::Other { .. }));
        for bad in [
            "{}",
            r#"[{"relation":[],"target":{"namespace":"android_app"}}]"#,
            r#"[{"relation":[],"target":{"namespace":"web","site":1}}]"#,
            r#"[{"relation":[],"target":{"namespace":"android_app","package_name":"p","sha256_cert_fingerprints":[1]}}]"#,
        ] {
            assert!(AssetLinks::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn apple_app_site_association() {
        let a = AppleAppSiteAssociation::parse(
            r#"{"applinks":{"details":[
                  {"appIDs":["ABCDE12345.com.example.app","ABCDE12345.com.example.app2"],
                   "components":[{"/":"/buy/*","exclude":true,"comment":"no"},{"/":"/help/*","?":{"articleNumber":"????"}}]},
                  {"appID":"ABCDE12345.com.example.legacy","paths":["/old/*","NOT /old/private/*"]}]},
                "webcredentials":{"apps":["ABCDE12345.com.example.app"]},
                "appclips":{"apps":["ABCDE12345.com.example.app.Clip"]}}"#,
        )
        .unwrap();
        let links = a.applinks.as_ref().unwrap();
        assert!(links.details[0].components[0].exclude);
        assert_eq!(
            links.details[0].components[1].path.as_deref(),
            Some("/help/*")
        );
        assert_eq!(links.details[1].paths.len(), 2);
        assert_eq!(
            a.app_ids(),
            [
                "ABCDE12345.com.example.app",
                "ABCDE12345.com.example.app2",
                "ABCDE12345.com.example.legacy",
                "ABCDE12345.com.example.app.Clip"
            ]
        );
        assert!(AppleAppSiteAssociation::parse(r#"{"applinks":{"details":{}}}"#).is_err());
    }
}
