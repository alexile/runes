//! [`VaultProvider`]: `vault:mount/path#field` from Vault's KV
//! secrets engine (v1 or v2).
//!
//! The core is sans-I/O: [`VaultConfig::request`] turns a reference into a
//! [`VaultRequest`] (URL and headers) and [`VaultConfig::parse_response`]
//! turns the [`VaultResponse`] into a [`SecretValue`]. A
//! [`VaultTransport`] performs the HTTP `GET` in between; the `vault-ureq`
//! feature provides one, and any closure with the right signature is one
//! too (handy for tests, or to bridge an async client).
//!
//! API references: [KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version),
//! [KV v1](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#read-secret).

#[cfg(feature = "vault-ureq")]
mod ureq_transport;

use std::fmt;

use rune_secret_ref::{SecretRef, SecretValue};
use serde_json::Value;

use crate::error::BoxError;
use crate::provider::{check_value, expect_scheme};
use crate::{ProviderError, SecretProvider};

#[cfg(feature = "vault-ureq")]
pub use ureq_transport::UreqTransport;

/// The version of a KV secrets engine mount.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KvVersion {
    /// KV version 1: `GET /v1/<mount>/<path>`, fields under `data`.
    V1,
    /// KV version 2 (versioned): `GET /v1/<mount>/data/<path>`, fields
    /// under `data.data`. The default, as on a Vault dev server.
    #[default]
    V2,
}

/// Where the Vault server is and how to authenticate to it.
///
/// Authentication is bring-your-own-token: obtain a token however your
/// deployment does (`AppRole`, Kubernetes auth, `VAULT_TOKEN`) and pass it in
/// as a [`SecretValue`]. The library never reads `VAULT_ADDR` or
/// `VAULT_TOKEN` on its own.
///
/// A reference `vault:MOUNT/PATH#FIELD` names the KV mount, the secret's
/// path inside it and one of its fields. The mount is the first path
/// segment unless a longer mount registered with
/// [`with_mount`](Self::with_mount) matches; `#FIELD` may be left out when
/// the secret has exactly one field.
///
/// ```
/// use rune_secret_ref::SecretValue;
/// use rune_secret_vault::{KvVersion, VaultConfig};
///
/// let config = VaultConfig::new("https://vault.example:8200", SecretValue::new("hvs.token"))?
///     .with_namespace("team-a")
///     .with_mount("legacy", KvVersion::V1);
///
/// let request = config.request(&"vault:secret/app/db#password".parse()?)?;
/// assert_eq!(request.url, "https://vault.example:8200/v1/secret/data/app/db");
///
/// let request = config.request(&"vault:legacy/app#password".parse()?)?;
/// assert_eq!(request.url, "https://vault.example:8200/v1/legacy/app");
/// # Ok::<(), rune_secret_vault::ProviderError>(())
/// ```
#[derive(Clone)]
pub struct VaultConfig {
    address: String,
    token: SecretValue,
    namespace: Option<String>,
    default_kv: KvVersion,
    /// Registered mounts as path segments, with their engine version.
    mounts: Vec<(Vec<String>, KvVersion)>,
    max_len: usize,
}

impl VaultConfig {
    /// A configuration for the server at `address` (`http://` or
    /// `https://`, optionally with a path prefix), authenticating with
    /// `token`.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Config`] when the address is not an `http(s)://`
    /// URL, has a query or fragment, or the token is empty.
    pub fn new(address: impl Into<String>, token: SecretValue) -> Result<Self, ProviderError> {
        let mut address = address.into();
        let rest = address
            .strip_prefix("https://")
            .or_else(|| address.strip_prefix("http://"))
            .ok_or(ProviderError::Config(
                "vault address must start with `http://` or `https://`",
            ))?;
        if rest.is_empty() || rest.starts_with('/') {
            return Err(ProviderError::Config("vault address has no host"));
        }
        if rest.contains(['?', '#']) || rest.contains(char::is_whitespace) {
            return Err(ProviderError::Config(
                "vault address must not contain a query, fragment or whitespace",
            ));
        }
        if token.expose().is_empty() {
            return Err(ProviderError::Config("vault token is empty"));
        }
        while address.ends_with('/') {
            address.pop();
        }
        Ok(Self {
            address,
            token,
            namespace: None,
            default_kv: KvVersion::V2,
            mounts: Vec::new(),
            max_len: 64 * 1024,
        })
    }

    /// Sends requests to this Vault Enterprise / HCP namespace
    /// (`X-Vault-Namespace`).
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// The KV version assumed for mounts not registered with
    /// [`with_mount`](Self::with_mount). Default [`KvVersion::V2`].
    #[must_use]
    pub const fn with_kv_version(mut self, version: KvVersion) -> Self {
        self.default_kv = version;
        self
    }

    /// Registers a mount, which may span several segments (`team/kv`), and
    /// its KV version. The longest registered mount that prefixes a
    /// reference's path wins.
    #[must_use]
    pub fn with_mount(mut self, mount: &str, version: KvVersion) -> Self {
        let segments: Vec<String> = mount
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(str::to_owned)
            .collect();
        if !segments.is_empty() {
            self.mounts.retain(|(existing, _)| *existing != segments);
            self.mounts.push((segments, version));
        }
        self
    }

    /// Sets the largest secret accepted, in bytes. Default 64 KiB.
    #[must_use]
    pub const fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_len = max_len;
        self
    }

    /// The server address, without a trailing slash.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The largest secret accepted, in bytes.
    #[must_use]
    pub const fn max_len(&self) -> usize {
        self.max_len
    }

    /// Builds the HTTP request that reads `reference`.
    ///
    /// # Errors
    ///
    /// [`ProviderError::WrongScheme`] for a non-`vault:` reference and
    /// [`ProviderError::InvalidReference`] for a path with empty, `.` or
    /// `..` segments, a trailing slash, no secret path after the mount, or
    /// an empty `#field`.
    pub fn request(&self, reference: &SecretRef) -> Result<VaultRequest, ProviderError> {
        let target = self.target(reference)?;
        let mut url = format!("{}/v1/", self.address);
        push_segments(&mut url, target.mount);
        if target.kv == KvVersion::V2 {
            url.push_str("/data");
        }
        url.push('/');
        push_segments(&mut url, target.path);
        Ok(VaultRequest {
            url,
            token: self.token.clone(),
            namespace: self.namespace.clone(),
        })
    }

    /// Extracts the secret from the server's response to
    /// [`request`](Self::request).
    ///
    /// # Errors
    ///
    /// [`ProviderError::NotFound`] for HTTP 404 (or a deleted KV v2
    /// version), [`ProviderError::PermissionDenied`] for 401 and 403,
    /// [`ProviderError::HttpStatus`] for any other non-200 status,
    /// [`ProviderError::InvalidResponse`] for a body that is not a KV read
    /// response, and the field errors ([`ProviderError::MissingField`],
    /// [`ProviderError::AmbiguousField`], [`ProviderError::NotAString`]).
    /// None of them includes the response body.
    pub fn parse_response(
        &self,
        reference: &SecretRef,
        response: &VaultResponse,
    ) -> Result<SecretValue, ProviderError> {
        let target = self.target(reference)?;
        match response.status {
            200 => {}
            404 => {
                return Err(ProviderError::NotFound {
                    reference: reference.clone(),
                });
            }
            401 | 403 => {
                return Err(ProviderError::PermissionDenied {
                    reference: reference.clone(),
                });
            }
            status => {
                return Err(ProviderError::HttpStatus {
                    reference: reference.clone(),
                    status,
                });
            }
        }
        let invalid = |reason| ProviderError::InvalidResponse {
            reference: reference.clone(),
            reason,
        };
        let mut body: Value =
            serde_json::from_slice(&response.body).map_err(|_| invalid("body is not JSON"))?;
        let data = match target.kv {
            KvVersion::V1 => body.get_mut("data"),
            KvVersion::V2 => body.get_mut("data").and_then(|data| data.get_mut("data")),
        };
        let fields = match data {
            Some(Value::Object(fields)) => fields,
            // KV v2 reports a deleted or destroyed version as `data: null`.
            Some(Value::Null) if target.kv == KvVersion::V2 => {
                return Err(ProviderError::NotFound {
                    reference: reference.clone(),
                });
            }
            _ => return Err(invalid("missing secret `data` object")),
        };
        let (name, value) = if let Some(field) = target.field {
            let Some(value) = fields.get_mut(field) else {
                return Err(ProviderError::MissingField {
                    reference: reference.clone(),
                    field: field.to_owned(),
                });
            };
            (field.to_owned(), value.take())
        } else {
            if fields.len() > 1 {
                return Err(ProviderError::AmbiguousField {
                    reference: reference.clone(),
                });
            }
            let Some((name, value)) = fields.iter_mut().next() else {
                return Err(ProviderError::NotFound {
                    reference: reference.clone(),
                });
            };
            (name.clone(), value.take())
        };
        match value {
            Value::String(secret) => check_value(reference, secret, self.max_len),
            _ => Err(ProviderError::NotAString {
                reference: reference.clone(),
                field: name,
            }),
        }
    }

    /// Splits a reference into mount, path and field.
    fn target<'r>(&self, reference: &'r SecretRef) -> Result<Target<'r>, ProviderError> {
        expect_scheme("vault", reference)?;
        let SecretRef::Vault(location) = reference else {
            return Err(ProviderError::WrongScheme {
                provider: "vault",
                scheme: reference.scheme(),
            });
        };
        let invalid = |reason| ProviderError::InvalidReference {
            scheme: "vault",
            reason,
        };
        let (path, field) = match location.split_once('#') {
            Some((_, "")) => return Err(invalid("empty field name after `#`")),
            Some((path, field)) => (path, Some(field)),
            None => (location.as_str(), None),
        };
        let path = path.strip_prefix('/').unwrap_or(path);
        let segments: Vec<&str> = path.split('/').collect();
        if segments.iter().any(|segment| segment.is_empty()) {
            return Err(invalid("empty path segment"));
        }
        if segments
            .iter()
            .any(|segment| matches!(*segment, "." | ".."))
        {
            return Err(invalid("`.` and `..` path segments are not allowed"));
        }
        let (mount_len, kv) = self
            .mounts
            .iter()
            .filter(|(mount, _)| {
                mount.len() <= segments.len() && mount.iter().zip(&segments).all(|(a, b)| a == b)
            })
            .max_by_key(|(mount, _)| mount.len())
            .map_or((1, self.default_kv), |(mount, kv)| (mount.len(), *kv));
        if segments.len() <= mount_len {
            return Err(invalid("expected `vault:MOUNT/PATH[#FIELD]`"));
        }
        let (mount, path) = segments.split_at(mount_len);
        Ok(Target {
            mount: mount.to_vec(),
            path: path.to_vec(),
            field,
            kv,
        })
    }
}

impl fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultConfig")
            .field("address", &self.address)
            .field("token", &self.token)
            .field("namespace", &self.namespace)
            .field("default_kv", &self.default_kv)
            .field("mounts", &self.mounts)
            .field("max_len", &self.max_len)
            .finish()
    }
}

/// A parsed `vault:` reference.
struct Target<'r> {
    mount: Vec<&'r str>,
    path: Vec<&'r str>,
    field: Option<&'r str>,
    kv: KvVersion,
}

/// Appends `/`-joined, percent-encoded path segments.
fn push_segments(url: &mut String, segments: Vec<&str>) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (index, segment) in segments.into_iter().enumerate() {
        if index > 0 {
            url.push('/');
        }
        for byte in segment.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                url.push(char::from(byte));
            } else {
                url.push('%');
                url.push(char::from(HEX[usize::from(byte >> 4)]));
                url.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
}

/// An HTTP `GET` a [`VaultTransport`] must perform.
///
/// The token is kept as a [`SecretValue`], so printing a request does not
/// leak it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VaultRequest {
    /// The full URL, path segments percent-encoded.
    pub url: String,
    /// The Vault token, sent as `X-Vault-Token`.
    pub token: SecretValue,
    /// The namespace, sent as `X-Vault-Namespace` when set.
    pub namespace: Option<String>,
}

impl VaultRequest {
    /// The headers to send, token included **in plain text**: pass them to
    /// the HTTP client and nowhere else.
    #[must_use]
    pub fn headers(&self) -> Vec<(&'static str, &str)> {
        let mut headers = vec![
            ("X-Vault-Token", self.token.expose()),
            ("X-Vault-Request", "true"),
            ("Accept", "application/json"),
        ];
        if let Some(namespace) = &self.namespace {
            headers.push(("X-Vault-Namespace", namespace));
        }
        headers
    }
}

/// The server's answer to a [`VaultRequest`].
///
/// The body holds the secret, so `Debug` shows only its length.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VaultResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The response body.
    pub body: Vec<u8>,
}

impl VaultResponse {
    /// A response with this status and body.
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
}

impl fmt::Debug for VaultResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Performs the HTTP `GET` for a [`VaultRequest`].
///
/// Implementations send [`VaultRequest::headers`], must not follow
/// redirects (the token would go with them) and must return non-2xx
/// statuses as a [`VaultResponse`], not as an error: errors are for
/// failures to get any response at all. Closures
/// `Fn(&VaultRequest) -> Result<VaultResponse, BoxError>` implement it.
pub trait VaultTransport {
    /// Sends the request and returns the response.
    ///
    /// # Errors
    ///
    /// Connection, TLS, timeout or I/O failures.
    fn get(&self, request: &VaultRequest) -> Result<VaultResponse, BoxError>;
}

impl<F> VaultTransport for F
where
    F: Fn(&VaultRequest) -> Result<VaultResponse, BoxError>,
{
    fn get(&self, request: &VaultRequest) -> Result<VaultResponse, BoxError> {
        self(request)
    }
}

/// Resolves `vault:MOUNT/PATH#FIELD` references by reading KV secrets
/// through a [`VaultTransport`].
///
/// ```
/// use rune_secret_ref::SecretValue;
/// use rune_secret_vault::{SecretProvider, VaultConfig, VaultProvider, VaultRequest, VaultResponse};
///
/// // An in-memory transport standing in for the server.
/// let transport = |request: &VaultRequest| {
///     assert_eq!(request.url, "http://127.0.0.1:8200/v1/secret/data/app");
///     Ok(VaultResponse::new(200, r#"{"data":{"data":{"token":"s3cr3t"},"metadata":{}}}"#))
/// };
/// let config = VaultConfig::new("http://127.0.0.1:8200", SecretValue::new("hvs.dev"))?;
/// let vault = VaultProvider::new(config, transport);
///
/// let token = vault.resolve(&"vault:secret/app#token".parse()?)?;
/// assert_eq!(token.expose(), "s3cr3t");
/// # Ok::<(), rune_secret_vault::ProviderError>(())
/// ```
#[derive(Clone, Debug)]
pub struct VaultProvider<T> {
    config: VaultConfig,
    transport: T,
}

impl<T: VaultTransport> VaultProvider<T> {
    /// A provider for `config`'s server, reached through `transport`.
    pub const fn new(config: VaultConfig, transport: T) -> Self {
        Self { config, transport }
    }

    /// The configuration.
    pub const fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// The transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: VaultTransport> SecretProvider for VaultProvider<T> {
    fn handles(&self, scheme: &str) -> bool {
        scheme == "vault"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError> {
        let request = self.config.request(reference)?;
        let response = self
            .transport
            .get(&request)
            .map_err(|source| ProviderError::Transport {
                reference: reference.clone(),
                source,
            })?;
        self.config.parse_response(reference, &response)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use rune_secret_ref::SecretError;

    use super::*;

    const TOKEN: &str = "hvs.TEST-token-value";
    const SECRET: &str = "vault-s3cret-Value";

    fn reference(text: &str) -> SecretRef {
        text.parse().unwrap()
    }

    fn config() -> VaultConfig {
        VaultConfig::new("https://vault.test:8200/", SecretValue::new(TOKEN)).unwrap()
    }

    fn url(config: &VaultConfig, text: &str) -> String {
        config.request(&reference(text)).unwrap().url
    }

    #[test]
    fn builds_kv_urls() {
        let config = config()
            .with_mount("legacy", KvVersion::V1)
            .with_mount("/team/kv/", KvVersion::V2)
            .with_mount("team", KvVersion::V1);
        assert_eq!(config.address(), "https://vault.test:8200");
        assert_eq!(
            url(&config, "vault:secret/app/db#password"),
            "https://vault.test:8200/v1/secret/data/app/db"
        );
        assert_eq!(
            url(&config, "vault:/secret/app"),
            "https://vault.test:8200/v1/secret/data/app"
        );
        assert_eq!(
            url(&config, "vault:legacy/a"),
            "https://vault.test:8200/v1/legacy/a"
        );
        assert_eq!(
            url(&config, "vault:team/kv/a"),
            "https://vault.test:8200/v1/team/kv/data/a"
        );
        assert_eq!(
            url(&config, "vault:team/other"),
            "https://vault.test:8200/v1/team/other"
        );
        assert_eq!(
            url(&config, "vault:secret/a b/ü?x=1#f"),
            "https://vault.test:8200/v1/secret/data/a%20b/%C3%BC%3Fx%3D1"
        );
        let v1 = config.with_kv_version(KvVersion::V1);
        assert_eq!(url(&v1, "vault:kv/a"), "https://vault.test:8200/v1/kv/a");
    }

    #[test]
    fn rejects_bad_paths() {
        let config = config().with_mount("team/kv", KvVersion::V2);
        for text in [
            "vault:secret",
            "vault:secret/",
            "vault:secret//a",
            "vault:secret/../sys/seal",
            "vault:secret/./a",
            "vault:secret/a#",
            "vault:team/kv",
            "vault:/",
        ] {
            assert!(
                matches!(
                    config.request(&reference(text)),
                    Err(ProviderError::InvalidReference {
                        scheme: "vault",
                        ..
                    })
                ),
                "{text}"
            );
        }
        assert!(matches!(
            config.request(&reference("env:X")),
            Err(ProviderError::WrongScheme { .. })
        ));
    }

    #[test]
    fn validates_config() {
        for address in [
            "vault.test",
            "ftp://x",
            "https://",
            "https:///x",
            "http://h?x",
            "http://h #",
        ] {
            assert!(
                matches!(
                    VaultConfig::new(address, SecretValue::new(TOKEN)),
                    Err(ProviderError::Config(_))
                ),
                "{address}"
            );
        }
        assert!(VaultConfig::new("http://h", SecretValue::new("")).is_err());
        assert_eq!(
            VaultConfig::new("http://h:1/prefix//", SecretValue::new(TOKEN))
                .unwrap()
                .address(),
            "http://h:1/prefix"
        );
    }

    #[test]
    fn request_headers_and_debug() {
        let request = config()
            .with_namespace("ns1")
            .request(&reference("vault:kv/a"))
            .unwrap();
        let headers = request.headers();
        assert!(headers.contains(&("X-Vault-Token", TOKEN)));
        assert!(headers.contains(&("X-Vault-Namespace", "ns1")));
        assert!(!format!("{request:?}").contains(TOKEN));
        assert!(!format!("{:?}", config()).contains(TOKEN));
        let response = VaultResponse::new(200, SECRET);
        assert_eq!(
            format!("{response:?}"),
            "VaultResponse { status: 200, body_len: 18 }"
        );
    }

    fn parse(
        config: &VaultConfig,
        text: &str,
        status: u16,
        body: &str,
    ) -> Result<SecretValue, ProviderError> {
        config.parse_response(&reference(text), &VaultResponse::new(status, body))
    }

    #[test]
    fn parses_kv2_and_kv1_bodies() {
        let v2 = config();
        let body = format!(
            r#"{{"data":{{"data":{{"password":"{SECRET}","user":"app"}},"metadata":{{"version":3}}}}}}"#
        );
        assert_eq!(
            parse(&v2, "vault:kv/db#password", 200, &body)
                .unwrap()
                .expose(),
            SECRET
        );
        assert_eq!(
            parse(&v2, "vault:kv/db#user", 200, &body).unwrap().expose(),
            "app"
        );

        let v1 = config().with_kv_version(KvVersion::V1);
        let body = format!(r#"{{"lease_duration":2764800,"data":{{"only":"{SECRET}"}}}}"#);
        assert_eq!(
            parse(&v1, "vault:kv/db", 200, &body).unwrap().expose(),
            SECRET
        );
    }

    type Case = (&'static str, u16, String, fn(&ProviderError) -> bool);

    #[test]
    fn maps_failures_without_leaking() {
        let config = config().with_max_len(8);
        let two = format!(r#"{{"data":{{"data":{{"a":"{SECRET}","b":"x"}}}}}}"#);
        let cases: Vec<Case> = vec![
            ("vault:kv/a#a", 404, String::new(), |e| {
                matches!(e, ProviderError::NotFound { .. })
            }),
            ("vault:kv/a#a", 403, String::new(), |e| {
                matches!(e, ProviderError::PermissionDenied { .. })
            }),
            ("vault:kv/a#a", 401, String::new(), |e| {
                matches!(e, ProviderError::PermissionDenied { .. })
            }),
            ("vault:kv/a#a", 503, String::new(), |e| {
                matches!(e, ProviderError::HttpStatus { status: 503, .. })
            }),
            ("vault:kv/a#a", 307, String::new(), |e| {
                matches!(e, ProviderError::HttpStatus { status: 307, .. })
            }),
            ("vault:kv/a#a", 200, format!("not json {SECRET}"), |e| {
                matches!(e, ProviderError::InvalidResponse { .. })
            }),
            ("vault:kv/a#a", 200, r#"{"data":[]}"#.into(), |e| {
                matches!(e, ProviderError::InvalidResponse { .. })
            }),
            (
                "vault:kv/a#a",
                200,
                r#"{"data":{"data":null}}"#.into(),
                |e| matches!(e, ProviderError::NotFound { .. }),
            ),
            ("vault:kv/a", 200, r#"{"data":{"data":{}}}"#.into(), |e| {
                matches!(e, ProviderError::NotFound { .. })
            }),
            ("vault:kv/a", 200, two.clone(), |e| {
                matches!(e, ProviderError::AmbiguousField { .. })
            }),
            ("vault:kv/a#c", 200, two.clone(), |e| {
                matches!(e, ProviderError::MissingField { .. })
            }),
            ("vault:kv/a#a", 200, two, |e| {
                matches!(
                    e,
                    ProviderError::Ref(SecretError::TooLarge { limit: 8, .. })
                )
            }),
            (
                "vault:kv/a#n",
                200,
                r#"{"data":{"data":{"n":42}}}"#.into(),
                |e| matches!(e, ProviderError::NotAString { .. }),
            ),
            (
                "vault:kv/a#e",
                200,
                r#"{"data":{"data":{"e":""}}}"#.into(),
                |e| matches!(e, ProviderError::Ref(SecretError::Empty { .. })),
            ),
        ];
        for (text, status, body, expected) in cases {
            let error = parse(&config, text, status, &body).unwrap_err();
            assert!(expected(&error), "{text} {status} {body}: {error:?}");
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains(SECRET) && !shown.contains(TOKEN), "{shown}");
        }
    }

    #[test]
    fn provider_round_trip_through_mock_transport() {
        let seen = RefCell::new(Vec::new());
        let transport = |request: &VaultRequest| -> Result<VaultResponse, BoxError> {
            seen.borrow_mut().push(request.url.clone());
            match request.url.as_str() {
                "https://vault.test:8200/v1/kv/data/app" => Ok(VaultResponse::new(
                    200,
                    format!(r#"{{"data":{{"data":{{"token":"{SECRET}"}}}}}}"#),
                )),
                "https://vault.test:8200/v1/kv/data/down" => Err("connection refused".into()),
                _ => Ok(VaultResponse::new(404, r#"{"errors":[]}"#)),
            }
        };
        let provider = VaultProvider::new(config(), transport);
        assert!(provider.handles("vault"));
        assert!(!provider.handles("env"));
        assert_eq!(provider.config().address(), "https://vault.test:8200");

        let value = provider.resolve(&reference("vault:kv/app#token")).unwrap();
        assert_eq!(value.expose(), SECRET);
        assert!(matches!(
            provider.resolve(&reference("vault:kv/missing")),
            Err(ProviderError::NotFound { .. })
        ));
        let error = provider.resolve(&reference("vault:kv/down")).unwrap_err();
        assert!(matches!(error, ProviderError::Transport { .. }));
        assert!(error.to_string().contains("connection refused"));
        assert_eq!(seen.borrow().len(), 3);
        assert!(matches!(
            provider.resolve(&reference("keychain:a/b")),
            Err(ProviderError::WrongScheme { .. })
        ));
        assert_eq!(seen.borrow().len(), 3);
    }
}
