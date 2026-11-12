//! The normalized API model and import options.

use std::collections::BTreeMap;
use std::fmt;

use rune_http_model::HttpRequest;
use serde_json::Value;
use url::Url;

use crate::schema::{ExampleStrategy, Schema, SchemaType};

/// The specification version a document declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SpecVersion {
    /// Swagger 2.0 (`swagger: "2.0"`).
    Swagger2,
    /// `OpenAPI` 3.0.x.
    OpenApi30,
    /// `OpenAPI` 3.1.x.
    OpenApi31,
    /// `OpenAPI` 3.2.x.
    OpenApi32,
}

impl SpecVersion {
    /// Whether the document is Swagger 2.0.
    #[must_use]
    pub const fn is_swagger2(self) -> bool {
        matches!(self, Self::Swagger2)
    }

    /// A short stable name: `swagger-2.0`, `openapi-3.0`, `openapi-3.1`
    /// or `openapi-3.2`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Swagger2 => "swagger-2.0",
            Self::OpenApi30 => "openapi-3.0",
            Self::OpenApi31 => "openapi-3.1",
            Self::OpenApi32 => "openapi-3.2",
        }
    }
}

impl fmt::Display for SpecVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An imported API: its endpoints plus anything worth telling the user.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct ApiSpec {
    /// The specification version.
    pub version: SpecVersion,
    /// The version text exactly as declared, such as `3.0.3`.
    pub version_text: String,
    /// `info.title`.
    pub title: Option<String>,
    /// `info.version`: the version of the API itself.
    pub api_version: Option<String>,
    /// Document-level server URLs, with variables set to their defaults.
    pub servers: Vec<String>,
    /// One entry per operation: paths in map order (sorted unless
    /// `serde_json`'s `preserve_order` feature is on), then methods in
    /// `get`, `put`, `post`, `delete`, `options`, `head`, `patch`, `trace`,
    /// `query` order.
    pub endpoints: Vec<Endpoint>,
    /// Non-fatal problems: external or dangling `$ref`s, undefined security
    /// schemes, relative or missing server URLs, truncated schemas.
    pub warnings: Vec<String>,
    /// Whether [`Options::max_endpoints`] stopped the import early.
    pub truncated: bool,
}

impl ApiSpec {
    /// The endpoint with the given `operationId`.
    #[must_use]
    pub fn endpoint(&self, operation_id: &str) -> Option<&Endpoint> {
        self.endpoints
            .iter()
            .find(|endpoint| endpoint.operation_id.as_deref() == Some(operation_id))
    }
}

/// One operation: a method on a path, with everything needed to call it.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Endpoint {
    /// Upper-case method, such as `GET`.
    pub method: String,
    /// The path template as declared, such as `/pets/{petId}`.
    pub path: String,
    /// JSON pointer to the operation in the document, such as
    /// `#/paths/~1pets~1{petId}/get`.
    pub pointer: String,
    /// `operationId`.
    pub operation_id: Option<String>,
    /// `summary`.
    pub summary: Option<String>,
    /// `description`.
    pub description: Option<String>,
    /// `tags`.
    pub tags: Vec<String>,
    /// Whether the operation is marked `deprecated`.
    pub deprecated: bool,
    /// Server URLs that apply to this operation (operation, then path item,
    /// then document level), with variables set to their defaults. They may
    /// be relative.
    pub servers: Vec<String>,
    /// Path, query, header and cookie parameters; operation-level entries
    /// override path-item entries with the same name and location.
    pub parameters: Vec<Parameter>,
    /// The request body, including Swagger 2.0 `body` and `formData`
    /// parameters.
    pub request_body: Option<RequestBody>,
    /// Declared responses, keyed by status code or `default`.
    pub responses: Vec<Response>,
    /// Alternative security requirements; any one of them suffices. An
    /// empty requirement means anonymous access is allowed.
    pub security: Vec<SecurityRequirement>,
    /// An example request built with the import [`Options`].
    pub request: HttpRequest,
    /// Where [`request`](Self::request) can be mutated, with the schema of
    /// each spot.
    pub insertion_points: Vec<InsertionPoint>,
}

impl Endpoint {
    /// The parameter with the given name and location.
    #[must_use]
    pub fn parameter(&self, name: &str, location: ParameterLocation) -> Option<&Parameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.location == location && parameter.name == name)
    }

    /// The insertion point with the given location and name.
    #[must_use]
    pub fn insertion_point(
        &self,
        location: InsertionLocation,
        name: &str,
    ) -> Option<&InsertionPoint> {
        self.insertion_points
            .iter()
            .find(|point| point.location == location && point.name == name)
    }
}

/// Where a declared parameter lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ParameterLocation {
    /// A templated path segment.
    Path,
    /// A query-string parameter.
    Query,
    /// A request header.
    Header,
    /// A cookie in the `Cookie` header.
    Cookie,
}

/// How a parameter value is serialized (`OpenAPI` 3 `style`; Swagger 2.0
/// `collectionFormat` maps onto it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[non_exhaustive]
pub enum ParameterStyle {
    /// `name=value`, arrays comma-separated or repeated (query, cookie).
    Form,
    /// `a,b,c` (path, header).
    Simple,
    /// `.a.b` path segments.
    Label,
    /// `;name=a` path segments.
    Matrix,
    /// Space-separated arrays (Swagger `ssv`).
    SpaceDelimited,
    /// Pipe-separated arrays (Swagger `pipes`).
    PipeDelimited,
    /// Tab-separated arrays (Swagger `tsv`).
    TabDelimited,
    /// `name[key]=value` objects.
    DeepObject,
}

impl ParameterStyle {
    /// The `OpenAPI` default style for a location.
    #[must_use]
    pub const fn default_for(location: ParameterLocation) -> Self {
        match location {
            ParameterLocation::Query | ParameterLocation::Cookie => Self::Form,
            ParameterLocation::Path | ParameterLocation::Header => Self::Simple,
        }
    }

    /// Parses an `OpenAPI` 3 `style` value.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "form" => Self::Form,
            "simple" => Self::Simple,
            "label" => Self::Label,
            "matrix" => Self::Matrix,
            "spaceDelimited" => Self::SpaceDelimited,
            "pipeDelimited" => Self::PipeDelimited,
            "deepObject" => Self::DeepObject,
            _ => return None,
        })
    }
}

/// A declared path, query, header or cookie parameter.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Parameter {
    /// Parameter name.
    pub name: String,
    /// Where it lives.
    pub location: ParameterLocation,
    /// Whether it is required (path parameters always are).
    pub required: bool,
    /// Whether it is marked `deprecated`.
    pub deprecated: bool,
    /// `description`.
    pub description: Option<String>,
    /// Serialization style.
    pub style: ParameterStyle,
    /// Whether arrays and objects are exploded into separate values.
    pub explode: bool,
    /// The value schema (from `schema`, the first `content` entry, or the
    /// Swagger 2.0 parameter itself).
    pub schema: Schema,
    /// The media type when the value is given through `content`.
    pub content_type: Option<String>,
    /// A parameter-level example (`example`, first of `examples`,
    /// `x-example`).
    pub example: Option<Value>,
}

impl Parameter {
    /// The value to place in a request: the parameter example, then the
    /// schema example (see [`Schema::example_value`]).
    #[must_use]
    pub fn example_value(&self, strategy: ExampleStrategy) -> Value {
        match (&self.example, strategy) {
            (Some(example), ExampleStrategy::PreferExamples) => example.clone(),
            _ => self.schema.example_value(strategy),
        }
    }
}

/// A request body and the media types it may be sent as.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct RequestBody {
    /// Whether the body is required.
    pub required: bool,
    /// `description`.
    pub description: Option<String>,
    /// One entry per media type, in map order.
    pub content: Vec<MediaType>,
}

impl RequestBody {
    /// The media type example requests use: JSON first, then other `+json`
    /// types, URL-encoded forms, multipart, XML, then anything else.
    #[must_use]
    pub fn preferred(&self) -> Option<&MediaType> {
        self.content
            .iter()
            .min_by_key(|media| media_rank(&media.content_type))
    }
}

fn media_rank(media: &str) -> u8 {
    let media = media.to_ascii_lowercase();
    if media.starts_with("application/json") {
        0
    } else if media.contains("json") {
        1
    } else if media.contains("x-www-form-urlencoded") {
        2
    } else if media.starts_with("multipart/") {
        3
    } else if media.contains("xml") {
        4
    } else {
        5
    }
}

/// A body schema for one media type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct MediaType {
    /// The media type, such as `application/json` or `multipart/form-data`.
    pub content_type: String,
    /// The body schema.
    pub schema: Schema,
    /// A media-level example (`example`, first of `examples`, `x-example`).
    pub example: Option<Value>,
}

impl MediaType {
    /// The body value to send: the media example, then the schema example.
    #[must_use]
    pub fn example_value(&self, strategy: ExampleStrategy) -> Value {
        match (&self.example, strategy) {
            (Some(example), ExampleStrategy::PreferExamples) => example.clone(),
            _ => self.schema.example_value(strategy),
        }
    }
}

/// A declared response.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Response {
    /// Status code (`200`), range (`2XX`) or `default`, as declared.
    pub status: String,
    /// `description`.
    pub description: Option<String>,
    /// Response bodies per media type.
    pub content: Vec<MediaType>,
}

/// One way to satisfy an operation's security: all of its schemes at once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct SecurityRequirement {
    /// The schemes to apply together; empty for anonymous access.
    pub schemes: Vec<SecuritySchemeRef>,
}

/// A security scheme named by a requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct SecuritySchemeRef {
    /// The scheme's name in `securitySchemes` / `securityDefinitions`.
    pub name: String,
    /// Required `OAuth2` scopes or roles.
    pub scopes: Vec<String>,
    /// The scheme definition; `None` when the document does not define it.
    pub scheme: Option<SecurityScheme>,
}

/// A security scheme definition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SecurityScheme {
    /// A key sent in a header, query parameter or cookie.
    ApiKey {
        /// Header, parameter or cookie name.
        name: String,
        /// Where the key goes.
        location: ApiKeyLocation,
    },
    /// HTTP authentication (`Authorization: <scheme> …`). Swagger 2.0
    /// `basic` maps to scheme `basic`.
    Http {
        /// Lower-case scheme, such as `bearer` or `basic`.
        scheme: String,
        /// `bearerFormat`, such as `JWT`.
        bearer_format: Option<String>,
    },
    /// `OAuth2`; requests carry a bearer token.
    OAuth2,
    /// `OpenID` Connect; requests carry a bearer token.
    OpenIdConnect {
        /// The discovery URL.
        url: Option<String>,
    },
    /// Mutual TLS: nothing goes into the request.
    MutualTls,
    /// A scheme type this crate does not know.
    Other {
        /// The declared `type`.
        kind: String,
    },
}

/// Where an API key is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ApiKeyLocation {
    /// A request header.
    Header,
    /// A query parameter.
    Query,
    /// A cookie.
    Cookie,
}

/// Where in a request an [`InsertionPoint`] sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum InsertionLocation {
    /// A path parameter; the name is the template variable.
    Path,
    /// A query parameter.
    Query,
    /// A header.
    Header,
    /// A cookie.
    Cookie,
    /// A URL-encoded form field.
    Form,
    /// A `multipart/form-data` part.
    Multipart,
    /// A JSON body value; the name is its JSON pointer (`/owner/name`).
    JsonPointer,
    /// An XML element's text; the name is its element path (`/Pet/name`).
    Xml,
    /// The whole body of another media type; the name is empty.
    Body,
}

/// A spot in an example request where a fuzzer or scanner can put a
/// payload, with the schema that describes the expected value.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct InsertionPoint {
    /// Where the value sits.
    pub location: InsertionLocation,
    /// Parameter name, JSON pointer or element path (see
    /// [`InsertionLocation`]).
    pub name: String,
    /// Whether the document marks the value as required.
    pub required: bool,
    /// The value placed in the example request.
    pub value: Value,
    /// The schema of the value (inferred from the value when the document
    /// does not describe it).
    pub schema: Schema,
}

impl InsertionPoint {
    /// Creates a point whose schema is inferred from `value`.
    #[must_use]
    pub fn new(location: InsertionLocation, name: impl Into<String>, value: Value) -> Self {
        let schema = Schema::new(SchemaType::of(&value));
        Self {
            location,
            name: name.into(),
            required: false,
            value,
            schema,
        }
    }

    /// The declared (or inferred) type of the value.
    #[must_use]
    pub fn schema_type(&self) -> SchemaType {
        if self.schema.kind == SchemaType::Unknown {
            SchemaType::of(&self.value)
        } else {
            self.schema.kind
        }
    }
}

/// An example request and its insertion points, from
/// [`Endpoint::render`](crate::Endpoint::render).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct RenderedRequest {
    /// The request.
    pub request: HttpRequest,
    /// Where it can be mutated.
    pub insertion_points: Vec<InsertionPoint>,
    /// Problems met while building it (relative server URL, undefined
    /// security scheme).
    pub warnings: Vec<String>,
}

/// Import options.
///
/// ```
/// use rune_openapi::{ExampleStrategy, Options, Url};
///
/// let options = Options::default()
///     .with_base_url(Url::parse("http://127.0.0.1:8080/").unwrap())
///     .with_auth_value("bearerAuth", "token-123")
///     .with_example_strategy(ExampleStrategy::TypeDefaults)
///     .with_max_endpoints(100);
/// assert_eq!(options.max_endpoints, 100);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Sends requests here instead of the declared servers.
    pub base_url: Option<Url>,
    /// Replaces the path of the base URL (declared or overridden).
    pub base_path: Option<String>,
    /// How example values are chosen.
    pub example_strategy: ExampleStrategy,
    /// Credentials per security scheme name. Schemes without a value get
    /// the placeholder `{{name}}`.
    pub auth_values: BTreeMap<String, String>,
    /// Most endpoints to import; [`ApiSpec::truncated`] reports a cut.
    pub max_endpoints: usize,
    /// Largest input accepted, in bytes.
    pub max_input_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            base_url: None,
            base_path: None,
            example_strategy: ExampleStrategy::default(),
            auth_values: BTreeMap::new(),
            max_endpoints: 10_000,
            max_input_bytes: 64 * 1024 * 1024,
        }
    }
}

impl Options {
    /// Sets [`base_url`](Self::base_url).
    #[must_use]
    pub fn with_base_url(mut self, base_url: Url) -> Self {
        self.base_url = Some(base_url);
        self
    }

    /// Sets [`base_path`](Self::base_path).
    #[must_use]
    pub fn with_base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = Some(base_path.into());
        self
    }

    /// Sets [`example_strategy`](Self::example_strategy).
    #[must_use]
    pub const fn with_example_strategy(mut self, strategy: ExampleStrategy) -> Self {
        self.example_strategy = strategy;
        self
    }

    /// Adds a credential for the security scheme `scheme`.
    #[must_use]
    pub fn with_auth_value(mut self, scheme: impl Into<String>, value: impl Into<String>) -> Self {
        self.auth_values.insert(scheme.into(), value.into());
        self
    }

    /// Sets [`max_endpoints`](Self::max_endpoints).
    #[must_use]
    pub const fn with_max_endpoints(mut self, max: usize) -> Self {
        self.max_endpoints = max;
        self
    }

    /// Sets [`max_input_bytes`](Self::max_input_bytes).
    #[must_use]
    pub const fn with_max_input_bytes(mut self, max: usize) -> Self {
        self.max_input_bytes = max;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn media(content_type: &str) -> MediaType {
        MediaType {
            content_type: content_type.into(),
            schema: Schema::default(),
            example: None,
        }
    }

    #[test]
    fn preferred_media_type() {
        let body = RequestBody {
            required: false,
            description: None,
            content: vec![
                media("text/plain"),
                media("application/xml"),
                media("application/vnd.api+json"),
                media("multipart/form-data"),
            ],
        };
        assert_eq!(
            body.preferred().map(|media| media.content_type.as_str()),
            Some("application/vnd.api+json")
        );
    }

    #[test]
    fn styles() {
        assert_eq!(
            ParameterStyle::parse("deepObject"),
            Some(ParameterStyle::DeepObject)
        );
        assert_eq!(ParameterStyle::parse("nope"), None);
        assert_eq!(
            ParameterStyle::default_for(ParameterLocation::Header),
            ParameterStyle::Simple
        );
        assert_eq!(SpecVersion::OpenApi31.to_string(), "openapi-3.1");
        assert!(SpecVersion::Swagger2.is_swagger2());
    }

    #[test]
    fn insertion_point_type() {
        let point = InsertionPoint::new(InsertionLocation::Query, "q", serde_json::json!(3));
        assert_eq!(point.schema_type(), SchemaType::Integer);
    }
}
