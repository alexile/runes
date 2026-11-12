//! The normalized service model and import options.

use std::collections::BTreeMap;
use std::fmt;

use rune_http_model::HttpRequest;
use url::Url;

use crate::render;

/// The WSDL version a document uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum WsdlVersion {
    /// [WSDL 1.1](https://www.w3.org/TR/2001/NOTE-wsdl-20010315) (`definitions`).
    Wsdl11,
    /// [WSDL 2.0](https://www.w3.org/TR/wsdl20/) (`description`).
    Wsdl20,
}

impl WsdlVersion {
    /// `wsdl-1.1` or `wsdl-2.0`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wsdl11 => "wsdl-1.1",
            Self::Wsdl20 => "wsdl-2.0",
        }
    }
}

impl fmt::Display for WsdlVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The SOAP version a binding uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SoapVersion {
    /// [SOAP 1.1](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/):
    /// `text/xml` and a `SOAPAction` header.
    Soap11,
    /// [SOAP 1.2](https://www.w3.org/TR/soap12-part1/):
    /// `application/soap+xml` with an `action` parameter.
    Soap12,
}

impl SoapVersion {
    /// The envelope namespace.
    #[must_use]
    pub const fn envelope_namespace(self) -> &'static str {
        match self {
            Self::Soap11 => "http://schemas.xmlsoap.org/soap/envelope/",
            Self::Soap12 => "http://www.w3.org/2003/05/soap-envelope",
        }
    }

    /// `soap11` or `soap12`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Soap11 => "soap11",
            Self::Soap12 => "soap12",
        }
    }
}

impl fmt::Display for SoapVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How the body is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum OperationStyle {
    /// Each part's element sits directly in the body.
    Document,
    /// Parts are wrapped in an element named after the operation.
    Rpc,
}

/// Whether part types are literal schemas or SOAP-encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum BodyUse {
    /// `use="literal"`.
    Literal,
    /// `use="encoded"` (SOAP section 5 encoding).
    Encoded,
}

/// A message part (WSDL 1.1) or an operation's message element (WSDL 2.0).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct MessagePart {
    /// Part name (the element name for WSDL 2.0).
    pub name: String,
    /// The global element it refers to, as `{namespace}local`.
    pub element: Option<String>,
    /// The type it refers to, as `{namespace}local`.
    pub type_name: Option<String>,
}

/// An attribute in a sample message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct XmlAttribute {
    /// Namespace URI, if qualified.
    pub namespace: Option<String>,
    /// Local name.
    pub name: String,
    /// Value.
    pub value: String,
}

/// An element in a sample message; text-only when it has a value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct XmlNode {
    /// Namespace URI, if qualified.
    pub namespace: Option<String>,
    /// Local name.
    pub name: String,
    /// Attributes.
    pub attributes: Vec<XmlAttribute>,
    /// Child elements.
    pub children: Vec<Self>,
    /// Text content.
    pub value: Option<String>,
}

impl XmlNode {
    /// An empty element.
    #[must_use]
    pub fn new(namespace: Option<String>, name: impl Into<String>) -> Self {
        Self {
            namespace,
            name: name.into(),
            ..Self::default()
        }
    }
}

/// The value category of an XSD simple type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ValueKind {
    /// Text (`string`, `token`, `anyURI`, `QName`, …).
    String,
    /// A whole number (`int`, `long`, `nonNegativeInteger`, …).
    Integer,
    /// A decimal or floating-point number.
    Number,
    /// `true` / `false`.
    Boolean,
    /// A date, time, date-time or duration.
    Temporal,
    /// `base64Binary` or `hexBinary`.
    Binary,
    /// Undeclared or `anyType` content.
    Any,
}

/// Where in a request an [`InsertionPoint`] sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum InsertionLocation {
    /// An element's text; the name is its path (`/Body/GetQuote/symbol`,
    /// `/Header/Auth/user`), local names with `[n]` for the n-th same-named
    /// sibling.
    Element,
    /// An attribute value; the name is the element path plus `/@name`.
    Attribute,
    /// An HTTP header, such as `SOAPAction`.
    HttpHeader,
}

/// A spot in a sample request where a scanner or fuzzer can put a payload,
/// with what the schema says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct InsertionPoint {
    /// Where the value sits.
    pub location: InsertionLocation,
    /// Element path, attribute path or header name.
    pub name: String,
    /// The value in the sample request.
    pub value: String,
    /// The XSD type's local name, such as `int`.
    pub xsd_type: String,
    /// The value category.
    pub kind: ValueKind,
    /// Whether the schema requires it (`minOccurs` ≠ 0, `use="required"`).
    pub required: bool,
    /// Whether the element is `nillable`.
    pub nillable: bool,
    /// Whether the element may repeat (`maxOccurs` > 1).
    pub repeated: bool,
    /// Allowed values from `enumeration` facets.
    pub enum_values: Vec<String>,
}

/// One binding operation: everything needed to call it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct SoapOperation {
    /// Operation name.
    pub name: String,
    /// Service name, when a service exposes the binding.
    pub service: Option<String>,
    /// Port (WSDL 1.1) or endpoint (WSDL 2.0) name.
    pub port: Option<String>,
    /// Binding name.
    pub binding: String,
    /// Port type (WSDL 1.1) or interface (WSDL 2.0) name.
    pub interface: Option<String>,
    /// SOAP version of the binding.
    pub soap_version: SoapVersion,
    /// Body style.
    pub style: OperationStyle,
    /// Body encoding.
    pub body_use: BodyUse,
    /// The SOAP action, if declared.
    pub soap_action: Option<String>,
    /// The declared endpoint address.
    pub address: Option<String>,
    /// `documentation` of the abstract operation.
    pub documentation: Option<String>,
    /// Input parts.
    pub input: Vec<MessagePart>,
    /// Output parts.
    pub output: Vec<MessagePart>,
    /// Fault names.
    pub faults: Vec<String>,
    /// Sample SOAP header blocks.
    pub header: Vec<XmlNode>,
    /// Sample body content.
    pub body: Vec<XmlNode>,
    /// The sample envelope, serialized.
    pub envelope: String,
    /// The sample request.
    pub request: HttpRequest,
    /// Where the request can be mutated.
    pub insertion_points: Vec<InsertionPoint>,
}

impl SoapOperation {
    /// The insertion point with the given path or header name.
    #[must_use]
    pub fn insertion_point(&self, name: &str) -> Option<&InsertionPoint> {
        self.insertion_points
            .iter()
            .find(|point| point.name == name)
    }

    /// The envelope with values replaced at element and attribute paths
    /// (the names of [`insertion_points`](Self::insertion_points)). Values
    /// are escaped; to send raw markup, edit
    /// [`envelope`](Self::envelope) and use
    /// [`to_request_with_envelope`](Self::to_request_with_envelope).
    #[must_use]
    pub fn envelope_with(&self, values: &BTreeMap<String, String>) -> String {
        render::envelope(self.soap_version, &self.header, &self.body, Some(values))
    }

    /// Builds the request again with other options (endpoint, headers).
    #[must_use]
    pub fn to_request(&self, options: &Options) -> HttpRequest {
        self.to_request_with_envelope(&self.envelope, options)
    }

    /// The request carrying another envelope.
    #[must_use]
    pub fn to_request_with_envelope(&self, envelope: &str, options: &Options) -> HttpRequest {
        render::request(self, envelope, options)
    }
}

/// An imported WSDL: its operations plus anything worth telling the user.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct WsdlSpec {
    /// The WSDL version.
    pub version: WsdlVersion,
    /// The `name` of the definitions, if any.
    pub name: Option<String>,
    /// `targetNamespace`.
    pub target_namespace: Option<String>,
    /// Service names, in document order.
    pub services: Vec<String>,
    /// One per SOAP binding operation reachable from a service (or from
    /// every SOAP binding when there are no services).
    pub operations: Vec<SoapOperation>,
    /// Non-fatal problems: unresolved references, imports not fetched,
    /// non-SOAP bindings, recursion and size cut-offs.
    pub warnings: Vec<String>,
    /// Whether [`Options::max_operations`] stopped the import early.
    pub truncated: bool,
}

impl WsdlSpec {
    /// The first operation with the given name.
    #[must_use]
    pub fn operation(&self, name: &str) -> Option<&SoapOperation> {
        self.operations
            .iter()
            .find(|operation| operation.name == name)
    }

    /// The operation with the given name and SOAP version.
    #[must_use]
    pub fn operation_for(&self, name: &str, version: SoapVersion) -> Option<&SoapOperation> {
        self.operations
            .iter()
            .find(|operation| operation.name == name && operation.soap_version == version)
    }
}

/// Import options.
///
/// ```
/// use rune_wsdl::{Options, Url};
///
/// let options = Options::default()
///     .with_endpoint(Url::parse("http://127.0.0.1:8080/ws").unwrap())
///     .with_header("Authorization", "Basic {{credentials}}")
///     .with_optional(false)
///     .with_max_depth(8);
/// assert!(!options.include_optional);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Sends requests here instead of the declared addresses.
    pub endpoint: Option<Url>,
    /// Extra headers on every request, such as credentials.
    pub headers: Vec<(String, String)>,
    /// Include optional (`minOccurs="0"`) elements and attributes.
    pub include_optional: bool,
    /// Deepest element nesting expanded from the schema.
    pub max_depth: usize,
    /// Most elements and attributes in one sample message.
    pub max_nodes: usize,
    /// Most operations imported; [`WsdlSpec::truncated`] reports a cut.
    pub max_operations: usize,
    /// Largest input accepted, in bytes.
    pub max_input_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            endpoint: None,
            headers: Vec::new(),
            include_optional: true,
            max_depth: 12,
            max_nodes: 2_000,
            max_operations: 10_000,
            max_input_bytes: 16 * 1024 * 1024,
        }
    }
}

impl Options {
    /// Sets [`endpoint`](Self::endpoint).
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: Url) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Adds a header to every request.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets [`include_optional`](Self::include_optional).
    #[must_use]
    pub const fn with_optional(mut self, include: bool) -> Self {
        self.include_optional = include;
        self
    }

    /// Sets [`max_depth`](Self::max_depth).
    #[must_use]
    pub const fn with_max_depth(mut self, max: usize) -> Self {
        self.max_depth = max;
        self
    }

    /// Sets [`max_nodes`](Self::max_nodes).
    #[must_use]
    pub const fn with_max_nodes(mut self, max: usize) -> Self {
        self.max_nodes = max;
        self
    }

    /// Sets [`max_operations`](Self::max_operations).
    #[must_use]
    pub const fn with_max_operations(mut self, max: usize) -> Self {
        self.max_operations = max;
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

    #[test]
    fn names() {
        assert_eq!(WsdlVersion::Wsdl20.to_string(), "wsdl-2.0");
        assert_eq!(SoapVersion::Soap12.to_string(), "soap12");
        assert_eq!(
            SoapVersion::Soap11.envelope_namespace(),
            "http://schemas.xmlsoap.org/soap/envelope/"
        );
        let options = Options::default().with_max_nodes(5).with_max_operations(2);
        assert_eq!((options.max_nodes, options.max_operations), (5, 2));
    }
}
