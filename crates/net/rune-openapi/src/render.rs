//! Building an example request and its insertion points from an endpoint.

use std::fmt::Write as _;

use rune_http_model::{HttpBody, HttpRequest};
use serde_json::{Map, Value};
use url::Url;

use crate::document::{encode_segment, escape_pointer, scalar_text};
use crate::model::{
    ApiKeyLocation, Endpoint, InsertionLocation, InsertionPoint, MediaType, Options, Parameter,
    ParameterLocation, ParameterStyle, RenderedRequest, SecurityScheme,
};
use crate::schema::{ExampleStrategy, Schema, SchemaType};

/// Boundary used for generated `multipart/form-data` bodies.
pub const MULTIPART_BOUNDARY: &str = "----runeOpenApiBoundary7MA4YWxkTrZu0gW";
/// Most insertion points produced for one request.
const MAX_POINTS: usize = 10_000;
/// Deepest body nesting walked for insertion points.
const MAX_BODY_DEPTH: usize = 32;
/// Most `{name}` placeholders filled in one path.
const MAX_PLACEHOLDERS: usize = 64;

impl Endpoint {
    /// Builds an example request and its insertion points with `options`.
    ///
    /// [`parse`](crate::parse) already stores the result for the import
    /// options in [`request`](Self::request) and
    /// [`insertion_points`](Self::insertion_points); call this to render the
    /// same endpoint against another server, with other credentials or with
    /// another [`ExampleStrategy`].
    ///
    /// ```
    /// use rune_openapi::{Options, Url, parse};
    ///
    /// let doc = br#"{"swagger": "2.0", "host": "api.example.test",
    ///   "securityDefinitions": {"key": {"type": "apiKey", "name": "X-Key", "in": "header"}},
    ///   "security": [{"key": []}],
    ///   "paths": {"/ping": {"get": {}}}}"#;
    /// let spec = parse(doc, &Options::default())?;
    /// let endpoint = &spec.endpoints[0];
    /// assert_eq!(endpoint.request.header("X-Key"), Some("{{key}}"));
    ///
    /// let local = Options::default()
    ///     .with_base_url(Url::parse("http://127.0.0.1:8080/").unwrap())
    ///     .with_auth_value("key", "s3cret");
    /// let rendered = endpoint.render(&local);
    /// assert_eq!(rendered.request.url, "http://127.0.0.1:8080/ping");
    /// assert_eq!(rendered.request.header("X-Key"), Some("s3cret"));
    /// # Ok::<(), rune_openapi::OpenApiError>(())
    /// ```
    #[must_use]
    pub fn render(&self, options: &Options) -> RenderedRequest {
        render(self, options)
    }
}

/// See [`Endpoint::render`].
pub fn render(endpoint: &Endpoint, options: &Options) -> RenderedRequest {
    let strategy = options.example_strategy;
    let mut warnings = Vec::new();
    let mut points = Vec::new();
    let mut path = endpoint.path.clone();
    let mut query: Vec<(String, String)> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut cookies: Vec<(String, String)> = Vec::new();

    for parameter in &endpoint.parameters {
        let value = parameter.example_value(strategy);
        match parameter.location {
            ParameterLocation::Path => {
                let text = path_text(parameter, &value);
                path = path.replace(&format!("{{{}}}", parameter.name), &text);
            }
            ParameterLocation::Query => query.extend(query_pairs(parameter, &value)),
            ParameterLocation::Header => {
                headers.push((parameter.name.clone(), plain_text(parameter, &value)));
            }
            ParameterLocation::Cookie => {
                cookies.push((parameter.name.clone(), plain_text(parameter, &value)));
            }
        }
        points.push(InsertionPoint {
            location: match parameter.location {
                ParameterLocation::Path => InsertionLocation::Path,
                ParameterLocation::Query => InsertionLocation::Query,
                ParameterLocation::Header => InsertionLocation::Header,
                ParameterLocation::Cookie => InsertionLocation::Cookie,
            },
            name: parameter.name.clone(),
            required: parameter.required,
            value,
            schema: parameter.schema.clone(),
        });
    }
    fill_undeclared_path(&mut path, &mut points);

    let mut url = request_url(endpoint, options, &path, &mut warnings);
    let mut auth_query = Vec::new();
    let mut auth_headers = Vec::new();
    apply_security(
        endpoint,
        options,
        &mut auth_headers,
        &mut auth_query,
        &mut cookies,
        &mut warnings,
    );
    if let Ok(parsed) = url.as_mut()
        && (!query.is_empty() || !auth_query.is_empty())
    {
        let mut pairs = parsed.query_pairs_mut();
        for (name, value) in query.iter().chain(&auth_query) {
            pairs.append_pair(name, value);
        }
    }
    let url = match url {
        Ok(url) => url.to_string(),
        Err(fallback) => fallback,
    };

    let mut request = HttpRequest::new(endpoint.method.clone(), url);
    for (name, value) in headers.into_iter().chain(auth_headers) {
        request.set_header(&name, value);
    }
    if !cookies.is_empty() {
        let cookie = cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        request.set_header("Cookie", cookie);
    }
    if let Some(body) = &endpoint.request_body
        && let Some(media) = body.preferred()
    {
        encode_body(media, body.required, strategy, &mut request, &mut points);
    }
    points.truncate(MAX_POINTS);
    RenderedRequest {
        request,
        insertion_points: points,
        warnings,
    }
}

// ----- URL ---------------------------------------------------------------

/// The request URL with the filled path, or a plain string when no
/// absolute base URL can be built.
fn request_url(
    endpoint: &Endpoint,
    options: &Options,
    path: &str,
    warnings: &mut Vec<String>,
) -> Result<Url, String> {
    let mut base = if let Some(base) = &options.base_url {
        base.clone()
    } else {
        let declared = endpoint
            .servers
            .first()
            .map(|server| server.trim())
            .filter(|server| !server.is_empty());
        match declared.map(Url::parse) {
            Some(Ok(url)) if !url.cannot_be_a_base() => url,
            other => {
                let relative = declared.unwrap_or("/");
                if other.is_none() {
                    warnings.push(String::from(
                        "no server URL declared; using http://localhost/ (set base_url)",
                    ));
                } else {
                    warnings.push(format!(
                        "server URL `{relative}` is relative; resolved against http://localhost/ (set base_url)"
                    ));
                }
                let joined = Url::parse("http://localhost/").and_then(|local| local.join(relative));
                match joined {
                    Ok(url) => url,
                    Err(_) => return Err(format!("http://localhost{path}")),
                }
            }
        }
    };
    if let Some(base_path) = &options.base_path {
        base.set_path(base_path);
    }
    base.set_fragment(None);
    let prefix = base.path().trim_end_matches('/').to_owned();
    let suffix = path.trim_start_matches('/');
    let joined = if suffix.is_empty() {
        if prefix.is_empty() {
            String::from("/")
        } else {
            prefix
        }
    } else {
        format!("{prefix}/{suffix}")
    };
    base.set_path(&joined);
    Ok(base)
}

/// Replaces `{name}` placeholders no parameter declares with `1`.
fn fill_undeclared_path(path: &mut String, points: &mut Vec<InsertionPoint>) {
    for _ in 0..MAX_PLACEHOLDERS {
        let Some(start) = path.find('{') else {
            return;
        };
        let Some(length) = path.get(start..).and_then(|rest| rest.find('}')) else {
            return;
        };
        let name = path
            .get(start + 1..start + length)
            .unwrap_or_default()
            .to_owned();
        path.replace_range(start..=start + length, "1");
        let mut point = InsertionPoint::new(InsertionLocation::Path, name, Value::from("1"));
        point.required = true;
        point.schema = Schema::default();
        points.push(point);
    }
}

// ----- parameter serialization -----------------------------------------

fn is_json(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|media| media.to_ascii_lowercase().contains("json"))
}

/// Value text for content-encoded parameters (`content: application/json`).
fn content_text(parameter: &Parameter, value: &Value) -> Option<String> {
    if is_json(parameter.content_type.as_deref()) {
        Some(value.to_string())
    } else {
        None
    }
}

fn object_pairs(map: &Map<String, Value>) -> impl Iterator<Item = (&str, String)> {
    map.iter()
        .map(|(key, item)| (key.as_str(), scalar_text(item)))
}

fn path_text(parameter: &Parameter, value: &Value) -> String {
    let name = &parameter.name;
    if let Some(text) = content_text(parameter, value) {
        return encode_segment(&text);
    }
    let explode = parameter.explode;
    match value {
        Value::Array(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|item| encode_segment(&scalar_text(item)))
                .collect();
            match parameter.style {
                ParameterStyle::Label => {
                    format!(".{}", parts.join(if explode { "." } else { "," }))
                }
                ParameterStyle::Matrix if explode => {
                    parts.iter().fold(String::new(), |mut out, part| {
                        let _ = write!(out, ";{name}={part}");
                        out
                    })
                }
                ParameterStyle::Matrix => format!(";{name}={}", parts.join(",")),
                _ => parts.join(","),
            }
        }
        Value::Object(map) => {
            let pairs: Vec<(String, String)> = object_pairs(map)
                .map(|(key, item)| (encode_segment(key), encode_segment(&item)))
                .collect();
            let exploded = |separator: &str| {
                pairs
                    .iter()
                    .map(|(key, item)| format!("{key}={item}"))
                    .collect::<Vec<_>>()
                    .join(separator)
            };
            let flat = pairs
                .iter()
                .flat_map(|(key, item)| [key.as_str(), item.as_str()])
                .collect::<Vec<_>>()
                .join(",");
            match (parameter.style, explode) {
                (ParameterStyle::Label, true) => format!(".{}", exploded(".")),
                (ParameterStyle::Label, false) => format!(".{flat}"),
                (ParameterStyle::Matrix, true) => format!(";{}", exploded(";")),
                (ParameterStyle::Matrix, false) => format!(";{name}={flat}"),
                (_, true) => exploded(","),
                (_, false) => flat,
            }
        }
        scalar => {
            let text = encode_segment(&scalar_text(scalar));
            match parameter.style {
                ParameterStyle::Label => format!(".{text}"),
                ParameterStyle::Matrix => format!(";{name}={text}"),
                _ => text,
            }
        }
    }
}

fn query_pairs(parameter: &Parameter, value: &Value) -> Vec<(String, String)> {
    let name = &parameter.name;
    if let Some(text) = content_text(parameter, value) {
        return vec![(name.clone(), text)];
    }
    let form_explode = parameter.style == ParameterStyle::Form && parameter.explode;
    match value {
        Value::Array(items) => {
            let texts = items.iter().map(scalar_text);
            if form_explode {
                return texts.map(|text| (name.clone(), text)).collect();
            }
            let separator = match parameter.style {
                ParameterStyle::SpaceDelimited => " ",
                ParameterStyle::PipeDelimited => "|",
                ParameterStyle::TabDelimited => "\t",
                _ => ",",
            };
            vec![(name.clone(), texts.collect::<Vec<_>>().join(separator))]
        }
        Value::Object(map) => match parameter.style {
            ParameterStyle::DeepObject => object_pairs(map)
                .map(|(key, item)| (format!("{name}[{key}]"), item))
                .collect(),
            _ if form_explode => object_pairs(map)
                .map(|(key, item)| (key.to_owned(), item))
                .collect(),
            _ => vec![(name.clone(), plain_text(parameter, value))],
        },
        scalar => vec![(name.clone(), scalar_text(scalar))],
    }
}

/// `simple`-style text for headers and cookies (and non-exploded objects).
fn plain_text(parameter: &Parameter, value: &Value) -> String {
    if let Some(text) = content_text(parameter, value) {
        return text;
    }
    match value {
        Value::Array(items) => items.iter().map(scalar_text).collect::<Vec<_>>().join(","),
        Value::Object(map) => {
            let explode = parameter.explode && parameter.location == ParameterLocation::Header;
            object_pairs(map)
                .map(|(key, item)| {
                    if explode {
                        format!("{key}={item}")
                    } else {
                        format!("{key},{item}")
                    }
                })
                .collect::<Vec<_>>()
                .join(",")
        }
        scalar => scalar_text(scalar),
    }
}

// ----- security ----------------------------------------------------------

fn apply_security(
    endpoint: &Endpoint,
    options: &Options,
    headers: &mut Vec<(String, String)>,
    query: &mut Vec<(String, String)>,
    cookies: &mut Vec<(String, String)>,
    warnings: &mut Vec<String>,
) {
    let Some(requirement) = endpoint.security.first() else {
        return;
    };
    for applied in &requirement.schemes {
        let name = &applied.name;
        let value = options
            .auth_values
            .get(name)
            .cloned()
            .unwrap_or_else(|| format!("{{{{{name}}}}}"));
        let authorization =
            |scheme: &str| (String::from("Authorization"), format!("{scheme} {value}"));
        match &applied.scheme {
            None | Some(SecurityScheme::MutualTls) => {}
            Some(SecurityScheme::ApiKey {
                name: key,
                location,
            }) => {
                let key = if key.is_empty() { name } else { key };
                let pair = (key.clone(), value.clone());
                match location {
                    ApiKeyLocation::Query => query.push(pair),
                    ApiKeyLocation::Cookie => cookies.push(pair),
                    ApiKeyLocation::Header => headers.push(pair),
                }
            }
            Some(SecurityScheme::Http { scheme, .. }) => {
                let scheme = match scheme.as_str() {
                    "bearer" => "Bearer",
                    "basic" => "Basic",
                    "digest" => "Digest",
                    other => other,
                };
                headers.push(authorization(scheme));
            }
            Some(SecurityScheme::OAuth2 | SecurityScheme::OpenIdConnect { .. }) => {
                headers.push(authorization("Bearer"));
            }
            Some(SecurityScheme::Other { kind }) => {
                warnings.push(format!("security scheme type `{kind}` not supported"));
            }
        }
    }
}

// ----- bodies ------------------------------------------------------------

fn encode_body(
    media: &MediaType,
    required: bool,
    strategy: ExampleStrategy,
    request: &mut HttpRequest,
    points: &mut Vec<InsertionPoint>,
) {
    let value = media.example_value(strategy);
    let schema = &media.schema;
    let lower = media.content_type.to_ascii_lowercase();
    if lower.contains("x-www-form-urlencoded") {
        let fields = form_fields(&value);
        form_points(schema, &value, InsertionLocation::Form, points);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(
                fields
                    .iter()
                    .map(|(key, item)| (key.as_str(), item.as_str())),
            )
            .finish();
        request.set_header("Content-Type", media.content_type.clone());
        request.body = HttpBody::from_text(body);
    } else if lower.starts_with("multipart/") {
        let fields = form_fields(&value);
        form_points(schema, &value, InsertionLocation::Multipart, points);
        let binary: Vec<&str> = schema
            .shape()
            .properties
            .iter()
            .chain(&schema.properties)
            .filter(|property| property.schema.is_binary())
            .map(|property| property.name.as_str())
            .collect();
        let essence = media
            .content_type
            .split(';')
            .next()
            .unwrap_or("multipart/form-data")
            .trim();
        request.set_header(
            "Content-Type",
            format!("{essence}; boundary={MULTIPART_BOUNDARY}"),
        );
        request.body = HttpBody::from_text(multipart_body(&fields, &binary));
    } else if lower.contains("json") || lower == "*/*" {
        json_points(&value, Some(schema), String::new(), required, 0, points);
        let content_type = if lower == "*/*" {
            "application/json"
        } else {
            media.content_type.as_str()
        };
        request.set_header("Content-Type", content_type);
        request.body = HttpBody::from_text(value.to_string());
    } else if lower.contains("xml") {
        let root = schema.name.as_deref().unwrap_or("root");
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        let path = format!("/{}", xml_name(root));
        let mut writer = XmlWriter {
            out: &mut xml,
            points,
        };
        writer.write(root, &value, &path, Some(schema), required, 0);
        request.set_header("Content-Type", media.content_type.clone());
        request.body = HttpBody::from_text(xml);
    } else {
        let text = match &value {
            Value::String(text) => text.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        let mut point =
            InsertionPoint::new(InsertionLocation::Body, "", Value::String(text.clone()));
        point.required = required;
        point.schema = schema.clone();
        points.push(point);
        request.set_header("Content-Type", media.content_type.clone());
        request.body = HttpBody::from_text(text);
    }
}

fn leaf_schema(schema: Option<&Schema>, value: &Value) -> Schema {
    schema.map_or_else(|| Schema::new(SchemaType::of(value)), Clone::clone)
}

fn json_points(
    value: &Value,
    schema: Option<&Schema>,
    pointer: String,
    required: bool,
    depth: usize,
    points: &mut Vec<InsertionPoint>,
) {
    if points.len() >= MAX_POINTS || depth > MAX_BODY_DEPTH {
        return;
    }
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, item) in map {
                let property = schema.and_then(|schema| schema.property(key));
                json_points(
                    item,
                    property.map(|property| &property.schema),
                    format!("{pointer}/{}", escape_pointer(key)),
                    property.is_some_and(|property| property.required),
                    depth + 1,
                    points,
                );
            }
        }
        Value::Array(items) if !items.is_empty() => {
            let item_schema = schema.and_then(Schema::item_schema);
            for (index, item) in items.iter().enumerate() {
                json_points(
                    item,
                    item_schema,
                    format!("{pointer}/{index}"),
                    required,
                    depth + 1,
                    points,
                );
            }
        }
        leaf => points.push(InsertionPoint {
            location: InsertionLocation::JsonPointer,
            name: pointer,
            required,
            value: leaf.clone(),
            schema: leaf_schema(schema, leaf),
        }),
    }
}

/// Form fields of an object value; arrays repeat the field.
fn form_fields(value: &Value) -> Vec<(String, String)> {
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, item) in map {
        match item {
            Value::Array(items) => {
                out.extend(
                    items
                        .iter()
                        .map(|element| (key.clone(), scalar_text(element))),
                );
            }
            Value::Object(_) => out.push((key.clone(), item.to_string())),
            other => out.push((key.clone(), scalar_text(other))),
        }
    }
    out
}

fn form_points(
    schema: &Schema,
    value: &Value,
    location: InsertionLocation,
    points: &mut Vec<InsertionPoint>,
) {
    let Some(map) = value.as_object() else {
        return;
    };
    for (key, item) in map {
        let property = schema.property(key);
        points.push(InsertionPoint {
            location,
            name: key.clone(),
            required: property.is_some_and(|property| property.required),
            value: item.clone(),
            schema: leaf_schema(property.map(|property| &property.schema), item),
        });
    }
}

fn multipart_body(fields: &[(String, String)], binary: &[&str]) -> String {
    let mut body = String::new();
    for (name, value) in fields {
        let name_attr = name.replace('"', "%22");
        let _ = write!(body, "--{MULTIPART_BOUNDARY}\r\n");
        if binary.contains(&name.as_str()) {
            let _ = write!(
                body,
                "Content-Disposition: form-data; name=\"{name_attr}\"; filename=\"{name_attr}.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n{value}\r\n"
            );
        } else {
            let _ = write!(
                body,
                "Content-Disposition: form-data; name=\"{name_attr}\"\r\n\r\n{value}\r\n"
            );
        }
    }
    let _ = write!(body, "--{MULTIPART_BOUNDARY}--\r\n");
    body
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A valid XML element name for a JSON key.
fn xml_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|ch| {
            if ch.is_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if cleaned
        .chars()
        .next()
        .is_some_and(|ch| ch.is_alphabetic() || ch == '_')
    {
        cleaned
    } else {
        format!("_{cleaned}")
    }
}

struct XmlWriter<'w> {
    out: &'w mut String,
    points: &'w mut Vec<InsertionPoint>,
}

impl XmlWriter<'_> {
    #[expect(clippy::too_many_arguments, reason = "recursive walker state")]
    fn write(
        &mut self,
        name: &str,
        value: &Value,
        path: &str,
        schema: Option<&Schema>,
        required: bool,
        depth: usize,
    ) {
        if depth > MAX_BODY_DEPTH {
            return;
        }
        let tag = xml_name(name);
        match value {
            Value::Array(items) => {
                let item_schema = schema.and_then(Schema::item_schema);
                for (index, item) in items.iter().enumerate() {
                    let item_path = format!("{path}[{}]", index + 1);
                    self.write(name, item, &item_path, item_schema, required, depth + 1);
                }
            }
            Value::Object(map) => {
                let _ = write!(self.out, "<{tag}>");
                for (key, item) in map {
                    let property = schema.and_then(|schema| schema.property(key));
                    let child_path = format!("{path}/{}", xml_name(key));
                    self.write(
                        key,
                        item,
                        &child_path,
                        property.map(|property| &property.schema),
                        property.is_some_and(|property| property.required),
                        depth + 1,
                    );
                }
                let _ = write!(self.out, "</{tag}>");
            }
            scalar => {
                let _ = write!(
                    self.out,
                    "<{tag}>{}</{tag}>",
                    xml_escape(&scalar_text(scalar))
                );
                if self.points.len() < MAX_POINTS {
                    self.points.push(InsertionPoint {
                        location: InsertionLocation::Xml,
                        name: path.to_owned(),
                        required,
                        value: scalar.clone(),
                        schema: leaf_schema(schema, scalar),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{from_value, parse};

    fn parameter(style: ParameterStyle, explode: bool, location: ParameterLocation) -> Parameter {
        Parameter {
            name: "p".into(),
            location,
            required: false,
            deprecated: false,
            description: None,
            style,
            explode,
            schema: Schema::default(),
            content_type: None,
            example: None,
        }
    }

    #[test]
    fn path_styles() {
        let array = json!(["a b", 2]);
        let object = json!({"x": 1, "y": "z"});
        let cases = [
            (ParameterStyle::Simple, false, &array, "a%20b,2"),
            (ParameterStyle::Label, false, &array, ".a%20b,2"),
            (ParameterStyle::Label, true, &array, ".a%20b.2"),
            (ParameterStyle::Matrix, false, &array, ";p=a%20b,2"),
            (ParameterStyle::Matrix, true, &array, ";p=a%20b;p=2"),
            (ParameterStyle::Simple, false, &object, "x,1,y,z"),
            (ParameterStyle::Simple, true, &object, "x=1,y=z"),
            (ParameterStyle::Label, true, &object, ".x=1.y=z"),
            (ParameterStyle::Matrix, true, &object, ";x=1;y=z"),
            (ParameterStyle::Matrix, false, &object, ";p=x,1,y,z"),
        ];
        for (style, explode, value, expected) in cases {
            let parameter = parameter(style, explode, ParameterLocation::Path);
            assert_eq!(
                path_text(&parameter, value),
                expected,
                "{style:?} {explode}"
            );
        }
        let parameter = parameter(ParameterStyle::Matrix, false, ParameterLocation::Path);
        assert_eq!(path_text(&parameter, &json!("v/1")), ";p=v%2F1");
    }

    #[test]
    fn query_styles() {
        let array = json!(["a", "b"]);
        let pairs = |style, explode, value: &Value| {
            query_pairs(&parameter(style, explode, ParameterLocation::Query), value)
        };
        let owned = |items: &[(&str, &str)]| -> Vec<(String, String)> {
            items
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect()
        };
        assert_eq!(
            pairs(ParameterStyle::Form, true, &array),
            owned(&[("p", "a"), ("p", "b")])
        );
        assert_eq!(
            pairs(ParameterStyle::Form, false, &array),
            owned(&[("p", "a,b")])
        );
        assert_eq!(
            pairs(ParameterStyle::PipeDelimited, false, &array),
            owned(&[("p", "a|b")])
        );
        assert_eq!(
            pairs(ParameterStyle::SpaceDelimited, false, &array),
            owned(&[("p", "a b")])
        );
        let object = json!({"k": 1});
        assert_eq!(
            pairs(ParameterStyle::DeepObject, true, &object),
            owned(&[("p[k]", "1")])
        );
        assert_eq!(
            pairs(ParameterStyle::Form, true, &object),
            owned(&[("k", "1")])
        );
        assert_eq!(
            pairs(ParameterStyle::Form, false, &object),
            owned(&[("p", "k,1")])
        );
        let mut json_param = parameter(ParameterStyle::Form, true, ParameterLocation::Query);
        json_param.content_type = Some("application/json".into());
        assert_eq!(
            query_pairs(&json_param, &object),
            owned(&[("p", r#"{"k":1}"#)])
        );
    }

    #[test]
    fn undeclared_placeholders_are_filled() {
        let spec = from_value(
            &json!({"openapi": "3.0.0", "servers": [{"url": "https://x.test/api/"}],
                    "paths": {"/a/{id}/b/{other}": {"get": {}}}}),
            &Options::default(),
        )
        .unwrap();
        let endpoint = &spec.endpoints[0];
        assert_eq!(endpoint.request.url, "https://x.test/api/a/1/b/1");
        assert!(
            endpoint
                .insertion_point(InsertionLocation::Path, "other")
                .is_some()
        );
    }

    #[test]
    fn relative_and_missing_servers_warn() {
        let spec = from_value(
            &json!({"openapi": "3.0.0", "servers": [{"url": "/v1"}], "paths": {"/a": {"get": {}}}}),
            &Options::default(),
        )
        .unwrap();
        assert_eq!(spec.endpoints[0].request.url, "http://localhost/v1/a");
        assert!(
            spec.warnings
                .iter()
                .any(|warning| warning.contains("relative"))
        );
        let spec = from_value(
            &json!({"swagger": "2.0", "paths": {"/a": {"get": {}}}}),
            &Options::default().with_base_path("/root"),
        )
        .unwrap();
        assert_eq!(spec.endpoints[0].request.url, "http://localhost/root/a");
    }

    #[test]
    fn xml_and_text_bodies() {
        let spec = from_value(
            &json!({"openapi": "3.0.0", "servers": [{"url": "https://x.test"}],
              "paths": {"/x": {"post": {"requestBody": {"content": {
                "application/xml": {"schema": {"$ref": "#/components/schemas/Pet"}}
              }}}, "put": {"requestBody": {"content": {"text/plain": {"example": "hi"}}}}}},
              "components": {"schemas": {"Pet": {"type": "object", "required": ["name"], "properties": {
                "name": {"type": "string", "example": "a<b"},
                "tags": {"type": "array", "items": {"type": "string"}}
              }}}}}),
            &Options::default(),
        )
        .unwrap();
        let by_method = |method: &str| {
            spec.endpoints
                .iter()
                .find(|endpoint| endpoint.method == method)
                .unwrap()
        };
        let post = by_method("POST");
        assert_eq!(
            post.request.body.as_utf8(),
            Some(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Pet><name>a&lt;b</name><tags>string</tags></Pet>"
            )
        );
        let name = post
            .insertion_point(InsertionLocation::Xml, "/Pet/name")
            .unwrap();
        assert!(name.required);
        assert!(
            post.insertion_point(InsertionLocation::Xml, "/Pet/tags[1]")
                .is_some()
        );
        let put = by_method("PUT");
        assert_eq!(put.request.body.as_utf8(), Some("hi"));
        assert_eq!(put.request.content_type(), Some("text/plain"));
        assert!(put.insertion_point(InsertionLocation::Body, "").is_some());
    }

    #[test]
    fn security_variants() {
        let doc = br#"{"openapi": "3.0.0", "servers": [{"url": "https://x.test"}],
          "components": {"securitySchemes": {
            "c": {"type": "apiKey", "in": "cookie", "name": "sid"},
            "q": {"type": "apiKey", "in": "query", "name": "key"},
            "d": {"type": "http", "scheme": "Digest"},
            "m": {"type": "mutualTLS"},
            "w": {"type": "weird"}
          }},
          "paths": {"/x": {"get": {
            "parameters": [{"name": "theme", "in": "cookie", "example": "dark"}],
            "security": [{"c": [], "q": [], "d": [], "m": [], "w": [], "u": []}, {}]
          }}}}"#;
        let spec = parse(doc, &Options::default().with_auth_value("q", "k1")).unwrap();
        let request = &spec.endpoints[0].request;
        assert_eq!(request.url, "https://x.test/x?key=k1");
        assert_eq!(request.header("Cookie"), Some("theme=dark; sid={{c}}"));
        assert_eq!(request.header("Authorization"), Some("Digest {{d}}"));
        assert!(
            spec.warnings
                .iter()
                .any(|warning| warning.contains("weird"))
        );
        assert!(spec.warnings.iter().any(|warning| warning.contains("`u`")));
        assert_eq!(spec.endpoints[0].security.len(), 2);
        assert_eq!(spec.endpoints[0].security[1].schemes.len(), 0);
    }

    #[test]
    fn xml_names() {
        assert_eq!(xml_name("a b"), "a_b");
        assert_eq!(xml_name("1x"), "_1x");
        assert_eq!(xml_escape("<&\">"), "&lt;&amp;&quot;&gt;");
    }
}
