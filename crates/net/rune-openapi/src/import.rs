//! Walking a parsed document into the normalized model.

use serde_json::{Map, Value};

use crate::document::{escape_pointer, parse_document, percent_decode, scalar_text};
use crate::model::{
    ApiKeyLocation, ApiSpec, Endpoint, MediaType, Options, Parameter, ParameterLocation,
    ParameterStyle, RequestBody, Response, SecurityRequirement, SecurityScheme, SecuritySchemeRef,
    SpecVersion,
};
use crate::schema::{Property, Schema, SchemaType};
use crate::{OpenApiError, render};

/// Operation keys of a path item, in output order.
const METHODS: [&str; 9] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace", "query",
];
/// Deepest schema nesting expanded.
const MAX_SCHEMA_DEPTH: usize = 16;
/// Schema nodes expanded per top-level schema.
const NODES_PER_SCHEMA: usize = 4_096;
/// Schema nodes expanded per document.
const NODES_PER_DOCUMENT: usize = 2_000_000;
/// Longest `$ref` chain followed.
const MAX_REF_HOPS: usize = 32;
/// Most warnings kept.
const MAX_WARNINGS: usize = 500;
/// Per-list caps that keep hostile documents cheap.
const MAX_PARAMETERS: usize = 500;
const MAX_PROPERTIES: usize = 500;
const MAX_VARIANTS: usize = 32;
const MAX_ENUM: usize = 100;
const MAX_MEDIA_TYPES: usize = 32;
const MAX_RESPONSES: usize = 100;

static NULL: Value = Value::Null;

/// Imports an `OpenAPI` 3.x or Swagger 2.0 document given as JSON or YAML
/// bytes.
///
/// ```
/// use rune_openapi::{Options, ParameterLocation, parse};
///
/// let doc = br#"{
///   "openapi": "3.0.3",
///   "info": {"title": "Demo", "version": "1"},
///   "servers": [{"url": "https://api.example.test"}],
///   "paths": {"/items/{id}": {"get": {
///     "operationId": "getItem",
///     "parameters": [{"name": "id", "in": "path", "required": true,
///                     "schema": {"type": "integer", "minimum": 7}}]
///   }}}
/// }"#;
/// let spec = parse(doc, &Options::default())?;
/// let endpoint = spec.endpoint("getItem").unwrap();
/// assert_eq!(endpoint.request.url, "https://api.example.test/items/7");
/// assert!(endpoint.parameter("id", ParameterLocation::Path).unwrap().required);
/// # Ok::<(), rune_openapi::OpenApiError>(())
/// ```
pub fn parse(input: &[u8], options: &Options) -> Result<ApiSpec, OpenApiError> {
    let document = parse_document(input, options.max_input_bytes)?;
    from_value(&document, options)
}

/// Imports a document that is already a JSON value.
///
/// ```
/// use rune_openapi::{Options, SpecVersion, from_value};
///
/// let doc = serde_json::json!({"swagger": "2.0", "host": "api.example.test", "paths": {}});
/// let spec = from_value(&doc, &Options::default())?;
/// assert_eq!(spec.version, SpecVersion::Swagger2);
/// assert!(spec.endpoints.is_empty());
/// # Ok::<(), rune_openapi::OpenApiError>(())
/// ```
pub fn from_value(document: &Value, options: &Options) -> Result<ApiSpec, OpenApiError> {
    let (version, version_text) = detect_version(document)?;
    let mut walker = Walker {
        root: document,
        version,
        warnings: Vec::new(),
        budget: NODES_PER_DOCUMENT,
    };
    let info = document.get("info");
    let mut spec = ApiSpec {
        version,
        version_text,
        title: info.and_then(|info| text(info, "title")),
        api_version: info.and_then(|info| info.get("version")).map(scalar_text),
        servers: walker.servers(&[document], None),
        endpoints: Vec::new(),
        warnings: Vec::new(),
        truncated: false,
    };
    if let Some(paths) = document.get("paths").and_then(Value::as_object) {
        'paths: for (path, item) in paths {
            if path.starts_with("x-") {
                continue;
            }
            let item = walker.resolve(item);
            for method in METHODS {
                if method == "query" && !matches!(version, SpecVersion::OpenApi32) {
                    continue;
                }
                let Some(operation) = item.get(method).filter(|value| value.is_object()) else {
                    continue;
                };
                if spec.endpoints.len() >= options.max_endpoints {
                    spec.truncated = true;
                    break 'paths;
                }
                let mut endpoint = walker.operation(path, item, method, operation);
                let rendered = render::render(&endpoint, options);
                for warning in rendered.warnings {
                    walker.warn(warning);
                }
                endpoint.request = rendered.request;
                endpoint.insertion_points = rendered.insertion_points;
                spec.endpoints.push(endpoint);
            }
        }
    } else {
        walker.warn(String::from("document has no `paths`"));
    }
    spec.warnings = walker.warnings;
    Ok(spec)
}

fn detect_version(document: &Value) -> Result<(SpecVersion, String), OpenApiError> {
    if !document.is_object() {
        return Err(OpenApiError::NotOpenApi(String::from(
            "the document is not a mapping",
        )));
    }
    if let Some(declared) = document.get("openapi") {
        let declared = scalar_text(declared).trim().to_owned();
        let version = if declared == "3.0" || declared.starts_with("3.0.") {
            SpecVersion::OpenApi30
        } else if declared == "3.1" || declared.starts_with("3.1.") {
            SpecVersion::OpenApi31
        } else if declared == "3.2" || declared.starts_with("3.2.") {
            SpecVersion::OpenApi32
        } else {
            return Err(OpenApiError::UnsupportedVersion(declared));
        };
        return Ok((version, declared));
    }
    if let Some(declared) = document.get("swagger") {
        let declared = scalar_text(declared).trim().to_owned();
        if declared == "2" || declared == "2.0" || declared.starts_with("2.0.") {
            return Ok((SpecVersion::Swagger2, declared));
        }
        return Err(OpenApiError::UnsupportedVersion(declared));
    }
    Err(OpenApiError::NotOpenApi(String::from(
        "missing `openapi` or `swagger` version field",
    )))
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn flag(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool) == Some(true)
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The last segment of a `$ref`, used as the schema name.
fn ref_name(reference: &str) -> Option<String> {
    reference
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty() && !name.starts_with('#'))
        .map(|name| percent_decode(name).replace("~1", "/").replace("~0", "~"))
}

struct Walker<'a> {
    root: &'a Value,
    version: SpecVersion,
    warnings: Vec<String>,
    budget: usize,
}

/// Body-related Swagger 2.0 parameters collected while reading parameters.
#[derive(Default)]
struct LegacyBody<'a> {
    body: Option<&'a Value>,
    form: Vec<&'a Value>,
}

impl<'a> Walker<'a> {
    fn warn(&mut self, message: String) {
        if self.warnings.len() < MAX_WARNINGS && !self.warnings.contains(&message) {
            self.warnings.push(message);
        }
    }

    /// Follows a `$ref` chain. External or dangling refs give `null`.
    fn resolve(&mut self, value: &'a Value) -> &'a Value {
        let mut current = value;
        for _ in 0..MAX_REF_HOPS {
            let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
                return current;
            };
            let Some(pointer) = reference.strip_prefix('#') else {
                self.warn(format!("external $ref `{reference}` skipped"));
                return &NULL;
            };
            let Some(target) = self.root.pointer(&percent_decode(pointer)) else {
                self.warn(format!("unresolved $ref `{reference}` skipped"));
                return &NULL;
            };
            current = target;
        }
        self.warn(String::from("$ref chain too long"));
        &NULL
    }

    /// The first `examples` value of a 3.x parameter or media type.
    fn first_example(&mut self, holder: &'a Value) -> Option<Value> {
        if let Some(example) = holder.get("example") {
            return Some(example.clone());
        }
        let examples = holder.get("examples")?.as_object()?;
        for example in examples.values() {
            if let Some(value) = self.resolve(example).get("value") {
                return Some(value.clone());
            }
        }
        None
    }

    // ----- schemas -------------------------------------------------------

    fn schema(&mut self, value: &'a Value) -> Schema {
        let mut nodes = NODES_PER_SCHEMA;
        let mut stack = Vec::new();
        self.schema_at(value, 0, &mut stack, &mut nodes)
    }

    fn schema_at(
        &mut self,
        value: &'a Value,
        depth: usize,
        stack: &mut Vec<&'a str>,
        nodes: &mut usize,
    ) -> Schema {
        if depth > MAX_SCHEMA_DEPTH || *nodes == 0 || self.budget == 0 {
            if self.budget == 0 {
                self.warn(String::from(
                    "schema size limit reached; remaining schemas truncated",
                ));
            }
            return Schema {
                truncated: true,
                ..Schema::default()
            };
        }
        *nodes -= 1;
        self.budget -= 1;
        if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
            let name = ref_name(reference);
            if stack.contains(&reference) {
                return Schema {
                    name,
                    truncated: true,
                    ..Schema::default()
                };
            }
            let target = self.resolve(value);
            stack.push(reference);
            let mut schema = self.schema_at(target, depth + 1, stack, nodes);
            stack.pop();
            if schema.name.is_none() {
                schema.name = name;
            }
            return schema;
        }
        let Some(object) = value.as_object() else {
            return Schema::default();
        };
        let mut schema = Schema {
            format: object
                .get("format")
                .and_then(Value::as_str)
                .map(str::to_owned),
            ..Schema::default()
        };
        self.read_type(object, &mut schema);
        schema.nullable |= flag(value, "nullable") || flag(value, "x-nullable");
        if let Some(values) = object.get("enum").and_then(Value::as_array) {
            schema.enum_values = values.iter().take(MAX_ENUM).cloned().collect();
        }
        if let Some(constant) = object.get("const")
            && schema.enum_values.is_empty()
        {
            schema.enum_values.push(constant.clone());
        }
        schema.default = object.get("default").cloned();
        schema.example = object
            .get("example")
            .or_else(|| object.get("x-example"))
            .cloned()
            .or_else(|| {
                object
                    .get("examples")
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .cloned()
            });
        read_bounds(object, &mut schema);
        schema.pattern = object
            .get("pattern")
            .and_then(Value::as_str)
            .map(str::to_owned);
        schema.read_only = flag(value, "readOnly");
        schema.write_only = flag(value, "writeOnly");
        if let Some(properties) = object.get("properties").and_then(Value::as_object) {
            for (name, property) in properties.iter().take(MAX_PROPERTIES) {
                let property = self.schema_at(property, depth + 1, stack, nodes);
                schema.properties.push(Property {
                    name: name.clone(),
                    required: false,
                    schema: property,
                });
            }
        }
        if let Some(items) = object.get("items").filter(|items| items.is_object()) {
            schema.items = Some(Box::new(self.schema_at(items, depth + 1, stack, nodes)));
        }
        for part in object
            .get("allOf")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(MAX_VARIANTS)
        {
            let part = self.schema_at(part, depth + 1, stack, nodes);
            schema.absorb(part);
        }
        for key in ["oneOf", "anyOf"] {
            for variant in object
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(MAX_VARIANTS)
            {
                let variant = self.schema_at(variant, depth + 1, stack, nodes);
                schema.variants.push(variant);
            }
        }
        let required = strings(object.get("required"));
        for property in &mut schema.properties {
            if required.contains(&property.name) {
                property.required = true;
            }
        }
        if schema.kind == SchemaType::Unknown {
            schema.kind = infer_kind(object, &schema);
        }
        schema
    }

    fn read_type(&self, object: &Map<String, Value>, schema: &mut Schema) {
        let declared = match object.get("type") {
            Some(Value::String(kind)) => Some(kind.as_str()),
            Some(Value::Array(kinds)) => {
                let mut found = None;
                for kind in kinds.iter().filter_map(Value::as_str) {
                    if kind == "null" {
                        schema.nullable = true;
                    } else if found.is_none() {
                        found = Some(kind);
                    }
                }
                found
            }
            _ => None,
        };
        schema.kind = match declared {
            Some("string") => SchemaType::String,
            Some("file") if self.version.is_swagger2() => {
                schema.format.get_or_insert_with(|| String::from("binary"));
                SchemaType::String
            }
            Some("integer") => SchemaType::Integer,
            Some("number") => SchemaType::Number,
            Some("boolean") => SchemaType::Boolean,
            Some("array") => SchemaType::Array,
            Some("object") => SchemaType::Object,
            Some("null") => {
                schema.nullable = true;
                SchemaType::Unknown
            }
            _ => SchemaType::Unknown,
        };
    }

    // ----- operations ----------------------------------------------------

    fn operation(
        &mut self,
        path: &str,
        item: &'a Value,
        method: &str,
        operation: &'a Value,
    ) -> Endpoint {
        let mut legacy = LegacyBody::default();
        let parameters = self.parameters(item, operation, &mut legacy);
        let request_body = if self.version.is_swagger2() {
            self.legacy_body(operation, &legacy)
        } else {
            operation
                .get("requestBody")
                .and_then(|body| self.request_body(body))
        };
        let servers = if self.version.is_swagger2() {
            self.servers(&[self.root], Some(operation))
        } else {
            self.servers(&[operation, item, self.root], None)
        };
        Endpoint {
            method: method.to_ascii_uppercase(),
            path: path.to_owned(),
            pointer: format!("#/paths/{}/{method}", escape_pointer(path)),
            operation_id: text(operation, "operationId"),
            summary: text(operation, "summary"),
            description: text(operation, "description"),
            tags: strings(operation.get("tags")),
            deprecated: flag(operation, "deprecated"),
            servers,
            parameters,
            request_body,
            responses: self.responses(operation),
            security: self.security(operation),
            request: rune_http_model::HttpRequest::new(method.to_ascii_uppercase(), ""),
            insertion_points: Vec::new(),
        }
    }

    /// Server URLs. For 3.x the first holder with a non-empty `servers`
    /// list wins; Swagger 2.0 builds them from `schemes`, `host` and
    /// `basePath`.
    fn servers(&self, holders: &[&'a Value], operation: Option<&'a Value>) -> Vec<String> {
        if self.version.is_swagger2() {
            let host = self.root.get("host").and_then(Value::as_str);
            let base_path = self
                .root
                .get("basePath")
                .and_then(Value::as_str)
                .unwrap_or("/");
            let Some(host) = host else {
                return vec![base_path.to_owned()];
            };
            let mut schemes = operation
                .map(|operation| strings(operation.get("schemes")))
                .filter(|schemes| !schemes.is_empty())
                .unwrap_or_else(|| strings(self.root.get("schemes")));
            if schemes.is_empty() {
                schemes.push(String::from("https"));
            }
            return schemes
                .iter()
                .map(|scheme| format!("{scheme}://{host}{base_path}"))
                .collect();
        }
        let Some(servers) = holders.iter().find_map(|holder| {
            holder
                .get("servers")
                .and_then(Value::as_array)
                .filter(|servers| !servers.is_empty())
        }) else {
            return vec![String::from("/")];
        };
        servers
            .iter()
            .take(MAX_MEDIA_TYPES)
            .filter_map(|server| {
                let mut url = server.get("url").and_then(Value::as_str)?.to_owned();
                if let Some(variables) = server.get("variables").and_then(Value::as_object) {
                    for (name, variable) in variables {
                        let value = variable.get("default").map(scalar_text).unwrap_or_default();
                        url = url.replace(&format!("{{{name}}}"), &value);
                    }
                }
                Some(url)
            })
            .collect()
    }

    fn parameters(
        &mut self,
        item: &'a Value,
        operation: &'a Value,
        legacy: &mut LegacyBody<'a>,
    ) -> Vec<Parameter> {
        let mut declared: Vec<&'a Value> = Vec::new();
        for holder in [item, operation] {
            let Some(list) = holder.get("parameters").and_then(Value::as_array) else {
                continue;
            };
            for parameter in list.iter().take(MAX_PARAMETERS) {
                let parameter = self.resolve(parameter);
                let key = |value: &Value| {
                    (
                        value.get("name").and_then(Value::as_str).map(str::to_owned),
                        value.get("in").and_then(Value::as_str).map(str::to_owned),
                    )
                };
                let this = key(parameter);
                if this.0.is_none() || this.1.is_none() {
                    continue;
                }
                declared.retain(|existing| key(existing) != this);
                declared.push(parameter);
            }
        }
        let mut out = Vec::new();
        for parameter in declared {
            match parameter.get("in").and_then(Value::as_str) {
                Some("body") if self.version.is_swagger2() => legacy.body = Some(parameter),
                Some("formData") if self.version.is_swagger2() => legacy.form.push(parameter),
                _ => {
                    if let Some(parameter) = self.parameter(parameter) {
                        out.push(parameter);
                    }
                }
            }
        }
        out
    }

    fn parameter(&mut self, parameter: &'a Value) -> Option<Parameter> {
        let name = parameter.get("name").and_then(Value::as_str)?;
        let location = match parameter.get("in").and_then(Value::as_str) {
            Some("path") => ParameterLocation::Path,
            Some("query") => ParameterLocation::Query,
            Some("header") => ParameterLocation::Header,
            Some("cookie") if !self.version.is_swagger2() => ParameterLocation::Cookie,
            other => {
                self.warn(format!(
                    "parameter `{name}` in `{}` not supported",
                    other.unwrap_or_default()
                ));
                return None;
            }
        };
        let (style, explode, schema, content_type, example) = if self.version.is_swagger2() {
            let (style, explode) = collection_style(location, parameter);
            let schema = self.schema(parameter);
            let example = parameter.get("x-example").cloned();
            (style, explode, schema, None, example)
        } else {
            let style = parameter
                .get("style")
                .and_then(Value::as_str)
                .and_then(ParameterStyle::parse)
                .unwrap_or_else(|| ParameterStyle::default_for(location));
            let explode = parameter
                .get("explode")
                .and_then(Value::as_bool)
                .unwrap_or(style == ParameterStyle::Form);
            let (schema, content_type) = if let Some(schema) = parameter.get("schema") {
                (self.schema(schema), None)
            } else if let Some((media, holder)) = parameter
                .get("content")
                .and_then(Value::as_object)
                .and_then(|content| content.iter().next())
            {
                let schema = holder.get("schema").map(|schema| self.schema(schema));
                (schema.unwrap_or_default(), Some(media.clone()))
            } else {
                (Schema::default(), None)
            };
            let example = self.first_example(parameter);
            (style, explode, schema, content_type, example)
        };
        Some(Parameter {
            name: name.to_owned(),
            location,
            required: location == ParameterLocation::Path || flag(parameter, "required"),
            deprecated: flag(parameter, "deprecated"),
            description: text(parameter, "description"),
            style,
            explode,
            schema,
            content_type,
            example,
        })
    }

    fn media_types(&mut self, content: &'a Value) -> Vec<MediaType> {
        let Some(content) = content.as_object() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (content_type, media) in content.iter().take(MAX_MEDIA_TYPES) {
            let schema = media
                .get("schema")
                .map(|schema| self.schema(schema))
                .unwrap_or_default();
            let example = self.first_example(media);
            out.push(MediaType {
                content_type: content_type.clone(),
                schema,
                example,
            });
        }
        out
    }

    fn request_body(&mut self, body: &'a Value) -> Option<RequestBody> {
        let body = self.resolve(body);
        if body.is_null() {
            return None;
        }
        let content = body
            .get("content")
            .map(|content| self.media_types(content))
            .unwrap_or_default();
        Some(RequestBody {
            required: flag(body, "required"),
            description: text(body, "description"),
            content,
        })
    }

    /// The media types a Swagger 2.0 operation consumes or produces.
    fn legacy_media(&self, operation: &Value, key: &str) -> Vec<String> {
        let declared = strings(operation.get(key));
        if declared.is_empty() {
            strings(self.root.get(key))
        } else {
            declared
        }
    }

    fn legacy_body(
        &mut self,
        operation: &'a Value,
        legacy: &LegacyBody<'a>,
    ) -> Option<RequestBody> {
        let consumes = self.legacy_media(operation, "consumes");
        if let Some(parameter) = legacy.body {
            let schema = parameter
                .get("schema")
                .map(|schema| self.schema(schema))
                .unwrap_or_default();
            let example = parameter.get("x-example").cloned();
            let types = if consumes.is_empty() {
                vec![String::from("application/json")]
            } else {
                consumes
            };
            return Some(RequestBody {
                required: flag(parameter, "required"),
                description: text(parameter, "description"),
                content: types
                    .into_iter()
                    .take(MAX_MEDIA_TYPES)
                    .map(|content_type| MediaType {
                        content_type,
                        schema: schema.clone(),
                        example: example.clone(),
                    })
                    .collect(),
            });
        }
        if legacy.form.is_empty() {
            return None;
        }
        let mut schema = Schema::new(SchemaType::Object);
        let mut has_file = false;
        let mut required = false;
        for parameter in &legacy.form {
            let Some(name) = parameter.get("name").and_then(Value::as_str) else {
                continue;
            };
            has_file |= parameter.get("type").and_then(Value::as_str) == Some("file");
            let property_required = flag(parameter, "required");
            required |= property_required;
            schema.properties.push(Property {
                name: name.to_owned(),
                required: property_required,
                schema: self.schema(parameter),
            });
        }
        let mut types: Vec<String> = consumes
            .into_iter()
            .filter(|media| {
                media.starts_with("multipart/") || media.contains("x-www-form-urlencoded")
            })
            .collect();
        if types.is_empty()
            || (has_file && !types.iter().any(|media| media.starts_with("multipart/")))
        {
            types = vec![String::from(if has_file {
                "multipart/form-data"
            } else {
                "application/x-www-form-urlencoded"
            })];
        }
        if has_file {
            types.retain(|media| media.starts_with("multipart/"));
        }
        Some(RequestBody {
            required,
            description: None,
            content: types
                .into_iter()
                .map(|content_type| MediaType {
                    content_type,
                    schema: schema.clone(),
                    example: None,
                })
                .collect(),
        })
    }

    fn responses(&mut self, operation: &'a Value) -> Vec<Response> {
        let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
            return Vec::new();
        };
        let produces = if self.version.is_swagger2() {
            let declared = self.legacy_media(operation, "produces");
            if declared.is_empty() {
                vec![String::from("application/json")]
            } else {
                declared
            }
        } else {
            Vec::new()
        };
        let mut out = Vec::new();
        for (status, response) in responses.iter().take(MAX_RESPONSES) {
            if status.starts_with("x-") {
                continue;
            }
            let response = self.resolve(response);
            let content = if self.version.is_swagger2() {
                self.legacy_response(response, &produces)
            } else {
                response
                    .get("content")
                    .map(|content| self.media_types(content))
                    .unwrap_or_default()
            };
            out.push(Response {
                status: status.clone(),
                description: text(response, "description"),
                content,
            });
        }
        out
    }

    /// Swagger 2.0 response bodies: one media type per `produces` entry.
    fn legacy_response(&mut self, response: &'a Value, produces: &[String]) -> Vec<MediaType> {
        let Some(schema) = response.get("schema") else {
            return Vec::new();
        };
        let schema = self.schema(schema);
        let examples = response.get("examples");
        produces
            .iter()
            .take(MAX_MEDIA_TYPES)
            .map(|content_type| MediaType {
                content_type: content_type.clone(),
                schema: schema.clone(),
                example: examples
                    .and_then(|examples| examples.get(content_type))
                    .cloned(),
            })
            .collect()
    }

    // ----- security ------------------------------------------------------

    fn security(&mut self, operation: &'a Value) -> Vec<SecurityRequirement> {
        let Some(requirements) = operation
            .get("security")
            .or_else(|| self.root.get("security"))
            .and_then(Value::as_array)
        else {
            return Vec::new();
        };
        let definitions = if self.version.is_swagger2() {
            self.root.get("securityDefinitions")
        } else {
            self.root.pointer("/components/securitySchemes")
        };
        let mut out = Vec::new();
        for requirement in requirements.iter().take(MAX_MEDIA_TYPES) {
            let Some(requirement) = requirement.as_object() else {
                continue;
            };
            let mut schemes = Vec::new();
            for (name, scopes) in requirement {
                let scheme = if let Some(definition) = definitions.and_then(|map| map.get(name)) {
                    let definition = self.resolve(definition);
                    Some(security_scheme(definition))
                } else {
                    self.warn(format!("security scheme `{name}` is not defined"));
                    None
                };
                schemes.push(SecuritySchemeRef {
                    name: name.clone(),
                    scopes: strings(Some(scopes)),
                    scheme,
                });
            }
            out.push(SecurityRequirement { schemes });
        }
        out
    }
}

fn security_scheme(definition: &Value) -> SecurityScheme {
    let kind = definition
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match kind {
        "apiKey" => SecurityScheme::ApiKey {
            name: text(definition, "name").unwrap_or_default(),
            location: match definition.get("in").and_then(Value::as_str) {
                Some("query") => ApiKeyLocation::Query,
                Some("cookie") => ApiKeyLocation::Cookie,
                _ => ApiKeyLocation::Header,
            },
        },
        "basic" => SecurityScheme::Http {
            scheme: String::from("basic"),
            bearer_format: None,
        },
        "http" => SecurityScheme::Http {
            scheme: definition
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or("bearer")
                .to_ascii_lowercase(),
            bearer_format: text(definition, "bearerFormat"),
        },
        "oauth2" => SecurityScheme::OAuth2,
        "openIdConnect" => SecurityScheme::OpenIdConnect {
            url: text(definition, "openIdConnectUrl"),
        },
        "mutualTLS" => SecurityScheme::MutualTls,
        other => SecurityScheme::Other {
            kind: other.to_owned(),
        },
    }
}

/// Maps Swagger 2.0 `collectionFormat` onto a style and explode flag.
fn collection_style(location: ParameterLocation, parameter: &Value) -> (ParameterStyle, bool) {
    let default = ParameterStyle::default_for(location);
    match parameter.get("collectionFormat").and_then(Value::as_str) {
        Some("multi") => (ParameterStyle::Form, true),
        Some("ssv") => (ParameterStyle::SpaceDelimited, false),
        Some("pipes") => (ParameterStyle::PipeDelimited, false),
        Some("tsv") => (ParameterStyle::TabDelimited, false),
        _ => (default, false),
    }
}

fn read_bounds(object: &Map<String, Value>, schema: &mut Schema) {
    schema.minimum = object.get("minimum").and_then(Value::as_f64);
    schema.maximum = object.get("maximum").and_then(Value::as_f64);
    match object.get("exclusiveMinimum") {
        Some(Value::Bool(flag)) => schema.exclusive_minimum = *flag,
        Some(Value::Number(number)) => {
            if let Some(bound) = number.as_f64()
                && schema.minimum.is_none_or(|minimum| bound >= minimum)
            {
                schema.minimum = Some(bound);
                schema.exclusive_minimum = true;
            }
        }
        _ => {}
    }
    match object.get("exclusiveMaximum") {
        Some(Value::Bool(flag)) => schema.exclusive_maximum = *flag,
        Some(Value::Number(number)) => {
            if let Some(bound) = number.as_f64()
                && schema.maximum.is_none_or(|maximum| bound <= maximum)
            {
                schema.maximum = Some(bound);
                schema.exclusive_maximum = true;
            }
        }
        _ => {}
    }
    schema.min_length = object.get("minLength").and_then(Value::as_u64);
    schema.max_length = object.get("maxLength").and_then(Value::as_u64);
}

fn infer_kind(object: &Map<String, Value>, schema: &Schema) -> SchemaType {
    if !schema.properties.is_empty() || object.contains_key("additionalProperties") {
        SchemaType::Object
    } else if schema.items.is_some() {
        SchemaType::Array
    } else if let Some(first) = schema.enum_values.iter().find(|value| !value.is_null()) {
        SchemaType::of(first)
    } else {
        SchemaType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn import(document: &Value) -> ApiSpec {
        from_value(document, &Options::default()).unwrap()
    }

    #[test]
    fn versions() {
        let cases = [
            (json!({"openapi": "3.0.3"}), SpecVersion::OpenApi30),
            (json!({"openapi": "3.1.0"}), SpecVersion::OpenApi31),
            (json!({"openapi": "3.2.0"}), SpecVersion::OpenApi32),
            (json!({"swagger": "2.0"}), SpecVersion::Swagger2),
            (json!({"swagger": 2.0}), SpecVersion::Swagger2),
        ];
        for (document, version) in cases {
            assert_eq!(import(&document).version, version);
        }
        let error = from_value(&json!({"openapi": "4.0.0"}), &Options::default()).unwrap_err();
        assert_eq!(error, OpenApiError::UnsupportedVersion("4.0.0".into()));
        let error = from_value(&json!({"swagger": "1.2"}), &Options::default()).unwrap_err();
        assert_eq!(error.code(), "unsupported_version");
        let error = from_value(&json!([]), &Options::default()).unwrap_err();
        assert_eq!(error.code(), "not_openapi");
    }

    #[test]
    fn no_paths_warns() {
        let spec = import(&json!({"openapi": "3.0.0"}));
        assert!(
            spec.warnings
                .iter()
                .any(|warning| warning.contains("paths"))
        );
    }

    #[test]
    fn recursive_schema_is_truncated() {
        let spec = import(&json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.test"}],
            "paths": {"/n": {"post": {
                "requestBody": {"content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Node"}}}}
            }}},
            "components": {"schemas": {"Node": {
                "type": "object",
                "properties": {"child": {"$ref": "#/components/schemas/Node"}, "v": {"type": "string"}}
            }}}
        }));
        let body = spec.endpoints[0].request_body.as_ref().unwrap();
        let schema = &body.content[0].schema;
        assert_eq!(schema.name.as_deref(), Some("Node"));
        let child = &schema.property("child").unwrap().schema;
        assert!(child.truncated);
        assert_eq!(child.name.as_deref(), Some("Node"));
        assert_eq!(
            spec.endpoints[0].request.body.as_utf8(),
            Some(r#"{"v":"string"}"#)
        );
    }

    #[test]
    fn ref_cycle_and_dangling_refs_do_not_hang() {
        let spec = import(&json!({
            "openapi": "3.0.0",
            "paths": {"/a": {"$ref": "#/paths/~1a"}, "/b": {"get": {"parameters": [
                {"$ref": "#/components/parameters/Nope"},
                {"$ref": "#/components/parameters/Loop"}
            ]}}},
            "components": {"parameters": {"Loop": {"$ref": "#/components/parameters/Loop"}}}
        }));
        assert_eq!(spec.endpoints.len(), 1);
        assert!(spec.warnings.iter().any(|warning| warning.contains("Nope")));
        assert!(
            spec.warnings
                .iter()
                .any(|warning| warning.contains("too long"))
        );
    }

    #[test]
    fn exponential_schema_is_bounded() {
        let mut schemas = Map::new();
        for level in 0..40 {
            let next = format!("#/components/schemas/S{}", level + 1);
            schemas.insert(
                format!("S{level}"),
                json!({"type": "object", "properties": {
                    "a": {"$ref": next}, "b": {"$ref": next}, "c": {"$ref": next}
                }}),
            );
        }
        let spec = import(&json!({
            "openapi": "3.0.0",
            "paths": {"/x": {"post": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/S0"}}}}}}},
            "components": {"schemas": Value::Object(schemas)}
        }));
        assert_eq!(spec.endpoints.len(), 1);
        assert!(spec.endpoints[0].insertion_points.len() < 20_000);
    }

    #[test]
    fn max_endpoints_truncates() {
        let spec = from_value(
            &json!({"openapi": "3.0.0", "paths": {
                "/a": {"get": {}, "post": {}}, "/b": {"get": {}}
            }}),
            &Options::default().with_max_endpoints(2),
        )
        .unwrap();
        assert_eq!(spec.endpoints.len(), 2);
        assert!(spec.truncated);
    }

    #[test]
    fn query_method_only_in_3_2() {
        let document = |version: &str| json!({"openapi": version, "paths": {"/s": {"query": {"operationId": "search"}}}});
        assert_eq!(import(&document("3.1.0")).endpoints.len(), 0);
        assert_eq!(import(&document("3.2.0")).endpoints[0].method, "QUERY");
    }

    #[test]
    fn schema_keywords() {
        let spec = import(&json!({
            "openapi": "3.1.0",
            "paths": {"/x": {"get": {"parameters": [
                {"name": "a", "in": "query", "schema": {
                    "type": ["integer", "null"], "exclusiveMinimum": 3, "maximum": 9,
                    "const": 5, "pattern": "^[0-9]+$"
                }},
                {"name": "b", "in": "query", "content": {"application/json": {
                    "schema": {"type": "object", "properties": {"k": {"type": "string"}}}
                }}},
                {"name": "c", "in": "querystring"}
            ]}}}
        }));
        let endpoint = &spec.endpoints[0];
        let a = &endpoint
            .parameter("a", ParameterLocation::Query)
            .unwrap()
            .schema;
        assert_eq!(a.kind, SchemaType::Integer);
        assert!(a.nullable);
        assert_eq!(a.minimum, Some(3.0));
        assert!(a.exclusive_minimum);
        assert_eq!(a.enum_values, vec![json!(5)]);
        assert_eq!(a.pattern.as_deref(), Some("^[0-9]+$"));
        let b = endpoint.parameter("b", ParameterLocation::Query).unwrap();
        assert_eq!(b.content_type.as_deref(), Some("application/json"));
        assert_eq!(b.schema.kind, SchemaType::Object);
        assert!(
            spec.warnings
                .iter()
                .any(|warning| warning.contains("querystring"))
        );
    }
}
