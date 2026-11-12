//! Reading a collection: walking folders, resolving variables and turning
//! each request item into an [`HttpRequest`].

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use rune_http_model::{HeaderEntry, HttpBody, HttpRequest};
use serde_json::{Map, Value};

use crate::environment::{Environment, Variable};
use crate::vars::{Layers, Resolved, Scope, resolve_with};
use crate::{PostmanError, json, script};

/// The multipart boundary used for `formdata` bodies. It is fixed, so that
/// the same collection always imports to the same bytes.
pub const MULTIPART_BOUNDARY: &str = "----------------------------rune-postman-boundary";

/// Deepest folder nesting read; deeper folders are skipped with a warning.
const MAX_FOLDER_DEPTH: usize = 64;

/// Settings for reading a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadOptions {
    /// Values that win over every scope, like Postman's data-file
    /// variables. Also the way to supply dynamic variables such as
    /// `$guid`, which are otherwise left unresolved.
    pub variables: BTreeMap<String, String>,
    /// The active environment.
    pub environment: Option<Environment>,
    /// Global variables, the weakest scope.
    pub globals: Option<Environment>,
    /// Turn auth helpers (`bearer`, `basic`, `apikey`, `oauth2` with a
    /// token) into headers or query parameters. On by default.
    pub apply_auth: bool,
    /// Apply literal variable assignments found in pre-request scripts.
    /// On by default. Scripts are never executed.
    pub script_values: bool,
    /// Scheme given to URLs that have none, as Postman does. `http` by
    /// default.
    pub default_scheme: String,
    /// Import at most this many requests.
    pub max_requests: Option<usize>,
    /// Longest a single resolved string may grow through variable
    /// expansion, in bytes (1 MiB by default). Expansion stops there with
    /// a warning, which bounds nested `{{a}}{{a}}` definitions.
    pub max_resolved_len: usize,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            variables: BTreeMap::new(),
            environment: None,
            globals: None,
            apply_auth: true,
            script_values: true,
            default_scheme: "http".to_owned(),
            max_requests: None,
            max_resolved_len: 1 << 20,
        }
    }
}

impl ReadOptions {
    /// Adds a value to [`ReadOptions::variables`].
    #[must_use]
    pub fn with_variable(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.variables.insert(key.into(), value.into());
        self
    }

    /// Sets [`ReadOptions::environment`].
    #[must_use]
    pub fn with_environment(mut self, environment: Environment) -> Self {
        self.environment = Some(environment);
        self
    }

    /// Sets [`ReadOptions::globals`].
    #[must_use]
    pub fn with_globals(mut self, globals: Environment) -> Self {
        self.globals = Some(globals);
        self
    }

    /// Sets [`ReadOptions::apply_auth`].
    #[must_use]
    pub const fn with_auth(mut self, apply: bool) -> Self {
        self.apply_auth = apply;
        self
    }

    /// Sets [`ReadOptions::script_values`].
    #[must_use]
    pub const fn with_script_values(mut self, apply: bool) -> Self {
        self.script_values = apply;
        self
    }

    /// Sets [`ReadOptions::default_scheme`].
    #[must_use]
    pub fn with_default_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.default_scheme = scheme.into();
        self
    }

    /// Sets [`ReadOptions::max_requests`].
    #[must_use]
    pub const fn with_max_requests(mut self, max_requests: usize) -> Self {
        self.max_requests = Some(max_requests);
        self
    }

    /// Sets [`ReadOptions::max_resolved_len`].
    #[must_use]
    pub const fn with_max_resolved_len(mut self, bytes: usize) -> Self {
        self.max_resolved_len = bytes;
        self
    }
}

/// Something in the input that was skipped, not applied or left unresolved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Warning {
    /// Path of the item it is about (`Folder/Sub/Request`), when it is
    /// about one.
    pub path: Option<String>,
    /// Stable, machine-readable kind, e.g. `invalid_item`.
    pub code: &'static str,
    /// Human-readable detail.
    pub message: String,
}

impl Warning {
    fn new(path: Option<&str>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            path: path.map(str::to_owned),
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(formatter, "{path}: {}", self.message),
            None => formatter.write_str(&self.message),
        }
    }
}

/// One request of a collection, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CollectionRequest {
    /// The item's name.
    pub name: String,
    /// Postman's id for the item, when exported.
    pub id: Option<String>,
    /// Names of the enclosing folders, outermost first.
    pub folders: Vec<String>,
    /// The request's (or else the item's) description.
    pub description: Option<String>,
    /// The request, with variables resolved, the body encoded and auth
    /// applied.
    pub request: HttpRequest,
    /// Source of the pre-request scripts that would run before the
    /// request, outermost (collection) first. They are data: nothing is
    /// executed.
    pub pre_request_scripts: Vec<String>,
    /// Variables the request refers to that no scope defines; their
    /// `{{name}}` placeholders are left in place.
    pub unresolved: Vec<String>,
}

impl CollectionRequest {
    /// The item's path: folder names and the item name joined by `/`.
    #[must_use]
    pub fn path(&self) -> String {
        join_path(&self.folders, &self.name)
    }
}

/// A collection's metadata and its requests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Collection {
    /// `info.name`.
    pub name: String,
    /// `info._postman_id`.
    pub id: Option<String>,
    /// `info.schema`, e.g. the v2.1.0 schema URL.
    pub schema: Option<String>,
    /// `info.description`.
    pub description: Option<String>,
    /// The collection variables, as declared (including disabled ones).
    pub variables: Vec<Variable>,
    /// Every usable request, in collection order (depth first).
    pub requests: Vec<CollectionRequest>,
    /// What was skipped, not applied or left unresolved.
    pub warnings: Vec<Warning>,
}

fn join_path(folders: &[String], name: &str) -> String {
    let mut path = String::new();
    for folder in folders {
        path.push_str(folder);
        path.push('/');
    }
    path.push_str(name);
    path
}

/// Reads a Postman v2.0 or v2.1 collection.
///
/// The input is UTF-8 JSON (a leading byte-order mark is ignored); the
/// Postman API's `{"collection": …}` wrapper is accepted. Each item is read
/// on its own: one with a field of the wrong shape is skipped with a
/// [`Warning`] instead of failing the whole collection.
///
/// # Errors
///
/// [`PostmanError::Json`] when the input is not JSON,
/// [`PostmanError::NotCollection`] when it has no `item` array (Postman v1
/// collections included).
pub fn read(input: &[u8], options: &ReadOptions) -> Result<Collection, PostmanError> {
    let document = json::parse(input)?;
    let Value::Object(root) = &document else {
        return Err(PostmanError::NotCollection(
            "the document is not a JSON object",
        ));
    };
    let root = match root.get("collection") {
        Some(Value::Object(inner)) => inner,
        _ => root,
    };
    let items = match root.get("item") {
        Some(Value::Array(items)) => items,
        Some(Value::Null) | None if root.contains_key("requests") => {
            return Err(PostmanError::NotCollection(
                "Postman v1 collections are not supported; export as v2.1",
            ));
        }
        Some(Value::Null) | None => return Err(PostmanError::NotCollection("no `item` array")),
        Some(_) => return Err(PostmanError::NotCollection("`item` is not an array")),
    };

    let mut collection = Collection::default();
    if let Ok(Some(info)) = json::object(root, "info") {
        collection.name = json::field(info, "name").unwrap_or_default();
        collection.id = json::non_empty(info, "_postman_id");
        collection.schema = json::non_empty(info, "schema");
        collection.description = json::description(info);
    }
    collection.variables = json::list(root, "variable")
        .unwrap_or_default()
        .iter()
        .filter_map(Variable::from_json)
        .collect();

    let mut scope = Scope::default();
    let layers = [
        (&options.globals, &mut scope.globals),
        (&options.environment, &mut scope.environment),
    ];
    for (source, layer) in layers {
        for (key, value) in source.iter().flat_map(Environment::enabled) {
            layer.insert(key.to_owned(), value.to_owned());
        }
    }
    let mut walker = Walker {
        options,
        requests: Vec::new(),
        warnings: Vec::new(),
        full: false,
    };
    let top = Context {
        auth: None,
        scope,
        scripts: Vec::new(),
    };
    let top = walker.enter(&top, root, None);
    walker.items(items, &top, &mut Vec::new(), 0);
    collection.requests = walker.requests;
    collection.warnings = walker.warnings;
    Ok(collection)
}

/// What a folder passes down to its items.
#[derive(Clone)]
struct Context<'a> {
    auth: Option<&'a Map<String, Value>>,
    scope: Scope,
    scripts: Vec<String>,
}

/// An auth object, unless it says to inherit.
fn own_auth<'a>(
    node: &'a Map<String, Value>,
    inherited: Option<&'a Map<String, Value>>,
) -> Result<Option<&'a Map<String, Value>>, String> {
    Ok(match json::object(node, "auth")? {
        Some(auth) if json::field(auth, "type").as_deref() != Some("inherit") => Some(auth),
        _ => inherited,
    })
}

/// The source of a script object: `exec` as lines or as one string.
fn script_source(script: &Map<String, Value>) -> Option<String> {
    let source = match script.get("exec")? {
        Value::Array(lines) => lines.iter().map(json::text).collect::<Vec<_>>().join("\n"),
        Value::String(text) => text.clone(),
        _ => return None,
    };
    (!source.trim().is_empty()).then_some(source)
}

struct Walker<'o> {
    options: &'o ReadOptions,
    requests: Vec<CollectionRequest>,
    warnings: Vec<Warning>,
    full: bool,
}

impl Walker<'_> {
    fn warn(&mut self, path: Option<&str>, code: &'static str, message: impl Into<String>) {
        self.warnings.push(Warning::new(path, code, message));
    }

    /// The context inside `node` (the collection, a folder or an item):
    /// its auth, variables and pre-request scripts on top of `outer`'s.
    fn enter<'a>(
        &mut self,
        outer: &Context<'a>,
        node: &'a Map<String, Value>,
        path: Option<&str>,
    ) -> Context<'a> {
        let mut context = outer.clone();
        match own_auth(node, outer.auth) {
            Ok(auth) => context.auth = auth,
            Err(reason) => self.warn(path, "invalid_auth", format!("auth ignored: {reason}")),
        }
        for variable in json::list(node, "variable")
            .unwrap_or_default()
            .iter()
            .filter_map(Variable::from_json)
            .filter(|variable| variable.enabled)
        {
            context
                .scope
                .collection
                .insert(variable.key, variable.value);
        }
        for event in json::list(node, "event").unwrap_or_default() {
            let Some(event) = event.as_object() else {
                continue;
            };
            if json::field(event, "listen").as_deref() != Some("prerequest")
                || json::disabled(event)
            {
                continue;
            }
            let Some(source) = json::object(event, "script")
                .ok()
                .flatten()
                .filter(|script| !json::disabled(script))
                .and_then(script_source)
            else {
                continue;
            };
            if self.options.script_values {
                let found = script::assignments(&source);
                for assignment in found.literal {
                    context
                        .scope
                        .set(assignment.target, assignment.key, assignment.value);
                }
                if !found.computed.is_empty() {
                    self.warn(
                        path,
                        "script_value_not_literal",
                        format!(
                            "pre-request script computes {}; not evaluated",
                            found.computed.join(", ")
                        ),
                    );
                }
            }
            context.scripts.push(source);
        }
        context
    }

    fn items<'a>(
        &mut self,
        items: &'a [Value],
        outer: &Context<'a>,
        folders: &mut Vec<String>,
        depth: usize,
    ) {
        for (index, item) in items.iter().enumerate() {
            if self.full {
                return;
            }
            let Value::Object(item) = item else {
                let path = join_path(folders, &format!("#{index}"));
                self.warn(Some(&path), "invalid_item", "skipped: not an object");
                continue;
            };
            let name = json::field(item, "name").unwrap_or_default();
            let path = join_path(folders, &name);
            let context = self.enter(outer, item, Some(&path));
            if item.get("item").is_some_and(|children| !children.is_null()) {
                let children = match json::list(item, "item") {
                    Ok(children) => children,
                    Err(reason) => {
                        self.warn(Some(&path), "invalid_item", format!("skipped: {reason}"));
                        continue;
                    }
                };
                if depth >= MAX_FOLDER_DEPTH {
                    self.warn(Some(&path), "too_deep", "folder nested too deeply; skipped");
                    continue;
                }
                folders.push(name);
                self.items(children, &context, folders, depth + 1);
                folders.pop();
                continue;
            }
            let Some(request) = item.get("request").filter(|request| !request.is_null()) else {
                self.warn(
                    Some(&path),
                    "no_request",
                    "skipped: neither `request` nor `item`",
                );
                continue;
            };
            if self
                .options
                .max_requests
                .is_some_and(|max| self.requests.len() >= max)
            {
                self.full = true;
                self.warn(None, "max_requests", "request limit reached; rest skipped");
                return;
            }
            let mut build = Build {
                options: self.options,
                layers: Layers {
                    overrides: &self.options.variables,
                    scope: &context.scope,
                },
                unresolved: Vec::new(),
                truncated: false,
                notes: Vec::new(),
            };
            match build.request(request, context.auth) {
                Ok((request, description)) => {
                    let Build {
                        unresolved,
                        truncated,
                        notes,
                        ..
                    } = build;
                    for (code, message) in notes {
                        self.warn(Some(&path), code, message);
                    }
                    if !unresolved.is_empty() {
                        self.warn(
                            Some(&path),
                            "unresolved_variable",
                            format!("undefined variables: {}", unresolved.join(", ")),
                        );
                    }
                    if truncated {
                        self.warn(
                            Some(&path),
                            "expansion_limit",
                            "variable expansion cut at the size limit",
                        );
                    }
                    self.requests.push(CollectionRequest {
                        name,
                        id: json::non_empty(item, "id"),
                        folders: folders.clone(),
                        description: description.or_else(|| json::description(item)),
                        request,
                        pre_request_scripts: context.scripts,
                        unresolved,
                    });
                }
                Err(reason) => {
                    self.warn(Some(&path), "invalid_item", format!("skipped: {reason}"));
                }
            }
        }
    }
}

/// Builds one request.
struct Build<'a> {
    options: &'a ReadOptions,
    layers: Layers<'a>,
    unresolved: Vec<String>,
    truncated: bool,
    /// Warnings about this request: code and message.
    notes: Vec<(&'static str, String)>,
}

impl Build<'_> {
    fn resolve(&mut self, text: &str) -> String {
        if !text.contains("{{") {
            return text.to_owned();
        }
        let Resolved {
            text,
            unresolved,
            truncated,
        } = resolve_with(text, &self.layers, self.options.max_resolved_len);
        for name in unresolved {
            if !self.unresolved.contains(&name) {
                self.unresolved.push(name);
            }
        }
        self.truncated |= truncated;
        text
    }

    fn note(&mut self, code: &'static str, message: impl Into<String>) {
        self.notes.push((code, message.into()));
    }

    /// The request and its description.
    fn request(
        &mut self,
        request: &Value,
        inherited_auth: Option<&Map<String, Value>>,
    ) -> Result<(HttpRequest, Option<String>), String> {
        let empty = Map::new();
        let (object, url) = match request {
            Value::String(url) => (&empty, url.clone()),
            Value::Object(object) => (object, url_text(object.get("url"))?),
            other => return Err(format!("`request` is {}", json::kind(other))),
        };
        let method = json::field(object, "method")
            .map(|method| method.trim().to_ascii_uppercase())
            .filter(|method| !method.is_empty())
            .unwrap_or_else(|| "GET".to_owned());
        let url = self.resolve(&url);
        let url = url.trim();
        if url.is_empty() {
            return Err("empty URL".to_owned());
        }
        let url = if url.contains("://") {
            url.to_owned()
        } else {
            format!("{}://{url}", self.options.default_scheme)
        };
        let mut http = HttpRequest::new(method, url);
        self.headers(object, &mut http)?;
        if let Some(body) = json::object(object, "body")? {
            self.body(body, &mut http)?;
        }
        let auth = own_auth(object, inherited_auth)?;
        if self.options.apply_auth
            && let Some(auth) = auth
        {
            self.auth(auth, &mut http);
        }
        Ok((http, json::description(object)))
    }

    fn headers(
        &mut self,
        object: &Map<String, Value>,
        http: &mut HttpRequest,
    ) -> Result<(), String> {
        match object.get("header") {
            None | Some(Value::Null) => {}
            Some(Value::Array(headers)) => {
                for (index, header) in headers.iter().enumerate() {
                    let header = match header {
                        Value::Null => continue,
                        Value::Object(header) => header,
                        other => {
                            return Err(format!("`header[{index}]` is {}", json::kind(other)));
                        }
                    };
                    if json::disabled(header) {
                        continue;
                    }
                    let Some(key) = json::non_empty(header, "key") else {
                        continue;
                    };
                    let value = json::field(header, "value").unwrap_or_default();
                    let (key, value) = (self.resolve(&key), self.resolve(&value));
                    http.headers.push(HeaderEntry::new(key, value));
                }
            }
            // v2.0 allows the headers as one `Name: value` block.
            Some(Value::String(block)) => {
                for line in block.lines() {
                    if let Some((key, value)) = line.split_once(':')
                        && !key.trim().is_empty()
                    {
                        let (key, value) = (self.resolve(key.trim()), self.resolve(value.trim()));
                        http.headers.push(HeaderEntry::new(key, value));
                    }
                }
            }
            Some(other) => return Err(format!("`header` is {}", json::kind(other))),
        }
        Ok(())
    }

    /// Enabled `key`/`value` pairs of a list, resolved.
    fn pairs(&mut self, list: &[Value]) -> Vec<(String, String)> {
        list.iter()
            .filter_map(Value::as_object)
            .filter(|pair| !json::disabled(pair))
            .filter_map(|pair| {
                let key = json::non_empty(pair, "key")?;
                Some((key, json::field(pair, "value").unwrap_or_default()))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(key, value)| (self.resolve(&key), self.resolve(&value)))
            .collect()
    }

    fn body(&mut self, body: &Map<String, Value>, http: &mut HttpRequest) -> Result<(), String> {
        if json::disabled(body) {
            return Ok(());
        }
        let mode = json::field(body, "mode").unwrap_or_default();
        match mode.as_str() {
            "" => {}
            "raw" => {
                let raw = json::field(body, "raw").unwrap_or_default();
                let raw = self.resolve(&raw);
                let language = body
                    .get("options")
                    .and_then(|options| options.pointer("/raw/language"))
                    .map(json::text)
                    .unwrap_or_default();
                let content_type = match language.as_str() {
                    "json" => Some("application/json"),
                    "xml" => Some("application/xml"),
                    "html" => Some("text/html"),
                    "javascript" => Some("application/javascript"),
                    "text" => Some("text/plain"),
                    _ => None,
                };
                if let Some(content_type) = content_type {
                    add_header(http, "Content-Type", content_type);
                }
                http.body = HttpBody::from_text(raw);
            }
            "urlencoded" => {
                let pairs = self.pairs(json::list(body, "urlencoded")?);
                let mut form = url::form_urlencoded::Serializer::new(String::new());
                for (key, value) in &pairs {
                    form.append_pair(key, value);
                }
                add_header(http, "Content-Type", "application/x-www-form-urlencoded");
                http.body = HttpBody::from_text(form.finish());
            }
            "formdata" => {
                let fields = json::list(body, "formdata")?;
                http.body = HttpBody::from_text(self.multipart(fields));
                http.set_header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}"),
                );
            }
            "graphql" => {
                let empty = Map::new();
                let graphql = json::object(body, "graphql")?.unwrap_or(&empty);
                let query = json::field(graphql, "query").unwrap_or_default();
                let mut payload = Map::new();
                payload.insert("query".to_owned(), Value::String(self.resolve(&query)));
                match graphql.get("variables") {
                    Some(Value::String(text)) if !text.trim().is_empty() => {
                        let text = self.resolve(text);
                        match serde_json::from_str::<Value>(&text) {
                            Ok(variables) => {
                                payload.insert("variables".to_owned(), variables);
                            }
                            Err(error) => self.note(
                                "invalid_graphql_variables",
                                format!("GraphQL variables are not JSON ({error}); left out"),
                            ),
                        }
                    }
                    Some(variables @ Value::Object(_)) => {
                        payload.insert("variables".to_owned(), variables.clone());
                    }
                    _ => {}
                }
                add_header(http, "Content-Type", "application/json");
                http.body = HttpBody::from_text(Value::Object(payload).to_string());
            }
            "file" => self.note(
                "file_not_embedded",
                "file body is not part of the export; body left empty",
            ),
            other => self.note(
                "unknown_body_mode",
                format!("body mode `{other}` is not imported"),
            ),
        }
        Ok(())
    }

    /// A `multipart/form-data` body for `formdata` fields.
    fn multipart(&mut self, fields: &[Value]) -> String {
        let mut text = String::new();
        let mut files = Vec::new();
        for field in fields.iter().filter_map(Value::as_object) {
            if json::disabled(field) {
                continue;
            }
            let Some(key) = json::non_empty(field, "key") else {
                continue;
            };
            let key = quote(&self.resolve(&key));
            let _ = write!(text, "--{MULTIPART_BOUNDARY}\r\n");
            let content_type = json::non_empty(field, "contentType");
            if json::field(field, "type").as_deref() == Some("file") {
                let source = match field.get("src") {
                    Some(Value::Array(sources)) => sources.first().map(json::text),
                    other => other.map(json::text),
                }
                .unwrap_or_default();
                let file = source
                    .rsplit(['/', '\\'])
                    .next()
                    .filter(|name| !name.is_empty())
                    .unwrap_or("file");
                files.push(file.to_owned());
                let _ = write!(
                    text,
                    "Content-Disposition: form-data; name=\"{key}\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n\r\n",
                    quote(file),
                    content_type
                        .as_deref()
                        .unwrap_or("application/octet-stream"),
                );
            } else {
                let value = json::field(field, "value").unwrap_or_default();
                let value = self.resolve(&value);
                let _ = write!(text, "Content-Disposition: form-data; name=\"{key}\"\r\n");
                if let Some(content_type) = content_type {
                    let _ = write!(text, "Content-Type: {content_type}\r\n");
                }
                let _ = write!(text, "\r\n{value}\r\n");
            }
        }
        let _ = write!(text, "--{MULTIPART_BOUNDARY}--\r\n");
        if !files.is_empty() {
            self.note(
                "file_not_embedded",
                format!(
                    "file contents are not part of the export; empty parts for {}",
                    files.join(", ")
                ),
            );
        }
        text
    }

    /// A parameter of an auth helper: v2.1 lists `[{key, value}]`, v2.0
    /// uses an object.
    fn auth_param(&mut self, auth: &Map<String, Value>, kind: &str, key: &str) -> Option<String> {
        let raw = match auth.get(kind)? {
            Value::Array(list) => list
                .iter()
                .filter_map(Value::as_object)
                .find(|entry| json::field(entry, "key").as_deref() == Some(key))
                .and_then(|entry| json::field(entry, "value")),
            Value::Object(map) => json::field(map, key),
            _ => None,
        }?;
        Some(self.resolve(&raw))
    }

    fn auth(&mut self, auth: &Map<String, Value>, http: &mut HttpRequest) {
        let kind = json::field(auth, "type").unwrap_or_default();
        match kind.as_str() {
            "" | "noauth" | "inherit" => {}
            "bearer" => match self.auth_param(auth, "bearer", "token") {
                Some(token) => add_header(http, "Authorization", &format!("Bearer {token}")),
                None => self.note("auth_not_applied", "bearer auth has no token"),
            },
            "basic" => {
                let user = self
                    .auth_param(auth, "basic", "username")
                    .unwrap_or_default();
                let password = self
                    .auth_param(auth, "basic", "password")
                    .unwrap_or_default();
                let credentials = rune_base64::encode(format!("{user}:{password}").as_bytes());
                add_header(http, "Authorization", &format!("Basic {credentials}"));
            }
            "apikey" => {
                let Some(key) = self
                    .auth_param(auth, "apikey", "key")
                    .filter(|key| !key.is_empty())
                else {
                    self.note("auth_not_applied", "API key auth has no key name");
                    return;
                };
                let value = self.auth_param(auth, "apikey", "value").unwrap_or_default();
                if self.auth_param(auth, "apikey", "in").as_deref() == Some("query") {
                    append_query(&mut http.url, &key, &value);
                } else {
                    add_header(http, &key, &value);
                }
            }
            "oauth2" => {
                let Some(token) = self
                    .auth_param(auth, "oauth2", "accessToken")
                    .filter(|token| !token.is_empty())
                else {
                    self.note(
                        "auth_not_applied",
                        "OAuth 2.0 auth has no access token in the export",
                    );
                    return;
                };
                if self.auth_param(auth, "oauth2", "addTokenTo").as_deref() == Some("queryParams") {
                    append_query(&mut http.url, "access_token", &token);
                } else {
                    let prefix = self
                        .auth_param(auth, "oauth2", "headerPrefix")
                        .unwrap_or_else(|| "Bearer".to_owned());
                    let value = if prefix.is_empty() {
                        token
                    } else {
                        format!("{prefix} {token}")
                    };
                    add_header(http, "Authorization", &value);
                }
            }
            other => self.note(
                "auth_not_applied",
                format!("`{other}` auth needs a live exchange or signature; not applied"),
            ),
        }
    }
}

/// Adds a header unless the request already sets it: headers written in
/// the collection win over generated ones.
fn add_header(http: &mut HttpRequest, name: &str, value: &str) {
    if !http.has_header(name) {
        http.headers.push(HeaderEntry::new(name, value));
    }
}

/// Appends a form-encoded `key=value` to the URL's query, before any
/// fragment.
fn append_query(url: &mut String, key: &str, value: &str) {
    let fragment = url.find('#').map(|at| url.split_off(at));
    let separator = if url.contains('?') { '&' } else { '?' };
    url.push(separator);
    url.extend(url::form_urlencoded::byte_serialize(key.as_bytes()));
    url.push('=');
    url.extend(url::form_urlencoded::byte_serialize(value.as_bytes()));
    if let Some(fragment) = fragment {
        url.push_str(&fragment);
    }
}

/// Escapes a multipart parameter value (RFC 7578 §4.2: quotes and line
/// breaks percent-encoded).
fn quote(value: &str) -> String {
    value
        .replace('"', "%22")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// The URL of a request, before variables are resolved.
fn url_text(value: Option<&Value>) -> Result<String, String> {
    match value {
        None | Some(Value::Null) => Err("no URL".to_owned()),
        Some(Value::String(url)) => Ok(url.clone()),
        Some(Value::Object(url)) => {
            let mut text = match json::non_empty(url, "raw") {
                Some(raw) => raw,
                None => structured_url(url)?,
            };
            for variable in json::list(url, "variable")?
                .iter()
                .filter_map(Value::as_object)
            {
                let (Some(key), Some(value)) = (
                    json::non_empty(variable, "key"),
                    json::field(variable, "value"),
                ) else {
                    continue;
                };
                text = replace_path_variable(&text, &key, &value);
            }
            Ok(text)
        }
        Some(other) => Err(format!("`url` is {}", json::kind(other))),
    }
}

/// A part of a structured URL: text, or `{"value": …}` (v2.0 path
/// segments).
fn part_text(value: &Value) -> String {
    match value {
        Value::Object(part) => json::field(part, "value").unwrap_or_default(),
        other => json::text(other),
    }
}

/// Joins a URL part given as a list (with `separator`) or as text.
fn joined(url: &Map<String, Value>, key: &str, separator: &str) -> String {
    match url.get(key) {
        Some(Value::Array(parts)) => parts
            .iter()
            .map(part_text)
            .collect::<Vec<_>>()
            .join(separator),
        Some(other) => json::text(other),
        None => String::new(),
    }
}

/// Builds a URL from `protocol`, `host`, `port`, `path`, `query` and
/// `hash`, for exports without `raw`.
fn structured_url(url: &Map<String, Value>) -> Result<String, String> {
    let host = joined(url, "host", ".");
    if host.is_empty() {
        return Err("URL has neither `raw` nor `host`".to_owned());
    }
    let mut text = String::new();
    if let Some(protocol) = json::non_empty(url, "protocol") {
        text.push_str(protocol.trim_end_matches("://"));
        text.push_str("://");
    }
    text.push_str(&host);
    if let Some(port) = json::non_empty(url, "port") {
        text.push(':');
        text.push_str(&port);
    }
    let path = joined(url, "path", "/");
    if !path.is_empty() {
        text.push('/');
        text.push_str(path.trim_start_matches('/'));
    }
    let query: Vec<String> = json::list(url, "query")?
        .iter()
        .filter_map(Value::as_object)
        .filter(|pair| !json::disabled(pair))
        .filter_map(|pair| {
            let key = json::field(pair, "key")?;
            Some(match json::field(pair, "value") {
                Some(value) => format!("{key}={value}"),
                None => key,
            })
        })
        .collect();
    if !query.is_empty() {
        text.push('?');
        text.push_str(&query.join("&"));
    }
    if let Some(hash) = json::non_empty(url, "hash") {
        text.push('#');
        text.push_str(&hash);
    }
    Ok(text)
}

/// Replaces the path segment `:key` with `value`.
fn replace_path_variable(url: &str, key: &str, value: &str) -> String {
    let needle = format!("/:{key}");
    let mut out = String::with_capacity(url.len());
    let mut rest = url;
    // Only the path is searched: stop at the query or fragment.
    let path_end = url.find(['?', '#']).unwrap_or(url.len());
    let mut consumed = 0;
    while let Some(at) = rest.find(&needle) {
        let start = consumed + at;
        let end = start + needle.len();
        if end > path_end {
            break;
        }
        let terminated = url[end..]
            .chars()
            .next()
            .is_none_or(|c| matches!(c, '/' | '?' | '#'));
        out.push_str(&rest[..at]);
        if terminated {
            out.push('/');
            out.push_str(value);
        } else {
            out.push_str(&needle);
        }
        rest = &rest[at + needle.len()..];
        consumed = end;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_variables_replace_whole_segments_only() {
        assert_eq!(
            replace_path_variable("{{h}}/users/:id/x/:idx?q=/:id", "id", "7"),
            "{{h}}/users/7/x/:idx?q=/:id"
        );
        assert_eq!(replace_path_variable("h/:id", "id", "7"), "h/7");
    }

    #[test]
    fn appends_query_before_fragment() {
        let mut url = "http://h.test/p#frag".to_owned();
        append_query(&mut url, "api key", "a&b");
        assert_eq!(url, "http://h.test/p?api+key=a%26b#frag");
        append_query(&mut url, "x", "1");
        assert_eq!(url, "http://h.test/p?api+key=a%26b&x=1#frag");
    }

    #[test]
    fn structured_urls() {
        let url = serde_json::json!({
            "protocol": "https", "host": ["api", "{{domain}}"], "port": "8443",
            "path": ["v1", {"type": "string", "value": "users"}],
            "query": [{"key": "a", "value": "1"}, {"key": "b", "disabled": true}, {"key": "flag"}],
            "hash": "top"
        });
        assert_eq!(
            url_text(Some(&url)).unwrap(),
            "https://api.{{domain}}:8443/v1/users?a=1&flag#top"
        );
        assert!(url_text(Some(&serde_json::json!({"path": ["x"]}))).is_err());
        assert!(url_text(Some(&serde_json::json!(5))).is_err());
    }
}
