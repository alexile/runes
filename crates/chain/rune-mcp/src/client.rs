//! [`McpClient`]: consume tools, resources and prompts from an MCP server.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, ClientConfig, GetPromptRequestParams,
    Implementation, ReadResourceRequestParams,
};
use rmcp::service::{NotificationContext, RunningService};
use rmcp::transport::IntoTransport;
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use rune_tool_schema::ToolDescriptor;
use serde_json::{Map, Value};
use tokio::sync::watch;

use crate::convert::{ImportLimits, ServerTrust, import_tool};
use crate::output::from_call_tool_result;
use crate::policy::{AllowAll, Decision, Side, ToolCall, ToolPolicy, gate};
use crate::resource::{PromptInfo, PromptMessage, PromptResult, ResourceContent, ResourceInfo};
use crate::sanitize::{clean_text, qualified_name, validate_namespace};
use crate::{Error, ToolError, ToolHandler, ToolOutput};

/// Default for [`ClientOptions::call_timeout`].
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Default for [`ClientOptions::request_timeout`].
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default for [`ClientOptions::max_list_items`].
pub const DEFAULT_MAX_LIST_ITEMS: usize = 256;
/// Default for [`ClientOptions::max_description_bytes`].
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 1024;
/// Default for [`ClientOptions::max_schema_bytes`].
pub const DEFAULT_MAX_SCHEMA_BYTES: usize = 64 * 1024;
/// Default for [`ClientOptions::max_result_bytes`].
pub const DEFAULT_MAX_RESULT_BYTES: usize = 128 * 1024;

/// How an [`McpClient`] identifies itself, and how far it trusts and how
/// much it accepts from the server.
///
/// The defaults assume a server you do not control: its safety claims are
/// ignored ([`ServerTrust::Untrusted`]), descriptions are cleaned and capped,
/// results are capped and fenced, and every request has a timeout.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientOptions {
    /// Client name sent in `initialize`.
    pub name: String,
    /// Client version sent in `initialize`.
    pub version: String,
    /// How far the server's tool metadata is believed.
    pub trust: ServerTrust,
    /// Policy consulted before every call and for listing.
    pub policy: Arc<dyn ToolPolicy>,
    /// Fail a listing on a definition that breaks a rule or limit, instead
    /// of skipping it (default: skip, and report it in
    /// [`McpClient::rejected`]).
    pub strict: bool,
    /// Expose the server's tools as `<namespace>__<tool>`
    /// ([`RemoteTool`], chain tools), so tools of different servers cannot
    /// collide or shadow each other. [`McpToolset`](crate::McpToolset) sets
    /// it per server.
    pub namespace: Option<String>,
    /// Only these remote tool names are listed and callable; `None` (the
    /// default) allows every tool the policy allows.
    pub allowed_tools: Option<BTreeSet<String>>,
    /// Timeout for one `tools/call` (default 60 s). The server is sent a
    /// cancellation when it expires.
    pub call_timeout: Duration,
    /// Timeout for `initialize`, listings, `resources/read` and
    /// `prompts/get` (default 30 s).
    pub request_timeout: Duration,
    /// Most tools, resources or prompts accepted from one listing
    /// (default 256). Beyond it the listing is cut (or fails, when strict).
    pub max_list_items: usize,
    /// Longest tool, resource or prompt description kept, in bytes
    /// (default 1 KiB); longer ones are cut.
    pub max_description_bytes: usize,
    /// Largest input or output schema accepted, in bytes of JSON (default
    /// 64 KiB); a tool with a larger one is rejected.
    pub max_schema_bytes: usize,
    /// Most bytes of a tool result kept (default 128 KiB; see
    /// [`ToolOutput::capped`]). Resource contents and prompts above it fail
    /// with [`Error::TooLarge`].
    pub max_result_bytes: usize,
    /// Wrap remote results handed to a `rune-chain` agent in an
    /// `<mcp_result>` fence (default on); see
    /// [`fence`](crate::sanitize::fence).
    pub fence_results: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            trust: ServerTrust::default(),
            policy: Arc::new(AllowAll),
            strict: false,
            namespace: None,
            allowed_tools: None,
            call_timeout: DEFAULT_CALL_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_list_items: DEFAULT_MAX_LIST_ITEMS,
            max_description_bytes: DEFAULT_MAX_DESCRIPTION_BYTES,
            max_schema_bytes: DEFAULT_MAX_SCHEMA_BYTES,
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
            fence_results: true,
        }
    }
}

impl fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientOptions")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("trust", &self.trust)
            .field("strict", &self.strict)
            .field("namespace", &self.namespace)
            .field("allowed_tools", &self.allowed_tools)
            .field("call_timeout", &self.call_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_list_items", &self.max_list_items)
            .field("max_description_bytes", &self.max_description_bytes)
            .field("max_schema_bytes", &self.max_schema_bytes)
            .field("max_result_bytes", &self.max_result_bytes)
            .field("fence_results", &self.fence_results)
            .finish_non_exhaustive()
    }
}

impl ClientOptions {
    /// Client name and version sent in `initialize`.
    #[must_use]
    pub fn with_client_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.name = name.into();
        self.version = version.into();
        self
    }

    /// Set how far the server's tool metadata is believed.
    #[must_use]
    pub const fn with_trust(mut self, trust: ServerTrust) -> Self {
        self.trust = trust;
        self
    }

    /// Set the policy consulted before every call and for listing.
    #[must_use]
    pub fn with_policy(mut self, policy: impl ToolPolicy + 'static) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    /// Fail on rejected definitions instead of skipping them.
    #[must_use]
    pub const fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Expose tools as `<namespace>__<tool>`; checked on connect.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Allow only these remote tools.
    #[must_use]
    pub fn with_allowed_tools<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_tools = Some(names.into_iter().map(Into::into).collect());
        self
    }

    /// Set the `tools/call` timeout.
    #[must_use]
    pub const fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// Set the timeout of every other request.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set the most items accepted from one listing.
    #[must_use]
    pub const fn with_max_list_items(mut self, max: usize) -> Self {
        self.max_list_items = max;
        self
    }

    /// Set the longest description kept.
    #[must_use]
    pub const fn with_max_description_bytes(mut self, max: usize) -> Self {
        self.max_description_bytes = max;
        self
    }

    /// Set the largest schema accepted.
    #[must_use]
    pub const fn with_max_schema_bytes(mut self, max: usize) -> Self {
        self.max_schema_bytes = max;
        self
    }

    /// Set the most result bytes kept.
    #[must_use]
    pub const fn with_max_result_bytes(mut self, max: usize) -> Self {
        self.max_result_bytes = max;
        self
    }

    /// Turn the `<mcp_result>` fence around chain-tool results on or off.
    #[must_use]
    pub const fn with_fence_results(mut self, on: bool) -> Self {
        self.fence_results = on;
        self
    }

    const fn import_limits(&self) -> ImportLimits {
        ImportLimits {
            trust: self.trust,
            max_description_bytes: self.max_description_bytes,
            max_schema_bytes: self.max_schema_bytes,
        }
    }
}

/// What the server reported about itself in `initialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerInfo {
    /// Server name, if the server sent one.
    pub name: Option<String>,
    /// Server version, if the server sent one.
    pub version: Option<String>,
    /// Usage instructions, if any (cleaned and capped like descriptions).
    /// These are the server's words: do not paste them into a system
    /// prompt unless you trust the server.
    pub instructions: Option<String>,
    /// Negotiated protocol version.
    pub protocol_version: String,
}

/// A server definition that a listing skipped, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rejection {
    /// The definition's name (cleaned and capped).
    pub name: String,
    /// The rule it broke.
    pub reason: String,
}

/// How many list-changed notifications the server has sent, per kind.
/// Watch it with [`McpClient::subscribe`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ListChanges {
    /// `notifications/tools/list_changed` count.
    pub tools: u64,
    /// `notifications/resources/list_changed` count.
    pub resources: u64,
    /// `notifications/prompts/list_changed` count.
    pub prompts: u64,
}

/// State shared between the client and its notification handler.
struct Shared {
    tools: Mutex<Option<BTreeMap<String, ToolDescriptor>>>,
    rejected: Mutex<Vec<Rejection>>,
    changes: watch::Sender<ListChanges>,
}

impl Shared {
    fn bump(&self, f: impl FnOnce(&mut ListChanges)) {
        self.changes.send_modify(f);
    }
}

/// The rmcp client handler: identifies the client and reacts to
/// list-changed notifications.
struct Handler {
    config: ClientConfig,
    shared: Arc<Shared>,
}

impl ClientHandler for Handler {
    fn get_info(&self) -> ClientConfig {
        self.config.clone()
    }

    fn on_tool_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        *self
            .shared
            .tools
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        self.shared.bump(|c| c.tools += 1);
        std::future::ready(())
    }

    fn on_resource_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.shared.bump(|c| c.resources += 1);
        std::future::ready(())
    }

    fn on_prompt_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl Future<Output = ()> + Send + '_ {
        self.shared.bump(|c| c.prompts += 1);
        std::future::ready(())
    }
}

async fn with_timeout<T, F>(operation: &'static str, after: Duration, future: F) -> Result<T, Error>
where
    F: Future<Output = Result<T, rmcp::ServiceError>>,
{
    tokio::time::timeout(after, future).await.map_or_else(
        |_| Err(Error::Timeout { operation, after }),
        |result| result.map_err(Error::from),
    )
}

/// A connected MCP client session.
///
/// [`connect`](McpClient::connect) on any rmcp transport (an in-process
/// stream, a child process with [`spawn`](McpClient::spawn), or Streamable
/// HTTP with `connect_http`), then list and call tools, read resources and
/// get prompts.
///
/// Everything the server sends is treated as untrusted:
///
/// - Tool definitions are validated (MCP name rules, object schemas within
///   [`max_schema_bytes`](ClientOptions::max_schema_bytes) and 32 levels),
///   descriptions are stripped of invisible characters and capped, and a
///   name listed twice is dropped entirely, so neither copy can shadow the
///   other. Rejected definitions are skipped and reported by
///   [`rejected`](Self::rejected), or fail the listing when
///   [`strict`](ClientOptions::strict).
/// - Safety claims are ignored unless the server is
///   [`Trusted`](ServerTrust::Trusted); every call passes the
///   [`ToolPolicy`] and the [allowlist](ClientOptions::allowed_tools).
/// - Every request has a timeout, and results are capped.
///
/// A `notifications/tools/list_changed` from the server drops the cached
/// tool list and bumps [`subscribe`](Self::subscribe)'s counter; a
/// [`RemoteTool`] created before then refuses to call a tool whose
/// definition has changed ([`Error::DefinitionChanged`]).
///
/// Dropping the client closes the session (and, for [`spawn`](Self::spawn),
/// kills the server process).
pub struct McpClient {
    service: RunningService<RoleClient, Handler>,
    options: ClientOptions,
    shared: Arc<Shared>,
}

impl fmt::Debug for McpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpClient")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl McpClient {
    /// Connect over an rmcp transport and run the `initialize` handshake.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidNamespace`] for a bad
    /// [`namespace`](ClientOptions::namespace); [`Error::Initialize`] if
    /// the transport fails or the handshake is rejected;
    /// [`Error::Timeout`] if it takes longer than
    /// [`request_timeout`](ClientOptions::request_timeout).
    pub async fn connect<T, E, A>(transport: T, options: ClientOptions) -> Result<Self, Error>
    where
        T: IntoTransport<RoleClient, E, A>,
        E: std::error::Error + Send + Sync + 'static,
    {
        if let Some(namespace) = &options.namespace {
            validate_namespace(namespace).map_err(|reason| Error::InvalidNamespace {
                namespace: namespace.clone(),
                reason,
            })?;
        }
        let (changes, _) = watch::channel(ListChanges::default());
        let shared = Arc::new(Shared {
            tools: Mutex::new(None),
            rejected: Mutex::new(Vec::new()),
            changes,
        });
        let handler = Handler {
            config: ClientConfig::new(
                ClientCapabilities::default(),
                Implementation::new(options.name.clone(), options.version.clone()),
            ),
            shared: Arc::clone(&shared),
        };
        let service =
            match tokio::time::timeout(options.request_timeout, handler.serve(transport)).await {
                Ok(Ok(service)) => service,
                Ok(Err(err)) => return Err(Error::Initialize(Box::new(err))),
                Err(_) => {
                    return Err(Error::Timeout {
                        operation: "initialize",
                        after: options.request_timeout,
                    });
                }
            };
        Ok(Self {
            service,
            options,
            shared,
        })
    }

    /// Spawn a local MCP server and talk to it over its stdin and stdout.
    ///
    /// The process gets only the environment the [`StdioServer`] lists, no
    /// shell is involved, and it is killed when the client is dropped or
    /// closed.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for an empty program, [`Error::Initialize`]
    /// if it cannot be spawned, otherwise as [`Self::connect`].
    ///
    /// [`StdioServer`]: crate::StdioServer
    #[cfg(feature = "stdio")]
    pub async fn spawn(server: &crate::StdioServer, options: ClientOptions) -> Result<Self, Error> {
        let (transport, _stderr) = rmcp::transport::TokioChildProcess::builder(server.command()?)
            .stderr(server.stderr_mode())
            .spawn()
            .map_err(|err| Error::Initialize(Box::new(err)))?;
        Self::connect(transport, options).await
    }

    /// Connect to a Streamable HTTP endpoint with `client`, any rmcp
    /// [`StreamableHttpClient`](rmcp::transport::streamable_http_client::StreamableHttpClient)
    /// (for example `reqwest::Client` with rmcp's
    /// `transport-streamable-http-client-reqwest` feature).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] if `config` is refused (plain HTTP to a
    /// remote host), otherwise as [`Self::connect`].
    #[cfg(feature = "http-client")]
    pub async fn connect_http<C>(
        client: C,
        config: &crate::HttpClientConfig,
        options: ClientOptions,
    ) -> Result<Self, Error>
    where
        C: rmcp::transport::streamable_http_client::StreamableHttpClient + 'static,
    {
        let transport = rmcp::transport::StreamableHttpClientTransport::with_client(
            client,
            config.to_transport_config()?,
        );
        Self::connect(transport, options).await
    }

    /// The options this client was connected with.
    #[must_use]
    pub const fn options(&self) -> &ClientOptions {
        &self.options
    }

    /// What the server reported in `initialize`.
    #[must_use]
    pub fn server_info(&self) -> Option<ServerInfo> {
        self.service.peer_info().map(|info| ServerInfo {
            name: info.server_info.as_ref().map(|i| clean_text(&i.name, 256)),
            version: info
                .server_info
                .as_ref()
                .map(|i| clean_text(&i.version, 256)),
            instructions: info
                .instructions
                .as_deref()
                .map(|s| clean_text(s, self.options.max_description_bytes)),
            protocol_version: info.protocol_version.to_string(),
        })
    }

    /// A receiver that sees [`ListChanges`] each time the server sends a
    /// list-changed notification. List again when it changes.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ListChanges> {
        self.shared.changes.subscribe()
    }

    /// The definitions the last listing skipped, and why.
    #[must_use]
    pub fn rejected(&self) -> Vec<Rejection> {
        self.shared
            .rejected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn record(&self, rejected: Vec<Rejection>) {
        *self
            .shared
            .rejected
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = rejected;
    }

    /// Apply the list-size limit: cut the list, or fail when strict.
    fn cap_list<T>(
        &self,
        mut items: Vec<T>,
        rejected: &mut Vec<Rejection>,
    ) -> Result<Vec<T>, Error> {
        let max = self.options.max_list_items;
        if items.len() > max {
            let reason = format!(
                "the server listed {} items, over the limit of {max}",
                items.len()
            );
            if self.options.strict {
                return Err(Error::Rejected {
                    name: "(listing)".to_owned(),
                    reason,
                });
            }
            items.truncate(max);
            rejected.push(Rejection {
                name: "(listing)".to_owned(),
                reason,
            });
        }
        Ok(items)
    }

    /// List the server's tools (following pagination), as descriptors with
    /// their remote names.
    ///
    /// Tools the policy hides or the allowlist leaves out are not
    /// returned. The result is cached for [`Self::call_tool`] until the
    /// server announces a change.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`], [`Error::Transport`] or [`Error::Timeout`] if
    /// the request fails; [`Error::Rejected`] for a bad definition in
    /// strict mode.
    pub async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, Error> {
        let listed = with_timeout(
            "tools/list",
            self.options.request_timeout,
            self.service.list_all_tools(),
        )
        .await?;
        let mut rejected = Vec::new();
        let listed = self.cap_list(listed, &mut rejected)?;

        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for tool in &listed {
            *counts.entry(tool.name.as_ref()).or_default() += 1;
        }
        let mut tools = BTreeMap::new();
        for tool in &listed {
            if counts.get(tool.name.as_ref()).copied().unwrap_or(0) > 1 {
                let err = Error::Rejected {
                    name: clean_text(&tool.name, 128),
                    reason: "listed more than once".to_owned(),
                };
                if self.options.strict {
                    return Err(err);
                }
                push_rejection(&mut rejected, err);
                continue;
            }
            let descriptor = match import_tool(tool, self.options.import_limits()) {
                Ok(descriptor) => descriptor,
                Err(err) if self.options.strict => return Err(err),
                Err(err) => {
                    push_rejection(&mut rejected, err);
                    continue;
                }
            };
            if self
                .options
                .allowed_tools
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&descriptor.name))
                || !self.options.policy.visible(&descriptor)
            {
                continue;
            }
            tools.insert(descriptor.name.clone(), descriptor);
        }
        let out = tools.values().cloned().collect();
        *self
            .shared
            .tools
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(tools);
        self.record(rejected);
        Ok(out)
    }

    /// The descriptor of a listed tool, listing the server's tools first if
    /// that has not happened yet (or the list changed since).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownTool`] if the server does not list it, or the policy
    /// or allowlist hides it; otherwise as [`Self::list_tools`].
    pub async fn tool(&self, name: &str) -> Result<ToolDescriptor, Error> {
        if let Some(found) = self.cached(name) {
            return found;
        }
        self.list_tools().await?;
        self.cached(name)
            .unwrap_or_else(|| Err(Error::UnknownTool(clean_text(name, 128))))
    }

    /// `Some` once tools have been listed: the descriptor, or `UnknownTool`.
    fn cached(&self, name: &str) -> Option<Result<ToolDescriptor, Error>> {
        let guard = self
            .shared
            .tools
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        guard.as_ref().map(|tools| {
            tools
                .get(name)
                .cloned()
                .ok_or_else(|| Error::UnknownTool(clean_text(name, 128)))
        })
    }

    /// Call a tool by its remote name, after checking it against the
    /// policy. The result is capped to
    /// [`max_result_bytes`](ClientOptions::max_result_bytes).
    ///
    /// A tool that runs and fails is `Ok` with
    /// [`is_error`](ToolOutput::is_error) set.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownTool`], [`Error::Denied`] (nothing is sent),
    /// [`Error::Timeout`], or [`Error::Protocol`] / [`Error::Transport`] if
    /// the request fails.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> Result<ToolOutput, Error> {
        let descriptor = self.tool(name).await?;
        self.call_listed(descriptor, arguments).await
    }

    async fn call_listed(
        &self,
        descriptor: ToolDescriptor,
        arguments: Map<String, Value>,
    ) -> Result<ToolOutput, Error> {
        let call = ToolCall::new(&descriptor, &arguments, Side::Client);
        if let Decision::Deny(reason) = gate(self.options.policy.as_ref(), &call) {
            return Err(Error::Denied {
                tool: descriptor.name,
                reason,
            });
        }
        let params = CallToolRequestParams::new(descriptor.name).with_arguments(arguments);
        let result = with_timeout(
            "tools/call",
            self.options.call_timeout,
            self.service.call_tool(params),
        )
        .await?;
        Ok(from_call_tool_result(&result)?.capped(self.options.max_result_bytes))
    }

    /// Every listed tool as a [`RemoteTool`], named
    /// `<namespace>__<tool>` when the client has a
    /// [`namespace`](ClientOptions::namespace). Ready to re-serve on an
    /// [`McpServer`](crate::McpServer) (a proxy or aggregator) or, with the
    /// `chain` feature, to hand to a `rune-chain` agent.
    ///
    /// MCP makes descriptions optional but a served [`ToolDescriptor`]
    /// needs one, so a tool listed without a description gets its title, or
    /// a generic sentence naming it.
    ///
    /// # Errors
    ///
    /// As [`Self::list_tools`].
    pub async fn remote_tools(self: &Arc<Self>) -> Result<Vec<RemoteTool>, Error> {
        let namespace = self.options.namespace.clone();
        self.remote_tools_in(namespace.as_deref()).await
    }

    pub(crate) async fn remote_tools_in(
        self: &Arc<Self>,
        namespace: Option<&str>,
    ) -> Result<Vec<RemoteTool>, Error> {
        let mut out = Vec::new();
        for remote in self.list_tools().await? {
            let mut exposed = remote.clone();
            exposed.name = qualified_name(namespace, &remote.name);
            if let Err(err) = rune_tool_schema::validate_name(&exposed.name) {
                if self.options.strict {
                    return Err(err.into());
                }
                continue;
            }
            if exposed.description.trim().is_empty() {
                exposed.description = exposed
                    .title
                    .clone()
                    .filter(|title| !title.trim().is_empty())
                    .unwrap_or_else(|| format!("Remote MCP tool {:?}.", remote.name));
            }
            out.push(RemoteTool {
                client: Arc::clone(self),
                namespace: namespace.map(str::to_owned),
                remote,
                descriptor: exposed,
            });
        }
        Ok(out)
    }

    /// List the server's resources (following pagination). Names and
    /// descriptions are cleaned and capped.
    ///
    /// # Errors
    ///
    /// As [`Self::list_tools`].
    pub async fn list_resources(&self) -> Result<Vec<ResourceInfo>, Error> {
        let listed = with_timeout(
            "resources/list",
            self.options.request_timeout,
            self.service.list_all_resources(),
        )
        .await?;
        let listed = self.cap_list(listed, &mut Vec::new())?;
        Ok(listed
            .iter()
            .map(|r| ResourceInfo::from_rmcp(r, self.options.max_description_bytes))
            .collect())
    }

    /// Read a resource.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] if its contents exceed
    /// [`max_result_bytes`](ClientOptions::max_result_bytes); otherwise as
    /// [`Self::list_tools`].
    pub async fn read_resource(&self, uri: &str) -> Result<Vec<ResourceContent>, Error> {
        let result = with_timeout(
            "resources/read",
            self.options.request_timeout,
            self.service
                .read_resource(ReadResourceRequestParams::new(uri)),
        )
        .await?;
        let contents: Vec<ResourceContent> = result
            .contents
            .into_iter()
            .filter_map(ResourceContent::from_rmcp)
            .collect();
        let total: usize = contents.iter().map(ResourceContent::len).sum();
        if total > self.options.max_result_bytes {
            return Err(Error::TooLarge {
                what: "resource contents",
                limit: self.options.max_result_bytes,
            });
        }
        Ok(contents)
    }

    /// List the server's prompts (following pagination). Descriptions are
    /// cleaned and capped.
    ///
    /// # Errors
    ///
    /// As [`Self::list_tools`].
    pub async fn list_prompts(&self) -> Result<Vec<PromptInfo>, Error> {
        let listed = with_timeout(
            "prompts/list",
            self.options.request_timeout,
            self.service.list_all_prompts(),
        )
        .await?;
        let listed = self.cap_list(listed, &mut Vec::new())?;
        Ok(listed
            .iter()
            .map(|p| PromptInfo::from_rmcp(p, self.options.max_description_bytes))
            .collect())
    }

    /// Render a prompt with string arguments.
    ///
    /// The messages are the server's text: treat them as untrusted input,
    /// not as instructions from you.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] if the messages exceed
    /// [`max_result_bytes`](ClientOptions::max_result_bytes); otherwise as
    /// [`Self::list_tools`].
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: BTreeMap<String, String>,
    ) -> Result<PromptResult, Error> {
        let mut params = GetPromptRequestParams::new(name);
        if !arguments.is_empty() {
            params = params.with_arguments(
                arguments
                    .into_iter()
                    .map(|(k, v)| (k, Value::String(v)))
                    .collect(),
            );
        }
        let result = with_timeout(
            "prompts/get",
            self.options.request_timeout,
            self.service.get_prompt(params),
        )
        .await?;
        let messages = result
            .messages
            .iter()
            .map(PromptMessage::from_rmcp)
            .collect::<Result<Vec<_>, _>>()?;
        let total: usize = messages
            .iter()
            .map(|m| match &m.content {
                crate::Content::Text(t) => t.len(),
                crate::Content::Other(v) => v.to_string().len(),
            })
            .sum();
        if total > self.options.max_result_bytes {
            return Err(Error::TooLarge {
                what: "prompt messages",
                limit: self.options.max_result_bytes,
            });
        }
        Ok(PromptResult {
            description: result
                .description
                .as_deref()
                .map(|d| clean_text(d, self.options.max_description_bytes)),
            messages,
        })
    }

    /// Close the session and wait for it to finish.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if the session task panicked or was aborted.
    pub async fn close(self) -> Result<(), Error> {
        self.service
            .cancel()
            .await
            .map(drop)
            .map_err(|err| Error::Transport(Box::new(err)))
    }
}

fn push_rejection(rejected: &mut Vec<Rejection>, err: Error) {
    let (name, reason) = match err {
        Error::Rejected { name, reason } => (name, reason),
        other => (String::new(), other.to_string()),
    };
    rejected.push(Rejection { name, reason });
}

/// One tool of a remote MCP server, callable through its [`McpClient`].
///
/// Its [`descriptor`](Self::descriptor) carries the exposed name
/// (`<namespace>__<tool>` when namespaced); [`remote_name`](Self::remote_name)
/// is the server's. It is bound to the definition it was created from: if
/// the server later changes that tool, calls fail with
/// [`Error::DefinitionChanged`] until the tools are listed and reviewed
/// again.
///
/// It is a [`ToolHandler`], so it can be registered on an
/// [`McpServer`](crate::McpServer) under its own descriptor. The client's
/// policy still applies to every call.
#[derive(Clone)]
pub struct RemoteTool {
    client: Arc<McpClient>,
    namespace: Option<String>,
    remote: ToolDescriptor,
    descriptor: ToolDescriptor,
}

impl fmt::Debug for RemoteTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTool")
            .field("name", &self.descriptor.name)
            .finish_non_exhaustive()
    }
}

impl RemoteTool {
    /// The tool's descriptor as exposed: imported from the server, renamed
    /// into the namespace.
    #[must_use]
    pub const fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    /// The tool's name on the server.
    #[must_use]
    pub fn remote_name(&self) -> &str {
        &self.remote.name
    }

    /// The namespace of the server it belongs to, if any.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The client it calls through.
    #[must_use]
    pub const fn client(&self) -> &Arc<McpClient> {
        &self.client
    }

    /// Call the tool; see [`McpClient::call_tool`].
    ///
    /// # Errors
    ///
    /// [`Error::DefinitionChanged`] if the server changed the tool since
    /// this handle was made; otherwise as [`McpClient::call_tool`].
    pub async fn call(&self, arguments: Map<String, Value>) -> Result<ToolOutput, Error> {
        let current = self.client.tool(&self.remote.name).await?;
        if current != self.remote {
            return Err(Error::DefinitionChanged(self.descriptor.name.clone()));
        }
        self.client.call_listed(current, arguments).await
    }
}

#[async_trait]
impl ToolHandler for RemoteTool {
    async fn call(&self, arguments: Map<String, Value>) -> Result<ToolOutput, ToolError> {
        Self::call(self, arguments)
            .await
            .map_err(|err| ToolError::new(err.to_string()))
    }
}
