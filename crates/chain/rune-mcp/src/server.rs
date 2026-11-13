//! [`McpServer`]: serve rune tools, resources and prompts over MCP.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, GetPromptRequestParams, GetPromptResponse,
    GetPromptResult, Implementation, ListPromptsResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, PromptsCapability, ReadResourceRequestParams, ReadResourceResponse,
    ReadResourceResult, ResourcesCapability, ServerCapabilities, ServerConfig, Tool,
    ToolsCapability,
};
use rmcp::service::{MaybeSendFuture, RequestContext, RunningService};
use rmcp::transport::IntoTransport;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use rune_tool_schema::{ToolDescriptor, Validator, validate_name};
use serde_json::{Map, Value};

use crate::convert::descriptor_to_tool;
use crate::output::to_call_tool_result;
use crate::policy::{AllowAll, Decision, Side, ToolCall, ToolPolicy, gate};
use crate::resource::{PromptHandler, PromptInfo, ResourceHandler, ResourceInfo};
use crate::sanitize::clean_text;
use crate::schema;
use crate::{Error, ToolHandler, ToolOutput};

/// The message a caller sees when a handler panics or is aborted.
const INTERNAL_FAILURE: &str = "the tool failed with an internal error";

struct Entry {
    descriptor: ToolDescriptor,
    tool: Tool,
    validator: Validator,
    handler: Arc<dyn ToolHandler>,
}

struct ResourceEntry {
    info: ResourceInfo,
    handler: Arc<dyn ResourceHandler>,
}

struct PromptEntry {
    info: PromptInfo,
    handler: Arc<dyn PromptHandler>,
}

#[derive(Clone)]
struct Inner {
    name: String,
    version: String,
    instructions: Option<String>,
    tools: BTreeMap<String, Arc<Entry>>,
    resources: BTreeMap<String, Arc<ResourceEntry>>,
    prompts: BTreeMap<String, Arc<PromptEntry>>,
    policy: Arc<dyn ToolPolicy>,
    call_timeout: Option<Duration>,
}

/// An MCP server that exposes registered tools, resources and prompts.
///
/// Build it with [`McpServer::new`], [`tool`](McpServer::tool),
/// [`resource`](McpServer::resource), [`prompt`](McpServer::prompt) and
/// [`with_policy`](McpServer::with_policy), then
/// [`serve`](McpServer::serve) it on any rmcp transport: an in-process
/// stream (`tokio::io::duplex`), stdio
/// ([`serve_stdio`](McpServer::serve_stdio), `stdio` feature), or Streamable
/// HTTP ([`into_http_service`](McpServer::into_http_service), `http-server`
/// feature).
///
/// `tools/list` returns every tool the policy lists, sorted by name.
/// `tools/call` then:
///
/// 1. answers an unknown or hidden tool with a protocol error
///    (`invalid params`);
/// 2. runs the policy gate;
/// 3. checks the arguments against the tool's input schema with a
///    [`Validator`] compiled at registration (limits from
///    [`schema_limits`](crate::schema_limits)), so the handler only ever
///    sees arguments that fit it;
/// 4. runs the handler in its own task, with the optional
///    [`call timeout`](McpServer::with_call_timeout).
///
/// A denied call, invalid arguments, a handler error and a
/// [`ToolOutput::error`] are tool results with `isError: true`, so the
/// model sees why. A handler that panics or times out gets a fixed message
/// with no internals.
///
/// Cloning is cheap; clones share the registrations and the policy.
#[derive(Clone)]
pub struct McpServer {
    inner: Arc<Inner>,
}

impl fmt::Debug for McpServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpServer")
            .field("name", &self.inner.name)
            .field("version", &self.inner.version)
            .field("tools", &self.inner.tools.keys().collect::<Vec<_>>())
            .field(
                "resources",
                &self.inner.resources.keys().collect::<Vec<_>>(),
            )
            .field("prompts", &self.inner.prompts.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl McpServer {
    /// An empty server that reports `name` and `version` in `initialize`,
    /// with the [`AllowAll`] policy and no call timeout.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Inner {
                name: name.into(),
                version: version.into(),
                instructions: None,
                tools: BTreeMap::new(),
                resources: BTreeMap::new(),
                prompts: BTreeMap::new(),
                policy: Arc::new(AllowAll),
                call_timeout: None,
            }),
        }
    }

    fn inner_mut(&mut self) -> &mut Inner {
        // Builder methods normally run before the server is shared; if it
        // already is, this copies the registry (the entries themselves are
        // shared) so other clones are unaffected.
        Arc::make_mut(&mut self.inner)
    }

    /// Instructions sent to the client in `initialize`.
    #[must_use]
    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.inner_mut().instructions = Some(instructions.into());
        self
    }

    /// Replace the policy consulted before every call (and for listing).
    #[must_use]
    pub fn with_policy(mut self, policy: impl ToolPolicy + 'static) -> Self {
        self.inner_mut().policy = Arc::new(policy);
        self
    }

    /// Stop a tool handler that runs longer than `timeout`; the caller gets
    /// an `isError` result. Off by default.
    #[must_use]
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.inner_mut().call_timeout = Some(timeout);
        self
    }

    /// Register a tool.
    ///
    /// # Errors
    ///
    /// [`Error::Descriptor`] if the descriptor breaks the MCP rules or its
    /// input schema cannot be compiled for argument checking
    /// ([`rune_tool_schema::Error::InvalidSchema`]: a `$ref` outside the
    /// document, an unusable `pattern`, a keyword with a value of the wrong
    /// type), or [`Error::Duplicate`] if the name is taken.
    pub fn tool(
        mut self,
        descriptor: ToolDescriptor,
        handler: impl ToolHandler + 'static,
    ) -> Result<Self, Error> {
        self.add_tool(descriptor, handler)?;
        Ok(self)
    }

    /// Register a tool in place; see [`Self::tool`].
    ///
    /// # Errors
    ///
    /// As [`Self::tool`].
    pub fn add_tool(
        &mut self,
        descriptor: ToolDescriptor,
        handler: impl ToolHandler + 'static,
    ) -> Result<(), Error> {
        let tool = descriptor_to_tool(&descriptor)?;
        let validator = schema::compile(&descriptor.input_schema)?;
        let tools = &mut self.inner_mut().tools;
        if tools.contains_key(&descriptor.name) {
            return Err(Error::Duplicate {
                kind: "tool",
                name: descriptor.name,
            });
        }
        tools.insert(
            descriptor.name.clone(),
            Arc::new(Entry {
                descriptor,
                tool,
                validator,
                handler: Arc::new(handler),
            }),
        );
        Ok(())
    }

    /// Register a resource, read by `handler`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for an empty URI or name;
    /// [`Error::Duplicate`] if the URI is taken.
    pub fn resource(
        mut self,
        info: ResourceInfo,
        handler: impl ResourceHandler + 'static,
    ) -> Result<Self, Error> {
        if info.uri.trim().is_empty() || info.name.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "a resource needs a URI and a name".to_owned(),
            ));
        }
        let resources = &mut self.inner_mut().resources;
        if resources.contains_key(&info.uri) {
            return Err(Error::Duplicate {
                kind: "resource",
                name: info.uri,
            });
        }
        resources.insert(
            info.uri.clone(),
            Arc::new(ResourceEntry {
                info,
                handler: Arc::new(handler),
            }),
        );
        Ok(self)
    }

    /// Register a prompt, rendered by `handler`.
    ///
    /// # Errors
    ///
    /// [`Error::Descriptor`] if the name breaks the MCP name rules;
    /// [`Error::Duplicate`] if it is taken.
    pub fn prompt(
        mut self,
        info: PromptInfo,
        handler: impl PromptHandler + 'static,
    ) -> Result<Self, Error> {
        validate_name(&info.name)?;
        let prompts = &mut self.inner_mut().prompts;
        if prompts.contains_key(&info.name) {
            return Err(Error::Duplicate {
                kind: "prompt",
                name: info.name,
            });
        }
        prompts.insert(
            info.name.clone(),
            Arc::new(PromptEntry {
                info,
                handler: Arc::new(handler),
            }),
        );
        Ok(self)
    }

    /// The descriptors of every registered tool, sorted by name, whether or
    /// not the policy lists them.
    pub fn descriptors(&self) -> impl Iterator<Item = &ToolDescriptor> {
        self.inner.tools.values().map(|entry| &entry.descriptor)
    }

    /// Run a registered tool directly, through the same policy gate,
    /// argument check and isolation as an MCP `tools/call`, without any
    /// transport.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownTool`] for a tool that is not registered or is hidden
    /// by the policy. A denied call or invalid arguments are an `Ok` result
    /// with [`is_error`](ToolOutput::is_error) set, exactly as a client
    /// would see it.
    ///
    /// Dropping the returned future aborts the handler's task.
    pub async fn call(
        &self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> Result<ToolOutput, Error> {
        let entry = self
            .visible_entry(name)
            .ok_or_else(|| Error::UnknownTool(clean_text(name, 128)))?;
        Ok(self.run(entry, arguments, std::future::pending()).await)
    }

    fn visible_entry(&self, name: &str) -> Option<Arc<Entry>> {
        self.inner
            .tools
            .get(name)
            .filter(|entry| self.inner.policy.visible(&entry.descriptor))
            .cloned()
    }

    /// Run the tool's handler in its own task. The task is aborted when
    /// `cancelled` completes (the client cancelled the request or the
    /// session ended), on timeout, or when this future is dropped.
    async fn run(
        &self,
        entry: Arc<Entry>,
        arguments: Map<String, Value>,
        cancelled: impl Future<Output = ()>,
    ) -> ToolOutput {
        let name = &entry.descriptor.name;
        let call = ToolCall::new(&entry.descriptor, &arguments, Side::Server);
        if let Decision::Deny(reason) = gate(self.inner.policy.as_ref(), &call) {
            return ToolOutput::error(format!("tool {name:?} denied by policy: {reason}"));
        }
        if let Err(reason) = schema::check(&entry.validator, &arguments) {
            return ToolOutput::error(format!("invalid arguments for tool {name:?}: {reason}"));
        }
        let handler = Arc::clone(&entry.handler);
        let task = AbortOnDrop(tokio::spawn(async move { handler.call(arguments).await }));
        let finished = async {
            match self.inner.call_timeout {
                Some(after) => tokio::time::timeout(after, task).await.map_err(|_| after),
                None => Ok(task.await),
            }
        };
        let joined = match until_cancelled(finished, cancelled).await {
            Some(Ok(joined)) => joined,
            Some(Err(after)) => {
                return ToolOutput::error(format!("tool {name:?} timed out after {after:?}"));
            }
            None => return ToolOutput::error(format!("tool {name:?} cancelled")),
        };
        match joined {
            Ok(Ok(output)) => output,
            Ok(Err(err)) => ToolOutput::error(err.0),
            Err(_) => ToolOutput::error(INTERNAL_FAILURE),
        }
    }

    fn server_config(&self) -> ServerConfig {
        let mut capabilities = ServerCapabilities::default();
        let mut tools = ToolsCapability::default();
        tools.list_changed = Some(true);
        capabilities.tools = Some(tools);
        if !self.inner.resources.is_empty() {
            capabilities.resources = Some(ResourcesCapability::default());
        }
        if !self.inner.prompts.is_empty() {
            capabilities.prompts = Some(PromptsCapability::default());
        }
        let config = ServerConfig::new(capabilities).with_server_info(Implementation::new(
            self.inner.name.clone(),
            self.inner.version.clone(),
        ));
        match &self.inner.instructions {
            Some(instructions) => config.with_instructions(instructions.clone()),
            None => config,
        }
    }

    /// Serve on an rmcp transport, such as one end of `tokio::io::duplex`,
    /// a `(reader, writer)` pair, or any `rmcp::transport::Transport`.
    ///
    /// Returns once the client has completed `initialize`; the session then
    /// runs in a background task until [`RunningServer::waiting`] sees it
    /// end or [`RunningServer::cancel`] stops it.
    ///
    /// # Errors
    ///
    /// [`Error::Initialize`] if the handshake fails.
    pub async fn serve<T, E, A>(self, transport: T) -> Result<RunningServer, Error>
    where
        T: IntoTransport<RoleServer, E, A>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let service = ServiceExt::serve(self, transport)
            .await
            .map_err(|err| Error::Initialize(Box::new(err)))?;
        Ok(RunningServer { service })
    }

    /// Serve on the process's stdin and stdout (the MCP stdio transport).
    ///
    /// # Errors
    ///
    /// As [`Self::serve`].
    #[cfg(feature = "stdio")]
    pub async fn serve_stdio(self) -> Result<RunningServer, Error> {
        self.serve(rmcp::transport::stdio()).await
    }

    /// A Streamable HTTP endpoint for this server: a `tower` service on
    /// `http::Request`, to mount in axum (`Router::nest_service("/mcp", …)`)
    /// or hyper. Each session gets a clone of this server.
    ///
    /// `config` controls sessions, allowed `Host`/`Origin` values (loopback
    /// only by default) and body limits; see rmcp's
    /// [`StreamableHttpServerConfig`](rmcp::transport::streamable_http_server::StreamableHttpServerConfig).
    /// Authentication is the job of the router in front of it.
    #[cfg(feature = "http-server")]
    #[must_use]
    pub fn into_http_service(
        self,
        config: rmcp::transport::streamable_http_server::StreamableHttpServerConfig,
    ) -> rmcp::transport::streamable_http_server::StreamableHttpService<
        Self,
        rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
    > {
        rmcp::transport::streamable_http_server::StreamableHttpService::new(
            move || Ok(self.clone()),
            Arc::default(),
            config,
        )
    }
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        self.server_config()
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + MaybeSendFuture + '_ {
        let tools = self
            .inner
            .tools
            .values()
            .filter(|entry| self.inner.policy.visible(&entry.descriptor))
            .map(|entry| entry.tool.clone())
            .collect();
        std::future::ready(Ok(ListToolsResult::with_all_items(tools)))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.visible_entry(name).map(|entry| entry.tool.clone())
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let Some(entry) = self.visible_entry(&request.name) else {
            return Err(ErrorData::invalid_params(
                format!("unknown tool {:?}", clean_text(&request.name, 128)),
                None,
            ));
        };
        let output = self
            .run(
                entry,
                request.arguments.unwrap_or_default(),
                context.ct.cancelled(),
            )
            .await;
        Ok(to_call_tool_result(output).into())
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, ErrorData>> + MaybeSendFuture + '_ {
        let resources = self
            .inner
            .resources
            .values()
            .map(|entry| entry.info.to_rmcp())
            .collect();
        std::future::ready(Ok(ListResourcesResult::with_all_items(resources)))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let Some(entry) = self.inner.resources.get(&request.uri).cloned() else {
            return Err(ErrorData::resource_not_found(
                format!("unknown resource {:?}", clean_text(&request.uri, 256)),
                None,
            ));
        };
        let uri = request.uri;
        let handler = Arc::clone(&entry.handler);
        let task = AbortOnDrop(tokio::spawn(async move { handler.read(&uri).await }));
        let Some(joined) = until_cancelled(task, context.ct.cancelled()).await else {
            return Err(ErrorData::internal_error("request cancelled", None));
        };
        match joined {
            Ok(Ok(contents)) => Ok(ReadResourceResult::new(
                contents
                    .iter()
                    .map(crate::ResourceContent::to_rmcp)
                    .collect(),
            )
            .into()),
            Ok(Err(err)) => Err(ErrorData::internal_error(err.0, None)),
            Err(_) => Err(ErrorData::internal_error(INTERNAL_FAILURE, None)),
        }
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, ErrorData>> + MaybeSendFuture + '_ {
        let prompts = self
            .inner
            .prompts
            .values()
            .map(|entry| entry.info.to_rmcp())
            .collect();
        std::future::ready(Ok(ListPromptsResult::with_all_items(prompts)))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let Some(entry) = self.inner.prompts.get(&request.name).cloned() else {
            return Err(ErrorData::invalid_params(
                format!("unknown prompt {:?}", clean_text(&request.name, 128)),
                None,
            ));
        };
        let mut arguments = BTreeMap::new();
        for (key, value) in request.arguments.unwrap_or_default() {
            let Value::String(value) = value else {
                return Err(ErrorData::invalid_params(
                    format!(
                        "prompt argument {:?} must be a string",
                        clean_text(&key, 64)
                    ),
                    None,
                ));
            };
            arguments.insert(key, value);
        }
        for arg in &entry.info.arguments {
            if arg.required && !arguments.contains_key(&arg.name) {
                return Err(ErrorData::invalid_params(
                    format!("missing required prompt argument {:?}", arg.name),
                    None,
                ));
            }
        }
        let handler = Arc::clone(&entry.handler);
        let task = AbortOnDrop(tokio::spawn(async move { handler.get(arguments).await }));
        let Some(joined) = until_cancelled(task, context.ct.cancelled()).await else {
            return Err(ErrorData::internal_error("request cancelled", None));
        };
        match joined {
            Ok(Ok(messages)) => {
                let mut result = GetPromptResult::new(
                    messages.iter().map(crate::PromptMessage::to_rmcp).collect(),
                );
                result.description.clone_from(&entry.info.description);
                Ok(result.into())
            }
            Ok(Err(err)) => Err(ErrorData::internal_error(err.0, None)),
            Err(_) => Err(ErrorData::internal_error(INTERNAL_FAILURE, None)),
        }
    }
}

/// A spawned handler task that is aborted when dropped, so a request that
/// is abandoned does not leave its work running in the background.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}

/// `work`'s output, or `None` if `cancelled` completes first (`work` is
/// then dropped).
async fn until_cancelled<F: Future>(
    work: F,
    cancelled: impl Future<Output = ()>,
) -> Option<F::Output> {
    let mut work = std::pin::pin!(work);
    let mut cancelled = std::pin::pin!(cancelled);
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(output) = work.as_mut().poll(cx) {
            return std::task::Poll::Ready(Some(output));
        }
        cancelled.as_mut().poll(cx).map(|()| None)
    })
    .await
}

/// A server session in progress; see [`McpServer::serve`].
///
/// Dropping it closes the session: hold it, or await
/// [`waiting`](Self::waiting), for as long as the session should run.
pub struct RunningServer {
    service: RunningService<RoleServer, McpServer>,
}

impl fmt::Debug for RunningServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunningServer").finish_non_exhaustive()
    }
}

impl RunningServer {
    /// The client's `initialize` info (name, version, capabilities).
    #[must_use]
    pub fn peer_info(&self) -> Option<Arc<rmcp::model::ClientConfig>> {
        self.service.peer_info()
    }

    /// Tell the client the tool list changed, for example after a policy
    /// that reads shared state now lists different tools.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if the notification cannot be sent.
    pub async fn notify_tool_list_changed(&self) -> Result<(), Error> {
        self.service
            .peer()
            .notify_tool_list_changed()
            .await
            .map_err(Error::from)
    }

    /// Wait until the session ends (the client disconnects or the transport
    /// closes).
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if the session task panicked or was aborted.
    pub async fn waiting(self) -> Result<(), Error> {
        self.service
            .waiting()
            .await
            .map(drop)
            .map_err(|err| Error::Transport(Box::new(err)))
    }

    /// Stop the session and wait for it to finish.
    ///
    /// # Errors
    ///
    /// As [`Self::waiting`].
    pub async fn cancel(self) -> Result<(), Error> {
        self.service
            .cancel()
            .await
            .map(drop)
            .map_err(|err| Error::Transport(Box::new(err)))
    }
}
