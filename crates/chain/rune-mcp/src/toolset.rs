//! [`McpToolset`]: several MCP servers as one namespaced tool set.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value};
use tokio::sync::watch;

use crate::client::ListChanges;
use crate::sanitize::{split_qualified, validate_namespace};
use crate::{Error, McpClient, RemoteTool, ToolOutput};

/// Several connected MCP servers used as one tool set.
///
/// Each server is registered under a namespace, and its tools are exposed
/// as `<namespace>__<tool>`: two servers can both offer `search`, and a
/// malicious server cannot shadow another server's tool by listing the same
/// name. Each client keeps its own options (trust, policy, allowlist,
/// limits).
///
/// ```
/// # use rune_mcp::{tool_fn, ClientOptions, McpClient, McpServer, McpToolset, ToolOutput};
/// # use rune_tool_schema::ToolDescriptor;
/// # async fn connect(name: &str) -> Result<McpClient, rune_mcp::Error> {
/// #     let server = McpServer::new(name, "1").tool(
/// #         ToolDescriptor::new("search", "Search."),
/// #         tool_fn(|_| async { Ok(ToolOutput::text("hit")) }),
/// #     )?;
/// #     let (a, b) = tokio::io::duplex(4096);
/// #     tokio::spawn(async move { server.serve(a).await?.waiting().await });
/// #     McpClient::connect(b, ClientOptions::default()).await
/// # }
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let toolset = McpToolset::new()
///     .with_server("docs", connect("docs").await?)?
///     .with_server("web", connect("web").await?)?;
/// let names: Vec<String> = toolset
///     .remote_tools()
///     .await?
///     .iter()
///     .map(|t| t.descriptor().name.clone())
///     .collect();
/// assert_eq!(names, ["docs__search", "web__search"]);
/// let out = toolset.call_tool("web__search", serde_json::Map::new()).await?;
/// assert_eq!(out.text_content(), "hit");
/// # Ok::<(), rune_mcp::Error>(())
/// # })?;
/// # Ok::<(), rune_mcp::Error>(())
/// ```
#[derive(Default, Clone)]
pub struct McpToolset {
    servers: Vec<(String, Arc<McpClient>)>,
}

impl fmt::Debug for McpToolset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpToolset")
            .field(
                "servers",
                &self.servers.iter().map(|(ns, _)| ns).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl McpToolset {
    /// An empty tool set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a server under `namespace`.
    ///
    /// # Errors
    ///
    /// As [`Self::add_server`].
    pub fn with_server(
        mut self,
        namespace: impl Into<String>,
        client: impl Into<Arc<McpClient>>,
    ) -> Result<Self, Error> {
        self.add_server(namespace, client)?;
        Ok(self)
    }

    /// Add a server under `namespace`, in place.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidNamespace`] if the namespace breaks the rules of
    /// [`validate_namespace`](crate::sanitize::validate_namespace);
    /// [`Error::Duplicate`] if it is taken.
    pub fn add_server(
        &mut self,
        namespace: impl Into<String>,
        client: impl Into<Arc<McpClient>>,
    ) -> Result<(), Error> {
        let namespace = namespace.into();
        validate_namespace(&namespace).map_err(|reason| Error::InvalidNamespace {
            namespace: namespace.clone(),
            reason,
        })?;
        if self.servers.iter().any(|(ns, _)| *ns == namespace) {
            return Err(Error::Duplicate {
                kind: "server",
                name: namespace,
            });
        }
        self.servers.push((namespace, client.into()));
        Ok(())
    }

    /// The registered namespaces and their clients, in insertion order.
    pub fn servers(&self) -> impl Iterator<Item = (&str, &Arc<McpClient>)> {
        self.servers
            .iter()
            .map(|(ns, client)| (ns.as_str(), client))
    }

    /// The client registered under `namespace`.
    #[must_use]
    pub fn client(&self, namespace: &str) -> Option<&Arc<McpClient>> {
        self.servers
            .iter()
            .find(|(ns, _)| ns == namespace)
            .map(|(_, client)| client)
    }

    /// List every server's tools, namespaced, sorted by exposed name.
    ///
    /// # Errors
    ///
    /// [`Error::Server`] naming the first server whose listing failed;
    /// [`Error::Duplicate`] if two exposed names collide (cannot happen
    /// with valid namespaces, checked anyway).
    pub async fn remote_tools(&self) -> Result<Vec<RemoteTool>, Error> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for (namespace, client) in &self.servers {
            let tools = client
                .remote_tools_in(Some(namespace))
                .await
                .map_err(|err| Error::Server {
                    namespace: namespace.clone(),
                    source: Box::new(err),
                })?;
            for tool in tools {
                if !seen.insert(tool.descriptor().name.clone()) {
                    return Err(Error::Duplicate {
                        kind: "tool",
                        name: tool.descriptor().name.clone(),
                    });
                }
                out.push(tool);
            }
        }
        out.sort_by(|a, b| a.descriptor().name.cmp(&b.descriptor().name));
        Ok(out)
    }

    /// Call a tool by its exposed name, `<namespace>__<tool>`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownServer`] if the namespace is not registered (or the
    /// name has none); otherwise as [`McpClient::call_tool`].
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> Result<ToolOutput, Error> {
        let (namespace, tool) = split_qualified(name)
            .ok_or_else(|| Error::UnknownTool(name.chars().take(128).collect()))?;
        let client = self
            .client(namespace)
            .ok_or_else(|| Error::UnknownServer(namespace.chars().take(64).collect()))?;
        client.call_tool(tool, arguments).await
    }

    /// One list-changed receiver per server.
    #[must_use]
    pub fn subscribe(&self) -> Vec<(String, watch::Receiver<ListChanges>)> {
        self.servers
            .iter()
            .map(|(ns, client)| (ns.clone(), client.subscribe()))
            .collect()
    }

    /// Close every session that nothing else holds (no [`RemoteTool`] or
    /// clone of the client is alive); the others close when their last
    /// holder is dropped.
    ///
    /// # Errors
    ///
    /// The first [`Error::Transport`] from a session that failed to close;
    /// the remaining sessions are still closed.
    pub async fn close(self) -> Result<(), Error> {
        let mut first = None;
        for (_, client) in self.servers {
            if let Ok(client) = Arc::try_unwrap(client)
                && let Err(err) = client.close().await
            {
                first.get_or_insert(err);
            }
        }
        first.map_or(Ok(()), Err)
    }
}
