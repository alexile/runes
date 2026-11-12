//! MCP resources and prompts: the types both sides share, the handler
//! traits a server registers, and their conversion to rmcp's wire types.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;

use async_trait::async_trait;
use rmcp::model::{self, ContentBlock};

use crate::output::{from_content_block, to_content_block};
use crate::sanitize::clean_text;
use crate::{Content, Error, ToolError};

/// A resource a server offers (`resources/list`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceInfo {
    /// The resource's URI, used to read it.
    pub uri: String,
    /// Short programmatic name.
    pub name: String,
    /// Human-readable title.
    pub title: Option<String>,
    /// What the resource holds.
    pub description: Option<String>,
    /// MIME type of its contents.
    pub mime_type: Option<String>,
}

impl ResourceInfo {
    /// A resource with this URI and name.
    #[must_use]
    pub fn new(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            title: None,
            description: None,
            mime_type: None,
        }
    }

    /// Set the title.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the MIME type.
    #[must_use]
    pub fn with_mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.mime_type = Some(mime_type.into());
        self
    }

    pub(crate) fn to_rmcp(&self) -> model::Resource {
        let mut resource = model::Resource::new(self.uri.clone(), self.name.clone());
        resource.title.clone_from(&self.title);
        resource.description.clone_from(&self.description);
        resource.mime_type.clone_from(&self.mime_type);
        resource
    }

    pub(crate) fn from_rmcp(resource: &model::Resource, max_description: usize) -> Self {
        let clean = |s: &Option<String>, max| s.as_deref().map(|s| clean_text(s, max));
        Self {
            uri: resource.uri.clone(),
            name: clean_text(&resource.name, 256),
            title: clean(&resource.title, 256),
            description: clean(&resource.description, max_description),
            mime_type: clean(&resource.mime_type, 128),
        }
    }
}

/// The body of one [`ResourceContent`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceBody {
    /// Text.
    Text(String),
    /// Binary data, base64-encoded as on the wire.
    Blob(String),
}

/// One piece of a resource's contents (`resources/read`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceContent {
    /// The URI these contents belong to.
    pub uri: String,
    /// MIME type, if known.
    pub mime_type: Option<String>,
    /// The data.
    pub body: ResourceBody,
}

impl ResourceContent {
    /// Text contents for `uri`.
    #[must_use]
    pub fn text(uri: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            mime_type: None,
            body: ResourceBody::Text(text.into()),
        }
    }

    /// Binary contents for `uri`, already base64-encoded.
    #[must_use]
    pub fn blob_base64(uri: impl Into<String>, base64: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            mime_type: None,
            body: ResourceBody::Blob(base64.into()),
        }
    }

    /// Set the MIME type.
    #[must_use]
    pub fn with_mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.mime_type = Some(mime_type.into());
        self
    }

    /// The text, if this is text contents.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match &self.body {
            ResourceBody::Text(text) => Some(text),
            ResourceBody::Blob(_) => None,
        }
    }

    pub(crate) const fn len(&self) -> usize {
        match &self.body {
            ResourceBody::Text(s) | ResourceBody::Blob(s) => s.len(),
        }
    }

    pub(crate) fn to_rmcp(&self) -> model::ResourceContents {
        match &self.body {
            ResourceBody::Text(text) => model::ResourceContents::TextResourceContents {
                uri: self.uri.clone(),
                mime_type: self.mime_type.clone(),
                text: text.clone(),
                meta: None,
            },
            ResourceBody::Blob(blob) => model::ResourceContents::BlobResourceContents {
                uri: self.uri.clone(),
                mime_type: self.mime_type.clone(),
                blob: blob.clone(),
                meta: None,
            },
        }
    }

    pub(crate) fn from_rmcp(contents: model::ResourceContents) -> Option<Self> {
        match contents {
            model::ResourceContents::TextResourceContents {
                uri,
                mime_type,
                text,
                ..
            } => Some(Self {
                uri,
                mime_type,
                body: ResourceBody::Text(text),
            }),
            model::ResourceContents::BlobResourceContents {
                uri,
                mime_type,
                blob,
                ..
            } => Some(Self {
                uri,
                mime_type,
                body: ResourceBody::Blob(blob),
            }),
            #[allow(unreachable_patterns, reason = "rmcp's enum is non-exhaustive")]
            _ => None,
        }
    }
}

/// An argument a prompt template takes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,
    /// What it is for.
    pub description: Option<String>,
    /// Whether `prompts/get` must supply it.
    pub required: bool,
}

impl PromptArgument {
    /// An optional argument.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            required: false,
        }
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Mark the argument as required.
    #[must_use]
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// A prompt template a server offers (`prompts/list`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PromptInfo {
    /// Prompt name, used to get it.
    pub name: String,
    /// Human-readable title.
    pub title: Option<String>,
    /// What the prompt does.
    pub description: Option<String>,
    /// The arguments it takes.
    pub arguments: Vec<PromptArgument>,
}

impl PromptInfo {
    /// A prompt with this name and no arguments.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: None,
            arguments: Vec::new(),
        }
    }

    /// Set the title.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add an argument.
    #[must_use]
    pub fn with_argument(mut self, argument: PromptArgument) -> Self {
        self.arguments.push(argument);
        self
    }

    pub(crate) fn to_rmcp(&self) -> model::Prompt {
        let arguments = (!self.arguments.is_empty()).then(|| {
            self.arguments
                .iter()
                .map(|arg| {
                    let mut out =
                        model::PromptArgument::new(arg.name.clone()).with_required(arg.required);
                    out.description.clone_from(&arg.description);
                    out
                })
                .collect()
        });
        let mut prompt = model::Prompt::new(self.name.clone(), self.description.clone(), arguments);
        prompt.title.clone_from(&self.title);
        prompt
    }

    pub(crate) fn from_rmcp(prompt: &model::Prompt, max_description: usize) -> Self {
        let clean = |s: &Option<String>, max| s.as_deref().map(|s| clean_text(s, max));
        Self {
            name: prompt.name.clone(),
            title: clean(&prompt.title, 256),
            description: clean(&prompt.description, max_description),
            arguments: prompt
                .arguments
                .iter()
                .flatten()
                .map(|arg| PromptArgument {
                    name: clean_text(&arg.name, 128),
                    description: clean(&arg.description, max_description),
                    required: arg.required.unwrap_or(false),
                })
                .collect(),
        }
    }
}

/// Who a [`PromptMessage`] is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PromptRole {
    /// The user.
    User,
    /// The assistant.
    Assistant,
}

/// One message of a rendered prompt.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PromptMessage {
    /// Who the message is from.
    pub role: PromptRole,
    /// What it says.
    pub content: Content,
}

impl PromptMessage {
    /// A text message.
    #[must_use]
    pub fn text(role: PromptRole, text: impl Into<String>) -> Self {
        Self {
            role,
            content: Content::Text(text.into()),
        }
    }

    pub(crate) fn to_rmcp(&self) -> model::PromptMessage {
        let role = match self.role {
            PromptRole::User => model::Role::User,
            PromptRole::Assistant => model::Role::Assistant,
        };
        model::PromptMessage::new(role, to_content_block(self.content.clone()))
    }

    pub(crate) fn from_rmcp(message: &model::PromptMessage) -> Result<Self, Error> {
        let role = match message.role {
            model::Role::Assistant => PromptRole::Assistant,
            model::Role::User => PromptRole::User,
        };
        let content: &ContentBlock = &message.content;
        Ok(Self {
            role,
            content: from_content_block(content)?,
        })
    }
}

/// A prompt rendered by `prompts/get`.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct PromptResult {
    /// Description of the rendered prompt.
    pub description: Option<String>,
    /// The messages.
    pub messages: Vec<PromptMessage>,
}

/// Serves one resource's contents; register it with
/// [`McpServer::resource`](crate::McpServer::resource).
#[async_trait]
pub trait ResourceHandler: Send + Sync {
    /// Read the resource registered under `uri`.
    async fn read(&self, uri: &str) -> Result<Vec<ResourceContent>, ToolError>;
}

/// Renders one prompt; register it with
/// [`McpServer::prompt`](crate::McpServer::prompt).
#[async_trait]
pub trait PromptHandler: Send + Sync {
    /// Render the prompt. Required arguments have been checked.
    async fn get(
        &self,
        arguments: BTreeMap<String, String>,
    ) -> Result<Vec<PromptMessage>, ToolError>;
}

/// A resource or prompt handler made from an async closure; see
/// [`resource_fn`] and [`prompt_fn`].
#[derive(Clone)]
pub struct FnSource<F>(F);

impl<F> fmt::Debug for FnSource<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FnSource")
    }
}

/// Wrap an async closure taking the URI as a [`ResourceHandler`].
pub const fn resource_fn<F, Fut>(f: F) -> FnSource<F>
where
    F: Fn(String) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Vec<ResourceContent>, ToolError>> + Send,
{
    FnSource(f)
}

/// Wrap an async closure taking the arguments as a [`PromptHandler`].
pub const fn prompt_fn<F, Fut>(f: F) -> FnSource<F>
where
    F: Fn(BTreeMap<String, String>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Vec<PromptMessage>, ToolError>> + Send,
{
    FnSource(f)
}

#[async_trait]
impl<F, Fut> ResourceHandler for FnSource<F>
where
    F: Fn(String) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Vec<ResourceContent>, ToolError>> + Send,
{
    async fn read(&self, uri: &str) -> Result<Vec<ResourceContent>, ToolError> {
        (self.0)(uri.to_owned()).await
    }
}

#[async_trait]
impl<F, Fut> PromptHandler for FnSource<F>
where
    F: Fn(BTreeMap<String, String>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Vec<PromptMessage>, ToolError>> + Send,
{
    async fn get(
        &self,
        arguments: BTreeMap<String, String>,
    ) -> Result<Vec<PromptMessage>, ToolError> {
        (self.0)(arguments).await
    }
}
