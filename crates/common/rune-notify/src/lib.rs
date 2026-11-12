//! Notification sinks for findings and alerts: Slack, Discord, a generic
//! JSON webhook and Jira, over a caller-supplied HTTP transport.
//!
//! - [`Message`] is the provider-neutral notification. Build one by hand or
//!   render it from a [`rune_finding::Finding`] with [`Message::from_finding`]
//!   or a [`MessageTemplate`] of `{placeholder}` [`Template`]s.
//! - A [`Sink`] turns a message into a provider request and reads the
//!   provider's answer: [`SlackSink`] ([incoming webhooks], Block Kit),
//!   [`DiscordSink`] ([execute webhook], one embed), [`WebhookSink`] (a
//!   stable JSON shape) and [`JiraSink`] ([create issue], REST v2). Each
//!   escapes finding text for its markup and cuts it to the provider's
//!   limits.
//! - A [`Transport`] moves the bytes. The crate has no HTTP client and does
//!   no I/O: implement the trait over the client you already use (a closure
//!   works), or call [`Sink::request`] and [`Sink::response`] around an async
//!   client.
//! - [`Notifier`] fans a message out to several sinks, filters by severity
//!   and retries throttled or failed deliveries with a
//!   [`rune_retry_queue`] backoff, dead-lettering what never gets through.
//!
//! Webhook URLs, API tokens and secret headers are
//! [`SecretValue`](rune_secret_ref::SecretValue)s: resolve them with
//! `rune-secret-ref`, and they stay out of `Debug` output and errors.
//!
//! [incoming webhooks]: https://api.slack.com/messaging/webhooks
//! [execute webhook]: https://discord.com/developers/docs/resources/webhook#execute-webhook
//! [create issue]: https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issues/#api-rest-api-2-issue-post
//!
//! # Example
//!
//! ```
//! use rune_finding::{Confidence, Finding, Location, Severity};
//! use rune_notify::{HttpRequest, HttpResponse, Message, Sink, SlackSink, TransportError};
//! use rune_secret_ref::SecretValue;
//!
//! let finding = Finding::<()>::new(
//!     "tls.weak_protocol",
//!     "TLS 1.0 enabled",
//!     Severity::Medium,
//!     Confidence::Certain,
//!     Location::network("mail.example.test", 465),
//! );
//! let message = Message::from_finding(&finding);
//! assert_eq!(message.title, "[MEDIUM] TLS 1.0 enabled");
//!
//! // In production the URL comes from `SecretRef::resolve`.
//! let slack = SlackSink::new(SecretValue::new("https://hooks.slack.com/services/T0/B0/XXXX"))?;
//!
//! // Any `Fn(&HttpRequest) -> Result<HttpResponse, TransportError>` is a
//! // transport; this one answers like Slack without touching the network.
//! let transport = |request: &HttpRequest| -> Result<HttpResponse, TransportError> {
//!     let body: serde_json::Value = serde_json::from_slice(&request.body)
//!         .map_err(|e| TransportError::permanent(e.to_string()))?;
//!     assert_eq!(body["blocks"][0]["text"]["text"], "[MEDIUM] TLS 1.0 enabled");
//!     Ok(HttpResponse::new(200).with_body("ok"))
//! };
//! let delivery = slack.send(&message, &transport)?;
//! assert_eq!(delivery.status, 200);
//! # Ok::<(), rune_notify::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod discord;
mod error;
mod http;
mod jira;
mod message;
mod notifier;
mod sink;
mod slack;
mod template;
mod text;
mod webhook;

pub use discord::DiscordSink;
pub use error::Error;
pub use http::{HeaderValue, HttpRequest, HttpResponse, Method, Transport, TransportError};
pub use jira::{JiraAuth, JiraSink};
pub use message::{Field, Message};
pub use notifier::{DeadLetter, Notifier, Outcome, RouteId, Status};
pub use sink::{Delivery, Sink};
pub use slack::SlackSink;
pub use template::{MessageTemplate, Template};
pub use webhook::{WEBHOOK_SCHEMA_VERSION, WebhookSink};

// Re-exported so callers name the same versions this crate uses.
pub use rune_finding;
pub use rune_retry_queue;
pub use rune_secret_ref;
