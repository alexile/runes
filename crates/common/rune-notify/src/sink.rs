//! The [`Sink`] trait every destination implements.

use crate::{Error, HttpRequest, HttpResponse, Message, Transport};

/// What a provider said about a delivered message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Delivery {
    /// The 2xx status the provider answered with.
    pub status: u16,
    /// The provider's id for what was created, when it returns one: a Jira
    /// issue key (`SEC-123`) or a Discord message id (with `wait`).
    pub id: Option<String>,
    /// A browsable link to what was created, when known (a Jira issue).
    pub url: Option<String>,
}

impl Delivery {
    /// A delivery with only a status.
    #[must_use]
    pub const fn new(status: u16) -> Self {
        Self {
            status,
            id: None,
            url: None,
        }
    }
}

/// A notification destination.
///
/// A sink is sans-I/O: [`request`](Self::request) turns a [`Message`] into
/// the provider's [`HttpRequest`], and [`response`](Self::response) reads
/// the provider's [`HttpResponse`]. [`send`](Self::send) joins the two over
/// a caller-supplied [`Transport`]. Async callers call the two halves around
/// their own client instead.
///
/// The trait is object safe, so a [`Notifier`](crate::Notifier) can hold
/// different sinks side by side.
pub trait Sink {
    /// Short, stable name of the sink kind (`slack`, `discord`, `webhook`,
    /// `jira`), for logs and errors. Never contains a URL.
    fn name(&self) -> &'static str;

    /// Builds the provider request for `message`.
    ///
    /// # Errors
    ///
    /// When the message cannot be expressed for this provider. The built-in
    /// sinks cut text to fit instead, so they do not fail here.
    fn request(&self, message: &Message) -> Result<HttpRequest, Error>;

    /// Reads the provider's answer.
    ///
    /// # Errors
    ///
    /// [`Error::RateLimited`], [`Error::Server`] or [`Error::Rejected`] for a
    /// non-2xx status, and [`Error::InvalidResponse`] for a 2xx the sink
    /// cannot read.
    fn response(&self, response: &HttpResponse) -> Result<Delivery, Error>;

    /// Builds the request, sends it over `transport` and reads the answer.
    ///
    /// # Errors
    ///
    /// Any error of [`request`](Self::request) or
    /// [`response`](Self::response), or [`Error::Transport`].
    fn send(&self, message: &Message, transport: &dyn Transport) -> Result<Delivery, Error> {
        let request = self.request(message)?;
        let response = transport.send(&request)?;
        self.response(&response)
    }
}

impl<S: Sink + ?Sized> Sink for Box<S> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    fn request(&self, message: &Message) -> Result<HttpRequest, Error> {
        (**self).request(message)
    }

    fn response(&self, response: &HttpResponse) -> Result<Delivery, Error> {
        (**self).response(response)
    }
}
