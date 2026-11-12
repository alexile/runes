//! Fan-out to several sinks with severity routing and retries.

use std::fmt;
use std::time::Instant;

use rune_finding::Severity;
use rune_retry_queue::{BackoffPolicy, RetryQueue};

use crate::{Delivery, Error, Message, Sink, Transport};

/// Identifies one sink added to a [`Notifier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteId(usize);

impl RouteId {
    /// The route's position in the order sinks were added.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// What happened to a message on one route.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Status {
    /// The provider accepted it.
    Delivered(Delivery),
    /// A retryable failure; the message is queued for
    /// [`Notifier::retry_due`].
    Retrying(Error),
    /// A retryable failure, but the route ran out of retries; the message
    /// is in [`Notifier::drain_dead_letters`].
    DeadLettered(Error),
    /// A permanent failure (bad payload, bad credentials). Not retried.
    Failed(Error),
}

/// The result of one delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Outcome {
    /// The route attempted.
    pub route: RouteId,
    /// The route's sink name.
    pub sink: &'static str,
    /// Retries made before this attempt (0 for the first send).
    pub attempt: u32,
    /// What happened.
    pub status: Status,
}

/// A message a route gave up on after its last retry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeadLetter {
    /// The route that gave up.
    pub route: RouteId,
    /// The message.
    pub message: Message,
    /// The last error.
    pub error: Error,
}

struct Route {
    sink: Box<dyn Sink + Send + Sync>,
    min_severity: Option<Severity>,
}

struct Pending {
    route: RouteId,
    message: Message,
    error: Error,
}

/// Sends each message to every matching sink and retries retryable
/// failures with a [`rune_retry_queue`] backoff.
///
/// Time is passed in, never read: call [`notify`](Self::notify) for new
/// messages and [`retry_due`](Self::retry_due) periodically with the current
/// `Instant`. A message that keeps failing is retried up to `max_retries`
/// times and then dead-lettered; a permanent failure ([`Error::Rejected`])
/// is reported once and dropped.
///
/// The backoff policy alone sets retry times. A provider's `Retry-After`
/// is available on the error ([`Error::retry_after`]) for callers that want
/// to wait longer before calling `retry_due`.
///
/// ```
/// use std::time::{Duration, Instant};
/// use rune_finding::Severity;
/// use rune_notify::{HttpRequest, HttpResponse, Message, Notifier, Status, TransportError, WebhookSink};
/// use rune_retry_queue::BackoffPolicy;
/// use rune_secret_ref::SecretValue;
///
/// let mut notifier = Notifier::new(BackoffPolicy::Fixed(Duration::from_secs(5)), 3);
/// notifier.add(WebhookSink::new(SecretValue::new("https://all.example.test/hook"))?);
/// notifier.add_route(
///     WebhookSink::new(SecretValue::new("https://pager.example.test/hook"))?,
///     Severity::Critical,
/// );
///
/// // A stand-in transport: the first host is down, the second is up.
/// let transport = |request: &HttpRequest| {
///     if request.url.expose().contains("all.") {
///         Err(TransportError::retryable("connection refused"))
///     } else {
///         Ok(HttpResponse::new(204))
///     }
/// };
///
/// let now = Instant::now();
/// let message = Message::new("Deploy blocked", "1 critical finding").with_severity(Severity::Critical);
/// let outcomes = notifier.notify(&message, &transport, now);
/// assert!(matches!(outcomes[0].status, Status::Retrying(_)));
/// assert!(matches!(outcomes[1].status, Status::Delivered(_)));
/// assert_eq!(notifier.pending(), 1);
///
/// // Low severity skips the pager route.
/// let low = Message::new("FYI", "").with_severity(Severity::Low);
/// assert_eq!(notifier.notify(&low, &transport, now).len(), 1);
///
/// assert!(notifier.retry_due(&transport, now).is_empty());
/// assert_eq!(notifier.retry_due(&transport, now + Duration::from_secs(5)).len(), 2);
/// # Ok::<(), rune_notify::Error>(())
/// ```
pub struct Notifier {
    routes: Vec<Route>,
    queue: RetryQueue<Pending>,
    max_retries: u32,
    pending: usize,
}

impl Notifier {
    /// A notifier with no sinks that retries each failed delivery up to
    /// `max_retries` times, waiting as `backoff` says between tries.
    #[must_use]
    pub const fn new(backoff: BackoffPolicy, max_retries: u32) -> Self {
        Self {
            routes: Vec::new(),
            queue: RetryQueue::new(backoff, max_retries),
            max_retries,
            pending: 0,
        }
    }

    /// Adds a sink that receives every message.
    pub fn add(&mut self, sink: impl Sink + Send + Sync + 'static) -> RouteId {
        self.push(Box::new(sink), None)
    }

    /// Adds a sink that receives only messages at `min_severity` or above.
    /// Messages without a severity go to every route.
    pub fn add_route(
        &mut self,
        sink: impl Sink + Send + Sync + 'static,
        min_severity: Severity,
    ) -> RouteId {
        self.push(Box::new(sink), Some(min_severity))
    }

    fn push(
        &mut self,
        sink: Box<dyn Sink + Send + Sync>,
        min_severity: Option<Severity>,
    ) -> RouteId {
        self.routes.push(Route { sink, min_severity });
        RouteId(self.routes.len() - 1)
    }

    /// Number of routes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether no sink was added.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Number of deliveries waiting for a retry.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.pending
    }

    /// Sends `message` to every route whose severity filter it passes, in
    /// the order the routes were added. Returns one [`Outcome`] per route
    /// tried.
    pub fn notify(
        &mut self,
        message: &Message,
        transport: &dyn Transport,
        now: Instant,
    ) -> Vec<Outcome> {
        let mut outcomes = Vec::new();
        for index in 0..self.routes.len() {
            let route = &self.routes[index];
            if let (Some(min), Some(severity)) = (route.min_severity, message.severity)
                && severity < min
            {
                continue;
            }
            let result = route.sink.send(message, transport);
            let outcome = self.settle(RouteId(index), message, 0, result, now);
            outcomes.push(outcome);
        }
        outcomes
    }

    /// Retries every queued delivery whose backoff has elapsed at `now`.
    pub fn retry_due(&mut self, transport: &dyn Transport, now: Instant) -> Vec<Outcome> {
        let due = self.queue.ready(now);
        self.pending = self.pending.saturating_sub(due.len());
        let mut outcomes = Vec::with_capacity(due.len());
        for (pending, attempt) in due {
            let attempt = attempt.saturating_add(1);
            let Some(route) = self.routes.get(pending.route.0) else {
                continue;
            };
            let result = route.sink.send(&pending.message, transport);
            outcomes.push(self.settle(pending.route, &pending.message, attempt, result, now));
        }
        outcomes
    }

    /// Removes and returns every dead-lettered message.
    pub fn drain_dead_letters(&mut self) -> Vec<DeadLetter> {
        self.queue
            .drain_dead_letters()
            .into_iter()
            .map(|p| DeadLetter {
                route: p.route,
                message: p.message,
                error: p.error,
            })
            .collect()
    }

    fn settle(
        &mut self,
        route: RouteId,
        message: &Message,
        attempt: u32,
        result: Result<Delivery, Error>,
        now: Instant,
    ) -> Outcome {
        let sink = self.routes.get(route.0).map_or("?", |r| r.sink.name());
        let status = match result {
            Ok(delivery) => Status::Delivered(delivery),
            Err(error) if error.is_retryable() => {
                // `attempt` retries are done; the queue dead-letters once
                // `max_retries` is reached.
                let exhausted = attempt >= self.max_retries;
                self.queue.push(
                    Pending {
                        route,
                        message: message.clone(),
                        error: error.clone(),
                    },
                    attempt,
                    now,
                );
                if exhausted {
                    Status::DeadLettered(error)
                } else {
                    self.pending += 1;
                    Status::Retrying(error)
                }
            }
            Err(error) => Status::Failed(error),
        };
        Outcome {
            route,
            sink,
            attempt,
            status,
        }
    }
}

impl fmt::Debug for Notifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let routes: Vec<_> = self
            .routes
            .iter()
            .map(|r| (r.sink.name(), r.min_severity))
            .collect();
        f.debug_struct("Notifier")
            .field("routes", &routes)
            .field("max_retries", &self.max_retries)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::Duration;

    use rune_secret_ref::SecretValue;

    use super::*;
    use crate::{HttpRequest, HttpResponse, TransportError, WebhookSink};

    fn hook(host: &str) -> WebhookSink {
        WebhookSink::new(SecretValue::new(format!("https://{host}/h"))).unwrap()
    }

    #[test]
    fn retries_then_dead_letters() {
        let mut n = Notifier::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 2);
        let route = n.add(hook("down.test"));
        let calls = Cell::new(0);
        let transport = |_: &HttpRequest| {
            calls.set(calls.get() + 1);
            Ok(HttpResponse::new(503))
        };
        let t0 = Instant::now();
        let first = n.notify(&Message::new("t", "b"), &transport, t0);
        assert!(matches!(
            first[0].status,
            Status::Retrying(Error::Server { status: 503, .. })
        ));
        assert_eq!(first[0].route, route);
        let second = n.retry_due(&transport, t0 + Duration::from_secs(1));
        assert_eq!(second[0].attempt, 1);
        assert!(matches!(second[0].status, Status::Retrying(_)));
        let third = n.retry_due(&transport, t0 + Duration::from_secs(2));
        assert_eq!(third[0].attempt, 2);
        assert!(matches!(third[0].status, Status::DeadLettered(_)));
        assert_eq!(n.pending(), 0);
        assert_eq!(calls.get(), 3);
        let dead = n.drain_dead_letters();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].message.title, "t");
        assert_eq!(n.retry_due(&transport, t0 + Duration::from_secs(60)), []);
    }

    #[test]
    fn permanent_failures_are_dropped() {
        let mut n = Notifier::new(BackoffPolicy::Fixed(Duration::ZERO), 5);
        n.add(hook("x.test"));
        let transport = |_: &HttpRequest| Ok(HttpResponse::new(400));
        let out = n.notify(&Message::new("t", ""), &transport, Instant::now());
        assert!(matches!(
            out[0].status,
            Status::Failed(Error::Rejected { .. })
        ));
        assert_eq!(n.pending(), 0);
        assert_eq!(n.drain_dead_letters(), []);
    }

    #[test]
    fn zero_retries_dead_letters_at_once() {
        let mut n = Notifier::new(BackoffPolicy::Fixed(Duration::ZERO), 0);
        n.add(hook("x.test"));
        let transport = |_: &HttpRequest| Err(TransportError::retryable("refused"));
        let out = n.notify(&Message::new("t", ""), &transport, Instant::now());
        assert!(matches!(
            out[0].status,
            Status::DeadLettered(Error::Transport { .. })
        ));
        assert_eq!(n.drain_dead_letters().len(), 1);
        assert!(format!("{n:?}").contains("webhook"));
        assert_eq!((n.len(), n.is_empty()), (1, false));
    }
}
