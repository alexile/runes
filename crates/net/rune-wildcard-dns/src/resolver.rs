//! The resolver interface this crate drives, and the answers it consumes.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use rune_dns_wire::{Message, Name, Rcode, Record, RecordType};

/// What a resolver answered for one query: the response code and the answer
/// section, CNAME chain included.
///
/// Only `rcode` and `answers` matter to wildcard detection; build one from a
/// full [`Message`] with [`Response::from`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// The response code. `NOERROR` and `NXDOMAIN` are answers; anything
    /// else is treated as a failed lookup.
    pub rcode: Rcode,
    /// The answer section, in the order received.
    pub answers: Vec<Record>,
}

impl Response {
    /// A response with the given code and answer records.
    #[must_use]
    pub const fn new(rcode: Rcode, answers: Vec<Record>) -> Self {
        Self { rcode, answers }
    }

    /// A `NOERROR` response carrying `answers` (empty for `NODATA`).
    #[must_use]
    pub const fn answer(answers: Vec<Record>) -> Self {
        Self::new(Rcode::NOERROR, answers)
    }

    /// An `NXDOMAIN` response.
    #[must_use]
    pub const fn nxdomain() -> Self {
        Self::new(Rcode::NXDOMAIN, Vec::new())
    }

    /// Whether the code is `NOERROR` or `NXDOMAIN`, i.e. the server gave an
    /// authoritative-looking answer rather than failing.
    #[must_use]
    pub fn is_answer(&self) -> bool {
        self.rcode == Rcode::NOERROR || self.rcode == Rcode::NXDOMAIN
    }

    /// Merges another response for the same name (for example the `AAAA`
    /// lookup after the `A` one): answers are appended, and the code becomes
    /// `NOERROR` if either is.
    pub fn merge(&mut self, other: Self) {
        if other.rcode == Rcode::NOERROR || !self.is_answer() {
            self.rcode = other.rcode;
        }
        self.answers.extend(other.answers);
    }
}

impl From<Message> for Response {
    fn from(message: Message) -> Self {
        Self::new(message.header.rcode, message.answers)
    }
}

impl From<&Message> for Response {
    fn from(message: &Message) -> Self {
        Self::new(message.header.rcode, message.answers.clone())
    }
}

/// A blocking DNS resolver supplied by the caller.
///
/// Implement it over any transport (system resolver, UDP socket,
/// `rune-dns-resolver`, a test double). The resolver must follow CNAMEs the
/// way a recursive resolver does, returning the whole chain in
/// [`Response::answers`]; it must not retry `NXDOMAIN` under a search list.
///
/// [`from_fn`] adapts a closure.
pub trait Resolver {
    /// The resolver's error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolves `name` (absolute) for `rtype`.
    ///
    /// # Errors
    ///
    /// A transport failure or timeout. Server failures should normally be
    /// returned as a [`Response`] with that `rcode` instead.
    fn resolve(&mut self, name: &Name, rtype: RecordType) -> Result<Response, Self::Error>;
}

impl<R: Resolver + ?Sized> Resolver for &mut R {
    type Error = R::Error;

    fn resolve(&mut self, name: &Name, rtype: RecordType) -> Result<Response, Self::Error> {
        (**self).resolve(name, rtype)
    }
}

/// An asynchronous DNS resolver supplied by the caller. Same contract as
/// [`Resolver`].
pub trait AsyncResolver {
    /// The resolver's error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolves `name` (absolute) for `rtype`.
    fn resolve(
        &mut self,
        name: &Name,
        rtype: RecordType,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send;
}

/// A [`Resolver`] backed by a closure, built by [`from_fn`].
#[derive(Debug, Clone)]
pub struct FromFn<F>(F);

/// Adapts a closure `FnMut(&Name, RecordType) -> Result<Response, E>` into a
/// [`Resolver`].
pub const fn from_fn<F, E>(f: F) -> FromFn<F>
where
    F: FnMut(&Name, RecordType) -> Result<Response, E>,
    E: std::error::Error + Send + Sync + 'static,
{
    FromFn(f)
}

impl<F, E> Resolver for FromFn<F>
where
    F: FnMut(&Name, RecordType) -> Result<Response, E>,
    E: std::error::Error + Send + Sync + 'static,
{
    type Error = E;

    fn resolve(&mut self, name: &Name, rtype: RecordType) -> Result<Response, E> {
        (self.0)(name, rtype)
    }
}

/// Runs a [`Resolver`] where an [`AsyncResolver`] is expected; its futures
/// are always ready.
pub struct Blocking<'a, R>(pub &'a mut R);

impl<R: Resolver> AsyncResolver for Blocking<'_, R> {
    type Error = R::Error;

    fn resolve(
        &mut self,
        name: &Name,
        rtype: RecordType,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
        core::future::ready(self.0.resolve(name, rtype))
    }
}

/// Drives a future whose only await points are [`Blocking`] resolver calls.
/// Those are ready on first poll, so this never actually waits.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        std::thread::yield_now();
    }
}
