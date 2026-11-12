//! The async resolver (feature `tokio`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rune_dns_wire::{Caa, Message, Mx, Name, Question, Rcode, RecordType, Soa, Srv};
use tokio::sync::Semaphore;

use crate::lookup::{Lookup, build_query, reverse_name};
use crate::{Error, ResolverOptions, Upstream, transport};

/// Something that names a domain: a [`Name`] or its text form.
pub trait IntoName {
    /// The name.
    ///
    /// # Errors
    ///
    /// [`Error::Wire`] for malformed text.
    fn into_name(self) -> Result<Name, Error>;
}

impl IntoName for Name {
    fn into_name(self) -> Result<Name, Error> {
        Ok(self)
    }
}

impl IntoName for &Name {
    fn into_name(self) -> Result<Name, Error> {
        Ok(self.clone())
    }
}

impl IntoName for &str {
    fn into_name(self) -> Result<Name, Error> {
        Ok(Name::from_ascii(self)?)
    }
}

impl IntoName for String {
    fn into_name(self) -> Result<Name, Error> {
        self.as_str().into_name()
    }
}

/// An async stub resolver. Cheap to clone: clones share the configuration
/// and the concurrency limit.
///
/// Each exchange opens a new socket or connection; TCP, TLS and HTTPS
/// connections are not reused between queries.
///
/// ```no_run
/// # async fn demo() -> Result<(), rune_dns_resolver::Error> {
/// use rune_dns_resolver::{Resolver, ResolverOptions};
///
/// let resolver = Resolver::new(ResolverOptions::default().with_upstream("192.0.2.53".parse()?))?;
/// let addresses = resolver.lookup_ip("www.example.com").await?;
/// let spf = resolver.lookup_txt("example.com").await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Resolver {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    options: ResolverOptions,
    permits: Semaphore,
    #[cfg(feature = "tls")]
    dot: Arc<tokio_rustls::rustls::ClientConfig>,
    #[cfg(feature = "doh")]
    doh: Arc<tokio_rustls::rustls::ClientConfig>,
}

impl Resolver {
    /// A resolver with `options`. With the `tls` feature, certificates are
    /// checked against the webpki root store.
    ///
    /// # Errors
    ///
    /// [`Error::NoUpstreams`] when `options.upstreams` is empty.
    pub fn new(options: ResolverOptions) -> Result<Self, Error> {
        #[cfg(feature = "tls")]
        {
            let config = transport::tls::default_config()?;
            Self::with_tls_config(options, &config)
        }
        #[cfg(not(feature = "tls"))]
        {
            Self::build(options)
        }
    }

    /// A resolver that uses `config` (roots, client certificates, ...) for
    /// DNS over TLS and HTTPS. ALPN is set by the resolver (`dot`, or `h2`
    /// and `http/1.1`).
    ///
    /// # Errors
    ///
    /// [`Error::NoUpstreams`] when `options.upstreams` is empty.
    #[cfg(feature = "tls")]
    pub fn with_tls_config(
        options: ResolverOptions,
        config: &tokio_rustls::rustls::ClientConfig,
    ) -> Result<Self, Error> {
        if options.upstreams.is_empty() {
            return Err(Error::NoUpstreams);
        }
        let permits = Semaphore::new(options.concurrency.max(1));
        Ok(Self {
            inner: Arc::new(Inner {
                options,
                permits,
                dot: transport::tls::with_alpn(config, &[b"dot"]),
                #[cfg(feature = "doh")]
                doh: transport::tls::with_alpn(config, &[b"h2", b"http/1.1"]),
            }),
        })
    }

    #[cfg(not(feature = "tls"))]
    fn build(options: ResolverOptions) -> Result<Self, Error> {
        if options.upstreams.is_empty() {
            return Err(Error::NoUpstreams);
        }
        let permits = Semaphore::new(options.concurrency.max(1));
        Ok(Self {
            inner: Arc::new(Inner { options, permits }),
        })
    }

    /// The configuration.
    #[must_use]
    pub fn options(&self) -> &ResolverOptions {
        &self.inner.options
    }

    /// Asks `question`, trying the upstreams in order for up to
    /// [`ResolverOptions::attempts`] rounds.
    ///
    /// Returns the first `NOERROR` or `NXDOMAIN` response; check
    /// [`Lookup::rcode`].
    ///
    /// # Errors
    ///
    /// The last failure once every attempt has failed: [`Error::Timeout`],
    /// [`Error::Io`], [`Error::Rcode`] (`SERVFAIL`, `REFUSED`, ...),
    /// [`Error::Mismatch`], [`Error::Tls`], [`Error::Http`], ...
    pub async fn query(&self, question: Question) -> Result<Lookup, Error> {
        let options = &self.inner.options;
        let _permit = self
            .inner
            .permits
            .acquire()
            .await
            .map_err(|_| Error::Io(std::io::Error::other("resolver closed")))?;
        let mut last = Error::NoUpstreams;
        for _ in 0..options.attempts.max(1) {
            for upstream in &options.upstreams {
                let id = match upstream {
                    Upstream::Https(_) => 0,
                    _ => rand::random(),
                };
                let query = build_query(id, question.clone(), options);
                // Boxed: the TLS and HTTP state machines would otherwise make
                // every lookup future tens of kilobytes.
                let exchange = Box::pin(self.exchange(upstream, &query));
                last = match tokio::time::timeout(options.timeout, exchange).await {
                    Err(_) => Error::Timeout(options.timeout),
                    Ok(Err(error)) => error,
                    Ok(Ok(response)) => match response.header.rcode {
                        Rcode::NOERROR | Rcode::NXDOMAIN => {
                            return Ok(Lookup::new(question, response)
                                .with_max_cname_chain(options.max_cname_chain));
                        }
                        rcode => Error::Rcode(rcode),
                    },
                };
            }
        }
        Err(last)
    }

    /// Sends one prepared query to one upstream, without timeout or retry,
    /// and returns the checked response whatever its `RCODE`.
    ///
    /// # Errors
    ///
    /// Transport errors, [`Error::Mismatch`] and [`Error::Truncated`].
    pub async fn exchange(&self, upstream: &Upstream, query: &Message) -> Result<Message, Error> {
        match upstream {
            Upstream::Udp(addr) => transport::udp(*addr, query).await,
            Upstream::Tcp(addr) => transport::tcp(*addr, query).await,
            #[cfg(feature = "tls")]
            Upstream::Tls { addr, server_name } => {
                transport::tls::exchange(Arc::clone(&self.inner.dot), *addr, server_name, query)
                    .await
            }
            #[cfg(feature = "doh")]
            Upstream::Https(endpoint) => {
                transport::doh::exchange(Arc::clone(&self.inner.doh), endpoint, query).await
            }
            #[cfg(not(feature = "tls"))]
            Upstream::Tls { .. } => Err(Error::InvalidUpstream {
                reason: "DNS over TLS needs the `tls` feature",
            }),
            #[cfg(not(feature = "doh"))]
            Upstream::Https(_) => Err(Error::InvalidUpstream {
                reason: "DNS over HTTPS needs the `doh` feature",
            }),
        }
    }

    /// Asks for `rtype` records of `name`, in class `IN`.
    ///
    /// # Errors
    ///
    /// As [`Resolver::query`], and [`Error::Wire`] for a malformed name.
    pub async fn lookup(&self, name: impl IntoName, rtype: RecordType) -> Result<Lookup, Error> {
        self.query(Question::new(name.into_name()?, rtype)).await
    }

    /// Like [`Resolver::lookup`], but `NXDOMAIN` is an error.
    async fn existing(&self, name: impl IntoName, rtype: RecordType) -> Result<Lookup, Error> {
        let lookup = self.lookup(name, rtype).await?;
        if lookup.is_nxdomain() {
            return Err(Error::NxDomain {
                name: lookup.question.name,
            });
        }
        Ok(lookup)
    }

    /// `A` addresses of `name`, following `CNAME`s. Empty when the name
    /// exists without `A` records.
    ///
    /// # Errors
    ///
    /// [`Error::NxDomain`], or as [`Resolver::query`].
    pub async fn lookup_a(&self, name: impl IntoName) -> Result<Vec<Ipv4Addr>, Error> {
        Ok(self.existing(name, RecordType::A).await?.ipv4())
    }

    /// `AAAA` addresses of `name`.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_aaaa(&self, name: impl IntoName) -> Result<Vec<Ipv6Addr>, Error> {
        Ok(self.existing(name, RecordType::AAAA).await?.ipv6())
    }

    /// `A` and `AAAA` addresses of `name`, asked concurrently, IPv4 first.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`]; an error for one family is returned only
    /// if the other family failed too or found nothing.
    pub async fn lookup_ip(&self, name: impl IntoName) -> Result<Vec<IpAddr>, Error> {
        let name = name.into_name()?;
        let (v4, v6) = tokio::join!(self.lookup_a(&name), self.lookup_aaaa(&name));
        match (v4, v6) {
            (Ok(v4), Ok(v6)) => Ok(v4
                .into_iter()
                .map(IpAddr::V4)
                .chain(v6.into_iter().map(IpAddr::V6))
                .collect()),
            (Ok(v4), Err(error)) if v4.is_empty() => Err(error),
            (Ok(v4), Err(_)) => Ok(v4.into_iter().map(IpAddr::V4).collect()),
            (Err(error), Ok(v6)) if v6.is_empty() => Err(error),
            (Err(_), Ok(v6)) => Ok(v6.into_iter().map(IpAddr::V6).collect()),
            (Err(error), Err(_)) => Err(error),
        }
    }

    /// The target of `name`'s `CNAME`, if it has one.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_cname(&self, name: impl IntoName) -> Result<Option<Name>, Error> {
        Ok(self
            .existing(name, RecordType::CNAME)
            .await?
            .names()
            .into_iter()
            .next())
    }

    /// `MX` records of `name`, by preference.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_mx(&self, name: impl IntoName) -> Result<Vec<Mx>, Error> {
        Ok(self.existing(name, RecordType::MX).await?.mx())
    }

    /// `TXT` records of `name`, each with its strings joined.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_txt(&self, name: impl IntoName) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.existing(name, RecordType::TXT).await?.txt())
    }

    /// `NS` names of `name`.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_ns(&self, name: impl IntoName) -> Result<Vec<Name>, Error> {
        Ok(self.existing(name, RecordType::NS).await?.names())
    }

    /// The `SOA` of `name`, when `name` is a zone apex.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_soa(&self, name: impl IntoName) -> Result<Option<Soa>, Error> {
        Ok(self.existing(name, RecordType::SOA).await?.soa())
    }

    /// `SRV` records of `name` (such as `_sip._tcp.example.com`), by
    /// priority and weight.
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_srv(&self, name: impl IntoName) -> Result<Vec<Srv>, Error> {
        Ok(self.existing(name, RecordType::SRV).await?.srv())
    }

    /// `PTR` names of `ip` (a reverse lookup).
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<Name>, Error> {
        Ok(self
            .existing(reverse_name(ip), RecordType::PTR)
            .await?
            .names())
    }

    /// `CAA` records at exactly `name` (no tree climbing; see RFC 8659 §3
    /// and `rune-dns-records` for the issuance decision).
    ///
    /// # Errors
    ///
    /// As [`Resolver::lookup_a`].
    pub async fn lookup_caa(&self, name: impl IntoName) -> Result<Vec<Caa>, Error> {
        Ok(self.existing(name, RecordType::CAA).await?.caa())
    }
}

/// Drives `rune-wildcard-dns` detection over this resolver (feature
/// `wildcard`). `NXDOMAIN` and `NOERROR` come back as answers with the whole
/// answer section (`CNAME` chain included); when every upstream fails with
/// a code such as `SERVFAIL`, that code is returned as the response, as the
/// trait asks. Transport failures and timeouts are errors.
#[cfg(feature = "wildcard")]
impl rune_wildcard_dns::AsyncResolver for Resolver {
    type Error = Error;

    fn resolve(
        &mut self,
        name: &Name,
        rtype: RecordType,
    ) -> impl Future<Output = Result<rune_wildcard_dns::Response, Error>> + Send {
        let resolver = self.clone();
        let question = Question::new(name.clone(), rtype);
        async move {
            match resolver.query(question).await {
                Ok(lookup) => Ok(rune_wildcard_dns::Response::from(lookup.response)),
                Err(Error::Rcode(rcode)) => Ok(rune_wildcard_dns::Response::new(rcode, Vec::new())),
                Err(error) => Err(error),
            }
        }
    }
}
