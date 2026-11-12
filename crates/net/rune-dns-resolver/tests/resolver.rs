//! The resolver against mock DNS servers on the loopback interface: UDP,
//! TCP, DNS over TLS and DNS over HTTPS. No test here leaves the machine;
//! the `online` tests at the end query public resolvers and are ignored by
//! default.

#![cfg(feature = "tokio")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test servers and helpers fail the test on bad input"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rune_dns_resolver::{Error, Resolver, ResolverOptions, Upstream};
use rune_dns_wire::{Caa, Message, Mx, Name, RData, Rcode, Record, RecordType, Soa, Srv};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// How a query reached a mock server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(feature = "doh"),
    allow(
        dead_code,
        reason = "the TLS and HTTPS variants are used by feature-gated tests"
    )
)]
enum Via {
    Udp,
    Tcp,
    Tls,
    Https,
}

/// What a mock sends back: zero or more raw messages after a delay.
struct Reply {
    messages: Vec<Vec<u8>>,
    delay: Duration,
}

impl Reply {
    fn one(message: &Message) -> Self {
        Self {
            messages: vec![message.encode().unwrap()],
            delay: Duration::ZERO,
        }
    }

    const fn silent() -> Self {
        Self {
            messages: Vec::new(),
            delay: Duration::ZERO,
        }
    }

    const fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

type Handler = Arc<dyn Fn(Via, &Message) -> Reply + Send + Sync>;

/// A mock server's address and what it saw.
#[derive(Clone)]
struct Mock {
    addr: SocketAddr,
    hits: Arc<Mutex<Vec<(Via, Message)>>>,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
}

impl Mock {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            hits: Arc::default(),
            in_flight: Arc::default(),
            max_in_flight: Arc::default(),
        }
    }

    fn vias(&self) -> Vec<Via> {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .map(|(via, _)| *via)
            .collect()
    }

    /// Records a query and runs the handler, tracking queries in flight
    /// until the reply has been sent (see `done`).
    fn handle(&self, handler: &Handler, via: Via, bytes: &[u8]) -> Option<Reply> {
        let query = Message::decode(bytes).ok()?;
        self.hits.lock().unwrap().push((via, query.clone()));
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        Some(handler(via, &query))
    }

    fn done(&self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn soa() -> Soa {
    Soa {
        mname: name("ns.test"),
        rname: name("hostmaster.test"),
        serial: 7,
        refresh: 1,
        retry: 2,
        expire: 3,
        minimum: 4,
    }
}

/// The mock zone `test.`.
fn zone(query: &Message) -> Message {
    let question = &query.questions[0];
    let qname = question.name.to_ascii_lowercase();
    let response = Message::response_to(query).with_recursion_available(true);
    let rec = |owner: &str, data: RData| Record::new(name(owner), 300, data);
    let records: Vec<Record> = match (qname.to_string().as_str(), question.qtype) {
        ("nx.test", _) => return response.with_rcode(Rcode::NXDOMAIN),
        ("a.test", RecordType::A) => vec![rec("a.test", RData::A(Ipv4Addr::new(192, 0, 2, 1)))],
        ("a.test", RecordType::AAAA) => {
            vec![rec(
                "a.test",
                RData::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            )]
        }
        ("alias.test", RecordType::A | RecordType::CNAME) => {
            let mut records = vec![rec("alias.test", RData::Cname(name("a.test")))];
            if question.qtype == RecordType::A {
                records.push(rec("a.test", RData::A(Ipv4Addr::new(192, 0, 2, 1))));
            }
            records
        }
        ("test", RecordType::MX) => vec![
            rec(
                "test",
                RData::Mx(Mx {
                    preference: 20,
                    exchange: name("mx2.test"),
                }),
            ),
            rec(
                "test",
                RData::Mx(Mx {
                    preference: 10,
                    exchange: name("mx1.test"),
                }),
            ),
        ],
        ("test", RecordType::TXT) => vec![rec(
            "test",
            RData::Txt(vec![b"v=spf1 ".to_vec(), b"-all".to_vec()]),
        )],
        ("test", RecordType::NS) => vec![rec("test", RData::Ns(name("ns.test")))],
        ("test", RecordType::SOA) => vec![rec("test", RData::Soa(soa()))],
        ("test", RecordType::CAA) => vec![rec(
            "test",
            RData::Caa(Caa {
                flags: 0,
                tag: "issue".into(),
                value: b"ca.test".to_vec(),
            }),
        )],
        ("_sip._tcp.test", RecordType::SRV) => vec![rec(
            "_sip._tcp.test",
            RData::Srv(Srv {
                priority: 1,
                weight: 5,
                port: 5060,
                target: name("sip.test"),
            }),
        )],
        ("1.2.0.192.in-addr.arpa", RecordType::PTR) => {
            vec![rec("1.2.0.192.in-addr.arpa", RData::Ptr(name("a.test")))]
        }
        ("big.test", RecordType::A) => (0..100u8)
            .map(|i| rec("big.test", RData::A(Ipv4Addr::new(10, 0, 0, i))))
            .collect(),
        _ => Vec::new(),
    };
    records.into_iter().fold(response, Message::with_answer)
}

fn zone_handler() -> Handler {
    Arc::new(|via, query| {
        let response = zone(query);
        // Over UDP, honour the 512-octet limit of a client without EDNS
        // (and the advertised size of one with it), setting TC.
        if via == Via::Udp {
            let limit = query
                .edns
                .as_ref()
                .map_or(512, |edns| usize::from(edns.udp_payload_size));
            return Reply {
                messages: vec![response.encode_with_limit(limit).unwrap()],
                delay: Duration::ZERO,
            };
        }
        Reply::one(&response)
    })
}

/// Starts UDP and TCP listeners on the same loopback port.
async fn mock(handler: Handler) -> Mock {
    let (tcp, udp) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await {
            break (tcp, udp);
        }
    };
    let mock = Mock::new(tcp.local_addr().unwrap());

    let udp = Arc::new(udp);
    let (server, udp_handler) = (mock.clone(), Arc::clone(&handler));
    tokio::spawn(async move {
        let mut buffer = vec![0; 65_535];
        loop {
            let Ok((len, peer)) = udp.recv_from(&mut buffer).await else {
                return;
            };
            let Some(reply) = server.handle(&udp_handler, Via::Udp, &buffer[..len]) else {
                continue;
            };
            let (socket, server) = (Arc::clone(&udp), server.clone());
            tokio::spawn(async move {
                tokio::time::sleep(reply.delay).await;
                for message in reply.messages {
                    let _ = socket.send_to(&message, peer).await;
                }
                server.done();
            });
        }
    });

    let server = mock.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else {
                return;
            };
            let (server, handler) = (server.clone(), Arc::clone(&handler));
            tokio::spawn(async move { serve_stream(stream, &server, &handler, Via::Tcp).await });
        }
    });
    mock
}

/// Serves length-prefixed messages on one stream connection.
async fn serve_stream<S>(mut stream: S, server: &Mock, handler: &Handler, via: Via)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut prefix = [0; 2];
        if stream.read_exact(&mut prefix).await.is_err() {
            return;
        }
        let mut body = vec![0; usize::from(u16::from_be_bytes(prefix))];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }
        let Some(reply) = server.handle(handler, via, &body) else {
            return;
        };
        tokio::time::sleep(reply.delay).await;
        for message in reply.messages {
            let len = u16::try_from(message.len()).unwrap().to_be_bytes();
            if stream.write_all(&len).await.is_err() || stream.write_all(&message).await.is_err() {
                server.done();
                return;
            }
        }
        server.done();
    }
}

fn options(upstreams: impl IntoIterator<Item = Upstream>) -> ResolverOptions {
    ResolverOptions::default()
        .with_upstreams(upstreams)
        .with_timeout(Duration::from_millis(500))
        .with_attempts(1)
}

fn new_resolver(options: ResolverOptions) -> Resolver {
    Resolver::new(options).unwrap()
}

#[tokio::test]
async fn typed_lookups_over_udp() {
    let server = mock(zone_handler()).await;
    let resolver = new_resolver(options([Upstream::udp(server.addr)]));

    assert_eq!(
        resolver.lookup_a("a.test").await.unwrap(),
        [Ipv4Addr::new(192, 0, 2, 1)]
    );
    assert_eq!(
        resolver.lookup_aaaa("A.TEST").await.unwrap(),
        ["2001:db8::1".parse::<Ipv6Addr>().unwrap()]
    );
    // The CNAME chain is followed inside the answer.
    assert_eq!(
        resolver.lookup_a(name("alias.test")).await.unwrap(),
        [Ipv4Addr::new(192, 0, 2, 1)]
    );
    assert_eq!(
        resolver.lookup_cname("alias.test").await.unwrap(),
        Some(name("a.test"))
    );
    assert_eq!(resolver.lookup_cname("a.test").await.unwrap(), None);
    let mx: Vec<u16> = resolver
        .lookup_mx("test")
        .await
        .unwrap()
        .iter()
        .map(|mx| mx.preference)
        .collect();
    assert_eq!(mx, [10, 20]);
    assert_eq!(
        resolver.lookup_txt("test".to_owned()).await.unwrap(),
        [b"v=spf1 -all".to_vec()]
    );
    assert_eq!(resolver.lookup_ns("test").await.unwrap(), [name("ns.test")]);
    assert_eq!(resolver.lookup_soa("test").await.unwrap(), Some(soa()));
    assert_eq!(
        resolver.lookup_srv("_sip._tcp.test").await.unwrap()[0].port,
        5060
    );
    assert_eq!(
        resolver
            .lookup_ptr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
            .await
            .unwrap(),
        [name("a.test")]
    );
    assert_eq!(resolver.lookup_caa("test").await.unwrap()[0].tag, "issue");
    assert_eq!(
        resolver.lookup_ip("a.test").await.unwrap(),
        [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6("2001:db8::1".parse().unwrap())
        ]
    );

    // Queries carry EDNS(0) and RD, and random ids.
    let hits = server.hits.lock().unwrap().clone();
    assert!(hits.iter().all(|(via, query)| *via == Via::Udp
        && query.header.recursion_desired
        && query.edns.as_ref().map(|e| e.udp_payload_size) == Some(1232)));
    let ids: std::collections::HashSet<u16> = hits.iter().map(|(_, q)| q.header.id).collect();
    assert!(ids.len() > hits.len() / 2, "ids are not random: {ids:?}");
}

#[tokio::test]
async fn nxdomain_and_nodata() {
    let server = mock(zone_handler()).await;
    let resolver = new_resolver(options([Upstream::udp(server.addr)]));
    match resolver.lookup_a("nx.test").await {
        Err(Error::NxDomain { name: missing }) => assert_eq!(missing, name("nx.test")),
        other => panic!("{other:?}"),
    }
    let lookup = resolver.lookup("nx.test", RecordType::A).await.unwrap();
    assert_eq!(lookup.rcode(), Rcode::NXDOMAIN);
    // NODATA: the name exists without records of the type.
    assert_eq!(resolver.lookup_mx("a.test").await.unwrap(), []);
    assert!(matches!(
        resolver.lookup_a("bad..name").await,
        Err(Error::Wire(_))
    ));
}

#[tokio::test]
async fn truncated_udp_answer_is_retried_over_tcp() {
    let server = mock(zone_handler()).await;
    // Without EDNS the 100-address answer does not fit in 512 octets.
    let resolver = new_resolver(options([Upstream::udp(server.addr)]).with_udp_payload_size(None));
    let addresses = resolver.lookup_a("big.test").await.unwrap();
    assert_eq!(addresses.len(), 100);
    assert_eq!(server.vias(), [Via::Udp, Via::Tcp]);

    // With a large enough EDNS size, UDP alone suffices.
    let server = mock(zone_handler()).await;
    let resolver =
        new_resolver(options([Upstream::udp(server.addr)]).with_udp_payload_size(Some(4096)));
    assert_eq!(resolver.lookup_a("big.test").await.unwrap().len(), 100);
    assert_eq!(server.vias(), [Via::Udp]);
}

#[tokio::test]
async fn tcp_upstream_and_truncation_over_tcp() {
    let server = mock(zone_handler()).await;
    let resolver = new_resolver(options([Upstream::tcp(server.addr)]));
    assert_eq!(resolver.lookup_a("big.test").await.unwrap().len(), 100);
    assert_eq!(server.vias(), [Via::Tcp]);

    let truncating = mock(Arc::new(|_, query: &Message| {
        let mut response = zone(query);
        response.header.truncated = true;
        Reply::one(&response)
    }))
    .await;
    let resolver = new_resolver(options([Upstream::tcp(truncating.addr)]));
    assert!(matches!(
        resolver.lookup_a("a.test").await,
        Err(Error::Truncated)
    ));
}

#[tokio::test]
async fn timeout_then_failover() {
    let silent = mock(Arc::new(|_, _: &Message| Reply::silent())).await;
    let good = mock(zone_handler()).await;
    let resolver = new_resolver(
        options([Upstream::udp(silent.addr), Upstream::udp(good.addr)])
            .with_timeout(Duration::from_millis(150)),
    );
    let started = Instant::now();
    assert_eq!(resolver.lookup_a("a.test").await.unwrap().len(), 1);
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert_eq!(silent.vias(), [Via::Udp]);
    assert_eq!(good.vias(), [Via::Udp]);
}

#[tokio::test]
async fn timeouts_are_retried_for_each_attempt() {
    let silent = mock(Arc::new(|_, _: &Message| Reply::silent())).await;
    let resolver = new_resolver(
        options([Upstream::udp(silent.addr)])
            .with_timeout(Duration::from_millis(50))
            .with_attempts(3),
    );
    let started = Instant::now();
    match resolver.lookup_a("a.test").await {
        Err(Error::Timeout(timeout)) => assert_eq!(timeout, Duration::from_millis(50)),
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(silent.vias().len(), 3);

    // A slow TCP server times out the same way.
    let slow = mock(Arc::new(|_, query: &Message| {
        Reply::one(&zone(query)).after(Duration::from_secs(5))
    }))
    .await;
    let resolver =
        new_resolver(options([Upstream::tcp(slow.addr)]).with_timeout(Duration::from_millis(50)));
    assert!(matches!(
        resolver.lookup_a("a.test").await,
        Err(Error::Timeout(_))
    ));
}

#[tokio::test]
async fn refused_port_fails_over_quickly() {
    // A UDP port nobody listens on: the ICMP error surfaces as an I/O
    // error well before the timeout.
    let closed = {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    };
    let good = mock(zone_handler()).await;
    let resolver = new_resolver(
        options([Upstream::udp(closed), Upstream::udp(good.addr)])
            .with_timeout(Duration::from_secs(5)),
    );
    let started = Instant::now();
    assert_eq!(resolver.lookup_a("a.test").await.unwrap().len(), 1);
    assert!(started.elapsed() < Duration::from_secs(2));

    let only_closed = resolver_for_closed(closed);
    assert!(matches!(
        only_closed.lookup_a("a.test").await,
        Err(Error::Io(_))
    ));
}

fn resolver_for_closed(addr: SocketAddr) -> Resolver {
    new_resolver(options([Upstream::udp(addr)]).with_timeout(Duration::from_secs(5)))
}

#[tokio::test]
async fn spoofed_answers_are_ignored() {
    let server = mock(Arc::new(|_, query: &Message| {
        let forged = |mut message: Message| {
            message.answers = vec![Record::new(
                name("a.test"),
                1,
                RData::A(Ipv4Addr::new(203, 0, 113, 66)),
            )];
            message.encode().unwrap()
        };
        let wrong_id = forged(zone(query).with_id(query.header.id.wrapping_add(1)));
        let mut other_question = zone(query);
        other_question.questions[0].name = name("b.test");
        let wrong_question = forged(other_question);
        Reply {
            messages: vec![
                b"garbage".to_vec(),
                wrong_id,
                wrong_question,
                zone(query).encode().unwrap(),
            ],
            delay: Duration::ZERO,
        }
    }))
    .await;
    let resolver = new_resolver(options([Upstream::udp(server.addr)]));
    assert_eq!(
        resolver.lookup_a("a.test").await.unwrap(),
        [Ipv4Addr::new(192, 0, 2, 1)]
    );
}

#[tokio::test]
async fn failure_codes_move_on() {
    let failing = mock(Arc::new(|_, query: &Message| {
        Reply::one(&Message::response_to(query).with_rcode(Rcode::SERVFAIL))
    }))
    .await;
    let good = mock(zone_handler()).await;
    let resolver = new_resolver(options([
        Upstream::udp(failing.addr),
        Upstream::udp(good.addr),
    ]));
    assert_eq!(resolver.lookup_a("a.test").await.unwrap().len(), 1);

    let refusing = mock(Arc::new(|_, query: &Message| {
        let mut response = Message::response_to(query).with_rcode(Rcode::REFUSED);
        response.questions.clear();
        Reply::one(&response)
    }))
    .await;
    let resolver = new_resolver(
        options([Upstream::udp(failing.addr), Upstream::udp(refusing.addr)]).with_attempts(2),
    );
    match resolver.lookup_a("a.test").await {
        Err(Error::Rcode(rcode)) => assert_eq!(rcode, Rcode::REFUSED),
        other => panic!("{other:?}"),
    }
    assert_eq!(failing.vias().len(), 3);
    assert_eq!(refusing.vias().len(), 2);
}

#[tokio::test]
async fn concurrency_is_capped() {
    let slow_zone: Handler =
        Arc::new(|_, query: &Message| Reply::one(&zone(query)).after(Duration::from_millis(40)));
    for (cap, expect_at_most) in [(2, 2), (16, 16)] {
        let server = mock(Arc::clone(&slow_zone)).await;
        let resolver = new_resolver(options([Upstream::udp(server.addr)]).with_concurrency(cap));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let resolver = resolver.clone();
            tasks.spawn(async move { resolver.lookup_a("a.test").await });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(result.unwrap().unwrap().len(), 1);
        }
        let max = server.max_in_flight.load(Ordering::SeqCst);
        assert!(max <= expect_at_most, "cap {cap}: {max} in flight");
        if cap > 2 {
            assert!(max > 2, "the server saw no parallelism: {max}");
        }
    }
}

#[tokio::test]
async fn configuration_errors() {
    assert!(matches!(
        Resolver::new(ResolverOptions::default()),
        Err(Error::NoUpstreams)
    ));
    let resolver = new_resolver(options([Upstream::udp("127.0.0.1:9".parse().unwrap())]));
    assert_eq!(resolver.options().attempts, 1);
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn tls_needs_its_feature() {
    let resolver = new_resolver(options([Upstream::tls(
        "127.0.0.1:853".parse().unwrap(),
        "x",
    )]));
    assert!(matches!(
        resolver.lookup_a("a.test").await,
        Err(Error::InvalidUpstream { .. })
    ));
}

#[cfg(feature = "wildcard")]
#[tokio::test]
async fn wildcard_dns_adapter() {
    use rune_wildcard_dns::AsyncResolver;

    let server = mock(zone_handler()).await;
    let mut resolver = new_resolver(options([Upstream::udp(server.addr)]));
    let response = resolver
        .resolve(&name("alias.test"), RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.rcode, Rcode::NOERROR);
    assert_eq!(response.answers.len(), 2, "the CNAME chain is included");
    let response = resolver
        .resolve(&name("nx.test"), RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.rcode, Rcode::NXDOMAIN);

    let failing = mock(Arc::new(|_, query: &Message| {
        Reply::one(&Message::response_to(query).with_rcode(Rcode::SERVFAIL))
    }))
    .await;
    let mut resolver = resolver_for(failing.addr);
    let response = resolver
        .resolve(&name("a.test"), RecordType::A)
        .await
        .unwrap();
    assert_eq!(response.rcode, Rcode::SERVFAIL);
    assert!(!response.is_answer());

    let silent = mock(Arc::new(|_, _: &Message| Reply::silent())).await;
    let mut resolver =
        new_resolver(options([Upstream::udp(silent.addr)]).with_timeout(Duration::from_millis(30)));
    assert!(matches!(
        resolver.resolve(&name("a.test"), RecordType::A).await,
        Err(Error::Timeout(_))
    ));
}

#[cfg(feature = "wildcard")]
fn resolver_for(addr: SocketAddr) -> Resolver {
    new_resolver(options([Upstream::udp(addr)]))
}

#[cfg(feature = "tls")]
mod tls {
    //! DNS over TLS and HTTPS against mocks with a test CA
    //! (`tests/fixtures`: a P-256 CA and a leaf for `dns.test` and
    //! `127.0.0.1`, valid until 2126).

    use std::sync::Arc;

    use rune_dns_resolver::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rune_dns_resolver::rustls::{self, ClientConfig, RootCertStore, ServerConfig};
    use tokio_rustls::TlsAcceptor;

    use super::*;

    const CA: &[u8] = include_bytes!("fixtures/ca.der");
    const CERT: &[u8] = include_bytes!("fixtures/server.der");
    const KEY: &[u8] = include_bytes!("fixtures/server.key.der");

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    pub fn client_config() -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(CA.to_vec())).unwrap();
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    pub fn acceptor(alpn: &[&[u8]]) -> TlsAcceptor {
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERT.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
            )
            .unwrap();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsAcceptor::from(Arc::new(config))
    }

    pub fn tls_resolver(upstream: Upstream) -> Resolver {
        Resolver::with_tls_config(options([upstream]), &client_config()).unwrap()
    }

    async fn dot_mock(handler: Handler) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock = Mock::new(listener.local_addr().unwrap());
        let server = mock.clone();
        let acceptor = acceptor(&[b"dot"]);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (server, handler, acceptor) =
                    (server.clone(), Arc::clone(&handler), acceptor.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"dot"[..]));
                        serve_stream(stream, &server, &handler, Via::Tls).await;
                    }
                });
            }
        });
        mock
    }

    #[tokio::test]
    async fn dns_over_tls() {
        let server = dot_mock(zone_handler()).await;
        let resolver = tls_resolver(Upstream::tls(server.addr, "dns.test"));
        assert_eq!(
            resolver.lookup_a("a.test").await.unwrap(),
            [Ipv4Addr::new(192, 0, 2, 1)]
        );
        // The 100-address answer needs no fallback over a stream.
        assert_eq!(resolver.lookup_a("big.test").await.unwrap().len(), 100);
        assert_eq!(server.vias(), [Via::Tls, Via::Tls]);

        // The certificate also names 127.0.0.1, the text form's default.
        let by_ip = tls_resolver(format!("tls://{}", server.addr).parse().unwrap());
        assert_eq!(by_ip.lookup_a("a.test").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dns_over_tls_checks_the_certificate() {
        let server = dot_mock(zone_handler()).await;
        let wrong_name = tls_resolver(Upstream::tls(server.addr, "other.test"));
        assert!(matches!(
            wrong_name.lookup_a("a.test").await,
            Err(Error::Tls(_))
        ));

        // The default config trusts the webpki roots, not the test CA.
        let untrusted = Resolver::new(options([Upstream::tls(server.addr, "dns.test")])).unwrap();
        assert!(matches!(
            untrusted.lookup_a("a.test").await,
            Err(Error::Tls(_))
        ));

        let bad_name = tls_resolver(Upstream::tls(server.addr, "bad name"));
        assert!(matches!(
            bad_name.lookup_a("a.test").await,
            Err(Error::InvalidUpstream { .. })
        ));
        assert_eq!(server.vias(), []);
    }
}

#[cfg(feature = "doh")]
mod doh {
    //! DNS over HTTPS against a hyper server: HTTP/2 and HTTP/1.1 over TLS,
    //! and plain HTTP.

    use std::convert::Infallible;

    use bytes::Bytes;
    use http::{Request, Response, StatusCode, Version};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rune_dns_resolver::DohEndpoint;

    use super::tls::{acceptor, tls_resolver};
    use super::*;

    /// What the HTTP server saw for each request.
    #[derive(Debug, Clone)]
    struct Seen {
        version: Version,
        method: String,
        path: String,
        host: Option<String>,
        content_type: Option<String>,
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Http1,
        Http2,
        Plain,
        Status(u16),
        WrongType,
    }

    async fn doh_mock(mode: Mode) -> (Mock, Arc<Mutex<Vec<Seen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock = Mock::new(listener.local_addr().unwrap());
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let handler = zone_handler();
        let (server, log) = (mock.clone(), Arc::clone(&seen));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (server, log, handler) =
                    (server.clone(), Arc::clone(&log), Arc::clone(&handler));
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let (server, log, handler) =
                            (server.clone(), Arc::clone(&log), Arc::clone(&handler));
                        async move {
                            let header = |name| {
                                request
                                    .headers()
                                    .get(name)
                                    .and_then(|v: &http::HeaderValue| v.to_str().ok())
                                    .map(str::to_owned)
                            };
                            log.lock().unwrap().push(Seen {
                                version: request.version(),
                                method: request.method().to_string(),
                                path: request.uri().path().to_owned(),
                                host: header(http::header::HOST),
                                content_type: header(http::header::CONTENT_TYPE),
                            });
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            let reply = server.handle(&handler, Via::Https, &body);
                            server.done();
                            let message = reply
                                .and_then(|r| r.messages.into_iter().next())
                                .unwrap_or_default();
                            let (status, content_type) = match mode {
                                Mode::Status(code) => (code, "application/dns-message"),
                                Mode::WrongType => (200, "text/html"),
                                _ => (200, "application/dns-message"),
                            };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::from_u16(status).unwrap())
                                    .header(http::header::CONTENT_TYPE, content_type)
                                    .body(Full::new(Bytes::from(message)))
                                    .unwrap(),
                            )
                        }
                    });
                    if matches!(mode, Mode::Plain) {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                        return;
                    }

                    let alpn: &[&[u8]] = match mode {
                        Mode::Http1 => &[b"http/1.1"],
                        _ => &[b"h2", b"http/1.1"],
                    };
                    let Ok(stream) = acceptor(alpn).accept(stream).await else {
                        return;
                    };
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    let io = TokioIo::new(stream);
                    if h2 {
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(io, service)
                            .await;
                    } else {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await;
                    }
                });
            }
        });
        (mock, seen)
    }

    fn https(server: &Mock, scheme: &str) -> Upstream {
        let url = format!("{scheme}://dns.test:{}/dns-query", server.addr.port());
        Upstream::Https(DohEndpoint::parse(&url).unwrap().with_addr(server.addr))
    }

    #[tokio::test]
    async fn doh_over_http2() {
        let (server, seen) = doh_mock(Mode::Http2).await;
        let resolver = tls_resolver(https(&server, "https"));
        assert_eq!(
            resolver.lookup_a("alias.test").await.unwrap(),
            [Ipv4Addr::new(192, 0, 2, 1)]
        );
        assert_eq!(resolver.lookup_a("big.test").await.unwrap().len(), 100);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].version, Version::HTTP_2);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, "/dns-query");
        assert_eq!(
            seen[0].content_type.as_deref(),
            Some("application/dns-message")
        );
        // RFC 8484 §4.1: id 0 over HTTPS.
        assert!(
            server
                .hits
                .lock()
                .unwrap()
                .iter()
                .all(|(_, q)| q.header.id == 0)
        );
    }

    #[tokio::test]
    async fn doh_over_http1() {
        let (server, seen) = doh_mock(Mode::Http1).await;
        let resolver = tls_resolver(https(&server, "https"));
        assert_eq!(resolver.lookup_mx("test").await.unwrap().len(), 2);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0].version, Version::HTTP_11);
        assert_eq!(
            seen[0].host.as_deref(),
            Some(format!("dns.test:{}", server.addr.port()).as_str())
        );
    }

    #[tokio::test]
    async fn doh_over_plain_http() {
        let (server, _) = doh_mock(Mode::Plain).await;
        let resolver = Resolver::new(options([https(&server, "http")])).unwrap();
        assert!(matches!(
            resolver.lookup_a("nx.test").await,
            Err(Error::NxDomain { .. })
        ));
        assert_eq!(server.vias(), [Via::Https]);
    }

    #[tokio::test]
    async fn doh_http_errors() {
        let (server, _) = doh_mock(Mode::Status(500)).await;
        let resolver = tls_resolver(https(&server, "https"));
        assert!(matches!(
            resolver.lookup_a("a.test").await,
            Err(Error::HttpStatus(500))
        ));

        let (server, _) = doh_mock(Mode::WrongType).await;
        let resolver = tls_resolver(https(&server, "https"));
        assert!(matches!(
            resolver.lookup_a("a.test").await,
            Err(Error::Http(_))
        ));
    }

    #[tokio::test]
    async fn doh_timeout_fails_over_to_udp() {
        // Nothing answers HTTPS on this port; the UDP mock then answers.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blackhole = Mock::new(listener.local_addr().unwrap());
        let good = mock(zone_handler()).await;
        let resolver = Resolver::with_tls_config(
            options([https(&blackhole, "https"), Upstream::udp(good.addr)])
                .with_timeout(Duration::from_millis(100)),
            &super::tls::client_config(),
        )
        .unwrap();
        assert_eq!(resolver.lookup_a("a.test").await.unwrap().len(), 1);
        drop(listener);
    }
}

#[cfg(feature = "online")]
mod online {
    //! Queries to public resolvers: `cargo test --features online -- --ignored`.

    use super::*;

    async fn check(upstream: &str) {
        let resolver = Resolver::new(
            ResolverOptions::default()
                .with_upstream(upstream.parse().unwrap())
                .with_timeout(Duration::from_secs(5)),
        )
        .unwrap();
        let addresses = resolver.lookup_ip("one.one.one.one").await.unwrap();
        assert!(
            addresses.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            "{upstream}"
        );
        assert_ne!(resolver.lookup_mx("gmail.com").await.unwrap().len(), 0);
    }

    #[tokio::test]
    #[ignore = "queries public resolvers"]
    async fn cloudflare_udp() {
        check("1.1.1.1").await;
    }

    #[tokio::test]
    #[ignore = "queries public resolvers"]
    async fn cloudflare_tls() {
        check("tls://1.1.1.1#cloudflare-dns.com").await;
    }

    #[tokio::test]
    #[ignore = "queries public resolvers"]
    async fn cloudflare_https() {
        check("https://cloudflare-dns.com/dns-query").await;
    }

    #[tokio::test]
    #[ignore = "queries public resolvers"]
    async fn google_https() {
        check("https://dns.google/dns-query").await;
    }
}
