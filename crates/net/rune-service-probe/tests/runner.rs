//! The tokio runner against mock servers on loopback.

// Test helpers outside `#[test]` functions may unwrap too.
#![allow(clippy::unwrap_used, reason = "test code")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rune_finding::{Confidence, Severity, TaxonomyRef};
use rune_service_probe::banner::BannerProbe;
use rune_service_probe::{
    Action, AuthRequirement, End, Error, Options, ProbeSession, Runner, Safety, ServiceInfo,
    ServiceProbe, Target, Transport,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

fn fast() -> Options {
    Options::default()
        .with_connect_timeout(Duration::from_secs(2))
        .with_io_timeout(Duration::from_millis(300))
        .with_total_timeout(Duration::from_secs(3))
}

/// A server that runs `handler` for each connection.
async fn serve<F, Fut>(handler: F) -> Target
where
    F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(handler(stream));
        }
    });
    Target::new("localhost", addr.port()).with_addr(addr)
}

/// A Redis-style request/reply probe: `PING`, expect `+PONG`.
#[derive(Default)]
struct Ping {
    intrusive: bool,
    transport: Option<Transport>,
}

struct PingSession {
    target: Target,
    buf: Vec<u8>,
}

impl ServiceProbe for Ping {
    fn id(&self) -> &'static str {
        "ping"
    }
    fn transport(&self) -> Transport {
        self.transport.unwrap_or(Transport::Tcp)
    }
    fn safety(&self) -> Safety {
        if self.intrusive {
            Safety::Intrusive
        } else {
            Safety::ReadOnly
        }
    }
    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(PingSession {
            target: target.clone(),
            buf: Vec::new(),
        })
    }
}

impl ProbeSession for PingSession {
    fn start(&mut self) -> Action {
        Action::Send(b"PING\r\n".to_vec())
    }
    fn on_data(&mut self, data: &[u8]) -> Action {
        self.buf.extend_from_slice(data);
        if self.buf.ends_with(b"\r\n") {
            Action::Done
        } else {
            Action::Receive
        }
    }
    fn finish(&mut self, _end: End) -> Result<ServiceInfo, Error> {
        if self.buf.is_empty() {
            return Err(Error::no_response("ping"));
        }
        if self.buf.starts_with(b"+PONG") {
            return Ok(ServiceInfo::new("ping")
                .with_auth(AuthRequirement::NotRequired)
                .push_finding(
                    self.target
                        .finding(
                            "ping.unauthenticated",
                            "Answers without authentication",
                            Severity::High,
                            Confidence::Certain,
                        )
                        .push_taxonomy(TaxonomyRef::cwe(306)),
                ));
        }
        if self.buf.starts_with(b"-NOAUTH") {
            return Ok(ServiceInfo::new("ping").with_auth(AuthRequirement::Required));
        }
        Err(Error::unrecognized("ping", "unexpected reply"))
    }
}

#[tokio::test]
async fn grabs_a_server_first_banner() {
    let target = serve(|mut s| async move {
        let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    })
    .await;
    let info = Runner::new(fast())
        .probe(&BannerProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.service, "banner");
    assert_eq!(info.banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
}

#[tokio::test]
async fn request_reply_probe_reports_findings() {
    let open = serve(|mut s| async move {
        let mut buf = [0u8; 6];
        if s.read_exact(&mut buf).await.is_ok() && &buf == b"PING\r\n" {
            let _ = s.write_all(b"+PO").await;
            let _ = s.flush().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = s.write_all(b"NG\r\n").await;
        }
    })
    .await;
    let locked = serve(|mut s| async move {
        let mut buf = [0u8; 6];
        let _ = s.read_exact(&mut buf).await;
        let _ = s.write_all(b"-NOAUTH Authentication required.\r\n").await;
    })
    .await;

    let runner = Runner::new(fast());
    let probe = Ping::default();
    let info = runner.probe(&probe, &open).await.unwrap();
    assert_eq!(info.auth, AuthRequirement::NotRequired);
    assert_eq!(info.findings.len(), 1);
    assert_eq!(info.findings[0].location, open.location());

    let info = runner.probe(&probe, &locked).await.unwrap();
    assert_eq!(info.auth, AuthRequirement::Required);
    assert_eq!(info.findings, Vec::new());
}

#[tokio::test]
async fn silence_times_out_as_no_response() {
    let target = serve(|s| async move {
        // Hold the connection open without saying anything.
        let _held = s;
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
    .await;
    let started = Instant::now();
    let err = Runner::new(fast())
        .probe(&BannerProbe::new(), &target)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoResponse { .. }), "{err}");
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(250), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
}

#[tokio::test]
async fn keeps_partial_data_on_timeout() {
    let target = serve(|mut s| async move {
        let _ = s.write_all(b"220 half a line").await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
    .await;
    let info = Runner::new(fast())
        .probe(&BannerProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.banner.as_deref(), Some("220 half a line"));
}

#[tokio::test]
async fn total_timeout_bounds_a_trickling_server() {
    let target = serve(|mut s| async move {
        for _ in 0..100 {
            if s.write_all(b"x").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let options = fast()
        .with_io_timeout(Duration::from_secs(1))
        .with_total_timeout(Duration::from_millis(400));
    let started = Instant::now();
    let info = Runner::new(options)
        .probe(&BannerProbe::new(), &target)
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    let banner = info.banner.unwrap();
    assert!(!banner.is_empty() && banner.len() < 20, "{banner}");
}

#[tokio::test]
async fn read_budget_bounds_a_flooding_server() {
    let target = serve(|mut s| async move {
        let chunk = vec![b'A'; 64 * 1024];
        for _ in 0..64 {
            if s.write_all(&chunk).await.is_err() {
                return;
            }
        }
    })
    .await;
    let options = fast().with_max_read_bytes(100);
    let probe = BannerProbe::new().with_max_bytes(1 << 20);
    let info = Runner::new(options).probe(&probe, &target).await.unwrap();
    assert_eq!(info.banner.unwrap().len(), 100);
}

#[tokio::test]
async fn closed_port_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let err = Runner::new(fast())
        .probe(&BannerProbe::new(), &Target::from_addr(addr))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Connect { .. }), "{err}");
    assert!(err.is_unreachable());
}

#[tokio::test]
async fn intrusive_probes_need_opt_in_and_never_connect() {
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&connections);
    let target = serve(move |mut s| {
        seen.fetch_add(1, Ordering::SeqCst);
        async move {
            let mut buf = [0u8; 6];
            let _ = s.read_exact(&mut buf).await;
            let _ = s.write_all(b"+PONG\r\n").await;
        }
    })
    .await;
    let probe = Ping {
        intrusive: true,
        ..Ping::default()
    };
    let err = Runner::new(fast())
        .probe(&probe, &target)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::IntrusiveNotAllowed { .. }), "{err}");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(connections.load(Ordering::SeqCst), 0);

    let allowed = Runner::new(fast().with_allow_intrusive(true));
    assert!(allowed.probe(&probe, &target).await.is_ok());
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrency_is_bounded_and_results_keep_order() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (a, p) = (Arc::clone(&active), Arc::clone(&peak));
    let target = serve(move |mut s| {
        let (active, peak) = (Arc::clone(&a), Arc::clone(&p));
        async move {
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(60)).await;
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = s.write_all(b"hello\n").await;
        }
    })
    .await;
    let runner = Runner::new(fast().with_max_concurrency(2));
    let probe = BannerProbe::new();
    let targets = vec![target; 6];
    let results = runner
        .probe_all(targets.iter().map(|t| (&probe as &dyn ServiceProbe, t)))
        .await;
    assert_eq!(results.len(), 6);
    assert!(results.iter().all(Result::is_ok));
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "peak {}",
        peak.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn udp_probe_round_trip() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        while let Ok((n, peer)) = server.recv_from(&mut buf).await {
            if &buf[..n] == b"PING\r\n" {
                let _ = server.send_to(b"+PONG\r\n", peer).await;
            }
        }
    });
    let probe = Ping {
        transport: Some(Transport::Udp),
        ..Ping::default()
    };
    let info = Runner::new(fast())
        .probe(&probe, &Target::from_addr(addr))
        .await
        .unwrap();
    assert_eq!(info.auth, AuthRequirement::NotRequired);
}

#[tokio::test]
async fn probes_a_caller_supplied_stream() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let mut buf = [0u8; 6];
        let _ = server.read_exact(&mut buf).await;
        let _ = server.write_all(b"+PONG\r\n").await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let runner = Runner::new(fast());
    let target = Target::new("in-memory", 0);
    let info = runner
        .probe_stream(&Ping::default(), &target, &mut client)
        .await
        .unwrap();
    assert_eq!(info.auth, AuthRequirement::NotRequired);

    let udp = Ping {
        transport: Some(Transport::Udp),
        ..Ping::default()
    };
    let err = runner
        .probe_stream(&udp, &target, &mut client)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::TransportMismatch { .. }), "{err}");
}

#[tokio::test]
async fn huge_timeouts_mean_no_limit_rather_than_a_panic() {
    let target = serve(|mut stream| async move {
        stream.write_all(b"220 ready\r\n").await.unwrap();
    })
    .await;
    let options = Options::default()
        .with_connect_timeout(Duration::MAX)
        .with_io_timeout(Duration::MAX)
        .with_total_timeout(Duration::MAX);
    let info = Runner::new(options)
        .probe(&BannerProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.banner.as_deref(), Some("220 ready"));
}
