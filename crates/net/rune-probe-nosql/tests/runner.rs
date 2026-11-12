//! The probes over real sockets, against mock servers on loopback that
//! replay captured replies.

#![allow(clippy::unwrap_used, reason = "test code")]

use std::time::Duration;

use rune_probe_nosql::bson::{Bson, Document};
use rune_probe_nosql::{
    ElasticsearchProbe, MemcachedProbe, MemcachedUdpProbe, MongodbProbe, RedisProbe, memcached,
    redis,
};
use rune_service_probe::{AuthRequirement, Error, Options, Runner, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn runner() -> Runner {
    Runner::new(
        Options::default()
            .with_io_timeout(Duration::from_millis(500))
            .with_total_timeout(Duration::from_secs(3)),
    )
}

/// Serve one connection with `handler` and return the target.
async fn serve<F, Fut>(handler: F) -> Target
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            handler(stream).await;
        }
    });
    Target::from_addr(addr)
}

async fn expect(stream: &mut TcpStream, want: &[u8]) {
    let mut buf = vec![0; want.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, want);
}

/// Read one MongoDB message and return its opcode.
async fn read_mongo(stream: &mut TcpStream) -> u32 {
    let mut len = [0; 4];
    stream.read_exact(&mut len).await.unwrap();
    let mut rest = vec![0; u32::from_le_bytes(len) as usize - 4];
    stream.read_exact(&mut rest).await.unwrap();
    u32::from_le_bytes(rest[8..12].try_into().unwrap())
}

fn mongo_msg(doc: &[(&str, Bson)]) -> Vec<u8> {
    let body = Document::encode(doc);
    let len = u32::try_from(16 + 4 + 1 + body.len()).unwrap();
    let mut out = len.to_le_bytes().to_vec();
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&2013u32.to_le_bytes());
    out.extend_from_slice(&[0; 5]);
    out.extend_from_slice(&body);
    out
}

#[tokio::test]
async fn redis_noauth_then_closed() {
    let target = serve(|mut s| async move {
        expect(&mut s, redis::INFO_SERVER).await;
        s.write_all(b"-NOAUTH Authentication required.\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;
    let info = runner().probe(&RedisProbe::new(), &target).await.unwrap();
    assert_eq!(info.auth, AuthRequirement::Required);
}

#[tokio::test]
async fn redis_open() {
    let target = serve(|mut s| async move {
        expect(&mut s, redis::INFO_SERVER).await;
        let body = "# Server\r\nredis_version:6.2.14\r\nredis_mode:standalone\r\n";
        s.write_all(format!("${}\r\n{body}\r\n", body.len()).as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;
    let info = runner().probe(&RedisProbe::new(), &target).await.unwrap();
    assert_eq!(info.version.as_deref(), Some("6.2.14"));
    assert_eq!(info.findings[0].check_id, "redis.unauthenticated");
}

#[tokio::test]
async fn mongodb_open() {
    let target = serve(|mut s| async move {
        assert_eq!(read_mongo(&mut s).await, 2004);
        let hello = Document::encode(&[
            ("isWritablePrimary", Bson::Bool(true)),
            ("maxWireVersion", Bson::Int32(25)),
            ("ok", Bson::Double(1.0)),
        ]);
        let len = u32::try_from(16 + 20 + hello.len()).unwrap();
        let mut reply = len.to_le_bytes().to_vec();
        reply.extend_from_slice(&[0; 8]);
        reply.extend_from_slice(&1u32.to_le_bytes());
        reply.extend_from_slice(&[0; 20]);
        reply.extend_from_slice(&hello);
        s.write_all(&reply).await.unwrap();
        assert_eq!(read_mongo(&mut s).await, 2013);
        s.write_all(&mongo_msg(&[
            ("version", Bson::String("8.0.4".into())),
            ("ok", Bson::Double(1.0)),
        ]))
        .await
        .unwrap();
        assert_eq!(read_mongo(&mut s).await, 2013);
        s.write_all(&mongo_msg(&[
            ("totalSize", Bson::Int32(0)),
            ("ok", Bson::Double(1.0)),
        ]))
        .await
        .unwrap();
    })
    .await;
    let info = runner().probe(&MongodbProbe::new(), &target).await.unwrap();
    assert_eq!(info.version.as_deref(), Some("8.0.4"));
    assert_eq!(info.auth, AuthRequirement::NotRequired);
    assert_eq!(info.findings[0].check_id, "mongodb.unauthenticated");
}

#[tokio::test]
async fn memcached_tcp() {
    let target = serve(|mut s| async move {
        expect(&mut s, memcached::VERSION).await;
        s.write_all(b"VERSION 1.6.29\r\n").await.unwrap();
        expect(&mut s, memcached::STATS).await;
        s.write_all(b"STAT uptime 5\r\nEND\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;
    let info = runner()
        .probe(&MemcachedProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.version.as_deref(), Some("1.6.29"));
    assert_eq!(info.details["memcached.uptime"], "5");
}

#[tokio::test]
async fn memcached_udp() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = Target::from_addr(socket.local_addr().unwrap());
    tokio::spawn(async move {
        let mut buf = [0; 64];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        assert!(buf[..n].ends_with(b"version\r\n"));
        let mut reply = buf[..2].to_vec();
        reply.extend_from_slice(&[0, 0, 0, 1, 0, 0]);
        reply.extend_from_slice(b"VERSION 1.4.39\r\n");
        socket.send_to(&reply, peer).await.unwrap();
    });
    let info = runner()
        .probe(&MemcachedUdpProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.findings[0].check_id, "memcached.udp_amplification");
}

#[tokio::test]
async fn elasticsearch_keep_alive() {
    let target = serve(|mut s| async move {
        let mut buf = vec![0; 4096];
        let n = s.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"GET / HTTP/1.1\r\n"));
        let root = r#"{"name":"n","cluster_name":"c","version":{"number":"8.15.0"},"tagline":"You Know, for Search"}"#;
        s.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{root}", root.len()).as_bytes())
            .await
            .unwrap();
        let n = s.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"GET /_cluster/health HTTP/1.1\r\n"));
        let health = r#"{"status":"green","number_of_nodes":3}"#;
        s.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{health}", health.len()).as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;
    let info = runner()
        .probe(&ElasticsearchProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.version.as_deref(), Some("8.15.0"));
    assert_eq!(info.details["elasticsearch.health"], "green");
    assert_eq!(info.details["elasticsearch.number_of_nodes"], "3");
}

#[tokio::test]
async fn closed_port_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Target::from_addr(listener.local_addr().unwrap());
    drop(listener);
    let err = runner()
        .probe(&RedisProbe::new(), &target)
        .await
        .unwrap_err();
    assert!(err.is_unreachable(), "{err}");
    assert!(matches!(
        err,
        Error::Connect { .. } | Error::ConnectTimeout { .. }
    ));
}
