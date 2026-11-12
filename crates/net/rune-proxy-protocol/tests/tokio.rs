//! The tokio adapter over loopback TCP and in-memory duplex streams.

use rune_proxy_protocol::tokio::{read_header, write_header};
use std::net::{Ipv4Addr, SocketAddrV4};

use rune_proxy_protocol::{Addresses, Command, Error, Header, Transport, Version, tlv};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const fn header() -> Header {
    Header::new(
        Command::Proxy,
        Transport::Stream,
        Addresses::Ipv4 {
            source: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 40123),
            destination: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8443),
        },
    )
}

#[tokio::test]
async fn loopback_v1_and_v2_leave_payload_in_stream() {
    for version in [Version::V1, Version::V2] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            write_header(&mut stream, &header(), version).await.unwrap();
            stream.write_all(b"hello").await.unwrap();
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let parsed = read_header(&mut stream).await.unwrap();
        assert_eq!(parsed.version, version);
        assert_eq!(parsed.header, header());
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"hello");
        client.await.unwrap();
    }
}

#[tokio::test]
async fn v2_with_tlvs_over_duplex() {
    let (mut a, mut b) = tokio::io::duplex(64);
    let sent = header()
        .with_tlv(rune_proxy_protocol::Tlv::new(
            tlv::PP2_TYPE_UNIQUE_ID,
            vec![7; 100],
        ))
        .with_crc32c();
    let expected = sent.clone();
    let writer = tokio::spawn(async move {
        write_header(&mut a, &sent, Version::V2).await.unwrap();
        a.write_all(b"x").await.unwrap();
    });
    let parsed = read_header(&mut b).await.unwrap();
    assert_eq!(parsed.header.unique_id(), Some(&[7; 100][..]));
    assert_eq!(parsed.header.tlvs.len(), expected.tlvs.len());
    assert_eq!(b.read_u8().await.unwrap(), b'x');
    writer.await.unwrap();
}

#[tokio::test]
async fn non_proxy_stream_is_rejected() {
    let mut input: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
    assert!(matches!(
        read_header(&mut input).await,
        Err(Error::NotProxyProtocol)
    ));
    let mut input: &[u8] = b"\r\n\r\n\0\r\nQUIX\n\x21\x11\x00\x00";
    assert!(matches!(
        read_header(&mut input).await,
        Err(Error::NotProxyProtocol)
    ));
}

#[tokio::test]
async fn truncated_and_oversized_headers_fail() {
    let mut input: &[u8] = b"PROXY TCP4 1.2.3.4";
    assert!(matches!(read_header(&mut input).await, Err(Error::Io(_))));
    let long = [b'X'; 200];
    let mut input: Vec<u8> = b"PROXY ".to_vec();
    input.extend_from_slice(&long);
    let mut reader = input.as_slice();
    assert!(matches!(
        read_header(&mut reader).await,
        Err(Error::V1TooLong)
    ));
}

#[tokio::test]
async fn v1_refuses_tlvs_on_write() {
    let mut out = Vec::new();
    let result = write_header(&mut out, &header().with_crc32c(), Version::V1).await;
    assert!(matches!(result, Err(Error::NotRepresentableInV1(_))));
    assert_eq!(out, Vec::<u8>::new());
}
