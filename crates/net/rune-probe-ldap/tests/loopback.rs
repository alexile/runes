//! The probes over real sockets, against a mock LDAP server on loopback
//! that decodes each request with the crate's own codec.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::time::Duration;

use rune_probe_ldap::{
    Attribute, LdapAnonymousProbe, LdapProbe, LdapResult, Message, Op, ResultCode, SearchEntry,
    parse_message,
};
use rune_service_probe::{AuthRequirement, Options, Runner, Target, TlsSupport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn runner() -> Runner {
    Runner::new(
        Options::default()
            .with_io_timeout(Duration::from_millis(500))
            .with_total_timeout(Duration::from_secs(3))
            .with_allow_intrusive(true),
    )
}

async fn read_message(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Message> {
    loop {
        match parse_message(buf) {
            Ok((msg, used)) => {
                buf.drain(..used);
                return Some(msg);
            }
            Err(e) if e.is_truncated() => {}
            Err(e) => panic!("client sent garbage: {e}"),
        }
        let mut chunk = [0; 512];
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A tiny LDAP server: answers the root DSE search, accepts anonymous
/// binds, and returns one entry for any other search.
async fn serve(anonymous_read: bool) -> (Target, tokio::task::JoinHandle<Vec<Op>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut seen = Vec::new();
        while let Some(msg) = read_message(&mut s, &mut buf).await {
            seen.push(msg.op.clone());
            let reply = match msg.op {
                Op::SearchRequest(req) if req.base.is_empty() => {
                    let mut out = Message::new(
                        msg.id,
                        Op::SearchResultEntry(SearchEntry::new(
                            "",
                            vec![
                                Attribute::new("vendorName", ["389 Project"]),
                                Attribute::new(
                                    "vendorVersion",
                                    ["389-Directory/3.1.1 B2024.213.0000"],
                                ),
                                Attribute::new(
                                    "namingContexts",
                                    ["o=netscaperoot", "dc=example,dc=com"],
                                ),
                                Attribute::new("supportedExtension", ["1.3.6.1.4.1.1466.20037"]),
                                Attribute::new("supportedLDAPVersion", ["2", "3"]),
                            ],
                        )),
                    )
                    .encode();
                    out.extend(
                        Message::new(
                            msg.id,
                            Op::SearchResultDone(LdapResult::new(ResultCode::SUCCESS)),
                        )
                        .encode(),
                    );
                    out
                }
                Op::BindRequest(_) => Message::new(
                    msg.id,
                    Op::BindResponse(LdapResult::new(ResultCode::SUCCESS)),
                )
                .encode(),
                Op::SearchRequest(_) => {
                    let mut out = Vec::new();
                    if anonymous_read {
                        out.extend(
                            Message::new(
                                msg.id,
                                Op::SearchResultEntry(SearchEntry::new(
                                    "ou=People,dc=example,dc=com",
                                    Vec::new(),
                                )),
                            )
                            .encode(),
                        );
                    }
                    out.extend(
                        Message::new(
                            msg.id,
                            Op::SearchResultDone(LdapResult::new(ResultCode::SUCCESS)),
                        )
                        .encode(),
                    );
                    out
                }
                Op::UnbindRequest => break,
                _ => Vec::new(),
            };
            // Byte by byte for the first reply, to exercise reassembly.
            if seen.len() == 1 {
                for byte in reply {
                    s.write_all(&[byte]).await.unwrap();
                }
            } else {
                s.write_all(&reply).await.unwrap();
            }
        }
        seen
    });
    (Target::from_addr(addr), handle)
}

#[tokio::test]
async fn root_dse_over_tcp() {
    let (target, server) = serve(false).await;
    let info = runner().probe(&LdapProbe::new(), &target).await.unwrap();
    assert_eq!(info.product.as_deref(), Some("389 Project"));
    assert_eq!(
        info.version.as_deref(),
        Some("389-Directory/3.1.1 B2024.213.0000")
    );
    assert_eq!(info.tls, TlsSupport::Optional);
    assert_eq!(
        info.details["ldap.default_naming_context"],
        "dc=example,dc=com"
    );
    drop(server);
}

#[tokio::test]
async fn anonymous_read_over_tcp() {
    let (target, server) = serve(true).await;
    let info = runner()
        .probe(&LdapAnonymousProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.auth, AuthRequirement::NotRequired);
    assert!(
        info.findings
            .iter()
            .any(|f| f.check_id == "ldap.anonymous_read")
    );
    let seen = server.await.unwrap();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[3], Op::UnbindRequest);
}

#[tokio::test]
async fn anonymous_bind_without_visible_entries() {
    let (target, server) = serve(false).await;
    let info = runner()
        .probe(&LdapAnonymousProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.details["ldap.anonymous_search"], "empty");
    assert!(
        info.findings
            .iter()
            .any(|f| f.check_id == "ldap.anonymous_bind")
    );
    assert!(
        !info
            .findings
            .iter()
            .any(|f| f.check_id == "ldap.anonymous_read")
    );
    server.await.unwrap();
}
