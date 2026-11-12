//! The async adapter over an in-memory duplex pipe (no network).

use rune_ws::{
    ClientHandshake, CloseCode, CloseFrame, Error, Message, Options, ServerHandshake, WebSocket,
    random_nonce,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[tokio::test]
async fn echo_and_close() {
    let (client_io, server_io) = duplex(4096);
    let server = tokio::spawn(async move {
        let hs = ServerHandshake::default().with_protocol("echo");
        let mut ws = WebSocket::accept(server_io, &hs, Options::default())
            .await
            .unwrap();
        assert_eq!(ws.negotiated().protocol.as_deref(), Some("echo"));
        while let Some(message) = ws.recv().await {
            if let m @ (Message::Text(_) | Message::Binary(_)) = message.unwrap() {
                ws.send(m).await.unwrap();
            }
        }
    });

    let handshake = ClientHandshake::new("localhost", "/", random_nonce()).with_protocol("echo");
    let mut ws = WebSocket::connect(client_io, &handshake, Options::default())
        .await
        .unwrap();
    let big = vec![7u8; 100_000];
    ws.send(Message::Text("hello".into())).await.unwrap();
    ws.send(Message::Binary(big.clone())).await.unwrap();
    assert_eq!(
        ws.recv().await.unwrap().unwrap(),
        Message::Text("hello".into())
    );
    assert_eq!(ws.recv().await.unwrap().unwrap(), Message::Binary(big));
    ws.close(Some(CloseFrame::new(CloseCode::NORMAL, "")))
        .await
        .unwrap();
    assert_eq!(
        ws.recv().await.unwrap().unwrap(),
        Message::Close(Some(CloseFrame::new(CloseCode::NORMAL, "")))
    );
    assert!(ws.recv().await.is_none());
    server.await.unwrap();
}

#[cfg(feature = "deflate")]
#[tokio::test]
async fn deflate_negotiated_end_to_end() {
    use rune_ws::DeflateConfig;
    let (client_io, server_io) = duplex(4096);
    let server = tokio::spawn(async move {
        let hs = ServerHandshake::default().with_deflate(DeflateConfig::default());
        let mut ws = WebSocket::accept(server_io, &hs, Options::default())
            .await
            .unwrap();
        assert!(ws.negotiated().deflate.is_some());
        let message = ws.recv().await.unwrap().unwrap();
        ws.send(message).await.unwrap();
        while ws.recv().await.is_some() {}
    });
    let hs = ClientHandshake::new("localhost", "/", random_nonce())
        .with_deflate(DeflateConfig::default());
    let mut ws = WebSocket::connect(client_io, &hs, Options::default())
        .await
        .unwrap();
    let text = "compress me ".repeat(1000);
    ws.send(Message::Text(text.clone())).await.unwrap();
    assert_eq!(ws.recv().await.unwrap().unwrap(), Message::Text(text));
    ws.close(None).await.unwrap();
    while ws.recv().await.is_some() {}
    server.await.unwrap();
}

#[tokio::test]
async fn bad_version_gets_426() {
    let (mut client_io, server_io) = duplex(4096);
    let server = tokio::spawn(async move {
        WebSocket::accept(server_io, &ServerHandshake::default(), Options::default()).await
    });
    client_io
        .write_all(
            b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
        )
        .await
        .unwrap();
    let mut reply = String::new();
    client_io.read_to_string(&mut reply).await.unwrap();
    assert!(reply.starts_with("HTTP/1.1 426"));
    assert!(matches!(
        server.await.unwrap(),
        Err(Error::UnsupportedVersion(_))
    ));
}

#[tokio::test]
async fn eof_without_close_is_an_error() {
    let (client_io, server_io) = duplex(4096);
    let server = tokio::spawn(async move {
        let mut ws = WebSocket::accept(server_io, &ServerHandshake::default(), Options::default())
            .await
            .unwrap();
        ws.recv().await
    });
    let hs = ClientHandshake::new("x", "/", random_nonce());
    let ws = WebSocket::connect(client_io, &hs, Options::default())
        .await
        .unwrap();
    drop(ws);
    assert!(matches!(
        server.await.unwrap(),
        Some(Err(Error::UnexpectedEof))
    ));
}
