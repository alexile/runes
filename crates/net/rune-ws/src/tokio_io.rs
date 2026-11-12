//! Async adapter over any tokio `AsyncRead + AsyncWrite` transport.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::close::CloseFrame;
use crate::connection::{Connection, Message, Options};
use crate::error::{Error, Result};
use crate::handshake::{
    ClientHandshake, DEFAULT_MAX_HEAD, Negotiated, ServerHandshake, parse_request, parse_response,
    reject_bad_request, reject_version,
};

const READ_CHUNK: usize = 8 * 1024;

/// A random 16-byte nonce for [`ClientHandshake::new`], from the OS-seeded
/// thread RNG.
#[must_use]
pub fn random_nonce() -> [u8; 16] {
    rand::random()
}

/// A WebSocket over an async byte stream (TCP, TLS, a duplex pipe…).
///
/// ```no_run
/// # async fn demo() -> Result<(), rune_ws::Error> {
/// use rune_ws::{ClientHandshake, Message, Options, WebSocket, random_nonce};
///
/// let tcp = tokio::net::TcpStream::connect("127.0.0.1:9001").await?;
/// let handshake = ClientHandshake::new("127.0.0.1:9001", "/", random_nonce());
/// let mut ws = WebSocket::connect(tcp, &handshake, Options::default()).await?;
/// ws.send(Message::Text("hello".into())).await?;
/// while let Some(message) = ws.recv().await {
///     println!("{:?}", message?);
/// }
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct WebSocket<S> {
    io: S,
    conn: Connection,
    negotiated: Negotiated,
    eof: bool,
}

async fn read_head<S, T>(
    io: &mut S,
    parse: impl Fn(&[u8], usize) -> Result<Option<(T, usize)>>,
) -> Result<(T, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some((head, used)) = parse(&buf, DEFAULT_MAX_HEAD)? {
            return Ok((head, buf.split_off(used)));
        }
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocket<S> {
    /// Performs the client handshake on `io` and returns the open socket.
    ///
    /// # Errors
    ///
    /// Transport errors and every handshake error of
    /// [`ClientHandshake::verify`].
    pub async fn connect(mut io: S, handshake: &ClientHandshake, options: Options) -> Result<Self> {
        io.write_all(&handshake.request_bytes()).await?;
        io.flush().await?;
        let (response, rest) = read_head(&mut io, parse_response).await?;
        let negotiated = handshake.verify(&response)?;
        let mut conn = Connection::client(options, rand::random).with_negotiated(&negotiated);
        conn.receive(&rest);
        Ok(Self {
            io,
            conn,
            negotiated,
            eof: false,
        })
    }

    /// Reads an upgrade request from `io`, answers it and returns the open
    /// socket. A bad request is answered with `400` or `426` before the
    /// error is returned.
    ///
    /// # Errors
    ///
    /// Transport errors and every error of [`ServerHandshake::accept`].
    pub async fn accept(mut io: S, server: &ServerHandshake, options: Options) -> Result<Self> {
        let (request, rest) = read_head(&mut io, parse_request).await?;
        let (response, negotiated) = match server.accept(&request) {
            Ok(accepted) => accepted,
            Err(err) => {
                let reply = if matches!(err, Error::UnsupportedVersion(_)) {
                    reject_version()
                } else {
                    reject_bad_request()
                };
                // Best effort: the handshake error is what the caller needs.
                let _ = io.write_all(&reply).await;
                let _ = io.shutdown().await;
                return Err(err);
            }
        };
        io.write_all(&response).await?;
        io.flush().await?;
        let mut conn = Connection::server(options).with_negotiated(&negotiated);
        conn.receive(&rest);
        Ok(Self {
            io,
            conn,
            negotiated,
            eof: false,
        })
    }

    /// Wraps a transport whose handshake was done elsewhere.
    pub fn from_parts(io: S, conn: Connection) -> Self {
        Self {
            io,
            conn,
            negotiated: Negotiated::default(),
            eof: false,
        }
    }

    /// What the handshake negotiated.
    #[must_use]
    pub const fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// The underlying state machine.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The transport.
    #[must_use]
    pub const fn get_ref(&self) -> &S {
        &self.io
    }

    /// Consumes the socket and returns the transport.
    pub fn into_inner(self) -> S {
        self.io
    }

    async fn flush_outgoing(&mut self) -> Result<()> {
        let out = self.conn.take_outgoing();
        if !out.is_empty() {
            self.io.write_all(&out).await?;
            self.io.flush().await?;
        }
        Ok(())
    }

    /// Sends a message and flushes it.
    ///
    /// # Errors
    ///
    /// Errors from [`Connection::send`] and the transport.
    pub async fn send(&mut self, message: Message) -> Result<()> {
        self.conn.send(message)?;
        self.flush_outgoing().await
    }

    /// Starts the close handshake; keep calling [`recv`](Self::recv) until
    /// it returns `None` to complete it.
    ///
    /// # Errors
    ///
    /// As for [`send`](Self::send).
    pub async fn close(&mut self, close: Option<CloseFrame>) -> Result<()> {
        self.conn.close(close)?;
        self.flush_outgoing().await
    }

    /// The next message. Automatic replies (pongs, the close echo) are
    /// flushed before it is returned. Returns `None` once the connection is
    /// closed; the transport is shut down at that point.
    pub async fn recv(&mut self) -> Option<Result<Message>> {
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            let next = self.conn.next_message();
            if let Err(err) = self.flush_outgoing().await {
                return Some(Err(err));
            }
            if let Some(item) = next {
                return Some(item);
            }
            if self.conn.is_closed() || self.eof {
                let _ = self.io.shutdown().await;
                return None;
            }
            match self.io.read(&mut chunk).await {
                Ok(0) => {
                    self.eof = true;
                    return Some(Err(Error::UnexpectedEof));
                }
                Ok(n) => self.conn.receive(&chunk[..n]),
                Err(err) => return Some(Err(err.into())),
            }
        }
    }
}
