//! Async client and server over tokio streams (feature `tokio`).
//!
//! Both sides read each message with exact-length reads driven by
//! [`Decoded::Incomplete`], so no byte after the
//! handshake is consumed: once [`Client::connect`] returns, the stream
//! carries the tunnelled connection. Wrap calls in `tokio::time::timeout`;
//! a peer that stalls mid-handshake otherwise holds the task.

mod client;
mod server;

pub use client::{Client, ClientVersion};
pub use server::{Authenticator, Connector, Server, TcpConnector};

use ::tokio::io::{AsyncRead, AsyncReadExt};

use crate::{Decoded, Error};

/// Reads one message, starting from the bytes already in `buf`.
async fn read_message<R, T>(
    reader: &mut R,
    mut buf: Vec<u8>,
    decode: impl Fn(&[u8]) -> Result<Decoded<T>, Error>,
) -> Result<T, Error>
where
    R: AsyncRead + Unpin + ?Sized,
{
    loop {
        match decode(&buf)? {
            Decoded::Complete(value, _) => return Ok(value),
            Decoded::Incomplete(more) => {
                let start = buf.len();
                buf.resize(start + more, 0);
                reader.read_exact(&mut buf[start..]).await?;
            }
        }
    }
}
