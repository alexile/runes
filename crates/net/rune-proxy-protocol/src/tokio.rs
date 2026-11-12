//! Async adapters over tokio streams (feature `tokio`).
//!
//! [`read_header`] reads exactly the PROXY header and nothing more, so the
//! stream is left positioned at the first byte of application data. It reads
//! a v1 line one byte at a time; wrap a raw socket in a
//! [`::tokio::io::BufReader`] if that matters, and keep using the reader
//! afterwards. Apply a timeout (`tokio::time::timeout`) around the call: a
//! peer that never finishes its header otherwise holds the task.

use ::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Header, Parsed, Version, v1, v2};

/// Reads one PROXY header (v1 or v2) from `reader`.
///
/// # Errors
///
/// [`Error::NotProxyProtocol`] if the stream does not start with a PROXY
/// signature, any decoding error, or [`Error::Io`] (including
/// `UnexpectedEof` when the peer closes mid-header).
pub async fn read_header<R>(reader: &mut R) -> Result<Parsed, Error>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = vec![0; v1::SIGNATURE.len()];
    reader.read_exact(&mut buf).await?;
    if buf == v1::SIGNATURE {
        loop {
            if let Some(parsed) = crate::decode(&buf)? {
                return Ok(parsed);
            }
            buf.push(reader.read_u8().await?);
        }
    }
    if buf != v2::SIGNATURE[..buf.len()] {
        return Err(Error::NotProxyProtocol);
    }
    buf.resize(v2::FIXED_LEN, 0);
    reader.read_exact(&mut buf[v1::SIGNATURE.len()..]).await?;
    if buf[..v2::SIGNATURE.len()] != *v2::SIGNATURE {
        return Err(Error::NotProxyProtocol);
    }
    let len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    buf.resize(v2::FIXED_LEN + len, 0);
    reader.read_exact(&mut buf[v2::FIXED_LEN..]).await?;
    crate::decode(&buf)?.ok_or(Error::NotProxyProtocol)
}

/// Encodes `header` in `version` and writes it to `writer`.
///
/// # Errors
///
/// Any encoding error, or [`Error::Io`].
pub async fn write_header<W>(writer: &mut W, header: &Header, version: Version) -> Result<(), Error>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let bytes = header.encode(version)?;
    writer.write_all(&bytes).await?;
    Ok(())
}
