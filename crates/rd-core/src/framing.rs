//! Length-prefixed (u32 big-endian) postcard messages over any async byte stream.

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for a single message (a 4K keyframe compresses far below this).
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = postcard::to_allocvec(msg).context("serialize message")?;
    if body.len() > MAX_MESSAGE {
        bail!("message too large: {} bytes", body.len());
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Upper bound for the first message on a connection, before the peer has signed in
/// (a sign-in or relay hello is a few hundred bytes).
pub const MAX_HELLO: usize = 64 * 1024;

pub async fn read_msg<R, T>(r: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    read_msg_max(r, MAX_MESSAGE).await
}

/// [`read_msg`] with a smaller size limit, for peers that haven't signed in yet.
pub async fn read_msg_max<R, T>(r: &mut R, max: usize) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        bail!("peer sent oversized message ({len} bytes)");
    }
    // Grow the buffer as bytes arrive rather than trusting the announced length, so a
    // peer can't make us hold a large buffer without sending it.
    let mut body = Vec::with_capacity(len.min(64 * 1024));
    let n = (&mut *r).take(len as u64).read_to_end(&mut body).await?;
    if n < len {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    postcard::from_bytes(&body).context("malformed message")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_and_limits() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &("hello".to_string(), 7u32)).await.unwrap();
        let got: (String, u32) = read_msg(&mut buf.as_slice()).await.unwrap();
        assert_eq!(got, ("hello".to_string(), 7));
        // Over the limit: refused before reading the body.
        assert!(read_msg_max::<_, (String, u32)>(&mut buf.as_slice(), 4).await.is_err());
        // Announces more than it sends: an error, not a hang or a huge buffer.
        let mut short = (MAX_HELLO as u32).to_be_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert!(read_msg_max::<_, String>(&mut short.as_slice(), MAX_HELLO).await.is_err());
    }
}
