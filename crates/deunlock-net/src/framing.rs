//! Length-prefixed messages over a byte stream.
//!
//! TLS gives us confidentiality and integrity for the byte stream, but not
//! message boundaries. Every deunlock message on the LAN transport is therefore
//! `u32be(len) || body`, and both ends enforce [`MAX_MESSAGE_BYTES`] *before*
//! allocating: a 4-byte prefix claiming 4 GiB is refused, not reserved.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::NetError;

/// Largest message either side will accept.
///
/// A v2 challenge frame is `1 + 16 + 2 + 4 + 48 + 8 + 32 + 64 = 175` bytes; the
/// signature response is 64. A 4 KiB ceiling leaves room for future fields while
/// keeping a hostile peer from making us allocate megabytes.
pub const MAX_MESSAGE_BYTES: usize = 4096;

/// Write one length-prefixed message.
///
/// The write is a single `write_all` of the prefix plus a `write_all` of the
/// body; callers flush.
///
/// # Errors
///
/// [`NetError::MessageTooLarge`] when `message` exceeds
/// [`MAX_MESSAGE_BYTES`], otherwise any I/O error.
pub async fn write_message<W>(writer: &mut W, message: &[u8]) -> Result<(), NetError>
where
    W: AsyncWrite + Unpin,
{
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(NetError::MessageTooLarge {
            len: u32::try_from(message.len()).unwrap_or(u32::MAX),
            max: MAX_MESSAGE_BYTES,
        });
    }
    let len = u32::try_from(message.len()).map_err(|_| NetError::MessageTooLarge {
        len: u32::MAX,
        max: MAX_MESSAGE_BYTES,
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(message).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one length-prefixed message.
///
/// # Errors
///
/// [`NetError::MessageTooLarge`] when the peer declares more than
/// [`MAX_MESSAGE_BYTES`] (the body is not read at all), [`NetError::Truncated`]
/// when the stream ends mid-message, otherwise any I/O error.
pub async fn read_message<R>(reader: &mut R) -> Result<Vec<u8>, NetError>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).await?;
    let declared = u32::from_be_bytes(prefix);
    let len = usize::try_from(declared).unwrap_or(usize::MAX);
    if len > MAX_MESSAGE_BYTES {
        return Err(NetError::MessageTooLarge {
            len: declared,
            max: MAX_MESSAGE_BYTES,
        });
    }
    let mut body = vec![0u8; len];
    let mut read = 0usize;
    while read < len {
        let n = reader.read(&mut body[read..]).await?;
        if n == 0 {
            return Err(NetError::Truncated {
                read,
                expected: len,
            });
        }
        read += n;
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_message_survives_the_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let writer = tokio::spawn(async move {
            write_message(&mut client, b"challenge frame").await.expect("write");
        });
        let read = read_message(&mut server).await.expect("read");
        writer.await.expect("join");
        assert_eq!(read, b"challenge frame");
    }

    #[tokio::test]
    async fn an_empty_message_is_legal_but_an_oversized_one_is_not() {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            write_message(&mut client, b"").await.expect("write");
        });
        assert!(read_message(&mut server).await.expect("read").is_empty());

        // The writer refuses to emit an oversized message at all...
        let (mut client, _server) = tokio::io::duplex(8192);
        let too_big = vec![0xAAu8; MAX_MESSAGE_BYTES + 1];
        match write_message(&mut client, &too_big).await {
            Err(NetError::MessageTooLarge { .. }) => {}
            other => panic!("expected MessageTooLarge from the writer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_hostile_length_prefix_is_refused_before_allocating() {
        let (mut attacker, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // 4 GiB declared, nothing behind it.
            attacker.write_all(&u32::MAX.to_be_bytes()).await.expect("write");
        });
        match read_message(&mut server).await {
            Err(NetError::MessageTooLarge { len, max }) => {
                assert_eq!(len, u32::MAX);
                assert_eq!(max, MAX_MESSAGE_BYTES);
            }
            other => panic!("expected MessageTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_stream_that_stops_mid_message_is_truncated() {
        let (mut attacker, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            attacker.write_all(&10u32.to_be_bytes()).await.expect("len");
            attacker.write_all(b"abc").await.expect("partial");
            drop(attacker);
        });
        match read_message(&mut server).await {
            Err(NetError::Truncated { read, expected }) => {
                assert_eq!(read, 3);
                assert_eq!(expected, 10);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }
}
