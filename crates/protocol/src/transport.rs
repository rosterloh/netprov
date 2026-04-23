//! Length-prefixed transport, shared by client and server.
//! Part 2 will add a GATT-fragmented transport; this one stays as the
//! loopback transport for tests.

use crate::MAX_MESSAGE_SIZE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    TooLarge(usize),
}

pub async fn write_message<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    body: &[u8],
) -> Result<(), TransportError> {
    if body.len() > MAX_MESSAGE_SIZE {
        return Err(TransportError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_message<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(TransportError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = vec![1u8, 2, 3, 4, 5];
        let t = tokio::spawn(async move {
            write_message(&mut a, &payload).await.unwrap();
        });
        let got = read_message(&mut b).await.unwrap();
        t.await.unwrap();
        assert_eq!(got, vec![1u8, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn rejects_oversize_write() {
        let (mut a, _b) = tokio::io::duplex(4096);
        let big = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let e = write_message(&mut a, &big).await.unwrap_err();
        assert!(matches!(e, TransportError::TooLarge(_)));
    }
}
