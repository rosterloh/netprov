use crate::ops::{CLIENT_TIMEOUT, ProvisioningClient, SdkError};
use async_trait::async_trait;
use netprov_protocol::*;
use tokio::io::{AsyncRead, AsyncWrite};

/// Length-prefixed TCP client used for development and tests.
///
/// Production clients should prefer the BLE transport.
pub struct TcpClient<IO> {
    r: tokio::io::ReadHalf<IO>,
    w: tokio::io::WriteHalf<IO>,
    next_id: u16,
    authenticated: bool,
}

impl<IO: AsyncRead + AsyncWrite> TcpClient<IO> {
    pub fn new(io: IO) -> Self {
        let (r, w) = tokio::io::split(io);
        Self {
            r,
            w,
            next_id: 1,
            authenticated: false,
        }
    }

    async fn send(&mut self, env: Envelope) -> Result<(), SdkError> {
        let bytes = encode(&env)?;
        write_message(&mut self.w, &bytes).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Envelope, SdkError> {
        let bytes = read_message(&mut self.r).await?;
        Ok(decode(&bytes)?)
    }
}

impl<IO> TcpClient<IO>
where
    IO: AsyncRead + AsyncWrite + Send,
{
    pub async fn authenticate(&mut self, psk: Psk) -> Result<(), SdkError> {
        <Self as ProvisioningClient>::authenticate(self, psk).await
    }

    pub async fn request(&mut self, op: Op) -> Result<OpResult, SdkError> {
        <Self as ProvisioningClient>::request(self, op).await
    }
}

#[async_trait]
impl<IO> ProvisioningClient for TcpClient<IO>
where
    IO: AsyncRead + AsyncWrite + Send,
{
    async fn authenticate(&mut self, psk: Psk) -> Result<(), SdkError> {
        // `recv()` blocks forever on a silent peer, so bound the whole
        // exchange with the client deadline.
        tokio::time::timeout(CLIENT_TIMEOUT, async {
            self.send(Envelope::NonceRequest).await?;
            let nonce = match self.recv().await? {
                Envelope::NonceReply(bytes) => {
                    if bytes.len() != NONCE_LEN {
                        return Err(SdkError::UnexpectedMessage("nonce length"));
                    }
                    let mut n = [0u8; NONCE_LEN];
                    n.copy_from_slice(&bytes);
                    n
                }
                Envelope::AuthFail => return Err(SdkError::AuthFailed),
                _ => return Err(SdkError::UnexpectedMessage("expected NonceReply")),
            };
            let tag = hmac_compute(&psk, &nonce);
            self.send(Envelope::AuthSubmit(tag.to_vec())).await?;
            match self.recv().await? {
                Envelope::AuthOk => {
                    self.authenticated = true;
                    Ok(())
                }
                Envelope::AuthFail => Err(SdkError::AuthFailed),
                _ => Err(SdkError::UnexpectedMessage("expected AuthOk/AuthFail")),
            }
        })
        .await
        .map_err(|_| SdkError::Timeout(CLIENT_TIMEOUT))?
    }

    async fn request(&mut self, op: Op) -> Result<OpResult, SdkError> {
        tokio::time::timeout(CLIENT_TIMEOUT, async {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            self.send(Envelope::Req(Request { request_id: id, op }))
                .await?;
            match self.recv().await? {
                Envelope::Resp(resp) => {
                    if resp.request_id != id {
                        return Err(SdkError::IdMismatch {
                            expected: id,
                            got: resp.request_id,
                        });
                    }
                    resp.result.map_err(Into::into)
                }
                _ => Err(SdkError::UnexpectedMessage("expected Resp")),
            }
        })
        .await
        .map_err(|_| SdkError::Timeout(CLIENT_TIMEOUT))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A silent peer must not hang the client forever: `request` returns
    /// `SdkError::Timeout` once the client deadline elapses. `start_paused`
    /// auto-advances virtual time to the timer, so the test is instant.
    #[tokio::test(start_paused = true)]
    async fn request_times_out_when_peer_is_silent() {
        // The far end is held open (never written to, never dropped) so the
        // read parks pending rather than hitting EOF.
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let mut client = TcpClient::new(client_io);

        let err = client
            .request(Op::ListInterfaces)
            .await
            .expect_err("silent peer must not resolve");
        assert!(
            matches!(err, SdkError::Timeout(_)),
            "expected Timeout, got {err:?}"
        );
    }

    /// The same deadline guards the auth handshake.
    #[tokio::test(start_paused = true)]
    async fn authenticate_times_out_when_peer_is_silent() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let mut client = TcpClient::new(client_io);

        let err = client
            .authenticate([0u8; PSK_LEN])
            .await
            .expect_err("silent peer must not resolve");
        assert!(
            matches!(err, SdkError::Timeout(_)),
            "expected Timeout, got {err:?}"
        );
    }
}
