use crate::ops::{ProvisioningClient, SdkError};
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
    }

    async fn request(&mut self, op: Op) -> Result<OpResult, SdkError> {
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
    }
}
