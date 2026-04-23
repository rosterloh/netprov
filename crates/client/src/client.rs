use netprov_protocol::*;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("decode: {0}")]
    Decode(#[from] CodecError),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("authentication failed")]
    AuthFailed,
    #[error("unexpected server message: {0}")]
    UnexpectedMessage(&'static str),
    #[error("response id mismatch: expected {expected}, got {got}")]
    IdMismatch { expected: u16, got: u16 },
}

pub struct Client<IO> {
    r: tokio::io::ReadHalf<IO>,
    w: tokio::io::WriteHalf<IO>,
    psk: Psk,
    next_id: u16,
    authenticated: bool,
}

impl<IO: AsyncRead + AsyncWrite> Client<IO> {
    pub fn new(io: IO, psk: Psk) -> Self {
        let (r, w) = tokio::io::split(io);
        Self { r, w, psk, next_id: 1, authenticated: false }
    }

    pub async fn authenticate(&mut self) -> Result<(), ClientError> {
        self.send(Envelope::NonceRequest).await?;
        let nonce = match self.recv().await? {
            Envelope::NonceReply(bytes) => {
                if bytes.len() != NONCE_LEN {
                    return Err(ClientError::UnexpectedMessage("nonce length"));
                }
                let mut n = [0u8; NONCE_LEN];
                n.copy_from_slice(&bytes);
                n
            }
            Envelope::AuthFail => return Err(ClientError::AuthFailed),
            _ => return Err(ClientError::UnexpectedMessage("expected NonceReply")),
        };
        let tag = hmac_compute(&self.psk, &nonce);
        self.send(Envelope::AuthSubmit(tag.to_vec())).await?;
        match self.recv().await? {
            Envelope::AuthOk => {
                self.authenticated = true;
                Ok(())
            }
            Envelope::AuthFail => Err(ClientError::AuthFailed),
            _ => Err(ClientError::UnexpectedMessage("expected AuthOk/AuthFail")),
        }
    }

    pub async fn request(&mut self, op: Op) -> Result<OpResult, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.send(Envelope::Req(Request { request_id: id, op })).await?;
        match self.recv().await? {
            Envelope::Resp(resp) => {
                if resp.request_id != id {
                    return Err(ClientError::IdMismatch { expected: id, got: resp.request_id });
                }
                resp.result.map_err(Into::into)
            }
            _ => Err(ClientError::UnexpectedMessage("expected Resp")),
        }
    }

    async fn send(&mut self, env: Envelope) -> Result<(), ClientError> {
        let bytes = encode(&env)?;
        write_message(&mut self.w, &bytes).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Envelope, ClientError> {
        let bytes = read_message(&mut self.r).await?;
        Ok(decode(&bytes)?)
    }
}
