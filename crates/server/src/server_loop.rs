use crate::facade::NetworkFacade;
use crate::rate_limit::{CheckResult, RateLimiter};
use crate::session::Session;
use netprov_protocol::*;
use netprov_protocol::{read_message, write_message, TransportError};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, ToSocketAddrs};
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("decode: {0}")]
    Decode(#[from] CodecError),
}

pub struct ServerConfig {
    pub psk: Psk,
    pub peer_id: String,
}

pub async fn run_server<F, IO>(
    io: IO,
    cfg: ServerConfig,
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<(), ServerError>
where
    F: NetworkFacade + 'static,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(io);
    let mut session = Session::new(cfg.psk, cfg.peer_id.clone(), facade, rate_limiter.clone());

    loop {
        let bytes = match read_message(&mut r).await {
            Ok(b) => b,
            Err(TransportError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("peer closed connection");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        let env: Envelope = decode(&bytes)?;

        let reply = match env {
            Envelope::NonceRequest => {
                if let CheckResult::Locked { retry_after } = rate_limiter.check(&cfg.peer_id) {
                    warn!(peer = %cfg.peer_id, retry_after_s = retry_after.as_secs(), "peer is locked out");
                    // Reply with AuthFail so the client stops; they won't know the timer.
                    Envelope::AuthFail
                } else {
                    let nonce = session.issue_nonce();
                    Envelope::NonceReply(nonce.to_vec())
                }
            }
            Envelope::AuthSubmit(tag) => {
                if session.submit_auth(&tag) {
                    info!(peer = %cfg.peer_id, "authenticated");
                    Envelope::AuthOk
                } else {
                    warn!(peer = %cfg.peer_id, "auth failed");
                    Envelope::AuthFail
                }
            }
            Envelope::Req(req) => {
                let resp = session.handle_request(req).await;
                Envelope::Resp(resp)
            }
            // Client should never send these server-origin envelopes.
            Envelope::NonceReply(_) | Envelope::AuthOk | Envelope::AuthFail | Envelope::Resp(_) => {
                warn!("client sent server-origin envelope; closing");
                return Ok(());
            }
        };

        let out = encode(&reply)?;
        write_message(&mut w, &out).await?;
    }
}

pub async fn run_tcp_server<F, A>(
    addr: A,
    psk: Psk,
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
) -> anyhow::Result<()>
where
    F: NetworkFacade + 'static,
    A: ToSocketAddrs,
{
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %listener.local_addr()?, "netprov tcp loopback listener");
    loop {
        let (sock, peer) = listener.accept().await?;
        let facade = facade.clone();
        let rl = rate_limiter.clone();
        let peer_id = peer.to_string();
        tokio::spawn(async move {
            if let Err(e) = run_server(
                sock,
                ServerConfig {
                    psk,
                    peer_id: peer_id.clone(),
                },
                facade,
                rl,
            )
            .await
            {
                warn!(peer = %peer_id, error = ?e, "session ended with error");
            }
        });
    }
}
