use crate::facade::NetworkFacade;
use crate::rate_limit::{CheckResult, RateLimiter};
use crate::validate::validate_static_ipv4;
use netprov_protocol::*;
use rand::RngCore;
use std::sync::Arc;

pub struct Session<F: NetworkFacade> {
    psk: Psk,
    peer_id: String, // e.g., BLE peer MAC; opaque identifier.
    facade: Arc<F>,
    rate_limiter: Arc<RateLimiter>,
    state: SessionAuthState,
}

enum SessionAuthState {
    Unauthenticated { pending_nonce: Option<Nonce> },
    Authenticated,
}

pub enum HandleIncoming {
    /// No response required (e.g., successful auth handshake progress).
    Ack,
    /// Send this response frame to the peer.
    Response(Response),
    /// Terminate the connection.
    Disconnect,
}

impl<F: NetworkFacade> Session<F> {
    pub fn new(psk: Psk, peer_id: String, facade: Arc<F>, rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            psk,
            peer_id,
            facade,
            rate_limiter,
            state: SessionAuthState::Unauthenticated {
                pending_nonce: None,
            },
        }
    }

    /// Called when peer reads `ChallengeNonce`. Generates and returns a fresh
    /// nonce, invalidates any prior pending nonce.
    pub fn issue_nonce(&mut self) -> Nonce {
        let mut nonce: Nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        self.state = SessionAuthState::Unauthenticated {
            pending_nonce: Some(nonce),
        };
        nonce
    }

    /// Called when peer writes `AuthResponse`. Consumes the nonce regardless of
    /// outcome. Returns `true` if auth succeeded.
    pub fn submit_auth(&mut self, tag: &[u8]) -> bool {
        if matches!(
            self.rate_limiter.check(&self.peer_id),
            CheckResult::Locked { .. }
        ) {
            return false;
        }
        let (tag_len_ok, nonce) = match &self.state {
            SessionAuthState::Unauthenticated {
                pending_nonce: Some(n),
            } => (true, *n),
            _ => (false, [0u8; NONCE_LEN]),
        };
        self.state = SessionAuthState::Unauthenticated {
            pending_nonce: None,
        };
        if !tag_len_ok {
            return false;
        }
        if hmac_verify(&self.psk, &nonce, tag) {
            self.state = SessionAuthState::Authenticated;
            self.rate_limiter.record_success(&self.peer_id);
            true
        } else {
            self.rate_limiter.record_failure(&self.peer_id);
            false
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, SessionAuthState::Authenticated)
    }

    /// Dispatch an already-decoded `Request`. Returns a `Response` to send
    /// back over the transport.
    pub async fn handle_request(&self, req: Request) -> Response {
        if !self.is_authenticated() {
            return Response {
                request_id: req.request_id,
                result: Err(ProtocolError::NotAuthenticated),
            };
        }
        let request_id = req.request_id;
        let result = match req.op {
            Op::ListInterfaces => self
                .facade
                .list_interfaces()
                .await
                .map(OpResult::Interfaces)
                .map_err(Into::into),
            Op::GetIpConfig { iface } => self
                .facade
                .get_ip_config(&iface)
                .await
                .map(OpResult::IpConfig)
                .map_err(Into::into),
            Op::WifiStatus => self
                .facade
                .wifi_status()
                .await
                .map(OpResult::WifiStatus)
                .map_err(Into::into),
            Op::WifiScan => self
                .facade
                .scan_wifi()
                .await
                .map(OpResult::WifiNetworks)
                .map_err(Into::into),
            Op::SetDhcp { iface } => self
                .facade
                .set_dhcp(&iface)
                .await
                .map(|_| OpResult::Ok)
                .map_err(Into::into),
            Op::SetStaticIpv4 { iface, cfg } => {
                if let Err(e) = validate_static_ipv4(&cfg) {
                    Err(e.into())
                } else {
                    self.facade
                        .set_static_ipv4(&iface, cfg)
                        .await
                        .map(|_| OpResult::Ok)
                        .map_err(Into::into)
                }
            }
            Op::ConnectWifi { ssid, credential } => self
                .facade
                .connect_wifi(&ssid, credential)
                .await
                .map(|_| OpResult::Ok)
                .map_err(Into::into),
        };
        Response { request_id, result }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade_mock::MockFacade;

    fn fixture() -> (Psk, Session<MockFacade>) {
        let psk = [9u8; PSK_LEN];
        let s = Session::new(
            psk,
            "peer-A".into(),
            Arc::new(MockFacade::new()),
            Arc::new(RateLimiter::with_defaults()),
        );
        (psk, s)
    }

    #[tokio::test]
    async fn unauth_rejects_request() {
        let (_psk, s) = fixture();
        let r = Request {
            request_id: 1,
            op: Op::ListInterfaces,
        };
        let resp = s.handle_request(r).await;
        assert!(matches!(resp.result, Err(ProtocolError::NotAuthenticated)));
    }

    #[tokio::test]
    async fn auth_flow_then_list() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let tag = hmac_compute(&psk, &nonce);
        assert!(s.submit_auth(&tag));
        let resp = s
            .handle_request(Request {
                request_id: 1,
                op: Op::ListInterfaces,
            })
            .await;
        assert!(matches!(resp.result, Ok(OpResult::Interfaces(_))));
    }

    #[tokio::test]
    async fn wrong_tag_stays_unauth() {
        let (_psk, mut s) = fixture();
        s.issue_nonce();
        assert!(!s.submit_auth(&[0u8; TAG_LEN]));
        assert!(!s.is_authenticated());
    }

    #[tokio::test]
    async fn nonce_is_single_use() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let tag = hmac_compute(&psk, &nonce);
        // Wrong first attempt consumes the nonce.
        assert!(!s.submit_auth(&[0u8; TAG_LEN]));
        // Second attempt with the correct tag but stale nonce must fail.
        assert!(!s.submit_auth(&tag));
    }

    #[tokio::test]
    async fn static_ip_validation_runs() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let tag = hmac_compute(&psk, &nonce);
        s.submit_auth(&tag);
        let bad = StaticIpv4 {
            address: "224.0.0.1/24".parse().unwrap(),
            gateway: None,
            dns: vec![],
        };
        let resp = s
            .handle_request(Request {
                request_id: 2,
                op: Op::SetStaticIpv4 {
                    iface: "eth0".into(),
                    cfg: bad,
                },
            })
            .await;
        assert!(matches!(
            resp.result,
            Err(ProtocolError::InvalidArgument { .. })
        ));
    }
}
