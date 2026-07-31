use crate::facade::NetworkFacade;
use crate::rate_limit::{CheckResult, RateLimiter};
use netprov_protocol::*;
use rand::Rng;
use std::sync::Arc;

pub async fn dispatch<F: NetworkFacade>(facade: &F, req: Request) -> Response {
    use netprov_protocol::{Op, OpResult};
    let request_id = req.request_id;
    let result = match req.op {
        Op::ListInterfaces => facade
            .list_interfaces()
            .await
            .map(OpResult::Interfaces)
            .map_err(Into::into),
        Op::GetIpConfig { iface } => facade
            .get_ip_config(&iface)
            .await
            .map(OpResult::IpConfig)
            .map_err(Into::into),
        Op::WifiStatus => facade
            .wifi_status()
            .await
            .map(OpResult::WifiStatus)
            .map_err(Into::into),
        Op::WifiScan => facade
            .scan_wifi()
            .await
            .map(OpResult::WifiNetworks)
            .map_err(Into::into),
        Op::SetDhcp { iface } => facade
            .set_dhcp(&iface)
            .await
            .map(|_| OpResult::Ok)
            .map_err(Into::into),
        Op::SetStaticIpv4 { iface, cfg } => {
            if let Err(e) = crate::validate::validate_static_ipv4(&cfg) {
                Err(e.into())
            } else {
                facade
                    .set_static_ipv4(&iface, cfg)
                    .await
                    .map(|_| OpResult::Ok)
                    .map_err(Into::into)
            }
        }
        Op::ConnectWifi { ssid, credential } => facade
            .connect_wifi(&ssid, credential)
            .await
            .map(|_| OpResult::Ok)
            .map_err(Into::into),
    };
    Response { request_id, result }
}

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
        rand::rng().fill_bytes(&mut nonce);
        self.state = SessionAuthState::Unauthenticated {
            pending_nonce: Some(nonce),
        };
        nonce
    }

    /// Called when peer writes `AuthResponse`. `payload` is the client nonce
    /// followed by the client tag. Consumes the nonce regardless of outcome.
    ///
    /// Returns the server's own tag on success, for the peer to verify. The
    /// tag is only ever computed after the client's tag has been checked, so
    /// it cannot be used as a PSK oracle.
    pub fn submit_auth(&mut self, payload: &[u8]) -> Option<Tag> {
        // Consume the pending nonce first, so a lockout cannot park a still-
        // valid nonce for the whole window and let the first attempt after it
        // expires spend it (#19).
        let pending = match &self.state {
            SessionAuthState::Unauthenticated {
                pending_nonce: Some(n),
            } => Some(*n),
            _ => None,
        };
        self.state = SessionAuthState::Unauthenticated {
            pending_nonce: None,
        };
        if matches!(
            self.rate_limiter.check(&self.peer_id),
            CheckResult::Locked { .. }
        ) {
            return None;
        }
        let server_nonce = pending?;
        let (client_nonce, tag) = split_auth_payload(payload)?;

        if verify_client_tag(&self.psk, &server_nonce, &client_nonce, tag) {
            self.state = SessionAuthState::Authenticated;
            self.rate_limiter.record_success(&self.peer_id);
            Some(server_tag(&self.psk, &server_nonce, &client_nonce))
        } else {
            self.rate_limiter.record_failure(&self.peer_id);
            None
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
        dispatch(&*self.facade, req).await
    }

    pub fn facade_clone(&self) -> Arc<F> {
        self.facade.clone()
    }

    pub fn peer_id_for_log(&self) -> &str {
        &self.peer_id
    }

    /// Whether a nonce is still awaiting an `AuthResponse`. Test-only: the
    /// nonce-consumption rule in `submit_auth` has no other observable effect
    /// while a peer is locked out.
    #[cfg(test)]
    fn pending_nonce(&self) -> Option<Nonce> {
        match &self.state {
            SessionAuthState::Unauthenticated { pending_nonce } => *pending_nonce,
            SessionAuthState::Authenticated => None,
        }
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

    /// Valid `AuthSubmit` payload for `nonce`, with a fixed client nonce.
    fn payload(psk: &Psk, nonce: &Nonce) -> [u8; AUTH_PAYLOAD_LEN] {
        let client_nonce = [0xABu8; NONCE_LEN];
        auth_payload(&client_nonce, &client_tag(psk, nonce, &client_nonce))
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
        assert!(s.submit_auth(&payload(&psk, &nonce)).is_some());
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
        assert!(s.submit_auth(&[0u8; AUTH_PAYLOAD_LEN]).is_none());
        assert!(!s.is_authenticated());
    }

    /// The tag the server returns must verify under the client's own check,
    /// or a correct client would reject a correct server.
    #[tokio::test]
    async fn server_tag_verifies_client_side() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let client_nonce = [0xABu8; NONCE_LEN];
        let tag = s
            .submit_auth(&auth_payload(
                &client_nonce,
                &client_tag(&psk, &nonce, &client_nonce),
            ))
            .expect("auth succeeds");
        assert!(verify_server_tag(&psk, &nonce, &client_nonce, &tag));
        // And it must not be the client's own tag echoed back.
        assert!(!verify_client_tag(&psk, &nonce, &client_nonce, &tag));
    }

    /// A payload that isn't exactly nonce+tag is rejected outright rather than
    /// being padded or truncated into something that might verify.
    #[tokio::test]
    async fn malformed_payload_rejected() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let good = payload(&psk, &nonce);
        assert!(s.submit_auth(&good[..AUTH_PAYLOAD_LEN - 1]).is_none());
        assert!(!s.is_authenticated());
    }

    /// #19: a nonce issued just before lockout must not survive the lockout
    /// window, or the first attempt after it expires could still spend it.
    #[tokio::test]
    async fn lockout_still_consumes_pending_nonce() {
        let psk = [9u8; PSK_LEN];
        let limiter = Arc::new(RateLimiter::with_defaults());
        let mut s = Session::new(
            psk,
            "peer-A".into(),
            Arc::new(MockFacade::new()),
            limiter.clone(),
        );
        let nonce = s.issue_nonce();
        for _ in 0..5 {
            limiter.record_failure("peer-A");
        }
        // Refused because the peer is locked out, not because the tag is bad.
        assert!(s.submit_auth(&payload(&psk, &nonce)).is_none());
        assert!(
            s.pending_nonce().is_none(),
            "lockout must still consume the pending nonce"
        );
    }

    #[tokio::test]
    async fn nonce_is_single_use() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        let good = payload(&psk, &nonce);
        // Wrong first attempt consumes the nonce.
        assert!(s.submit_auth(&[0u8; AUTH_PAYLOAD_LEN]).is_none());
        // Second attempt with the correct tag but stale nonce must fail.
        assert!(s.submit_auth(&good).is_none());
    }

    #[tokio::test]
    async fn static_ip_validation_runs() {
        let (psk, mut s) = fixture();
        let nonce = s.issue_nonce();
        s.submit_auth(&payload(&psk, &nonce));
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
