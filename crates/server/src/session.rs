use crate::facade::NetworkFacade;
use crate::rate_limit::{CheckResult, RateLimiter};
use netprov_protocol::*;
use rand::Rng;
use std::sync::Arc;
use tracing::warn;

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
            .map(|nets| OpResult::WifiNetworks(bound_wifi_networks(nets, request_id)))
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

/// Drops the weakest networks until the encoded response fits under
/// `MAX_MESSAGE_SIZE`.
///
/// A scan result carries ~60–80 CBOR bytes per AP, so somewhere north of 50
/// visible networks — an office or a block of flats — pushed the response over
/// the 4 KiB ceiling. `encode` then failed and the peer got
/// "response too large to encode" instead of a network list, in exactly the
/// crowded places where provisioning is most awkward (#16).
///
/// Strongest first, because the network someone is trying to join is almost
/// always one they are standing near. The trial encode is the fitness test
/// rather than a hardcoded count, so a handful of unusually long SSIDs cannot
/// slip past a limit tuned for average ones. Popping one at a time is O(n)
/// encodes of a ≤4 KiB buffer in the worst case, which is nothing next to the
/// seconds the scan itself takes.
fn bound_wifi_networks(mut nets: Vec<WifiNetwork>, request_id: u16) -> Vec<WifiNetwork> {
    // Descending signal; `None` sorts weakest so unknown-strength APs are shed
    // first.
    nets.sort_by_key(|n| std::cmp::Reverse(n.signal));

    let total = nets.len();
    while !nets.is_empty() && !wifi_response_fits(&nets, request_id) {
        nets.pop();
    }
    if nets.len() < total {
        warn!(
            total,
            returned = nets.len(),
            "truncated Wi-Fi scan to fit the message size limit"
        );
    }
    nets
}

/// Whether `nets` encodes within the protocol's size limit, measured on the
/// real `Response` so framing overhead is counted rather than estimated.
fn wifi_response_fits(nets: &[WifiNetwork], request_id: u16) -> bool {
    encode_response(&Response {
        request_id,
        result: Ok(OpResult::WifiNetworks(nets.to_vec())),
    })
    .is_ok()
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

    fn net(i: usize, signal: u8) -> WifiNetwork {
        WifiNetwork {
            ssid: format!("network-{i:04}-with-a-realistically-long-name"),
            signal: Some(signal),
            security: Some(Security::Wpa2Psk),
            bssid: format!("aa:bb:cc:dd:{:02x}:{:02x}", i / 256, i % 256),
        }
    }

    /// #16: a dense environment used to blow the 4 KiB ceiling, so the peer got
    /// an encode error instead of any networks at all.
    #[test]
    fn dense_scan_is_truncated_to_fit() {
        let dense: Vec<_> = (0..200).map(|i| net(i, (i % 100) as u8)).collect();
        let bounded = bound_wifi_networks(dense, 7);

        assert!(!bounded.is_empty(), "must return something usable");
        assert!(bounded.len() < 200, "must have shed some networks");
        assert!(
            encode_response(&Response {
                request_id: 7,
                result: Ok(OpResult::WifiNetworks(bounded.clone())),
            })
            .is_ok(),
            "the whole point: the response now encodes"
        );
    }

    /// The networks kept must be the strong ones — those are the ones the
    /// operator is standing next to.
    #[test]
    fn truncation_keeps_the_strongest() {
        let mut nets: Vec<_> = (0..200).map(|i| net(i, (i % 100) as u8)).collect();
        nets.push(WifiNetwork {
            ssid: "the-one-you-want".into(),
            signal: Some(100),
            security: Some(Security::Wpa2Psk),
            bssid: "aa:bb:cc:dd:ee:ff".into(),
        });

        let bounded = bound_wifi_networks(nets, 1);
        assert_eq!(
            bounded.first().map(|n| n.ssid.as_str()),
            Some("the-one-you-want")
        );
        let weakest_kept = bounded.last().unwrap().signal.unwrap();
        assert!(
            bounded.iter().all(|n| n.signal.unwrap() >= weakest_kept),
            "kept set must be the top slice by signal"
        );
    }

    /// A scan that already fits must come back untouched apart from ordering.
    #[test]
    fn small_scan_is_not_truncated() {
        let few: Vec<_> = (0..5).map(|i| net(i, (i * 10) as u8)).collect();
        assert_eq!(bound_wifi_networks(few, 1).len(), 5);
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
