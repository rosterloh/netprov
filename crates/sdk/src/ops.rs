use async_trait::async_trait;
use netprov_protocol::{
    CodecError, FramingError, Interface, IpConfig, Op, OpResult, ProtocolError, Psk, StaticIpv4,
    TransportError, WifiCredential, WifiNetwork, WifiStatus,
};

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("authentication failed")]
    AuthFailed,
    #[error("unexpected server message: {0}")]
    UnexpectedMessage(&'static str),
    #[error("response id mismatch: expected {expected}, got {got}")]
    IdMismatch { expected: u16, got: u16 },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("framing: {0}")]
    Framing(#[from] FramingError),
    #[cfg(feature = "ble")]
    #[error("ble: {0}")]
    Ble(String),
}

#[cfg(feature = "ble")]
impl From<bluer::Error> for SdkError {
    fn from(value: bluer::Error) -> Self {
        Self::Ble(value.to_string())
    }
}

#[async_trait]
pub trait ProvisioningClient {
    async fn authenticate(&mut self, psk: Psk) -> Result<(), SdkError>;
    async fn request(&mut self, op: Op) -> Result<OpResult, SdkError>;
}

/// Typed app-facing wrapper over a concrete transport client.
pub struct Netprov<C> {
    inner: C,
}

impl<C> Netprov<C> {
    pub fn new(inner: C) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &C {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut C {
        &mut self.inner
    }

    pub fn into_inner(self) -> C {
        self.inner
    }
}

impl<C: ProvisioningClient + Send> Netprov<C> {
    pub async fn authenticate(&mut self, psk: Psk) -> Result<(), SdkError> {
        self.inner.authenticate(psk).await
    }

    pub async fn list_interfaces(&mut self) -> Result<Vec<Interface>, SdkError> {
        match self.inner.request(Op::ListInterfaces).await? {
            OpResult::Interfaces(value) => Ok(value),
            _ => Err(SdkError::UnexpectedMessage("expected Interfaces result")),
        }
    }

    pub async fn get_ip_config(&mut self, iface: impl Into<String>) -> Result<IpConfig, SdkError> {
        match self
            .inner
            .request(Op::GetIpConfig {
                iface: iface.into(),
            })
            .await?
        {
            OpResult::IpConfig(value) => Ok(value),
            _ => Err(SdkError::UnexpectedMessage("expected IpConfig result")),
        }
    }

    pub async fn wifi_status(&mut self) -> Result<WifiStatus, SdkError> {
        match self.inner.request(Op::WifiStatus).await? {
            OpResult::WifiStatus(value) => Ok(value),
            _ => Err(SdkError::UnexpectedMessage("expected WifiStatus result")),
        }
    }

    pub async fn wifi_scan(&mut self) -> Result<Vec<WifiNetwork>, SdkError> {
        match self.inner.request(Op::WifiScan).await? {
            OpResult::WifiNetworks(value) => Ok(value),
            _ => Err(SdkError::UnexpectedMessage("expected WifiNetworks result")),
        }
    }

    pub async fn set_dhcp(&mut self, iface: impl Into<String>) -> Result<(), SdkError> {
        expect_ok(
            self.inner
                .request(Op::SetDhcp {
                    iface: iface.into(),
                })
                .await?,
        )
    }

    pub async fn set_static_ipv4(
        &mut self,
        iface: impl Into<String>,
        cfg: StaticIpv4,
    ) -> Result<(), SdkError> {
        expect_ok(
            self.inner
                .request(Op::SetStaticIpv4 {
                    iface: iface.into(),
                    cfg,
                })
                .await?,
        )
    }

    pub async fn connect_wifi(
        &mut self,
        ssid: impl Into<String>,
        credential: WifiCredential,
    ) -> Result<(), SdkError> {
        expect_ok(
            self.inner
                .request(Op::ConnectWifi {
                    ssid: ssid.into(),
                    credential,
                })
                .await?,
        )
    }
}

fn expect_ok(result: OpResult) -> Result<(), SdkError> {
    match result {
        OpResult::Ok => Ok(()),
        _ => Err(SdkError::UnexpectedMessage("expected Ok result")),
    }
}
