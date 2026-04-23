use netprov_protocol::{NetError, StaticIpv4};

pub fn validate_static_ipv4(cfg: &StaticIpv4) -> Result<(), NetError> {
    let addr = cfg.address.addr();
    let prefix = cfg.address.prefix_len();

    if !(1..=30).contains(&prefix) {
        return Err(NetError::InvalidArgument(format!(
            "prefix length {prefix} out of range (1..=30)"
        )));
    }
    if addr.is_loopback() {
        return Err(NetError::InvalidArgument("address is loopback".into()));
    }
    if addr.is_multicast() {
        return Err(NetError::InvalidArgument("address is multicast".into()));
    }
    if addr.is_broadcast() {
        return Err(NetError::InvalidArgument("address is broadcast".into()));
    }
    if addr.is_unspecified() {
        return Err(NetError::InvalidArgument("address is unspecified".into()));
    }
    if addr == cfg.address.broadcast() {
        return Err(NetError::InvalidArgument(
            "address equals subnet broadcast".into(),
        ));
    }
    if addr == cfg.address.network() {
        return Err(NetError::InvalidArgument(
            "address equals subnet network".into(),
        ));
    }
    if let Some(gw) = cfg.gateway {
        if !cfg.address.contains(&gw) {
            return Err(NetError::InvalidArgument(
                "gateway is outside subnet".into(),
            ));
        }
        if gw == addr {
            return Err(NetError::InvalidArgument(
                "gateway equals host address".into(),
            ));
        }
    }
    for dns in &cfg.dns {
        if dns.is_unspecified() || dns.is_multicast() || dns.is_broadcast() {
            return Err(NetError::InvalidArgument(
                "dns server has invalid address".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(addr: &str, gw: Option<&str>, dns: &[&str]) -> StaticIpv4 {
        StaticIpv4 {
            address: addr.parse().unwrap(),
            gateway: gw.map(|s| s.parse().unwrap()),
            dns: dns.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn valid_config_accepted() {
        assert!(
            validate_static_ipv4(&cfg("192.168.1.10/24", Some("192.168.1.1"), &["1.1.1.1"]))
                .is_ok()
        );
    }

    #[test]
    fn zero_prefix_rejected() {
        assert!(validate_static_ipv4(&cfg("10.0.0.1/0", None, &[])).is_err());
    }

    #[test]
    fn host_route_prefix_rejected() {
        assert!(validate_static_ipv4(&cfg("10.0.0.1/31", None, &[])).is_err());
    }

    #[test]
    fn loopback_rejected() {
        assert!(validate_static_ipv4(&cfg("127.0.0.2/8", None, &[])).is_err());
    }

    #[test]
    fn multicast_rejected() {
        assert!(validate_static_ipv4(&cfg("224.0.0.1/24", None, &[])).is_err());
    }

    #[test]
    fn subnet_broadcast_rejected() {
        assert!(validate_static_ipv4(&cfg("192.168.1.255/24", None, &[])).is_err());
    }

    #[test]
    fn subnet_network_rejected() {
        assert!(validate_static_ipv4(&cfg("192.168.1.0/24", None, &[])).is_err());
    }

    #[test]
    fn gateway_outside_subnet_rejected() {
        assert!(validate_static_ipv4(&cfg("192.168.1.10/24", Some("10.0.0.1"), &[])).is_err());
    }

    #[test]
    fn gateway_equals_host_rejected() {
        assert!(validate_static_ipv4(&cfg("192.168.1.10/24", Some("192.168.1.10"), &[])).is_err());
    }
}
