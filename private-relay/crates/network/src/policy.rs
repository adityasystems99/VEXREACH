use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use private_relay_protocol::MAX_TARGET_ADDR_LEN;
use tokio::net::lookup_host;

use crate::error::NetworkError;

/// Exit outbound policy enforcing controlled destinations and SSRF IP blocklists (`THREAT_MODEL` Threat 3 / `KI-05`).
#[derive(Debug, Clone, Default)]
pub struct DestinationPolicy {
    pub allow_loopback_for_test: bool,
    pub allowed_targets: Vec<String>,
}

impl DestinationPolicy {
    /// Resolves `target` (`host:port`) once at Exit, enforces allowlist & SSRF checks on EVERY
    /// returned IP, and returns the exact validated `SocketAddr` for `TcpStream::connect` (`KI-05`).
    pub async fn resolve_and_validate(&self, target: &str) -> Result<SocketAddr, NetworkError> {
        if target.is_empty()
            || target.len() > MAX_TARGET_ADDR_LEN
            || target.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(NetworkError::PolicyDenied(
                "malformed target address".into(),
            ));
        }

        if !self.allowed_targets.is_empty() && !self.allowed_targets.iter().any(|a| a == target) {
            return Err(NetworkError::PolicyDenied(
                "destination is not in controlled exit allowlist".into(),
            ));
        }

        let resolved: Vec<SocketAddr> = lookup_host(target)
            .await
            .map_err(|_| NetworkError::DnsResolutionFailed)?
            .collect();

        if resolved.is_empty() {
            return Err(NetworkError::DnsResolutionFailed);
        }

        for addr in &resolved {
            self.validate_ip(addr.ip())?;
        }

        Ok(resolved[0])
    }

    /// Synchronously validates an `IpAddr` against private, loopback, link-local, and multicast ranges.
    pub fn validate_ip(&self, ip: IpAddr) -> Result<(), NetworkError> {
        match ip {
            IpAddr::V4(v4) => self.validate_ipv4(v4),
            IpAddr::V6(v6) => self.validate_ipv6(v6),
        }
    }

    fn validate_ipv4(&self, ip: Ipv4Addr) -> Result<(), NetworkError> {
        let octets = ip.octets();
        let is_loopback = octets[0] == 127;
        if is_loopback {
            if self.allow_loopback_for_test {
                return Ok(());
            }
            return Err(NetworkError::PolicyDenied("loopback IPv4 denied".into()));
        }

        let is_cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 64;
        let is_this_network = octets[0] == 0;
        let is_benchmark = octets[0] == 198 && (octets[1] == 18 || octets[1] == 19);
        let is_ietf_prot = octets[0] == 192 && octets[1] == 0 && octets[2] == 0;
        if is_this_network
            || ip.is_unspecified()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_broadcast()
            || ip.is_documentation()
            || is_cgnat
            || is_benchmark
            || is_ietf_prot
            || octets[0] >= 240
        {
            return Err(NetworkError::PolicyDenied(
                "private or reserved IPv4 denied".into(),
            ));
        }

        Ok(())
    }

    fn validate_ipv6(&self, ip: Ipv6Addr) -> Result<(), NetworkError> {
        if let Some(mapped_v4) = ip.to_ipv4_mapped() {
            return self.validate_ipv4(mapped_v4);
        }

        if ip.is_loopback() {
            if self.allow_loopback_for_test {
                return Ok(());
            }
            return Err(NetworkError::PolicyDenied("loopback IPv6 denied".into()));
        }

        let segments = ip.segments();
        let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
        let is_unique_local = (segments[0] & 0xfe00) == 0xfc00;
        let is_nat64 = segments[0] == 0x0064 && segments[1] == 0xff9b;
        let is_doc = segments[0] == 0x2001 && segments[1] == 0x0db8;
        if ip.is_unspecified()
            || ip.is_multicast()
            || is_link_local
            || is_unique_local
            || is_nat64
            || is_doc
        {
            return Err(NetworkError::PolicyDenied(
                "private or reserved IPv6 denied".into(),
            ));
        }

        Ok(())
    }
}
