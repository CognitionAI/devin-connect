//! Default-deny allowlist routing.
//!
//! Destinations are matched on the client-requested hostname (before DNS
//! resolution) or literal IP. No route match means deny.

use std::{collections::HashSet, net::IpAddr};

use cidr::{Ipv4Cidr, Ipv6Cidr};
use color_eyre::eyre::{self, WrapErr};

use crate::{
    config::{RouteConfig, RouteRule, UpstreamProxyConfig},
    hostname::HostnamePattern,
};

/// A destination as requested by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestHost<'a> {
    Name(&'a str),
    Ip(IpAddr),
}

impl DestHost<'_> {
    /// Parse a CONNECT authority host: a literal IP (v6 brackets already
    /// stripped) or a hostname.
    pub fn parse(host: &str) -> DestHost<'_> {
        match host.parse::<IpAddr>() {
            Ok(ip) => DestHost::Ip(ip),
            Err(_) => DestHost::Name(host),
        }
    }
}

impl std::fmt::Display for DestHost<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DestHost::Name(name) => f.write_str(name),
            DestHost::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// A compiled allowlist route.
#[derive(Debug)]
pub struct CompiledRoute {
    pub name: String,
    hostname_patterns: Vec<HostnamePattern>,
    ipv4: Vec<Ipv4Cidr>,
    ipv6: Vec<Ipv6Cidr>,
    ports: Option<HashSet<u16>>,
    pub upstream_proxy: Option<UpstreamProxyConfig>,
}

impl CompiledRoute {
    fn matches(&self, host: &DestHost<'_>, port: u16) -> bool {
        if let Some(ports) = &self.ports
            && !ports.contains(&port)
        {
            return false;
        }
        match host {
            DestHost::Name(name) => {
                let name = name.strip_suffix('.').unwrap_or(name);
                self.hostname_patterns.iter().any(|p| p.is_match(name))
            }
            DestHost::Ip(IpAddr::V4(ip)) => self.ipv4.iter().any(|c| c.contains(ip)),
            DestHost::Ip(IpAddr::V6(ip)) => self.ipv6.iter().any(|c| c.contains(ip)),
        }
    }
}

/// The compiled allowlist. Routes are evaluated in config order; the first
/// match wins, and no match means deny.
#[derive(Debug)]
pub struct PolicyEngine {
    routes: Vec<CompiledRoute>,
}

impl PolicyEngine {
    pub fn new(routes: &[RouteConfig]) -> eyre::Result<Self> {
        let routes = routes
            .iter()
            .map(|route| {
                let mut hostname_patterns = Vec::new();
                let mut ipv4 = Vec::new();
                let mut ipv6 = Vec::new();
                for rule in &route.rules {
                    match rule {
                        RouteRule::Hostname(pattern) => {
                            hostname_patterns.push(
                                HostnamePattern::compile(pattern).wrap_err_with(|| {
                                    format!("route {:?}: invalid pattern {:?}", route.name, pattern)
                                })?,
                            );
                        }
                        RouteRule::Ipv4(cidr) => ipv4.push(*cidr),
                        RouteRule::Ipv6(cidr) => ipv6.push(*cidr),
                    }
                }
                Ok(CompiledRoute {
                    name: route.name.clone(),
                    hostname_patterns,
                    ipv4,
                    ipv6,
                    ports: route.ports.as_ref().map(|p| p.iter().copied().collect()),
                    upstream_proxy: route.upstream_proxy.clone(),
                })
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        Ok(Self { routes })
    }

    /// Find the first route allowing this destination; `None` means deny.
    pub fn find_route(&self, host: &DestHost<'_>, port: u16) -> Option<&CompiledRoute> {
        self.routes.iter().find(|route| route.matches(host, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;

    fn engine(routes_yaml: &str) -> PolicyEngine {
        let yaml = format!(
            "schema_version: 1\nlisten: 127.0.0.1:1\nadmin_listen: 127.0.0.1:2\nroutes:\n{routes_yaml}"
        );
        let config = GatewayConfig::parse(&yaml).unwrap();
        PolicyEngine::new(&config.routes).unwrap()
    }

    fn route_name<'a>(engine: &'a PolicyEngine, host: &str, port: u16) -> Option<&'a str> {
        engine
            .find_route(&DestHost::parse(host), port)
            .map(|r| r.name.as_str())
    }

    #[test]
    fn matches_exact_and_wildcard_hostnames() {
        let engine = engine(
            r#"
  - name: scm
    rules: [{hostname: "*.corp.example"}, {hostname: "git.internal"}]
"#,
        );
        assert_eq!(
            route_name(&engine, "bitbucket.corp.example", 443),
            Some("scm")
        );
        assert_eq!(route_name(&engine, "GIT.INTERNAL", 443), Some("scm"));
        assert_eq!(route_name(&engine, "git.internal.", 443), Some("scm"));
        assert_eq!(route_name(&engine, "corp.example", 443), None);
        assert_eq!(route_name(&engine, "evil.example", 443), None);
        assert_eq!(route_name(&engine, "git.internal.evil.example", 443), None);
    }

    #[test]
    fn matches_cidrs() {
        let engine = engine(
            r#"
  - name: db
    rules: [{ipv4: 10.20.0.0/16}, {ipv6: "fd00::/8"}]
"#,
        );
        assert_eq!(route_name(&engine, "10.20.30.40", 5432), Some("db"));
        assert_eq!(route_name(&engine, "10.21.0.1", 5432), None);
        assert_eq!(route_name(&engine, "fd00::1", 5432), Some("db"));
        assert_eq!(route_name(&engine, "fe80::1", 5432), None);
        // A hostname never matches a CIDR-only route.
        assert_eq!(route_name(&engine, "db.corp.example", 5432), None);
    }

    #[test]
    fn restricts_ports() {
        let engine = engine(
            r#"
  - name: https-only
    rules: [{hostname: "registry.corp.example"}]
    ports: [443, 8443]
"#,
        );
        assert_eq!(
            route_name(&engine, "registry.corp.example", 443),
            Some("https-only")
        );
        assert_eq!(
            route_name(&engine, "registry.corp.example", 8443),
            Some("https-only")
        );
        assert_eq!(route_name(&engine, "registry.corp.example", 80), None);
    }

    #[test]
    fn first_match_wins() {
        let engine = engine(
            r#"
  - name: specific
    rules: [{hostname: "git.corp.example"}]
  - name: broad
    rules: [{hostname: "*.corp.example"}]
"#,
        );
        assert_eq!(
            route_name(&engine, "git.corp.example", 443),
            Some("specific")
        );
        assert_eq!(
            route_name(&engine, "other.corp.example", 443),
            Some("broad")
        );
    }
}
