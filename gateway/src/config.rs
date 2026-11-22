//! Versioned gateway configuration with strict validation.
//!
//! The gateway is default-deny and fail-closed: a config that fails to parse,
//! validate, or compile is rejected as a whole and never partially applied.

use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use cidr::{Ipv4Cidr, Ipv6Cidr};
use color_eyre::eyre::{self, WrapErr, bail, ensure, eyre};
use serde::Deserialize;
use tunnel::protocol::{HEARTBEAT_INTERVAL_RANGE, MAX_STREAMS_RANGE};

use crate::hostname::HostnamePattern;

/// The config document schema version this binary understands.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Root gateway config document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Schema version of this document; must equal [`SUPPORTED_SCHEMA_VERSION`].
    pub schema_version: u32,

    /// Monotonic version assigned by whoever rendered this document.
    /// Exposed as a metric.
    #[serde(default)]
    pub config_version: Option<u64>,

    /// Data-plane listen address (HTTP CONNECT). Required in direct mode
    /// (no `tunnel`), forbidden in tunnel mode: CONNECT requests then arrive
    /// only over the authenticated tunnel, and nothing on the gateway's
    /// network can use it as an open proxy into the allowlisted routes.
    #[serde(default)]
    pub listen: Option<SocketAddr>,

    /// Admin listen address (/healthz, /readyz, /metrics).
    pub admin_listen: SocketAddr,

    /// Timeout for dialing upstream targets.
    #[serde(default = "default_dial_timeout", with = "humantime_serde")]
    pub dial_timeout: Duration,

    /// Silence tolerated on a half-closed connection's surviving direction
    /// before the splice is reaped. After one side closes, the splice waits
    /// for the peer to close its side; a peer that never answers the FIN
    /// otherwise pins the task and the socket in FIN_WAIT-2, leaking a file
    /// descriptor per connection until the process hits rlimit. Bytes that
    /// still arrive restart the timer, so only a truly silent drain is cut.
    #[serde(default = "default_half_close_timeout", with = "humantime_serde")]
    pub half_close_timeout: Duration,

    /// Customer DNS resolution settings.
    #[serde(default)]
    pub dns: DnsConfig,

    /// Allowlist routes. Anything not matched by a route is denied.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Outbound tunnel to the Devin-side edge. Omitted means direct mode:
    /// the gateway serves its local listener only.
    #[serde(default)]
    pub tunnel: Option<TunnelConfig>,
}

fn default_dial_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_half_close_timeout() -> Duration {
    Duration::from_secs(60)
}

/// Customer DNS settings. An empty nameserver list means the system resolver.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// DNS servers to resolve target hostnames with (`ip:port`).
    #[serde(default)]
    pub nameservers: Vec<SocketAddr>,

    /// Per-query timeout.
    #[serde(default = "default_dns_timeout", with = "humantime_serde")]
    pub timeout: Duration,

    /// Permit hostname routes to resolve to loopback addresses (e.g. for
    /// colocated targets). Off by default: hostname resolutions to
    /// loopback, link-local, and unspecified addresses are refused so
    /// customer DNS cannot steer an allowlisted name at the gateway itself
    /// or a metadata endpoint.
    #[serde(default)]
    pub allow_loopback: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            timeout: default_dns_timeout(),
            allow_loopback: false,
        }
    }
}

fn default_dns_timeout() -> Duration {
    Duration::from_secs(5)
}

/// An allowlist entry: a set of destination match rules plus the policy to
/// apply to matching connections.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Unique route name (appears in logs).
    pub name: String,

    /// Destination match rules; the route matches if any rule matches.
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub rules: Vec<RouteRule>,

    /// Allowed destination ports. Omitted means any port.
    #[serde(default)]
    pub ports: Option<Vec<u16>>,

    /// Optional upstream HTTP CONNECT proxy to chain through.
    #[serde(default)]
    pub upstream_proxy: Option<UpstreamProxyConfig>,
}

/// A destination match rule. Hostname patterns support `*` wildcards.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteRule {
    Hostname(String),
    Ipv4(Ipv4Cidr),
    Ipv6(Ipv6Cidr),
}

/// Upstream HTTP CONNECT proxy to chain through for a route.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProxyConfig {
    /// Proxy address as `host:port`; hostnames are resolved with the
    /// configured DNS settings.
    pub addr: String,

    /// Value for the `Proxy-Authorization` header sent to the proxy.
    #[serde(default)]
    pub auth: Option<String>,
}

/// Outer carrier for the tunnel connection. Both carriers run inside the
/// same TLS connection to the edge and speak the identical tunnel protocol;
/// `websocket` only adds HTTP Upgrade + WebSocket framing for egress paths
/// (HTTP-aware proxies, ingress infrastructure) that do not pass raw TLS
/// traffic. TLS is mandatory either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    Direct,
    #[default]
    Websocket,
}

/// Outbound tunnel to the Devin-side edge. The gateway keeps a persistent
/// authenticated connection to the edge and serves CONNECT requests arriving
/// over it with the same datapath and policy as the local listener.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    /// Edge endpoint as `host:port`. The host is also the TLS server name
    /// the edge's certificate is verified against. The endpoint and egress
    /// proxy are Devin infrastructure, not customer destinations, so both
    /// resolve through the system resolver — the `dns` settings apply only
    /// to route targets.
    pub endpoint: String,

    /// Stable identifier for this gateway deployment, sent in the tunnel
    /// handshake.
    pub gateway_id: String,

    /// Path to a file containing the enrollment token presented to the edge
    /// (relative paths resolved against the config file). Kept out of the
    /// config document itself and re-read on every connection attempt, so
    /// the token can be rotated without a restart.
    pub auth_token_file: PathBuf,

    /// PEM CA bundle to verify the edge certificate against instead of the
    /// built-in webpki roots (e.g. behind a corporate TLS-inspection proxy).
    #[serde(default)]
    pub ca_file: Option<PathBuf>,

    /// Customer egress HTTP CONNECT proxy to dial the edge through.
    #[serde(default)]
    pub egress_proxy: Option<UpstreamProxyConfig>,

    /// Interval between heartbeats on the tunnel control stream.
    #[serde(default = "default_heartbeat_interval", with = "humantime_serde")]
    pub heartbeat_interval: Duration,

    /// Outer carrier for the tunnel connection.
    #[serde(default)]
    pub carrier: Carrier,

    /// Pool of concurrent tunnel connections to the edge.
    #[serde(default)]
    pub connection_pool: ConnectionPoolConfig,
}

fn default_heartbeat_interval() -> Duration {
    Duration::from_secs(15)
}

/// Hard ceiling on `connection_pool.size`, so a config typo cannot open an
/// unbounded number of connections against the edge.
pub const MAX_POOL_SIZE: usize = 16;

/// Tunnel connection pool. Each member is an independent TLS connection
/// carrying its own yamux streams; the pool raises aggregate throughput past
/// a single TCP connection's ceiling and isolates the blast radius of one
/// connection failing. `size` is the one tunnel setting applied on config
/// reload (grow starts members, shrink drains them); everything else in the
/// tunnel stanza requires a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPoolConfig {
    /// Number of tunnel connections to maintain.
    #[serde(default = "default_pool_size")]
    pub size: usize,

    /// Cap on concurrent yamux streams per connection, declared to the edge
    /// in the hello. The edge stops routing new dials to a connection at
    /// this cap (minus the control stream).
    #[serde(default = "default_max_streams_per_connection")]
    pub max_streams_per_connection: usize,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            size: default_pool_size(),
            max_streams_per_connection: default_max_streams_per_connection(),
        }
    }
}

fn default_pool_size() -> usize {
    4
}

fn default_max_streams_per_connection() -> usize {
    tunnel::mux::DEFAULT_MAX_STREAMS
}

impl GatewayConfig {
    /// Parse and strictly validate a config document from YAML.
    pub fn parse(yaml: &str) -> eyre::Result<Self> {
        let config: Self = serde_yaml::from_str(yaml).wrap_err("failed to parse config")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> eyre::Result<()> {
        ensure!(
            self.schema_version == SUPPORTED_SCHEMA_VERSION,
            "unsupported schema_version {} (supported: {})",
            self.schema_version,
            SUPPORTED_SCHEMA_VERSION
        );
        ensure!(
            !self.half_close_timeout.is_zero(),
            "half_close_timeout must be positive"
        );
        match (self.listen, &self.tunnel) {
            (Some(listen), None) => ensure!(
                listen != self.admin_listen,
                "listen and admin_listen must be different addresses"
            ),
            (None, Some(_)) => {}
            (None, None) => bail!("direct mode (no tunnel) requires a listen address"),
            (Some(_), Some(_)) => bail!(
                "listen must not be set in tunnel mode: CONNECT requests are served \
                 only over the tunnel"
            ),
        }

        let mut route_names = HashSet::new();
        for route in &self.routes {
            ensure!(!route.name.is_empty(), "route name must not be empty");
            ensure!(
                route_names.insert(route.name.as_str()),
                "duplicate route name {:?}",
                route.name
            );
            ensure!(
                !route.rules.is_empty(),
                "route {:?}: rules must not be empty",
                route.name
            );
            for rule in &route.rules {
                if let RouteRule::Hostname(pattern) = rule {
                    ensure!(
                        !pattern.is_empty(),
                        "route {:?}: hostname pattern must not be empty",
                        route.name
                    );
                    HostnamePattern::compile(pattern).wrap_err_with(|| {
                        format!(
                            "route {:?}: invalid hostname pattern {:?}",
                            route.name, pattern
                        )
                    })?;
                }
            }
            if let Some(ports) = &route.ports {
                ensure!(
                    !ports.is_empty(),
                    "route {:?}: ports must not be empty when specified",
                    route.name
                );
            }
            if let Some(proxy) = &route.upstream_proxy {
                split_host_port(&proxy.addr).wrap_err_with(|| {
                    format!("route {:?}: invalid upstream_proxy addr", route.name)
                })?;
            }
        }

        if let Some(tunnel) = &self.tunnel {
            split_host_port(&tunnel.endpoint).wrap_err("tunnel: invalid endpoint")?;
            ensure!(
                !tunnel.gateway_id.is_empty(),
                "tunnel: gateway_id must not be empty"
            );
            ensure!(
                tunnel.heartbeat_interval.subsec_nanos() == 0
                    && HEARTBEAT_INTERVAL_RANGE.contains(&tunnel.heartbeat_interval.as_secs()),
                "tunnel: heartbeat_interval must be whole seconds between {}s and {}s",
                HEARTBEAT_INTERVAL_RANGE.start(),
                HEARTBEAT_INTERVAL_RANGE.end()
            );
            if let Some(proxy) = &tunnel.egress_proxy {
                split_host_port(&proxy.addr).wrap_err("tunnel: invalid egress_proxy addr")?;
            }
            ensure!(
                (1..=MAX_POOL_SIZE).contains(&tunnel.connection_pool.size),
                "tunnel: connection_pool.size must be between 1 and {MAX_POOL_SIZE}"
            );
            ensure!(
                MAX_STREAMS_RANGE.contains(&tunnel.connection_pool.max_streams_per_connection),
                "tunnel: connection_pool.max_streams_per_connection must be between {} and {}",
                MAX_STREAMS_RANGE.start(),
                MAX_STREAMS_RANGE.end()
            );
        }

        Ok(())
    }

    /// Load, parse, and validate a config file.
    pub async fn load(path: &Path) -> eyre::Result<(Self, String)> {
        let yaml = tokio::fs::read_to_string(path)
            .await
            .wrap_err_with(|| format!("failed to read config file {}", path.display()))?;
        let config = Self::parse(&yaml)?;
        Ok((config, yaml))
    }
}

/// Split a `host:port` string, supporting `[v6]:port` bracket syntax.
pub fn split_host_port(addr: &str) -> eyre::Result<(String, u16)> {
    let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| eyre!("invalid address {addr:?}: missing closing bracket"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| eyre!("invalid address {addr:?}: missing port"))?;
        (host, port)
    } else {
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| eyre!("invalid address {addr:?}: missing port"))?;
        ensure!(
            !host.contains(':'),
            "invalid address {addr:?}: IPv6 addresses need [brackets]"
        );
        (host, port)
    };
    ensure!(!host.is_empty(), "invalid address {addr:?}: empty host");
    ensure!(
        !host.contains('@'),
        "invalid address {addr:?}: userinfo is not allowed"
    );
    // Hostnames are ASCII letters/digits/`.`/`-`/`_` (IDNs must arrive
    // punycoded); bracketed IPv6 literals add hex digits and `:`. Anything
    // else is not a host and never reaches the resolver or the matcher.
    ensure!(
        host.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':')),
        "invalid address {addr:?}: host contains characters outside [A-Za-z0-9._-]"
    );
    let port: u16 = port
        .parse()
        .map_err(|_| eyre!("invalid address {addr:?}: invalid port"))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(extra: &str) -> String {
        format!("schema_version: 1\nlisten: 127.0.0.1:8443\nadmin_listen: 127.0.0.1:9090\n{extra}")
    }

    const MINIMAL_TUNNEL: &str =
        "tunnel:\n  endpoint: edge.example:443\n  gateway_id: gw-1\n  auth_token_file: token\n";

    fn minimal_tunnel_config(extra: &str) -> String {
        format!("schema_version: 1\nadmin_listen: 127.0.0.1:9090\n{MINIMAL_TUNNEL}{extra}")
    }

    #[test]
    fn tunnel_mode_has_no_data_listener() {
        let config = GatewayConfig::parse(&minimal_tunnel_config("")).unwrap();
        assert!(config.listen.is_none() && config.tunnel.is_some());
        let tunnel = config.tunnel.unwrap();
        assert_eq!(tunnel.carrier, Carrier::Websocket);
        assert_eq!(tunnel.connection_pool.size, 4);

        let err = GatewayConfig::parse(&minimal_config(MINIMAL_TUNNEL)).unwrap_err();
        assert!(
            err.to_string()
                .contains("listen must not be set in tunnel mode"),
            "{err}"
        );
    }

    #[test]
    fn direct_mode_requires_data_listener() {
        let err =
            GatewayConfig::parse("schema_version: 1\nadmin_listen: 127.0.0.1:9090\n").unwrap_err();
        assert!(
            err.to_string().contains("requires a listen address"),
            "{err}"
        );
        let err = GatewayConfig::parse(
            "schema_version: 1\nlisten: 127.0.0.1:9090\nadmin_listen: 127.0.0.1:9090\n",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("must be different addresses"),
            "{err}"
        );
    }

    #[test]
    fn parses_full_config() {
        let config = GatewayConfig::parse(&minimal_config(
            r#"
config_version: 42
dial_timeout: 3s
half_close_timeout: 45s
dns:
  nameservers: ["10.0.0.2:53"]
  timeout: 2s
routes:
  - name: scm
    rules:
      - hostname: "*.corp.example"
      - ipv4: 10.0.0.0/8
      - ipv6: fd00::/8
    ports: [443]
    upstream_proxy:
      addr: proxy.corp.example:3128
  - name: open
    rules:
      - hostname: echo.corp.example
"#,
        ))
        .unwrap();
        assert_eq!(config.config_version, Some(42));
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.dns.nameservers.len(), 1);
        assert_eq!(config.half_close_timeout, Duration::from_secs(45));
    }

    #[test]
    fn rejects_zero_half_close_timeout() {
        let err = GatewayConfig::parse(&minimal_config("half_close_timeout: 0s")).unwrap_err();
        assert!(err.to_string().contains("half_close_timeout"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = GatewayConfig::parse(&minimal_config("nonsense: true")).unwrap_err();
        assert!(err.to_string().contains("failed to parse config"), "{err}");
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let yaml = "schema_version: 2\nlisten: 127.0.0.1:8443\nadmin_listen: 127.0.0.1:9090\n";
        let err = GatewayConfig::parse(yaml).unwrap_err();
        assert!(
            err.to_string().contains("unsupported schema_version"),
            "{err}"
        );
    }

    #[test]
    fn rejects_duplicate_route_names() {
        let err = GatewayConfig::parse(&minimal_config(
            r#"
routes:
  - name: a
    rules: [{hostname: "x"}]
  - name: a
    rules: [{hostname: "y"}]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate route name"), "{err}");
    }

    #[test]
    fn rejects_legacy_route_auth() {
        let err = GatewayConfig::parse(&minimal_config(
            r#"
routes:
  - name: a
    rules: [{hostname: x}]
    auth: none
"#,
        ))
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("unknown field `auth`"),
            "{err:#}"
        );
    }

    #[test]
    fn rejects_heartbeat_interval_outside_edge_contract() {
        let tunnel =
            |interval: &str| minimal_tunnel_config(&format!("  heartbeat_interval: {interval}\n"));
        for bad in ["500ms", "301s"] {
            let err = GatewayConfig::parse(&tunnel(bad)).unwrap_err();
            assert!(
                err.to_string().contains("heartbeat_interval"),
                "{bad}: {err}"
            );
        }
        for good in ["1s", "300s"] {
            GatewayConfig::parse(&tunnel(good)).unwrap();
        }
    }

    #[test]
    fn splits_host_port() {
        assert_eq!(
            split_host_port("example.com:443").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            split_host_port("10.0.0.1:22").unwrap(),
            ("10.0.0.1".into(), 22)
        );
        assert_eq!(
            split_host_port("[fd00::1]:5432").unwrap(),
            ("fd00::1".into(), 5432)
        );
        assert!(split_host_port("example.com").is_err());
        assert!(split_host_port("example.com:notaport").is_err());
        assert!(split_host_port(":443").is_err());
        assert!(split_host_port("fd00::1").is_err());
        assert!(split_host_port("fd00::1:5432").is_err());
        assert!(split_host_port("user@example.com:443").is_err());
        assert!(split_host_port("aé:443").is_err());
        assert!(split_host_port("a b:443").is_err());
        assert!(split_host_port("a/b:443").is_err());
        assert!(split_host_port("a\x7fb:443").is_err());
    }
}
