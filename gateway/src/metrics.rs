//! Connection counters exposed in Prometheus text format on `/metrics`.

use std::sync::atomic::AtomicU64;

use common::prometheus::{counter, gauge};

#[derive(Debug, Default)]
pub struct Metrics {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub denied_no_route_total: AtomicU64,
    pub bad_requests_total: AtomicU64,
    pub dial_errors_total: AtomicU64,
    pub connections_reaped_total: AtomicU64,
    pub bytes_client_to_upstream_total: AtomicU64,
    pub bytes_upstream_to_client_total: AtomicU64,
    pub config_reloads_total: AtomicU64,
    pub config_reload_errors_total: AtomicU64,
    pub config_version: AtomicU64,
    pub tunnel_connected: AtomicU64,
    pub tunnel_connects_total: AtomicU64,
    pub tunnel_errors_total: AtomicU64,
    pub tunnel_streams_total: AtomicU64,
    pub tunnel_pool_target: AtomicU64,
    pub tunnel_pool_draining: AtomicU64,
}

impl Metrics {
    pub fn render(&self) -> String {
        [
            counter(
                "gateway_connections_total",
                "Connections accepted on the data-plane listener or tunnel.",
                &self.connections_total,
            ),
            gauge(
                "gateway_connections_active",
                "Connections currently spliced.",
                &self.connections_active,
            ),
            counter(
                "gateway_denied_no_route_total",
                "Connections denied because no allowlist route matched.",
                &self.denied_no_route_total,
            ),
            counter(
                "gateway_bad_requests_total",
                "Connections rejected due to malformed or non-CONNECT requests.",
                &self.bad_requests_total,
            ),
            counter(
                "gateway_dial_errors_total",
                "Failures resolving or dialing an allowed target.",
                &self.dial_errors_total,
            ),
            counter(
                "gateway_connections_reaped_total",
                "Connections reaped after the peer stayed silent past half_close_timeout.",
                &self.connections_reaped_total,
            ),
            counter(
                "gateway_bytes_client_to_upstream_total",
                "Bytes forwarded from clients to upstream targets.",
                &self.bytes_client_to_upstream_total,
            ),
            counter(
                "gateway_bytes_upstream_to_client_total",
                "Bytes forwarded from upstream targets to clients.",
                &self.bytes_upstream_to_client_total,
            ),
            counter(
                "gateway_config_reloads_total",
                "Successful config reloads.",
                &self.config_reloads_total,
            ),
            counter(
                "gateway_config_reload_errors_total",
                "Rejected config reloads (last-known-good config kept).",
                &self.config_reload_errors_total,
            ),
            gauge(
                "gateway_config_version",
                "config_version of the active config document (0 if unset).",
                &self.config_version,
            ),
            gauge(
                "gateway_tunnel_connected",
                "Tunnel pool members currently connected to the edge.",
                &self.tunnel_connected,
            ),
            gauge(
                "gateway_tunnel_pool_target",
                "Configured tunnel connection pool size.",
                &self.tunnel_pool_target,
            ),
            gauge(
                "gateway_tunnel_pool_draining",
                "Tunnel pool members draining after a pool shrink.",
                &self.tunnel_pool_draining,
            ),
            counter(
                "gateway_tunnel_connects_total",
                "Successful tunnel connections to the edge.",
                &self.tunnel_connects_total,
            ),
            counter(
                "gateway_tunnel_errors_total",
                "Tunnel connection attempts that failed or connections that dropped.",
                &self.tunnel_errors_total,
            ),
            counter(
                "gateway_tunnel_streams_total",
                "Streams accepted from the edge over the tunnel.",
                &self.tunnel_streams_total,
            ),
        ]
        .concat()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let metrics = Metrics::default();
        metrics.connections_total.store(3, Ordering::Relaxed);
        metrics.config_version.store(7, Ordering::Relaxed);
        let out = metrics.render();
        assert!(out.contains("# TYPE gateway_connections_total counter"));
        assert!(out.contains("gateway_connections_total 3\n"));
        assert!(out.contains("# TYPE gateway_config_version gauge"));
        assert!(out.contains("gateway_config_version 7\n"));
    }
}
