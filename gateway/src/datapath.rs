//! The per-connection datapath: accept CONNECT, match a route, resolve, splice.
//!
//! The gateway never terminates or inspects tunneled traffic: after the
//! CONNECT handshake it splices bytes at L4, so customer TLS stays
//! end-to-end and non-HTTP protocols work unchanged. Logs carry connection
//! metadata only, never payloads or tokens.

use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use color_eyre::eyre::{self, WrapErr, bail, ensure, eyre};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{Instant as TokioInstant, Sleep, timeout},
};
use tracing::{Instrument, info, info_span, warn};

use crate::{
    config::{UpstreamProxyConfig, split_host_port},
    metrics::Metrics,
    policy::DestHost,
    state::EngineState,
};

const MAX_REQUEST_HEAD: usize = 16 * 1024;
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_CANCELLATION_INTERVAL: Duration = Duration::from_millis(25);

pub(crate) trait ConnectionStream: AsyncRead + AsyncWrite + Unpin {
    fn is_reset(&self) -> bool;
}

impl ConnectionStream for TcpStream {
    fn is_reset(&self) -> bool {
        false
    }
}

impl ConnectionStream for tunnel::mux::TunnelStream {
    fn is_reset(&self) -> bool {
        self.get_ref().is_closed()
    }
}

/// Accept loop. Each connection is served with the state active at accept
/// time; config reloads apply to new connections only.
pub async fn serve(
    listener: TcpListener,
    state_rx: watch::Receiver<Arc<EngineState>>,
    metrics: Arc<Metrics>,
) -> eyre::Result<()> {
    loop {
        let (stream, peer) = common::net::accept(&listener, "data").await;
        // Small CONNECT/response writes interleave with spliced payload;
        // Nagle plus delayed ACKs stalls them for tens of milliseconds.
        if let Err(err) = stream.set_nodelay(true) {
            warn!(error = %err, "failed to set TCP_NODELAY on accepted connection");
            continue;
        }
        let state = state_rx.borrow().clone();
        let metrics = metrics.clone();
        tokio::spawn(
            async move {
                if let Err(err) = serve_conn(state, metrics, stream, &peer.to_string()).await {
                    warn!(error = format!("{err:#}"), "connection error");
                }
            }
            .instrument(info_span!("conn", client_addr = %peer)),
        );
    }
}

/// Serve one CONNECT connection. Generic over the client stream so the same
/// datapath (and thus the same policy) serves connections
/// from the local listener and streams arriving over the tunnel.
pub(crate) async fn serve_conn<S>(
    state: Arc<EngineState>,
    metrics: Arc<Metrics>,
    mut stream: S,
    client: &str,
) -> eyre::Result<()>
where
    S: ConnectionStream,
{
    metrics.connections_total.fetch_add(1, Ordering::Relaxed);

    let head = match timeout(
        REQUEST_HEAD_TIMEOUT,
        common::http::read_head(&mut stream, MAX_REQUEST_HEAD),
    )
    .await
    {
        Ok(Ok(head)) => head,
        Ok(Err(err)) => {
            metrics.bad_requests_total.fetch_add(1, Ordering::Relaxed);
            let _ = respond(&mut stream, "400 Bad Request", &[]).await;
            return Err(err.wrap_err("bad request"));
        }
        Err(_) => {
            metrics.bad_requests_total.fetch_add(1, Ordering::Relaxed);
            let _ = respond(&mut stream, "408 Request Timeout", &[]).await;
            bail!("timed out reading request");
        }
    };

    let request = match parse_connect(head.head()) {
        Ok(request) => request,
        Err(err) => {
            metrics.bad_requests_total.fetch_add(1, Ordering::Relaxed);
            let _ = respond(&mut stream, "400 Bad Request", &[]).await;
            return Err(err.wrap_err("bad request"));
        }
    };

    let dest = DestHost::parse(&request.host);
    let port = request.port;

    let Some(route) = state.policy.find_route(&dest, port) else {
        metrics
            .denied_no_route_total
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            event = "deny",
            reason = "no_route",
            host = %dest,
            port,
            "denied: no allowlist route matches"
        );
        let _ = respond(&mut stream, "403 Forbidden", &[]).await;
        return Ok(());
    };

    // One dial_timeout budget covers DNS resolution, TCP connect, and any
    // upstream-proxy CONNECT exchange.
    let dial = async {
        match &route.upstream_proxy {
            Some(proxy) => dial_via_proxy(&state, proxy, &request.host, port).await,
            None => dial_direct(&state, &dest, port)
                .await
                .map(|stream| (stream, Vec::new())),
        }
    };
    let mut pending_client_bytes = Vec::new();
    let mut pending_bytes = [0u8; 1024];
    let mut read_closed = false;
    let dial = timeout(state.config.dial_timeout, dial);
    tokio::pin!(dial);
    let dial_result = loop {
        let read_capacity = MAX_REQUEST_HEAD
            .saturating_sub(pending_client_bytes.len())
            .min(pending_bytes.len());
        tokio::select! {
            result = &mut dial => {
                break match result {
                    Ok(result) => result,
                    Err(_) => Err(eyre!("timed out establishing upstream connection")),
                };
            }
            result = stream.read(&mut pending_bytes[..read_capacity]), if !read_closed && read_capacity > 0 => {
                match result {
                    Ok(0) => {
                        if stream.is_reset() {
                            return Ok(());
                        }
                        read_closed = true;
                    }
                    Ok(count) => pending_client_bytes.extend_from_slice(&pending_bytes[..count]),
                    Err(error) => return Err(error.into()),
                }
            }
            _ = tokio::time::sleep(STREAM_CANCELLATION_INTERVAL), if read_closed || pending_client_bytes.len() >= MAX_REQUEST_HEAD => {
                if stream.is_reset() {
                    return Ok(());
                }
            }
        }
    };
    let (mut upstream, proxy_leftover) = match dial_result {
        Ok(v) => v,
        Err(err) => {
            metrics.dial_errors_total.fetch_add(1, Ordering::Relaxed);
            warn!(
                event = "dial_error",
                host = %dest,
                port,
                route = route.name,
                error = format!("{err:#}"),
                "failed to reach target"
            );
            let _ = respond(&mut stream, "502 Bad Gateway", &[]).await;
            return Ok(());
        }
    };

    info!(
        event = "conn_open",
        host = %dest,
        port,
        route = route.name,
        client_addr = client,
        via_proxy = route.upstream_proxy.is_some(),
        "connection opened"
    );

    respond_established(&mut stream).await?;
    // Bytes that arrived past either head belong to the tunneled stream and
    // count toward the transfer totals.
    let leftover_to_client = proxy_leftover.len() as u64;
    let leftover_to_upstream = (head.leftover().len() + pending_client_bytes.len()) as u64;
    if !proxy_leftover.is_empty() {
        stream.write_all(&proxy_leftover).await?;
    }
    if !head.leftover().is_empty() {
        upstream.write_all(head.leftover()).await?;
    }
    if !pending_client_bytes.is_empty() {
        upstream.write_all(&pending_client_bytes).await?;
    }
    metrics
        .bytes_upstream_to_client_total
        .fetch_add(leftover_to_client, Ordering::Relaxed);
    metrics
        .bytes_client_to_upstream_total
        .fetch_add(leftover_to_upstream, Ordering::Relaxed);

    metrics.connections_active.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let grace = state.config.half_close_timeout;
    let mut counted_stream = CountingStream::new(HalfCloseDeadline::new(&mut stream, grace));
    let mut counted_upstream = CountingStream::new(HalfCloseDeadline::new(&mut upstream, grace));
    let result = copy_bidirectional(&mut counted_stream, &mut counted_upstream).await;
    let client_to_upstream = counted_upstream.bytes_written;
    let upstream_to_client = counted_stream.bytes_written;
    let reaped = counted_stream.inner.expired() || counted_upstream.inner.expired();
    metrics
        .bytes_client_to_upstream_total
        .fetch_add(client_to_upstream, Ordering::Relaxed);
    metrics
        .bytes_upstream_to_client_total
        .fetch_add(upstream_to_client, Ordering::Relaxed);
    metrics.connections_active.fetch_sub(1, Ordering::Relaxed);
    if reaped {
        metrics
            .connections_reaped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    match result {
        Ok(_) => {
            info!(
                event = "conn_close",
                host = %dest,
                port,
                route = route.name,
                bytes_client_to_upstream = leftover_to_upstream + client_to_upstream,
                bytes_upstream_to_client = leftover_to_client + upstream_to_client,
                duration_ms = started.elapsed().as_millis() as u64,
                reaped,
                "connection closed"
            );
        }
        Err(err) => {
            info!(
                event = "conn_close",
                host = %dest,
                port,
                route = route.name,
                bytes_client_to_upstream = leftover_to_upstream + client_to_upstream,
                bytes_upstream_to_client = leftover_to_client + upstream_to_client,
                duration_ms = started.elapsed().as_millis() as u64,
                reaped,
                error = format!("{err:#}"),
                "connection closed with error"
            );
        }
    }
    Ok(())
}

/// Bounds the drain after a half-close. `copy_bidirectional` shuts down a
/// stream's writer once the opposite direction ends, then keeps reading
/// this side until the peer answers with its own close; a peer that never
/// answers leaves the socket in FIN_WAIT-2 and the task alive, leaking a
/// file descriptor per connection until the process hits rlimit. Once
/// `poll_shutdown` arms the deadline, each read that moves bytes resets
/// it; if the peer stays silent for `grace`, reads report EOF so the
/// splice ends and both sockets are dropped.
struct HalfCloseDeadline<S> {
    inner: S,
    grace: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
    expired: bool,
}

impl<S> HalfCloseDeadline<S> {
    fn new(inner: S, grace: Duration) -> Self {
        Self {
            inner,
            grace,
            deadline: None,
            expired: false,
        }
    }

    /// True once a shutdown-armed deadline fired and the read side was
    /// reported closed.
    fn expired(&self) -> bool {
        self.expired
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HalfCloseDeadline<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.expired {
            return Poll::Ready(Ok(()));
        }
        if let Some(deadline) = this.deadline.as_mut() {
            if deadline.as_mut().poll(cx).is_ready() {
                this.expired = true;
                return Poll::Ready(Ok(()));
            }
        }
        let filled = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() > filled => {
                // Bytes still arriving: the peer is draining normally, so
                // the silence deadline restarts from this read.
                if let Some(deadline) = this.deadline.as_mut() {
                    deadline.as_mut().reset(TokioInstant::now() + this.grace);
                }
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HalfCloseDeadline<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // The splice is done writing to this stream: the peer has `grace`
        // of silence left to close its side before the socket is reaped.
        this.deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(this.grace)));
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

struct CountingStream<S> {
    inner: S,
    bytes_written: u64,
}

impl<S> CountingStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                this.bytes_written += written as u64;
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct ConnectRequest {
    host: String,
    port: u16,
}

fn parse_connect(head: &[u8]) -> eyre::Result<ConnectRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    let status = request
        .parse(head)
        .map_err(|err| eyre!("invalid request: {err}"))?;
    if status.is_partial() {
        bail!("incomplete request head");
    }
    let method = request.method.unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT") {
        bail!("unsupported method {method:?}: only CONNECT is supported");
    }
    let authority = request.path.ok_or_else(|| eyre!("missing authority"))?;
    let (host, port) = split_host_port(authority)?;

    Ok(ConnectRequest { host, port })
}

async fn dial_direct(
    state: &EngineState,
    dest: &DestHost<'_>,
    port: u16,
) -> eyre::Result<TcpStream> {
    let addrs = match dest {
        // Literal-IP targets were explicitly allowlisted by a CIDR rule.
        DestHost::Ip(ip) => vec![*ip],
        // Hostname routes are matched before resolution, so guard what the
        // resolver returned: an allowlisted name must not steer the dial at
        // loopback (the gateway itself), link-local (cloud metadata), or
        // unspecified addresses.
        DestHost::Name(name) => {
            let allow_loopback = state.config.dns.allow_loopback;
            let (addrs, refused): (Vec<IpAddr>, Vec<IpAddr>) = state
                .resolver
                .resolve(name)
                .await?
                .into_iter()
                .partition(|ip| !is_restricted_target(ip, allow_loopback));
            if addrs.is_empty() {
                bail!(
                    "{name:?} resolved only to restricted addresses (e.g. {})",
                    refused[0]
                );
            }
            addrs
        }
    };
    for ip in &addrs {
        for listen in state
            .config
            .listen
            .into_iter()
            .chain([state.config.admin_listen])
        {
            ensure!(
                !is_self_listener(listen, *ip, port),
                "refusing to dial the gateway's own listener {listen}"
            );
        }
    }
    connect_first(&addrs, port, state.config.dial_timeout).await
}

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) connects to the embedded
/// IPv4 address, so the guards must classify it as that address.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn is_restricted_target(ip: &IpAddr, allow_loopback: bool) -> bool {
    let ip = canonical_ip(*ip);
    if ip.is_loopback() {
        return !allow_loopback;
    }
    ip.is_unspecified()
        || match ip {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_unicast_link_local(),
        }
}

/// A minimal self-dial guard: it cannot know every local interface address,
/// but it refuses the listener's exact address and any loopback dial on a
/// listener port bound to a wildcard address.
fn is_self_listener(listen: SocketAddr, ip: IpAddr, port: u16) -> bool {
    let ip = canonical_ip(ip);
    let listen_ip = canonical_ip(listen.ip());
    listen.port() == port && (ip == listen_ip || (ip.is_loopback() && listen_ip.is_unspecified()))
}

async fn connect_first(
    addrs: &[IpAddr],
    port: u16,
    dial_timeout: Duration,
) -> eyre::Result<TcpStream> {
    let mut last_err = eyre!("no addresses to dial");
    let started = Instant::now();
    for (index, addr) in addrs.iter().enumerate() {
        let remaining = dial_timeout.saturating_sub(started.elapsed());
        let attempts_left = u32::try_from(addrs.len() - index).unwrap_or(u32::MAX);
        match timeout(remaining / attempts_left, TcpStream::connect((*addr, port))).await {
            Ok(Ok(stream)) => {
                stream
                    .set_nodelay(true)
                    .wrap_err("failed to set TCP_NODELAY on upstream connection")?;
                return Ok(stream);
            }
            Ok(Err(err)) => {
                last_err = eyre!(err).wrap_err(format!("failed to dial {addr}:{port}"));
            }
            Err(err) => {
                last_err = eyre!(err).wrap_err(format!("timed out dialing {addr}:{port}"));
            }
        }
    }
    Err(last_err)
}

/// Chain through a customer HTTP CONNECT proxy, preserving the original
/// target hostname in the CONNECT authority.
async fn dial_via_proxy(
    state: &EngineState,
    proxy: &UpstreamProxyConfig,
    host: &str,
    port: u16,
) -> eyre::Result<(TcpStream, Vec<u8>)> {
    if let DestHost::Name(name) = DestHost::parse(host) {
        match state.resolver.resolve(name).await {
            Ok(addrs) => {
                for addr in addrs {
                    ensure!(
                        !is_restricted_target(&addr, state.config.dns.allow_loopback),
                        "{name:?} resolved to restricted address {addr}"
                    );
                    for listen in state
                        .config
                        .listen
                        .into_iter()
                        .chain([state.config.admin_listen])
                    {
                        ensure!(
                            !is_self_listener(listen, addr, port),
                            "refusing to dial the gateway's own listener {listen}"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    event = "proxy_dns_delegated",
                    host = name,
                    error = format!("{err:#}"),
                    "target cannot be resolved locally; delegating DNS to upstream proxy"
                );
            }
        }
    } else if let DestHost::Ip(addr) = DestHost::parse(host) {
        for listen in state
            .config
            .listen
            .into_iter()
            .chain([state.config.admin_listen])
        {
            ensure!(
                !is_self_listener(listen, addr, port),
                "refusing to dial the gateway's own listener {listen}"
            );
        }
    }
    let (proxy_host, proxy_port) = split_host_port(&proxy.addr)?;
    let mut upstream = dial_direct(state, &DestHost::parse(&proxy_host), proxy_port)
        .await
        .wrap_err_with(|| format!("failed to reach upstream proxy {}", proxy.addr))?;
    let leftover = proxy_connect_exchange(&mut upstream, proxy.auth.as_deref(), host, port).await?;
    Ok((upstream, leftover))
}

/// Send a CONNECT for `host:port` on an already-connected proxy stream and
/// check the response. Returns bytes the proxy sent past its response head;
/// they belong to the tunneled stream.
pub(crate) async fn proxy_connect_exchange<S>(
    upstream: &mut S,
    proxy_auth: Option<&str>,
    host: &str,
    port: u16,
) -> eyre::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = format_authority(host, port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = proxy_auth {
        request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    request.push_str("\r\n");
    upstream.write_all(request.as_bytes()).await?;

    let head = common::http::read_head(upstream, MAX_REQUEST_HEAD)
        .await
        .wrap_err("failed to read upstream proxy response")?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response
        .parse(head.head())
        .map_err(|err| eyre!("invalid upstream proxy response: {err}"))?;
    let code = response
        .code
        .ok_or_else(|| eyre!("upstream proxy response missing status"))?;
    if code != 200 {
        bail!("upstream proxy refused CONNECT with status {code}");
    }
    Ok(head.leftover().to_vec())
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn respond_established<S>(stream: &mut S) -> eyre::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    Ok(())
}

/// Callers on refusal paths discard this result (`let _ =`): the response is
/// a best-effort courtesy on a connection about to be closed, the refusal
/// itself is already counted and logged, and a client gone before the write
/// is not an event operators can act on.
async fn respond<S>(stream: &mut S, status: &str, extra_headers: &[&str]) -> eyre::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = format!("HTTP/1.1 {status}\r\n");
    for header in extra_headers {
        response.push_str(header);
        response.push_str("\r\n");
    }
    response.push_str("Connection: close\r\nContent-Length: 0\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    // FIN after the response: dropping a socket with unread client bytes
    // pending can discard the written response with a RST.
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_request() {
        let head = b"CONNECT git.corp.example:443 HTTP/1.1\r\nHost: git.corp.example:443\r\n\r\n";
        let request = parse_connect(head).unwrap();
        assert_eq!(request.host, "git.corp.example");
        assert_eq!(request.port, 443);
    }

    #[test]
    fn parses_ipv6_authority() {
        let head = b"CONNECT [fd00::1]:443 HTTP/1.1\r\n\r\n";
        let request = parse_connect(head).unwrap();
        assert_eq!(request.host, "fd00::1");
        assert_eq!(request.port, 443);
    }

    #[test]
    fn rejects_non_connect_methods() {
        let head = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let err = parse_connect(head).unwrap_err();
        assert!(err.to_string().contains("only CONNECT"), "{err}");
    }

    #[test]
    fn rejects_authority_without_port() {
        let head = b"CONNECT git.corp.example HTTP/1.1\r\n\r\n";
        assert!(parse_connect(head).is_err());
    }

    #[test]
    fn rejects_non_ascii_authority() {
        // httparse accepts 0x80+ bytes in the request target; the host
        // validator must reject them before route matching sees them.
        let head = "CONNECT aé:443 HTTP/1.1\r\n\r\n".as_bytes();
        let err = parse_connect(head).unwrap_err();
        assert!(err.to_string().contains("host contains"), "{err}");
    }

    #[test]
    fn restricts_resolved_targets() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_restricted_target(&ip("127.0.0.1"), false));
        assert!(!is_restricted_target(&ip("127.0.0.1"), true));
        assert!(is_restricted_target(&ip("::1"), false));
        assert!(is_restricted_target(&ip("0.0.0.0"), true));
        assert!(is_restricted_target(&ip("169.254.169.254"), false));
        assert!(is_restricted_target(&ip("fe80::1"), false));
        assert!(!is_restricted_target(&ip("10.0.0.5"), false));
        assert!(!is_restricted_target(&ip("fd00::1"), false));
    }

    #[test]
    fn restricts_ipv4_mapped_ipv6_targets() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_restricted_target(&ip("::ffff:127.0.0.1"), false));
        assert!(!is_restricted_target(&ip("::ffff:127.0.0.1"), true));
        assert!(is_restricted_target(&ip("::ffff:0.0.0.0"), false));
        assert!(is_restricted_target(&ip("::ffff:169.254.169.254"), false));
        assert!(!is_restricted_target(&ip("::ffff:10.0.0.5"), false));
    }

    #[test]
    fn detects_self_listener_dials() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let listen: SocketAddr = "10.0.0.5:8443".parse().unwrap();
        assert!(is_self_listener(listen, ip("10.0.0.5"), 8443));
        assert!(!is_self_listener(listen, ip("10.0.0.5"), 443));
        assert!(!is_self_listener(listen, ip("10.0.0.6"), 8443));
        let wildcard: SocketAddr = "0.0.0.0:9090".parse().unwrap();
        assert!(is_self_listener(wildcard, ip("127.0.0.1"), 9090));
        // Another host on the listener's port stays reachable.
        assert!(!is_self_listener(wildcard, ip("10.0.0.6"), 9090));
    }

    #[test]
    fn detects_self_listener_dials_via_mapped_addresses() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let listen: SocketAddr = "10.0.0.5:8443".parse().unwrap();
        assert!(is_self_listener(listen, ip("::ffff:10.0.0.5"), 8443));
        assert!(!is_self_listener(listen, ip("::ffff:10.0.0.6"), 8443));
        let wildcard: SocketAddr = "0.0.0.0:9090".parse().unwrap();
        assert!(is_self_listener(wildcard, ip("::ffff:127.0.0.1"), 9090));
        // A v6-wildcard listener refuses the mapped-loopback dial too.
        let wildcard6: SocketAddr = "[::]:9090".parse().unwrap();
        assert!(is_self_listener(wildcard6, ip("::ffff:127.0.0.1"), 9090));
    }

    #[test]
    fn formats_authorities() {
        assert_eq!(
            format_authority("git.corp.example", 443),
            "git.corp.example:443"
        );
        assert_eq!(format_authority("fd00::1", 443), "[fd00::1]:443");
    }

    #[tokio::test]
    async fn connect_first_tries_later_addresses_after_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addrs = ["127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        let stream = connect_first(&addrs, port, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), listener.local_addr().unwrap());
    }

    #[tokio::test]
    async fn half_close_deadline_reaps_silent_peer() {
        let (mut peer, inner) = tokio::io::duplex(16);
        let mut stream = HalfCloseDeadline::new(inner, Duration::from_millis(200));
        let mut buf = [0u8; 8];

        // Unarmed: a silent peer leaves reads pending.
        let pending = timeout(Duration::from_millis(100), stream.read(&mut buf)).await;
        assert!(pending.is_err());

        // Arming via shutdown starts the silence deadline; bytes that still
        // arrive restart it and are delivered normally.
        stream.shutdown().await.unwrap();
        peer.write_all(b"tail").await.unwrap();
        assert_eq!(stream.read(&mut buf).await.unwrap(), 4);

        // Once silent past the grace window, reads report a stable EOF.
        let eof = timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("armed deadline should fire")
            .unwrap();
        assert_eq!(eof, 0);
        assert!(stream.expired());
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn counting_stream_retains_bytes_after_write_error() {
        let (writer, mut reader) = tokio::io::duplex(16);
        let mut counted = CountingStream::new(writer);
        counted.write_all(b"forwarded").await.unwrap();
        assert_eq!(counted.bytes_written, 9);

        reader.shutdown().await.unwrap();
        drop(reader);
        assert!(counted.write_all(b"lost").await.is_err());
        assert_eq!(counted.bytes_written, 9);
    }
}
