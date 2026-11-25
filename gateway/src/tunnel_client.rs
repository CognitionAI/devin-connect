//! Outbound tunnel to the Devin-side edge.
//!
//! The gateway dials out (TCP, optionally through the customer's egress
//! proxy), terminates TLS against the edge, authenticates with its
//! enrollment token, and then serves CONNECT streams the edge opens with
//! the same datapath — and therefore the same policy, authorization, and
//! logging — as connections accepted on the local listener. The connection
//! is maintained forever with jittered exponential backoff.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use color_eyre::eyre::{self, WrapErr, bail, ensure, eyre};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{Notify, watch},
    task::JoinSet,
    time::{MissedTickBehavior, timeout},
};
use tokio_rustls::TlsConnector;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{Instrument, info, info_span, warn};
use tunnel::{
    mux,
    protocol::{
        self, ControlMessage, Heartbeat, Hello, HelloReply, PROTOCOL_VERSION, StreamAck,
        StreamPreamble,
    },
    ws,
};

use crate::{
    config::{Carrier, MAX_POOL_SIZE, TunnelConfig, split_host_port},
    datapath,
    metrics::Metrics,
    state::EngineState,
};

/// Budget for one connection attempt: TCP connect (optionally through the
/// egress proxy), TLS handshake, the WebSocket upgrade when that carrier is
/// configured, and the hello exchange.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A connection that lived at least this long resets the backoff.
const STABLE_CONNECTION: Duration = Duration::from_secs(60);
/// The edge writes each stream's preamble as soon as it opens the stream,
/// so a slow preamble means a broken or misbehaving peer.
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Delay between launching successive pool members, so a pool does not slam
/// the edge with a burst of simultaneous handshakes.
const MEMBER_START_STAGGER: Duration = Duration::from_millis(250);
/// How long a draining member waits for its streams to finish before
/// closing the connection anyway.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(600);
/// How long to wait for the edge's drain ack (sent after it deregisters
/// the member) before falling back to the grace period alone.
const DRAIN_ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// A draining connection closes only once its stream count has stayed at
/// zero for this long after the edge's drain ack: a dial admitted before
/// deregistration may still be in flight when the count first hits zero.
const DRAIN_GRACE: Duration = Duration::from_secs(1);

/// Tunnel client for one configured edge endpoint.
pub struct TunnelClient {
    config: TunnelConfig,
    endpoint_host: String,
    endpoint_port: u16,
    auth_token_path: PathBuf,
    server_name: ServerName<'static>,
    connector: TlsConnector,
}

impl TunnelClient {
    /// Resolve paths and TLS material once at startup; tunnel settings only
    /// change with a restart (config reloads warn about this). Fails if the
    /// token or CA file is unusable, so a misconfigured gateway does not
    /// start and then retry-loop against the edge.
    pub async fn build(config: TunnelConfig, config_dir: &Path) -> eyre::Result<Self> {
        let (endpoint_host, endpoint_port) = split_host_port(&config.endpoint)?;
        let server_name = ServerName::try_from(endpoint_host.clone()).map_err(|_| {
            eyre!("tunnel endpoint host {endpoint_host:?} is not a valid TLS server name")
        })?;

        let mut roots = rustls::RootCertStore::empty();
        match &config.ca_file {
            Some(path) => {
                let path = config_dir.join(path);
                let pem = tokio::fs::read(&path).await.wrap_err_with(|| {
                    format!("failed to read tunnel ca_file {}", path.display())
                })?;
                for cert in CertificateDer::pem_slice_iter(&pem) {
                    let cert = cert.wrap_err_with(|| {
                        format!("invalid certificate in tunnel ca_file {}", path.display())
                    })?;
                    roots.add(cert).wrap_err_with(|| {
                        format!("invalid certificate in tunnel ca_file {}", path.display())
                    })?;
                }
                ensure!(
                    !roots.is_empty(),
                    "tunnel ca_file {} contains no certificates",
                    path.display()
                );
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let auth_token_path = config_dir.join(&config.auth_token_file);
        read_token(&auth_token_path).await?;

        Ok(Self {
            config,
            endpoint_host,
            endpoint_port,
            auth_token_path,
            server_name,
            connector: TlsConnector::from(Arc::new(tls_config)),
        })
    }

    /// Maintain the configured pool of tunnel connections forever. Each
    /// member connects, authenticates, and reconnects independently.
    /// Config reloads that change `connection_pool.size` grow the pool by
    /// starting members and shrink it by draining them; every other tunnel
    /// setting keeps its build-time value until a restart.
    pub async fn run(self, mut state_rx: watch::Receiver<Arc<EngineState>>, metrics: Arc<Metrics>) {
        let client = Arc::new(self);
        let mut members: Vec<watch::Sender<bool>> = Vec::new();
        // Includes draining members: a slot frees only when its task exits,
        // so shrink/regrow cycles stay within MAX_POOL_SIZE.
        let mut tasks = JoinSet::new();
        let mut next_member = 0u64;
        // A reload that drops the tunnel stanza warns that a restart is
        // required, so the last applied size stays in force rather than
        // reverting to the build-time value.
        let mut target = client.config.connection_pool.size;
        loop {
            if let Some(tunnel) = &state_rx.borrow_and_update().config.tunnel {
                target = tunnel.connection_pool.size;
            }
            metrics
                .tunnel_pool_target
                .store(target as u64, Ordering::Relaxed);
            let mut started_now = 0u32;
            while members.len() < target && tasks.len() < MAX_POOL_SIZE {
                let (drain_tx, drain_rx) = watch::channel(false);
                let member = client.clone().run_member(
                    drain_rx,
                    state_rx.clone(),
                    metrics.clone(),
                    MEMBER_START_STAGGER * started_now,
                );
                tasks.spawn(member.instrument(info_span!("tunnel_member", member = next_member)));
                members.push(drain_tx);
                started_now += 1;
                next_member += 1;
            }
            // Shrink by draining the newest members; each member task
            // exits on its own once drained.
            while members.len() > target {
                let drain_tx = members.pop().expect("members is non-empty");
                metrics.tunnel_pool_draining.fetch_add(1, Ordering::Relaxed);
                let _ = drain_tx.send(true);
            }
            tokio::select! {
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        // The config publisher is gone: the process is
                        // shutting down. Park instead of returning so the
                        // members (and their drain channels) stay alive
                        // until the end.
                        std::future::pending::<()>().await;
                    }
                }
                Some(exited) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Err(err) = exited {
                        warn!(
                            event = "tunnel_member_panic",
                            error = %err,
                            "tunnel member task failed"
                        );
                    }
                    // Reap a panicked member's slot too, so the pool heals
                    // back to the target instead of silently degrading.
                    members.retain(|member| !member.is_closed());
                }
            }
        }
    }

    /// One pool member: maintain a tunnel connection with jittered
    /// exponential backoff until told to drain. Streams opened by the edge
    /// are served with the state active at the time each stream arrives, so
    /// config reloads apply to new tunnel streams just like new listener
    /// connections.
    async fn run_member(
        self: Arc<Self>,
        mut drain_rx: watch::Receiver<bool>,
        state_rx: watch::Receiver<Arc<EngineState>>,
        metrics: Arc<Metrics>,
        start_delay: Duration,
    ) {
        let _draining = DrainingGauge {
            metrics: &metrics,
            drain_rx: drain_rx.clone(),
        };
        let mut backoff = BACKOFF_INITIAL;
        let mut delay = start_delay;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = drain_signal(&mut drain_rx) => break,
            }
            let mut connected_at = None;
            match self
                .run_once(&state_rx, &metrics, &mut drain_rx, &mut connected_at)
                .await
            {
                Ok(Lifecycle::Drained) => break,
                Ok(Lifecycle::Closed) => {
                    metrics.tunnel_errors_total.fetch_add(1, Ordering::Relaxed);
                    warn!(event = "tunnel_closed", "edge closed the tunnel");
                }
                Err(err) => {
                    metrics.tunnel_errors_total.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        event = "tunnel_error",
                        error = format!("{err:#}"),
                        "tunnel failed"
                    );
                }
            }
            if connected_at
                .is_some_and(|connected_at: Instant| connected_at.elapsed() >= STABLE_CONNECTION)
            {
                backoff = BACKOFF_INITIAL;
            }
            // Equal jitter keeps a fleet of replicas from reconnecting in
            // lockstep after an edge restart.
            let base_ms = backoff.as_millis() as u64;
            delay = Duration::from_millis(base_ms / 2 + fastrand::u64(..=base_ms / 2));
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    /// One tunnel connection: connect + authenticate, then serve inbound
    /// streams and exchange heartbeats until something fails or the member
    /// is drained.
    async fn run_once(
        &self,
        state_rx: &watch::Receiver<Arc<EngineState>>,
        metrics: &Arc<Metrics>,
        drain_rx: &mut watch::Receiver<bool>,
        connected_at: &mut Option<Instant>,
    ) -> eyre::Result<Lifecycle> {
        let (carried, tenant) = tokio::select! {
            result = timeout(CONNECT_TIMEOUT, self.connect()) => {
                result.map_err(|_| eyre!("timed out connecting to edge {}", self.config.endpoint))??
            }
            // A drain order during connect/hello means the pool shrank
            // while this member was down: abandon the attempt rather than
            // register a connection that would immediately drain.
            _ = drain_signal(drain_rx) => return Ok(Lifecycle::Drained),
        };
        *connected_at = Some(Instant::now());
        metrics
            .tunnel_connects_total
            .fetch_add(1, Ordering::Relaxed);
        metrics.tunnel_connected.fetch_add(1, Ordering::Relaxed);
        let _connected = ConnectedGauge(metrics);
        info!(
            event = "tunnel_up",
            endpoint = self.config.endpoint,
            tenant,
            "tunnel established"
        );

        self.serve(carried, state_rx, metrics, drain_rx).await
    }

    /// Serve one established, authenticated tunnel connection until it
    /// fails or drains, independent of which carrier delivers the bytes.
    async fn serve(
        &self,
        io: Carried,
        state_rx: &watch::Receiver<Arc<EngineState>>,
        metrics: &Arc<Metrics>,
        drain_rx: &mut watch::Receiver<bool>,
    ) -> eyre::Result<Lifecycle> {
        // Local cap above the declared cap: see mux::local_max_streams.
        let (handle, driver) = mux::with_max_streams(
            io.compat(),
            mux::Mode::Client,
            mux::local_max_streams(self.config.connection_pool.max_streams_per_connection),
        )?;
        let active = Arc::new(ActiveStreams::default());
        let inbound_state = state_rx.clone();
        let inbound_metrics = metrics.clone();
        let inbound_active = active.clone();
        let driver_task = driver.run(move |mut stream| {
            inbound_metrics
                .tunnel_streams_total
                .fetch_add(1, Ordering::Relaxed);
            let state = inbound_state.borrow().clone();
            let metrics = inbound_metrics.clone();
            let guard = inbound_active.begin();
            tokio::spawn(
                async move {
                    let _guard = guard;
                    let preamble: StreamPreamble = match timeout(
                        PREAMBLE_TIMEOUT,
                        protocol::read_message(&mut stream),
                    )
                    .await
                    {
                        Ok(Ok(preamble)) => preamble,
                        Ok(Err(err)) => {
                            warn!(error = format!("{err:#}"), "invalid stream preamble");
                            return;
                        }
                        Err(_) => {
                            warn!("timed out reading stream preamble");
                            return;
                        }
                    };
                    // The ack tells the edge the stream reached this
                    // gateway; its dial deadline waits on it.
                    if preamble.want_ack
                        && let Err(err) = protocol::write_message(&mut stream, &StreamAck {}).await
                    {
                        warn!(error = format!("{err:#}"), "failed to write stream ack");
                        return;
                    }
                    let client = format!("tunnel:{}", preamble.peer_addr);
                    tracing::Span::current().record("client_addr", client.as_str());
                    if let Err(err) = datapath::serve_conn(state, metrics, stream, &client).await {
                        warn!(error = format!("{err:#}"), "connection error");
                    }
                }
                .instrument(info_span!("conn", client_addr = tracing::field::Empty)),
            );
        });
        tokio::pin!(driver_task);

        // The control stream is the one stream the gateway opens.
        let control = tokio::select! {
            result = &mut driver_task => {
                result?;
                bail!("tunnel closed before the control stream was opened");
            }
            stream = handle.open_stream() => stream.wrap_err("failed to open control stream")?,
        };
        let (mut control_read, mut control_write) = tokio::io::split(control);
        let interval = self.config.heartbeat_interval;

        tokio::select! {
            result = &mut driver_task => return result.map(|()| Lifecycle::Closed),
            result = send_heartbeats(&mut control_write, interval, metrics.clone(), drain_rx) => {
                // Ok is the drain order.
                result.wrap_err("heartbeat writer failed")?;
            }
            result = read_acks(&mut control_read, interval) => {
                return result
                    .wrap_err("control stream failed")
                    .map(|()| Lifecycle::Closed);
            }
        }

        // Half-closing the control stream tells the edge to stop routing
        // new streams here; the ones already running finish normally.
        info!(event = "tunnel_draining", "draining tunnel connection");
        tokio::select! {
            result = &mut driver_task => {
                result?;
                return Ok(Lifecycle::Drained);
            }
            result = control_write.shutdown() => {
                result.wrap_err("failed to close control stream")?;
            }
        }
        // Dials admitted before the edge deregistered this member may
        // still be in flight; the zero-stream grace only starts once the
        // edge acks the deregistration.
        tokio::select! {
            result = &mut driver_task => {
                result?;
                return Ok(Lifecycle::Drained);
            }
            ack = timeout(DRAIN_ACK_TIMEOUT, read_drain_ack(&mut control_read)) => match ack {
                Ok(Ok(())) => {}
                Ok(Err(err)) => warn!(
                    event = "tunnel_drain_ack_error",
                    error = format!("{err:#}"),
                    "control stream failed while draining"
                ),
                Err(_) => warn!(
                    event = "tunnel_drain_ack_timeout",
                    "no drain ack within {DRAIN_ACK_TIMEOUT:?}"
                ),
            }
        }
        tokio::select! {
            result = &mut driver_task => result?,
            _ = active.drained(DRAIN_GRACE) => {}
            _ = tokio::time::sleep(DRAIN_TIMEOUT) => {
                warn!(
                    event = "tunnel_drain_timeout",
                    "drain timed out; closing with streams still active"
                );
            }
        }
        Ok(Lifecycle::Drained)
    }

    /// TCP (optionally through the customer egress proxy) + TLS + the
    /// configured carrier's framing + hello.
    async fn connect(&self) -> eyre::Result<(Carried, String)> {
        // Re-read the token every attempt so it can be rotated on disk
        // without restarting the gateway.
        let token = read_token(&self.auth_token_path).await?;

        let tcp = match &self.config.egress_proxy {
            Some(proxy) => {
                let mut tcp = TcpStream::connect(proxy.addr.as_str())
                    .await
                    .wrap_err_with(|| format!("failed to reach egress proxy {}", proxy.addr))?;
                let leftover = datapath::proxy_connect_exchange(
                    &mut tcp,
                    proxy.auth.as_deref(),
                    &self.endpoint_host,
                    self.endpoint_port,
                )
                .await?;
                // The edge speaks TLS and never sends first; bytes here mean
                // a broken proxy, so fail loudly rather than desync TLS.
                ensure!(
                    leftover.is_empty(),
                    "egress proxy sent unexpected data after CONNECT"
                );
                tcp
            }
            None => TcpStream::connect((self.endpoint_host.as_str(), self.endpoint_port))
                .await
                .wrap_err_with(|| {
                    format!("failed to reach edge endpoint {}", self.config.endpoint)
                })?,
        };
        // The tunnel interleaves small yamux frames from many streams; Nagle
        // plus delayed ACKs stalls those frames for tens of milliseconds.
        tcp.set_nodelay(true)
            .wrap_err("failed to set TCP_NODELAY on tunnel socket")?;

        let tls = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await
            .wrap_err("TLS handshake with edge failed")?;

        match self.config.carrier {
            Carrier::Direct => {
                let mut io = tls;
                let tenant = self.hello(&mut io, token).await?;
                Ok((Box::new(io), tenant))
            }
            Carrier::Websocket => {
                let mut io =
                    ws::client_upgrade(tls, &self.endpoint_host, self.endpoint_port).await?;
                let tenant = self.hello(&mut io, token).await?;
                Ok((Box::new(io), tenant))
            }
        }
    }

    /// The hello exchange: identical over every carrier.
    async fn hello<S>(&self, io: &mut S, token: String) -> eyre::Result<String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        protocol::write_message(
            io,
            &Hello {
                protocol_version: PROTOCOL_VERSION,
                gateway_id: self.config.gateway_id.clone(),
                auth_token: token,
                heartbeat_interval_secs: self.config.heartbeat_interval.as_secs(),
                max_streams: Some(self.config.connection_pool.max_streams_per_connection),
                stream_acks: true,
            },
        )
        .await?;
        let reply: HelloReply = protocol::read_message(io).await?;
        tenant_from_reply(reply)
    }
}

/// An established tunnel connection, before yamux takes over.
type Carried = Box<dyn ByteStream>;

trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ByteStream for T {}

/// How one pool member's connection ended (beyond failing with an error).
enum Lifecycle {
    /// The edge closed the connection; reconnect.
    Closed,
    /// The member was told to drain and has finished doing so; exit.
    Drained,
}

/// Decrements `tunnel_connected` when a connection ends, however it ends.
struct ConnectedGauge<'a>(&'a Metrics);

impl Drop for ConnectedGauge<'_> {
    fn drop(&mut self) {
        self.0.tunnel_connected.fetch_sub(1, Ordering::Relaxed);
    }
}

struct DrainingGauge<'a> {
    metrics: &'a Metrics,
    drain_rx: watch::Receiver<bool>,
}

impl Drop for DrainingGauge<'_> {
    fn drop(&mut self) {
        if *self.drain_rx.borrow() {
            self.metrics
                .tunnel_pool_draining
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Live count of the streams being served on one tunnel connection, so a
/// draining connection can close as soon as its last stream finishes.
#[derive(Default)]
struct ActiveStreams {
    count: AtomicUsize,
    zero: Notify,
}

impl ActiveStreams {
    fn begin(self: &Arc<Self>) -> StreamGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        StreamGuard(self.clone())
    }

    async fn wait_zero(&self) {
        loop {
            // Created before the check: a `Notified` receives `notify_waiters`
            // wakeups from creation (not first poll), so a release landing
            // between the check and the await is not lost.
            let notified = self.zero.notified();
            if self.count.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Resolves once the count has stayed at zero for `grace`, so a stream
    /// routed here just before the peer deregistered the connection still
    /// gets a chance to arrive.
    async fn drained(&self, grace: Duration) {
        loop {
            self.wait_zero().await;
            tokio::time::sleep(grace).await;
            if self.count.load(Ordering::Acquire) == 0 {
                return;
            }
        }
    }
}

struct StreamGuard(Arc<ActiveStreams>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.zero.notify_waiters();
        }
    }
}

/// Resolves when the member is told to drain. A closed channel means the
/// supervisor is gone (the process is shutting down), which must not read
/// as a drain order: pend instead.
async fn drain_signal(drain_rx: &mut watch::Receiver<bool>) {
    if drain_rx.wait_for(|drain| *drain).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The tenant the edge authenticated us as. An accepting reply without a
/// tenant means a broken or incompatible edge, so fail loudly.
fn tenant_from_reply(reply: HelloReply) -> eyre::Result<String> {
    if !reply.ok {
        bail!(
            "edge rejected tunnel: {}",
            reply.error.as_deref().unwrap_or("unspecified")
        );
    }
    reply
        .tenant
        .ok_or_else(|| eyre!("edge accepted tunnel but did not name a tenant"))
}

async fn read_token(path: &Path) -> eyre::Result<String> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .wrap_err_with(|| format!("failed to read tunnel auth_token_file {}", path.display()))?;
    let token = raw.trim().to_string();
    ensure!(
        !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic()),
        "tunnel auth_token_file {} must hold a single non-empty printable token",
        path.display()
    );
    Ok(token)
}

/// Writes heartbeats until a drain order arrives (`Ok`) or a write fails.
/// The drain order is observed only between messages: an in-flight
/// heartbeat is finished first, never abandoned half-written on the
/// control stream.
async fn send_heartbeats<W>(
    mut writer: W,
    interval: Duration,
    metrics: Arc<Metrics>,
    drain_rx: &mut watch::Receiver<bool>,
) -> eyre::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut seq = 0u64;
    loop {
        tokio::select! {
            biased;
            _ = drain_signal(drain_rx) => return Ok(()),
            _ = ticker.tick() => {}
        }
        seq += 1;
        let message = ControlMessage::Heartbeat(Heartbeat {
            seq,
            active_connections: metrics.connections_active.load(Ordering::Relaxed),
            connections_total: metrics.connections_total.load(Ordering::Relaxed),
            config_version: metrics.config_version.load(Ordering::Relaxed),
        });
        protocol::write_message(&mut writer, &message).await?;
    }
}

/// The edge acks every heartbeat, so a silent control stream means the edge
/// (or the path to it) is dead even when TCP has not noticed; give up after
/// three missed intervals and reconnect.
async fn read_acks<R>(mut reader: R, interval: Duration) -> eyre::Result<()>
where
    R: AsyncRead + Unpin,
{
    let deadline = interval * 3;
    loop {
        let message: ControlMessage = timeout(deadline, protocol::read_message(&mut reader))
            .await
            .map_err(|_| eyre!("no heartbeat ack within {deadline:?}"))??;
        match message {
            ControlMessage::HeartbeatAck { .. } => {}
            ControlMessage::Heartbeat(_) => bail!("unexpected heartbeat from edge"),
            ControlMessage::DrainAck => bail!("unexpected drain ack from edge"),
        }
    }
}

/// Reads control messages during drain until the edge acks that it has
/// deregistered this member. Late heartbeat acks may still arrive first.
async fn read_drain_ack<R>(mut reader: R) -> eyre::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        match protocol::read_message(&mut reader).await? {
            ControlMessage::DrainAck => return Ok(()),
            ControlMessage::HeartbeatAck { .. } => {}
            ControlMessage::Heartbeat(_) => bail!("unexpected heartbeat from edge"),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::config::ConnectionPoolConfig;

    /// A drain order must not abandon a heartbeat half-written: the writer
    /// finishes the in-flight message and exits at the boundary.
    #[tokio::test]
    async fn drain_finishes_the_in_flight_heartbeat_write() {
        // A 1-byte pipe stalls the first heartbeat mid-write.
        let (writer, mut reader) = tokio::io::duplex(1);
        let (drain_tx, mut drain_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            send_heartbeats(
                writer,
                Duration::from_millis(1),
                Arc::new(Metrics::default()),
                &mut drain_rx,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drain_tx.send(true).unwrap();
        // Consuming the pipe unblocks the stalled write; the writer then
        // sees the drain order and returns, dropping its end (EOF here).
        let mut written = Vec::new();
        reader.read_to_end(&mut written).await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(
            written.iter().filter(|&&b| b == b'\n').count(),
            1,
            "expected exactly one complete heartbeat line: {:?}",
            String::from_utf8_lossy(&written)
        );
        assert!(written.ends_with(b"\n"), "heartbeat left half-written");
    }

    #[tokio::test]
    async fn build_accepts_ip_literal_endpoints() {
        let dir =
            std::env::temp_dir().join(format!("gateway-endpoint-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("token"), "test-token\n")
            .await
            .unwrap();
        for endpoint in ["127.0.0.1:8443", "[::1]:8443"] {
            let config = TunnelConfig {
                endpoint: endpoint.to_string(),
                gateway_id: "gw-test".to_string(),
                auth_token_file: "token".into(),
                ca_file: None,
                egress_proxy: None,
                heartbeat_interval: Duration::from_secs(15),
                carrier: Carrier::default(),
                connection_pool: ConnectionPoolConfig::default(),
            };
            let client = TunnelClient::build(config, &dir)
                .await
                .expect("an IP-literal endpoint must be accepted");
            assert!(matches!(client.server_name, ServerName::IpAddress(_)));
        }
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn rejects_multiline_tunnel_token() {
        let path = std::env::temp_dir().join(format!(
            "gateway-multiline-token-test-{}",
            std::process::id()
        ));
        tokio::fs::write(&path, "first-token\nsecond-token\n")
            .await
            .unwrap();
        let error = read_token(&path).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("single non-empty printable token")
        );
        tokio::fs::remove_file(path).await.unwrap();
    }
}
