//! Yamux stream multiplexing with a single driver task per tunnel.
//!
//! yamux's [`Connection`](yamux::Connection) is a poll-based state machine
//! that must be driven from one place: `poll_next_inbound` is what pumps the
//! underlying socket. [`MuxDriver::run`] owns the connection and interleaves
//! three concerns: completing outbound stream opens requested through
//! [`MuxHandle`]s, delivering peer-opened inbound streams, and pumping IO.

use std::{future::poll_fn, task::Poll};

use color_eyre::eyre::{self, ensure, eyre};
use futures::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::FuturesAsyncReadCompatExt;

/// A multiplexed tunnel stream, adapted to tokio IO traits.
pub type TunnelStream = tokio_util::compat::Compat<yamux::Stream>;

/// Stream-id parity per the yamux spec; the dialing side uses `Client`.
pub use yamux::Mode;

/// yamux's own default `max_num_streams`, made explicit so config defaults
/// and hello negotiation agree on the inherited cap.
pub const DEFAULT_MAX_STREAMS: usize = 512;

/// The largest local stream cap yamux accepts: its receive-window invariant
/// (256 KiB of window per stream against the default 1 GiB connection
/// window) is asserted at configuration time.
pub const MAX_LOCAL_STREAMS: usize = 4096;

/// The local yamux cap for a connection admitted at a declared cap: twice
/// the declared value. Each end garbage-collects a finished stream only
/// when its local handle drops, so the opener can reuse a freed slot while
/// the receiver still holds the finished stream — and an inbound open
/// arriving at the receiver's cap kills the whole connection. The headroom
/// absorbs those stale streams; [`crate::protocol::MAX_STREAMS_RANGE`]
/// keeps the result within [`MAX_LOCAL_STREAMS`].
pub fn local_max_streams(declared: usize) -> usize {
    declared * 2
}

const OPEN_QUEUE_DEPTH: usize = 64;

type OpenReply = oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>;

/// Cloneable handle for opening outbound streams on a live tunnel.
#[derive(Clone)]
pub struct MuxHandle {
    open_tx: mpsc::Sender<OpenReply>,
}

impl MuxHandle {
    /// Open a new outbound stream; fails once the tunnel is gone.
    pub async fn open_stream(&self) -> eyre::Result<TunnelStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open_tx
            .send(reply_tx)
            .await
            .map_err(|_| eyre!("tunnel closed"))?;
        let stream = reply_rx.await.map_err(|_| eyre!("tunnel closed"))??;
        Ok(stream.compat())
    }
}

/// Create a mux over an established transport (a TLS stream adapted to
/// futures IO traits via `TokioAsyncReadCompatExt::compat`), with the
/// default cap of [`DEFAULT_MAX_STREAMS`] concurrent streams.
pub fn new<T>(io: T, mode: Mode) -> (MuxHandle, MuxDriver<T>)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    with_max_streams(io, mode, DEFAULT_MAX_STREAMS).expect("default stream cap is in range")
}

/// [`new`] with an explicit cap on concurrent streams. The cap's failure
/// modes are asymmetric: a local open at the cap fails with
/// `TooManyStreams` (that open only), but an inbound open arriving at the
/// cap terminates the whole connection. Callers must therefore enforce
/// admission themselves (the edge does, with per-connection dial slots)
/// and the end receiving dials must run at [`local_max_streams`] headroom
/// over the declared cap. Caps past [`MAX_LOCAL_STREAMS`] would trip
/// yamux's receive-window assertion, so they are rejected here.
pub fn with_max_streams<T>(
    io: T,
    mode: Mode,
    max_streams: usize,
) -> eyre::Result<(MuxHandle, MuxDriver<T>)>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    ensure!(
        (2..=MAX_LOCAL_STREAMS).contains(&max_streams),
        "max_streams must be between 2 and {MAX_LOCAL_STREAMS}, got {max_streams}"
    );
    let mut config = yamux::Config::default();
    config.set_max_num_streams(max_streams);
    let (open_tx, open_rx) = mpsc::channel(OPEN_QUEUE_DEPTH);
    let connection = yamux::Connection::new(io, config, mode);
    Ok((
        MuxHandle { open_tx },
        MuxDriver {
            connection,
            open_rx,
            pending_open: None,
        },
    ))
}

/// Owns the yamux connection; see [`MuxDriver::run`].
pub struct MuxDriver<T> {
    connection: yamux::Connection<T>,
    open_rx: mpsc::Receiver<OpenReply>,
    pending_open: Option<OpenReply>,
}

impl<T> MuxDriver<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Drive the tunnel until the peer closes it (`Ok`) or the transport
    /// fails (`Err`). `on_inbound` is called inline for every peer-opened
    /// stream and must not block; spawn a task to serve the stream.
    pub async fn run(mut self, mut on_inbound: impl FnMut(TunnelStream)) -> eyre::Result<()> {
        poll_fn(move |cx| {
            loop {
                // Pump the socket first (this also garbage-collects streams
                // dropped by their tasks) and admit outbound opens only once
                // it runs dry: a slot freed by a finished stream must be
                // reflected in yamux's own accounting before the open that
                // reuses it, or the open fails spuriously with
                // `TooManyStreams`.
                match self.connection.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => {
                        on_inbound(stream.compat());
                        continue;
                    }
                    Poll::Ready(Some(Err(err))) => {
                        return Poll::Ready(Err(eyre!(err).wrap_err("tunnel transport failed")));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => {}
                }
                // Complete the in-flight open, if any, before taking another.
                if let Some(reply) = self.pending_open.take() {
                    match self.connection.poll_new_outbound(cx) {
                        // The requester may have gone away; that's its business.
                        Poll::Ready(result) => {
                            let _ = reply.send(result);
                            continue;
                        }
                        Poll::Pending => self.pending_open = Some(reply),
                    }
                }
                if self.pending_open.is_none() {
                    match self.open_rx.poll_recv(cx) {
                        Poll::Ready(Some(reply)) => {
                            self.pending_open = Some(reply);
                            continue;
                        }
                        // All handles dropped: keep serving inbound streams.
                        Poll::Ready(None) | Poll::Pending => {}
                    }
                }
                return Poll::Pending;
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;

    async fn wait_until(what: &str, mut poll: impl FnMut() -> bool) {
        for _ in 0..500 {
            if poll() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("timed out waiting for {what}");
    }

    fn spawn_pair() -> (MuxHandle, MuxHandle) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let (client, client_driver) = new(a.compat(), Mode::Client);
        let (server, server_driver) = new(b.compat(), Mode::Server);
        tokio::spawn(client_driver.run(echo_inbound));
        tokio::spawn(server_driver.run(echo_inbound));
        (client, server)
    }

    fn echo_inbound(stream: TunnelStream) {
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        });
    }

    async fn assert_echo(handle: &MuxHandle, payload: &[u8]) {
        let mut stream = handle.open_stream().await.unwrap();
        stream.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
    }

    #[tokio::test]
    async fn serves_many_concurrent_streams() {
        let (client, _server) = spawn_pair();
        let tasks: Vec<_> = (0..32u32)
            .map(|i| {
                let client = client.clone();
                tokio::spawn(async move {
                    let payload = i.to_be_bytes().repeat(1024);
                    assert_echo(&client, &payload).await;
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_out_of_range_stream_caps() {
        for cap in [1, 4097] {
            let (a, _b) = tokio::io::duplex(1024);
            match with_max_streams(a.compat(), Mode::Client, cap) {
                Err(err) => assert!(err.to_string().contains("max_streams"), "{err}"),
                Ok(_) => panic!("cap {cap} must be rejected"),
            }
        }
        for cap in [2, 4096] {
            let (a, _b) = tokio::io::duplex(1024);
            assert!(with_max_streams(a.compat(), Mode::Client, cap).is_ok());
        }
    }

    #[tokio::test]
    async fn opening_past_the_stream_cap_fails() {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let (client, client_driver) = with_max_streams(a.compat(), Mode::Client, 3).unwrap();
        let (_server, server_driver) = with_max_streams(b.compat(), Mode::Server, 3).unwrap();
        tokio::spawn(client_driver.run(echo_inbound));
        tokio::spawn(server_driver.run(echo_inbound));

        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(client.open_stream().await.unwrap());
        }
        // A local open at the cap fails with `TooManyStreams` — only that
        // open, not the connection. (Inbound opens past the receiver's cap
        // are what kill the connection, which is why the receiving end
        // runs at `local_max_streams` headroom.)
        let _ = client.open_stream().await.unwrap_err();
    }

    /// The cross-peer cleanup race behind [`local_max_streams`]: the opener
    /// frees its admission slot by dropping a finished stream, but the
    /// receiver only garbage-collects that stream once the handle it gave
    /// out drops locally. An inbound open arriving while stale streams
    /// still fill the declared cap must land in the receiver's headroom —
    /// at a bare declared-cap receiver it terminates the connection.
    #[tokio::test]
    async fn absorbs_inbound_opens_while_stale_streams_fill_the_declared_cap() {
        let declared = 2;
        let (a, b) = tokio::io::duplex(256 * 1024);
        let (_receiver, receiver_driver) =
            with_max_streams(a.compat(), Mode::Server, local_max_streams(declared)).unwrap();
        // The opener's own cap is not under test; admission (the edge's
        // dial slots) is what bounds it in production.
        let (opener, opener_driver) =
            with_max_streams(b.compat(), Mode::Client, 2 * declared).unwrap();
        let held = Arc::new(Mutex::new(Vec::new()));
        let receiver_task = tokio::spawn(receiver_driver.run({
            let held = held.clone();
            move |stream| held.lock().unwrap().push(stream)
        }));
        tokio::spawn(opener_driver.run(|_| {}));

        // Fill the declared cap with streams the opener has finished with
        // and dropped, while the receiver still holds every handle.
        for _ in 0..declared {
            let mut stream = opener.open_stream().await.unwrap();
            stream.write_all(b"x").await.unwrap();
            stream.flush().await.unwrap();
        }
        wait_until("the receiver holds the stale streams", || {
            held.lock().unwrap().len() == declared
        })
        .await;

        // The opener's freed slots get reused while the stale streams are
        // still in the receiver's map.
        let mut reused = Vec::new();
        for _ in 0..declared {
            let mut stream = opener.open_stream().await.unwrap();
            stream.write_all(b"y").await.unwrap();
            stream.flush().await.unwrap();
            reused.push(stream);
        }
        wait_until("the receiver absorbs the reused opens", || {
            held.lock().unwrap().len() == 2 * declared
        })
        .await;
        assert!(!receiver_task.is_finished(), "the connection was killed");
    }

    #[tokio::test]
    async fn open_fails_once_the_transport_is_gone() {
        let (a, b) = tokio::io::duplex(1024);
        let (client, client_driver) = new(a.compat(), Mode::Client);
        let (_server, server_driver) = new(b.compat(), Mode::Server);
        let client_task = tokio::spawn(client_driver.run(|_| {}));
        drop(server_driver);
        let _ = client_task.await.unwrap().unwrap_err();
        let _ = client.open_stream().await.unwrap_err();
    }
}
