//! The byte splice between a connection's two sides, shared by the gateway
//! datapath and the edge's dial and relay paths.

use std::{
    future::{Future, poll_fn},
    pin::{Pin, pin},
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional},
    time::{Instant as TokioInstant, Sleep, sleep_until},
};

/// What [`splice`] learned about a finished connection.
pub struct SpliceOutcome {
    pub result: std::io::Result<()>,
    pub client_to_upstream: u64,
    pub upstream_to_client: u64,
    pub half_close_timed_out: bool,
}

/// Copy bytes both ways until both directions finish.
///
/// After one side sends EOF, `copy_bidirectional` keeps the other direction
/// open until that peer closes too, so a peer that never closes would pin
/// the task and both sockets forever. Once one direction has finished, the
/// splice is cut when the other moves no byte for `half_close_timeout`
/// (zero disables). Bytes waiting on a slow reader are not idleness: only a
/// sender that stays silent is cut.
pub async fn splice<C, U>(
    client: &mut C,
    upstream: &mut U,
    half_close_timeout: Duration,
) -> SpliceOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let activity = SpliceActivity::new();
    let mut client = CountingStream::new(ActivityStream::new(client, &activity));
    let mut upstream = CountingStream::new(ActivityStream::new(upstream, &activity));
    let mut idle_timer: Option<Pin<Box<Sleep>>> = None;
    let result = {
        let copy = pin!(copy_bidirectional(&mut client, &mut upstream));
        let mut copy = copy;
        poll_fn(|cx| {
            if let Poll::Ready(result) = copy.as_mut().poll(cx) {
                return Poll::Ready(Some(result.map(drop)));
            }
            if half_close_timeout.is_zero() {
                return Poll::Pending;
            }
            // Runs after every poll of the copy, whichever half made
            // progress, so the timer is always registered while idle.
            let Some(idle_since) = activity.idle_since() else {
                return Poll::Pending;
            };
            let deadline = idle_since + half_close_timeout;
            let timer = idle_timer.get_or_insert_with(|| Box::pin(sleep_until(deadline)));
            if timer.deadline() != deadline {
                timer.as_mut().reset(deadline);
            }
            timer.as_mut().poll(cx).map(|()| None)
        })
        .await
    };
    SpliceOutcome {
        half_close_timed_out: result.is_none(),
        result: result.unwrap_or(Ok(())),
        client_to_upstream: upstream.bytes_written,
        upstream_to_client: client.bytes_written,
    }
}

/// Progress of a splice's two streams, shared with its half-close timer.
/// Atomics only because the splice future must be `Send`; one task uses it.
struct SpliceActivity {
    started: TokioInstant,
    half_closed: AtomicBool,
    /// Milliseconds after `started` of the last byte moved since half-close.
    last_progress_ms: AtomicU64,
    /// Streams holding bytes their peer has not accepted yet.
    blocked_writes: AtomicU8,
}

impl SpliceActivity {
    fn new() -> Self {
        Self {
            started: TokioInstant::now(),
            half_closed: AtomicBool::new(false),
            last_progress_ms: AtomicU64::new(0),
            blocked_writes: AtomicU8::new(0),
        }
    }

    fn progress(&self) {
        // The clock is read only once half-closed, to keep it off the
        // fully-open datapath.
        if self.half_closed.load(Ordering::Relaxed) {
            let elapsed = self.started.elapsed().as_millis() as u64;
            self.last_progress_ms.store(elapsed, Ordering::Relaxed);
        }
    }

    fn half_close(&self) {
        if !self.half_closed.swap(true, Ordering::Relaxed) {
            self.progress();
        }
    }

    /// When the half-closed splice last moved a byte, if it is idle now.
    fn idle_since(&self) -> Option<TokioInstant> {
        let idle = self.half_closed.load(Ordering::Relaxed)
            && self.blocked_writes.load(Ordering::Relaxed) == 0;
        idle.then(|| {
            self.started + Duration::from_millis(self.last_progress_ms.load(Ordering::Relaxed))
        })
    }
}

/// Reports one splice stream's reads, writes and shutdown to a
/// [`SpliceActivity`].
struct ActivityStream<'a, S> {
    inner: S,
    activity: &'a SpliceActivity,
    write_blocked: bool,
}

impl<'a, S> ActivityStream<'a, S> {
    fn new(inner: S, activity: &'a SpliceActivity) -> Self {
        Self {
            inner,
            activity,
            write_blocked: false,
        }
    }

    fn set_write_blocked(&mut self, blocked: bool) {
        if self.write_blocked == blocked {
            return;
        }
        self.write_blocked = blocked;
        if blocked {
            self.activity.blocked_writes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.activity.blocked_writes.fetch_sub(1, Ordering::Relaxed);
            self.activity.progress();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityStream<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > filled {
            this.activity.progress();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityStream<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.set_write_blocked(result.is_pending());
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            this.activity.progress();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        this.set_write_blocked(result.is_pending());
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.activity.half_close();
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

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        task::JoinHandle,
        time::timeout,
    };

    use super::*;

    const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(60);

    /// Splice two in-memory pipes; returns the client's and the upstream's
    /// ends and the running splice.
    fn spawn_splice(
        half_close_timeout: Duration,
    ) -> (DuplexStream, DuplexStream, JoinHandle<SpliceOutcome>) {
        let (client, mut client_side) = tokio::io::duplex(16);
        let (upstream, mut upstream_side) = tokio::io::duplex(16);
        let splice = tokio::spawn(async move {
            splice(&mut client_side, &mut upstream_side, half_close_timeout).await
        });
        (client, upstream, splice)
    }

    #[tokio::test(start_paused = true)]
    async fn splice_ends_when_one_side_closes_and_the_other_stays_silent() {
        for client_closes_first in [true, false] {
            let (mut client, mut upstream, splice) = spawn_splice(HALF_CLOSE_TIMEOUT);
            let (closer, silent) = if client_closes_first {
                (&mut client, &mut upstream)
            } else {
                (&mut upstream, &mut client)
            };
            closer.write_all(b"done").await.unwrap();
            closer.shutdown().await.unwrap();
            let mut received = Vec::new();
            silent.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"done");

            let outcome = timeout(HALF_CLOSE_TIMEOUT * 2, splice)
                .await
                .unwrap_or_else(|_| panic!("leaked (client_closes_first={client_closes_first})"))
                .unwrap();
            assert!(outcome.half_close_timed_out);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn splice_restarts_half_close_timeout_when_bytes_arrive() {
        let (mut client, mut upstream, splice) = spawn_splice(HALF_CLOSE_TIMEOUT);
        client.shutdown().await.unwrap();
        for _ in 0..4 {
            tokio::time::sleep(HALF_CLOSE_TIMEOUT * 3 / 4).await;
            upstream.write_all(b".").await.unwrap();
        }
        upstream.shutdown().await.unwrap();

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"....");
        assert!(!splice.await.unwrap().half_close_timed_out);
    }

    #[tokio::test(start_paused = true)]
    async fn splice_does_not_time_out_bytes_waiting_on_a_slow_reader() {
        let (mut client, mut upstream, splice) = spawn_splice(HALF_CLOSE_TIMEOUT);
        client.shutdown().await.unwrap();
        // More than the splice and both pipes can buffer.
        let payload = vec![7u8; 64 * 1024];
        let sent = payload.clone();
        tokio::spawn(async move {
            upstream.write_all(&sent).await.unwrap();
            upstream.shutdown().await.unwrap();
        });

        tokio::time::sleep(HALF_CLOSE_TIMEOUT * 3).await;
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
        assert!(!splice.await.unwrap().half_close_timed_out);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_half_close_timeout_never_ends_the_splice() {
        let (mut client, _upstream, splice) = spawn_splice(Duration::ZERO);
        client.shutdown().await.unwrap();
        assert!(
            timeout(Duration::from_secs(24 * 60 * 60), splice)
                .await
                .is_err()
        );
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
