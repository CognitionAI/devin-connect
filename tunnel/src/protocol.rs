//! Handshake and control-stream messages, with bounded JSON-line IO.
//!
//! Messages deliberately tolerate unknown fields (no `deny_unknown_fields`):
//! protocol evolution is additive, and a newer peer must be able to send new
//! optional fields without breaking an older one. Breaking changes bump
//! [`PROTOCOL_VERSION`] instead.

use color_eyre::eyre::{self, WrapErr, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Version of the hello exchange and stream conventions. The edge rejects
/// hellos with a version it does not support.
pub const PROTOCOL_VERSION: u32 = 1;

/// Upper bound for a single protocol message line, excluding the trailing
/// newline. [`read_message`] and [`write_message`] both enforce it.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024;

/// Heartbeat intervals (in seconds) a gateway may declare in its [`Hello`].
/// The edge rejects hellos outside this range, and the gateway refuses to
/// load a config outside it rather than reconnect forever.
pub const HEARTBEAT_INTERVAL_RANGE: std::ops::RangeInclusive<u64> = 1..=300;

/// Concurrent-stream caps a gateway may declare in its [`Hello`]. The lower
/// bound leaves room for the control stream plus at least one dial. Each
/// end runs its local yamux cap at twice the declared cap (see
/// [`crate::mux::local_max_streams`]), so the upper bound is half of
/// yamux's receive-window limit ([`crate::mux::MAX_LOCAL_STREAMS`]).
pub const MAX_STREAMS_RANGE: std::ops::RangeInclusive<usize> = 2..=2048;

/// First message on a fresh tunnel, gateway -> edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u32,

    /// Stable identifier of the gateway deployment, from gateway config.
    pub gateway_id: String,

    /// Enrollment credential identifying and authenticating the tenant.
    /// Never logged by either end.
    pub auth_token: String,

    /// Interval at which the gateway will send control-stream heartbeats;
    /// the edge treats the tunnel as dead after ~3 missed intervals.
    pub heartbeat_interval_secs: u64,

    /// Cap on concurrent streams for this connection, enforced by the
    /// edge's dial-slot admission; both ends run their local yamux cap at
    /// [`crate::mux::local_max_streams`] over it. Bounded by
    /// [`MAX_STREAMS_RANGE`]. `None` on hellos from older gateways, whose
    /// receivers have no headroom; the edge admits those conservatively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<usize>,

    /// Whether this gateway answers a [`StreamPreamble`] that requests an
    /// ack with a [`StreamAck`]. Absent/false on hellos from older
    /// gateways; the edge then relays without waiting for acks (and their
    /// black-holed paths are only caught by heartbeat eviction).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stream_acks: bool,
}

/// Edge's reply to a [`Hello`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloReply {
    pub ok: bool,

    /// Tenant id the gateway authenticated as (when `ok`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,

    /// Rejection reason (when not `ok`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// First message on each edge-opened dial stream, edge -> gateway, written
/// before any dialer bytes are relayed. Carries the Devin-side dialer's
/// peer address for connection logging.
/// Writing it eagerly also surfaces the lazily-opened yamux stream to the
/// gateway immediately, so its request-head timeout covers silent dialers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamPreamble {
    /// Peer address (`ip:port`) of the connection to the edge dial listener.
    pub peer_addr: String,

    /// Ask the gateway to answer with a [`StreamAck`] before any proxied
    /// bytes. Only set for gateways whose hello declared `stream_acks`, so
    /// an older gateway is never waited on for an ack it cannot send — and
    /// a newer gateway never sends one an older edge would relay as
    /// payload.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub want_ack: bool,
}

/// Gateway -> edge answer to a [`StreamPreamble`] with `want_ack`, written
/// before any proxied bytes. Completing it proves the stream reached the
/// gateway: yamux opens streams lazily and a preamble write sinks into the
/// stream's send window, so on a black-holed path both finish locally and
/// only this round trip can miss the edge's dial deadline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAck {}

/// Control-stream messages. Tagged so new message types can be added in
/// future protocol versions; at v1 an unknown type is a protocol error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    /// Periodic gateway -> edge liveness signal with aggregated counters.
    Heartbeat(Heartbeat),
    /// Edge -> gateway acknowledgement of a heartbeat.
    HeartbeatAck { seq: u64 },
    /// Edge -> gateway: the draining connection has been deregistered, so
    /// no further dials will be routed to it.
    DrainAck,
}

/// Aggregated gateway state carried on each heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub seq: u64,
    pub active_connections: u64,
    pub connections_total: u64,
    /// `config_version` of the gateway's active config (0 if unset).
    pub config_version: u64,
}

/// Write one message as a single JSON line.
pub async fn write_message<S, M>(stream: &mut S, message: &M) -> eyre::Result<()>
where
    S: AsyncWrite + Unpin,
    M: Serialize,
{
    let mut line = serde_json::to_vec(message).wrap_err("failed to encode protocol message")?;
    ensure!(
        line.len() <= MAX_MESSAGE_SIZE,
        "protocol message exceeds {MAX_MESSAGE_SIZE} bytes"
    );
    line.push(b'\n');
    stream.write_all(&line).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one JSON-line message, refusing lines over [`MAX_MESSAGE_SIZE`].
///
/// Reads byte-by-byte on purpose: the hello exchange happens on the raw TLS
/// stream right before it becomes the yamux transport, so this reader must
/// never consume bytes past the newline. Only handshake- and
/// heartbeat-frequency traffic flows through here, never proxied payload.
pub async fn read_message<S, M>(stream: &mut S) -> eyre::Result<M>
where
    S: AsyncRead + Unpin,
    M: DeserializeOwned,
{
    match read_message_or_eof(stream).await? {
        Some(message) => Ok(message),
        None => bail!("connection closed mid-message"),
    }
}

/// Like [`read_message`], but a clean end-of-stream at a message boundary
/// yields `None`: the peer finished writing on purpose (e.g. a draining
/// gateway half-closing its control stream) rather than dying mid-message.
pub async fn read_message_or_eof<S, M>(stream: &mut S) -> eyre::Result<Option<M>>
where
    S: AsyncRead + Unpin,
    M: DeserializeOwned,
{
    let mut line = Vec::with_capacity(256);
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await? == 0 {
            ensure!(line.is_empty(), "connection closed mid-message");
            return Ok(None);
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        ensure!(
            line.len() <= MAX_MESSAGE_SIZE,
            "protocol message exceeds {MAX_MESSAGE_SIZE} bytes"
        );
    }
    serde_json::from_slice(&line)
        .map(Some)
        .wrap_err("invalid protocol message")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrips_stream_preamble() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_message(
            &mut a,
            &StreamPreamble {
                peer_addr: "10.1.2.3:54321".to_string(),
                want_ack: true,
            },
        )
        .await
        .unwrap();
        // Dialer bytes follow the preamble on the same stream.
        a.write_all(b"CONNECT db.corp:5432 HTTP/1.1\r\n")
            .await
            .unwrap();
        let preamble: StreamPreamble = read_message(&mut b).await.unwrap();
        assert_eq!(preamble.peer_addr, "10.1.2.3:54321");
        assert!(preamble.want_ack);
        let mut head = [0u8; 7];
        b.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"CONNECT");
    }

    #[tokio::test]
    async fn hello_without_max_streams_reads_as_absent() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(
            b"{\"protocol_version\":1,\"gateway_id\":\"gw-old\",\"auth_token\":\"t\",\"heartbeat_interval_secs\":15}\n",
        )
        .await
        .unwrap();
        let hello: Hello = read_message(&mut b).await.unwrap();
        assert_eq!(hello.max_streams, None);
        assert!(!hello.stream_acks);
    }

    #[tokio::test]
    async fn preamble_from_an_old_edge_reads_as_no_ack_wanted() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(b"{\"peer_addr\":\"10.0.0.1:1\"}\n")
            .await
            .unwrap();
        let preamble: StreamPreamble = read_message(&mut b).await.unwrap();
        assert!(!preamble.want_ack);
    }

    #[tokio::test]
    async fn tolerates_unknown_fields_for_additive_evolution() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(b"{\"ok\":true,\"tenant\":\"acme\",\"new_field\":42}\n")
            .await
            .unwrap();
        let reply: HelloReply = read_message(&mut b).await.unwrap();
        assert!(reply.ok);
        assert_eq!(reply.tenant.as_deref(), Some("acme"));
    }

    #[tokio::test]
    async fn rejects_oversized_messages() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let big = vec![b'x'; MAX_MESSAGE_SIZE + 1];
        tokio::spawn(async move {
            let _ = a.write_all(&big).await;
        });
        let err = read_message::<_, HelloReply>(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn distinguishes_clean_eof_from_truncation() {
        let (a, mut b) = tokio::io::duplex(1024);
        drop(a);
        let reply = read_message_or_eof::<_, HelloReply>(&mut b).await.unwrap();
        assert!(reply.is_none());

        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(b"{\"ok\":true}\n{\"ok\":false").await.unwrap();
        drop(a);
        let reply = read_message_or_eof::<_, HelloReply>(&mut b).await.unwrap();
        assert!(reply.unwrap().ok);
        let err = read_message_or_eof::<_, HelloReply>(&mut b)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("closed mid-message"), "{err}");
    }
}
