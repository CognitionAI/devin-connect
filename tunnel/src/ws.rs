//! WebSocket carrier: the tunnel protocol framed as binary WebSocket
//! messages inside the same TLS connection (WSS on the wire), for networks
//! where only HTTP-shaped traffic passes. [`WsByteStream`] adapts the
//! WebSocket to the plain byte stream the protocol and mux layers consume,
//! so everything above the carrier is shared with direct mode.
//!
//! Compression is never negotiated (the payload is customer TLS), only
//! binary frames are valid, and WebSocket ping/pong is left to the library's
//! automatic pong replies — liveness belongs to the application heartbeats
//! on the control stream.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use color_eyre::eyre::{self, WrapErr};
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{
        Error as WsError, Message,
        client::ClientRequestBuilder,
        handshake::server::{ErrorResponse, Request, Response},
        http,
        protocol::WebSocketConfig,
    },
};

/// Request path of the tunnel upgrade endpoint on the edge.
pub const UPGRADE_PATH: &str = "/tunnel";

/// WebSocket subprotocol both ends must negotiate.
pub const SUBPROTOCOL: &str = "devin-tunnel";

/// Upper bound on one incoming WebSocket message/frame. Peers chunk writes
/// to [`WRITE_CHUNK_SIZE`], so anything near this limit is a broken or
/// hostile peer, not backpressure.
pub const MAX_WS_MESSAGE_SIZE: usize = 256 * 1024;

/// Largest binary message this end sends; larger writes are split.
pub const WRITE_CHUNK_SIZE: usize = 64 * 1024;

/// Log targets that dump raw frame payloads at TRACE — which on this
/// carrier means hello auth tokens and customer bytes. Every binary that
/// installs a subscriber must mask them with a dedicated filter layer, not
/// with `EnvFilter` directives: inside one `EnvFilter` a more specific
/// environment directive (`tungstenite::protocol=trace`) overrides a
/// crate-level `<target>=off`.
pub const PAYLOAD_LOGGING_TARGETS: &[&str] = &["tungstenite", "tokio_tungstenite"];

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        // Hand every frame to the underlying stream eagerly: the tunnel
        // interleaves small latency-sensitive frames, and flush cadence is
        // controlled by the layers above.
        .write_buffer_size(0)
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE))
}

/// Perform the client half of the tunnel upgrade over an established
/// stream (TLS to the edge). A non-default `port` rides along in the
/// authority, as HTTP requires.
pub async fn client_upgrade<S>(io: S, host: &str, port: u16) -> eyre::Result<WsByteStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let authority = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    let uri: http::Uri = format!("wss://{authority}{UPGRADE_PATH}")
        .parse()
        .wrap_err("failed to build upgrade request")?;
    let request = ClientRequestBuilder::new(uri).with_sub_protocol(SUBPROTOCOL);
    // tungstenite's client handshake enforces RFC 6455 subprotocol
    // confirmation: a reply that does not name exactly one of the offered
    // subprotocols is rejected before this returns.
    let (ws, _response) = client_async_with_config(request, io, Some(ws_config()))
        .await
        .wrap_err("websocket upgrade failed")?;
    Ok(WsByteStream::new(ws))
}

/// Perform the server half of the tunnel upgrade.
pub async fn server_upgrade<S>(io: S) -> eyre::Result<WsByteStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The callback's Result<Response, ErrorResponse> shape (and so the
    // large Err variant clippy flags) is fixed by tungstenite's Callback
    // trait.
    #[allow(clippy::result_large_err)]
    let callback = |request: &Request, mut response: Response| {
        validate_upgrade(request)?;
        response
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", SUBPROTOCOL.try_into().unwrap());
        Ok(response)
    };
    let ws = tokio_tungstenite::accept_hdr_async_with_config(io, callback, Some(ws_config()))
        .await
        .wrap_err("websocket upgrade failed")?;
    Ok(WsByteStream::new(ws))
}

fn error_response(status: http::StatusCode, reason: &str) -> ErrorResponse {
    let mut response = ErrorResponse::new(Some(reason.to_string()));
    *response.status_mut() = status;
    response
}

#[allow(clippy::result_large_err)] // Err type fixed by tungstenite's Callback trait
fn validate_upgrade(request: &Request) -> Result<(), ErrorResponse> {
    if request.uri().path() != UPGRADE_PATH {
        return Err(error_response(http::StatusCode::NOT_FOUND, "not found"));
    }
    let valid_host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|host| host.parse::<http::uri::Authority>().ok())
        .is_some_and(|authority| !authority.host().is_empty());
    if !valid_host {
        return Err(error_response(
            http::StatusCode::BAD_REQUEST,
            "missing or invalid host header",
        ));
    }
    let offered = request
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|list| list.split(',').any(|p| p.trim() == SUBPROTOCOL));
    if !offered {
        return Err(error_response(
            http::StatusCode::BAD_REQUEST,
            "missing required websocket subprotocol",
        ));
    }
    Ok(())
}

// Flattened to strings: tungstenite errors embed their source's Display, so
// preserving the source chain double-prints the message in report formatting.
fn ws_io_error(err: WsError) -> io::Error {
    match err {
        WsError::Io(io) => io,
        err @ (WsError::ConnectionClosed | WsError::AlreadyClosed) => {
            io::Error::new(io::ErrorKind::BrokenPipe, err.to_string())
        }
        err @ WsError::Capacity(_) => io::Error::new(io::ErrorKind::InvalidData, err.to_string()),
        other => io::Error::other(other.to_string()),
    }
}

/// A WebSocket carrying the tunnel as binary messages, adapted to
/// `AsyncRead`/`AsyncWrite`. Reads yield message payload bytes in order
/// (message boundaries carry no meaning); writes are chunked into binary
/// messages. Ping/pong frames are invisible to the byte stream, a text
/// frame from the peer is a protocol violation that poisons all further
/// reads, and a peer close — whatever the status code — or transport EOF
/// reads as EOF.
#[derive(Debug)]
pub struct WsByteStream<S> {
    inner: WebSocketStream<S>,
    read_buf: Bytes,
    poisoned: bool,
}

impl<S> WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Bytes::new(),
            poisoned: false,
        }
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.poisoned {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket stream unusable after a protocol violation",
            )));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf.split_to(n));
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => self.read_buf = data,
                // The library auto-queues pong replies; both are invisible
                // to the byte stream.
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(message @ (Message::Text(_) | Message::Frame(_)))) => {
                    self.poisoned = true;
                    let kind = if message.is_text() {
                        "text"
                    } else {
                        "raw frame"
                    };
                    // Only the message kind: the contents are peer-controlled
                    // (on the edge, pre-auth) and this error reaches logs.
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected {kind} websocket message"),
                    )));
                }
                Some(Err(err)) => return Poll::Ready(Err(ws_io_error(err))),
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(ws_io_error)?;
        let n = buf.len().min(WRITE_CHUNK_SIZE);
        Pin::new(&mut self.inner)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
            .map_err(ws_io_error)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(ws_io_error)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(ws_io_error)
    }
}

/// A byte stream with some already-read bytes put back in front, so a
/// listener can sniff the first byte to pick the carrier and still hand the
/// complete stream to the chosen handler.
pub struct Prefixed<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: &[u8], inner: S) -> Self {
        Self {
            prefix: Bytes::copy_from_slice(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix.split_to(n));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_SNI: &str = "acme.gw.devin.example";

    /// An upgraded client/server pair over an in-memory duplex.
    async fn ws_pair() -> (
        WsByteStream<tokio::io::DuplexStream>,
        WsByteStream<tokio::io::DuplexStream>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(server_upgrade(server_io));
        let client = client_upgrade(client_io, TEST_SNI, 443).await.unwrap();
        (client, server.await.unwrap().unwrap())
    }

    /// A full upgrade request with the standard handshake headers, and
    /// `host`/`subprotocol` overridable for the rejection tests.
    fn handshake_request(path: &str, host: &str, subprotocol: Option<&str>) -> http::Request<()> {
        let mut builder = http::Request::builder()
            .method("GET")
            .uri(format!("wss://{host}{path}"))
            .header(http::header::HOST, host)
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            );
        if let Some(subprotocol) = subprotocol {
            builder = builder.header("Sec-WebSocket-Protocol", subprotocol);
        }
        builder.body(()).unwrap()
    }

    /// A raw tungstenite peer (no limits) against our server adapter.
    async fn raw_client_pair() -> (
        WebSocketStream<tokio::io::DuplexStream>,
        WsByteStream<tokio::io::DuplexStream>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server = tokio::spawn(server_upgrade(server_io));
        let request = handshake_request(UPGRADE_PATH, TEST_SNI, Some(SUBPROTOCOL));
        let (raw, _response) = client_async_with_config(request, client_io, None)
            .await
            .unwrap();
        (raw, server.await.unwrap().unwrap())
    }

    #[tokio::test]
    async fn upgrade_and_byte_exact_roundtrip() {
        let (mut client, mut server) = ws_pair().await;

        // Bidirectional, byte-exact, including bytes that look like WS
        // control opcodes and a payload spanning several write chunks.
        let payload: Vec<u8> = (0..WRITE_CHUNK_SIZE * 3 + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            let mut reply = [0u8; 4];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
        });
        let mut got = vec![0u8; expected.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn reads_spanning_message_boundaries_and_partial_messages() {
        let (mut client, mut server) = ws_pair().await;
        client.write_all(b"hello").await.unwrap();
        client.write_all(b" world").await.unwrap();
        client.flush().await.unwrap();

        // Two messages read back as one contiguous byte stream, in pieces
        // smaller than either message.
        let mut got = Vec::new();
        while got.len() < 11 {
            let mut chunk = [0u8; 3];
            let n = server.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, b"hello world");
    }

    #[tokio::test]
    async fn peer_close_reads_as_eof() {
        let (mut client, mut server) = ws_pair().await;
        client.shutdown().await.unwrap();
        let mut sink = Vec::new();
        server.read_to_end(&mut sink).await.unwrap();
        assert!(sink.is_empty());
    }

    #[tokio::test]
    async fn text_frame_is_a_protocol_violation() {
        let (mut raw, mut server) = raw_client_pair().await;
        raw.send(Message::Text("TEXT_CONTENTS_MUST_NOT_ESCAPE".into()))
            .await
            .unwrap();
        let err = server.read(&mut [0u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        // The error names the message kind but never carries the contents:
        // on the edge this error is logged pre-auth, so the contents are
        // arbitrary unauthenticated bytes.
        assert!(!err.to_string().contains("MUST_NOT_ESCAPE"), "{err}");
        assert!(err.to_string().contains("text"), "{err}");
    }

    #[tokio::test]
    async fn protocol_violation_poisons_later_reads() {
        let (mut raw, mut server) = raw_client_pair().await;
        raw.send(Message::Text("nope".into())).await.unwrap();
        raw.send(Message::Binary(Bytes::from_static(b"data")))
            .await
            .unwrap();
        let err = server.read(&mut [0u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        // The violation latches: the stream must not quietly resume on the
        // binary message that followed.
        let err = server.read(&mut [0u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    #[tokio::test]
    async fn oversized_message_is_rejected() {
        let (mut raw, mut server) = raw_client_pair().await;
        let big = vec![0u8; MAX_WS_MESSAGE_SIZE + 1];
        raw.send(Message::Binary(big.into())).await.unwrap();
        let err = server.read(&mut [0u8; 16]).await.unwrap_err();
        assert!(err.to_string().contains("Space limit exceeded"), "{err}");
    }

    #[tokio::test]
    async fn pings_are_answered_and_invisible() {
        let (mut raw, mut server) = raw_client_pair().await;
        raw.send(Message::Ping(Bytes::from_static(b"marco")))
            .await
            .unwrap();
        raw.send(Message::Binary(Bytes::from_static(b"data")))
            .await
            .unwrap();

        // The adapter must skip the ping and deliver only payload bytes.
        let mut got = [0u8; 4];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"data");

        // Reading queues the automatic pong; tungstenite flushes it the
        // next time the server side reads or writes the connection (here:
        // a write).
        server.write_all(b"ok").await.unwrap();
        server.flush().await.unwrap();
        loop {
            match raw.next().await.unwrap().unwrap() {
                Message::Pong(payload) => {
                    assert_eq!(payload, Bytes::from_static(b"marco"));
                    break;
                }
                Message::Binary(_) => {}
                other => panic!("unexpected message: {other:?}"),
            }
        }
    }

    async fn upgrade_must_fail(request: http::Request<()>, expected_status: u16) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(server_upgrade(server_io));
        let client_err = client_async_with_config(request, client_io, None)
            .await
            .unwrap_err();
        match client_err {
            WsError::Http(response) => assert_eq!(response.status().as_u16(), expected_status),
            other => panic!("expected HTTP rejection, got {other:?}"),
        }
        let server_err = server.await.unwrap().unwrap_err();
        assert!(
            format!("{server_err:#}").contains("upgrade failed"),
            "{server_err:#}"
        );
    }

    #[tokio::test]
    async fn rejects_wrong_path() {
        let request = handshake_request("/other", TEST_SNI, Some(SUBPROTOCOL));
        upgrade_must_fail(request, 404).await;
    }

    #[tokio::test]
    async fn rejects_missing_subprotocol() {
        let request = handshake_request(UPGRADE_PATH, TEST_SNI, None);
        upgrade_must_fail(request, 400).await;
    }

    #[tokio::test]
    async fn accepts_host_with_port_and_mixed_case() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(server_upgrade(server_io));
        let host = format!("{}:443", TEST_SNI.to_ascii_uppercase());
        let request = handshake_request(UPGRADE_PATH, &host, Some(SUBPROTOCOL));
        client_async_with_config(request, client_io, None)
            .await
            .unwrap();
        server.await.unwrap().unwrap();
    }

    /// A non-default endpoint port must ride along in the upgrade's Host:
    /// the edge requires a non-empty authority, and an HTTP-aware
    /// intermediary may route on it.
    #[tokio::test]
    async fn client_upgrade_host_carries_a_non_default_port() {
        for (host, port, expected) in [
            (TEST_SNI, 8443u16, format!("{TEST_SNI}:8443")),
            (TEST_SNI, 443, TEST_SNI.into()),
            ("::1", 8443, "[::1]:8443".into()),
            ("::1", 443, "[::1]".into()),
        ] {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (host_tx, host_rx) = tokio::sync::oneshot::channel::<String>();
            let server = tokio::spawn(async move {
                #[allow(clippy::result_large_err)] // Err type fixed by the Callback trait
                let callback = move |request: &Request, mut response: Response| {
                    let host = request
                        .headers()
                        .get(http::header::HOST)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let _ = host_tx.send(host);
                    response
                        .headers_mut()
                        .insert("Sec-WebSocket-Protocol", SUBPROTOCOL.try_into().unwrap());
                    Ok::<_, ErrorResponse>(response)
                };
                tokio_tungstenite::accept_hdr_async(server_io, callback)
                    .await
                    .unwrap();
            });
            client_upgrade(client_io, host, port).await.unwrap();
            assert_eq!(host_rx.await.unwrap(), expected);
            server.await.unwrap();
        }
    }
}
