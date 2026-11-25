//! Just enough HTTP/1.1 for CONNECT heads and the admin endpoints.

use std::time::Duration;

use color_eyre::eyre::{self, bail};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::debug;

const MAX_ADMIN_HEAD: usize = 8 * 1024;
const ADMIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Bytes read from a client up to and including the request head; anything
/// past `head_len` arrived before the head was answered and must be kept.
#[derive(Debug)]
pub struct RequestHead {
    pub buf: Vec<u8>,
    pub head_len: usize,
}

impl RequestHead {
    pub fn head(&self) -> &[u8] {
        &self.buf[..self.head_len]
    }

    pub fn leftover(&self) -> &[u8] {
        &self.buf[self.head_len..]
    }
}

/// Read until the `\r\n\r\n` terminating the request head, failing past
/// `max` bytes.
pub async fn read_head<S>(stream: &mut S, max: usize) -> eyre::Result<RequestHead>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut scanned: usize = 0;
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before request head was complete");
        }
        buf.extend_from_slice(&chunk[..n]);
        // Rescan only the new bytes; the separator can span two reads.
        let from = scanned.saturating_sub(3);
        if let Some(pos) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let head_len = from + pos + 4;
            if head_len > max {
                bail!("request head exceeds {max} bytes");
            }
            return Ok(RequestHead { buf, head_len });
        }
        scanned = buf.len();
        if buf.len() > max {
            bail!("request head exceeds {max} bytes");
        }
    }
}

pub struct Response {
    pub status: &'static str,
    pub content_type: &'static str,
    pub body: String,
}

impl Response {
    pub fn text(status: &'static str, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain",
            body: body.to_string(),
        }
    }

    pub fn json(value: &serde_json::Value) -> Self {
        Self {
            status: "200 OK",
            content_type: "application/json",
            body: serde_json::to_string_pretty(value).expect("Value is always serializable") + "\n",
        }
    }

    pub fn prometheus(body: String) -> Self {
        Self {
            status: "200 OK",
            content_type: crate::prometheus::CONTENT_TYPE,
            body,
        }
    }

    pub fn not_found() -> Self {
        Self::text("404 Not Found", "not found\n")
    }
}

/// Serve fixed GET endpoints: `route` maps a request path to its response.
/// Deliberately minimal (no HTTP framework); the admin surface is a handful
/// of paths on a separate listener.
pub async fn serve_admin<F>(listener: TcpListener, route: F) -> eyre::Result<()>
where
    F: Fn(&str) -> Response + Send + Sync + 'static,
{
    let route = std::sync::Arc::new(route);
    loop {
        let (stream, _peer) = crate::net::accept(&listener, "admin").await;
        let route = route.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_admin_request(stream, &*route).await {
                debug!(error = format!("{err:#}"), "admin request error");
            }
        });
    }
}

async fn serve_admin_request(
    mut stream: TcpStream,
    route: &(dyn Fn(&str) -> Response + Send + Sync),
) -> eyre::Result<()> {
    let head = match timeout(
        ADMIN_REQUEST_TIMEOUT,
        read_head(&mut stream, MAX_ADMIN_HEAD),
    )
    .await
    {
        Ok(head) => head?,
        Err(_) => bail!("timed out reading request"),
    };
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    let response = if !matches!(
        request.parse(head.head()),
        Ok(httparse::Status::Complete(_))
    ) {
        Response::text("400 Bad Request", "bad request\n")
    } else if !request
        .method
        .unwrap_or_default()
        .eq_ignore_ascii_case("GET")
    {
        Response::text("405 Method Not Allowed", "method not allowed\n")
    } else {
        route(request.path.unwrap_or_default())
    };
    let wire = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.status,
        response.content_type,
        response.body.len(),
        response.body
    );
    stream.write_all(wire.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn read_head_keeps_leftover_and_splits_across_reads() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(b"CONNECT a:1 HTTP/1.1\r\n\r")
            .await
            .unwrap();
        let read = tokio::spawn(async move { read_head(&mut server, 1024).await.unwrap() });
        tokio::task::yield_now().await;
        client.write_all(b"\nhello").await.unwrap();
        drop(client);
        let head = read.await.unwrap();
        assert_eq!(head.head(), b"CONNECT a:1 HTTP/1.1\r\n\r\n");
        assert_eq!(head.leftover(), b"hello");
    }

    #[tokio::test]
    async fn read_head_rejects_oversized() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&[b'a'; 100]).await.unwrap();
        drop(client);
        let err = read_head(&mut server, 50).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn read_head_rejects_oversized_terminated_head() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&[b'a'; 51]).await.unwrap();
        client.write_all(b"\r\n\r\n").await.unwrap();
        let err = read_head(&mut server, 50).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn admin_routes_get_only() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_admin(listener, |path| match path {
            "/healthz" => Response::text("200 OK", "ok\n"),
            _ => Response::not_found(),
        }));
        for (request, expect) in [
            ("GET /healthz HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK"),
            (
                "POST /healthz HTTP/1.1\r\n\r\n",
                "HTTP/1.1 405 Method Not Allowed",
            ),
            ("garbage\r\n\r\n", "HTTP/1.1 400 Bad Request"),
        ] {
            let mut conn = TcpStream::connect(addr).await.unwrap();
            conn.write_all(request.as_bytes()).await.unwrap();
            let mut out = String::new();
            conn.read_to_string(&mut out).await.unwrap();
            assert!(out.starts_with(expect), "{request:?}: {out}");
        }
    }
}
