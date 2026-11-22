//! In-process integration tests: a real gateway listener, real TCP clients,
//! an in-process echo upstream, an in-process HTTP CONNECT proxy, and an
//! in-process DNS server.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, atomic::Ordering},
};

use gateway::{datapath, metrics::Metrics, state::StateHandle};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

/// A TCP server that echoes everything back.
async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// A minimal DNS server answering every A query with the given address.
async fn spawn_dns_server(answer: [u8; 4]) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if n < 12 {
                continue;
            }
            // Parse the question to find its end and the qtype.
            let mut pos = 12;
            while pos < n && buf[pos] != 0 {
                pos += 1 + buf[pos] as usize;
            }
            let question_end = pos + 5; // null byte + qtype + qclass
            if question_end + 2 > n {
                continue;
            }
            let qtype = u16::from_be_bytes([buf[pos + 1], buf[pos + 2]]);
            let is_a_query = qtype == 1;

            let mut response = Vec::with_capacity(question_end + 16);
            response.extend_from_slice(&buf[0..2]); // id
            response.extend_from_slice(&[0x81, 0x80]); // QR=1 RD=1 RA=1 NOERROR
            response.extend_from_slice(&[0, 1]); // QDCOUNT
            response.extend_from_slice(if is_a_query { &[0, 1] } else { &[0, 0] }); // ANCOUNT
            response.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
            response.extend_from_slice(&buf[12..question_end]);
            if is_a_query {
                response.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to question
                response.extend_from_slice(&[0, 1, 0, 1]); // TYPE A, CLASS IN
                response.extend_from_slice(&[0, 0, 0, 60]); // TTL
                response.extend_from_slice(&[0, 4]); // RDLENGTH
                response.extend_from_slice(&answer);
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    addr
}

/// An HTTP CONNECT proxy that records requested authorities and tunnels
/// everything to `target`.
async fn spawn_connect_proxy(target: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let authorities = Arc::new(Mutex::new(Vec::new()));
    let recorded = authorities.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    let mut chunk = [0u8; 1024];
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert!(n > 0, "proxy client closed early");
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let authority = head
                    .lines()
                    .next()
                    .unwrap()
                    .strip_prefix("CONNECT ")
                    .unwrap()
                    .split(' ')
                    .next()
                    .unwrap()
                    .to_string();
                recorded.lock().unwrap().push(authority);
                let mut upstream = TcpStream::connect(target).await.unwrap();
                stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
            });
        }
    });
    (addr, authorities)
}

/// A TCP server that accepts and holds each connection open without ever
/// writing or closing it.
async fn spawn_silent_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // Hold the socket without reading or closing it, so the
                // peer's FIN is never answered with a close of our own.
                let _held = stream;
                std::future::pending::<()>().await;
            });
        }
    });
    addr
}

struct TestGateway {
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    handle: StateHandle,
    config_path: std::path::PathBuf,
    _dir: tempdir::TempDir,
}

/// Minimal tempdir helper (no external crate): a unique dir removed on drop.
mod tempdir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "{prefix}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

async fn start_gateway(config_yaml: &str) -> TestGateway {
    let dir = tempdir::TempDir::new("gateway-int-test");
    let config_path = dir.path().join("gateway.yaml");
    std::fs::write(&config_path, config_yaml).unwrap();

    let metrics = Arc::new(Metrics::default());
    let (handle, state_rx) = StateHandle::load_initial(&config_path, metrics.clone())
        .await
        .expect("initial config must load");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(datapath::serve(listener, state_rx, metrics.clone()));

    TestGateway {
        addr,
        metrics,
        handle,
        config_path,
        _dir: dir,
    }
}

/// Send a CONNECT request and return (status line, connected stream).
async fn connect(gateway: SocketAddr, authority: &str) -> (String, TcpStream) {
    let mut stream = TcpStream::connect(gateway).await.unwrap();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head.lines().next().unwrap_or_default().to_string();
    (status, stream)
}

async fn assert_echo_roundtrip(stream: &mut TcpStream) {
    // Non-HTTP binary payload: L4 splice must preserve bytes exactly.
    let payload: Vec<u8> = (0..=255u8).chain([0x00, 0xff, 0x0d, 0x0a]).collect();
    stream.write_all(&payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn allowed_ip_route_splices_bytes() {
    let echo = spawn_echo_server().await;
    let gw = start_gateway(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: local
    rules: [{ipv4: 127.0.0.0/8}]
"#,
    )
    .await;

    let (status, mut stream) = connect(gw.addr, &format!("127.0.0.1:{}", echo.port())).await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    assert_echo_roundtrip(&mut stream).await;
    drop(stream);

    assert_eq!(gw.metrics.connections_total.load(Ordering::Relaxed), 1);
    assert_eq!(gw.metrics.denied_no_route_total.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn default_deny_rejects_unmatched_destinations() {
    let echo = spawn_echo_server().await;
    let gw = start_gateway(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: scm
    rules: [{hostname: "*.corp.example"}]
"#,
    )
    .await;

    // Unlisted hostname and unlisted IP are both denied before any dial.
    let (status, _stream) = connect(gw.addr, "evil.example:443").await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    let (status, _stream) = connect(gw.addr, &format!("127.0.0.1:{}", echo.port())).await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    assert_eq!(gw.metrics.denied_no_route_total.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn empty_config_denies_everything() {
    let gw = start_gateway(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
"#,
    )
    .await;
    let (status, _stream) = connect(gw.addr, "anything.example:443").await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
}

#[tokio::test]
async fn port_allowlist_is_enforced() {
    let echo = spawn_echo_server().await;
    let gw = start_gateway(&format!(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: local
    rules: [{{ipv4: 127.0.0.0/8}}]
    ports: [{}]
"#,
        echo.port()
    ))
    .await;

    let (status, mut stream) = connect(gw.addr, &format!("127.0.0.1:{}", echo.port())).await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    assert_echo_roundtrip(&mut stream).await;

    let (status, _stream) = connect(gw.addr, "127.0.0.1:9").await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
}

#[tokio::test]
async fn resolves_hostnames_with_configured_dns() {
    let echo = spawn_echo_server().await;
    let dns = spawn_dns_server([127, 0, 0, 1]).await;
    let gw = start_gateway(&format!(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
dns:
  nameservers: ["{dns}"]
  # The test echo server lives on loopback.
  allow_loopback: true
routes:
  - name: db
    rules: [{{hostname: "db.corp.internal"}}]
"#
    ))
    .await;

    let (status, mut stream) = connect(gw.addr, &format!("db.corp.internal:{}", echo.port())).await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    assert_echo_roundtrip(&mut stream).await;
}

#[tokio::test]
async fn refuses_hostname_resolutions_to_loopback_by_default() {
    let echo = spawn_echo_server().await;
    let dns = spawn_dns_server([127, 0, 0, 1]).await;
    let gw = start_gateway(&format!(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
dns:
  nameservers: ["{dns}"]
routes:
  - name: db
    rules: [{{hostname: "db.corp.internal"}}]
"#
    ))
    .await;

    let (status, _stream) = connect(gw.addr, &format!("db.corp.internal:{}", echo.port())).await;
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    assert_eq!(gw.metrics.dial_errors_total.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn forwards_client_bytes_sent_with_the_connect_head() {
    let echo = spawn_echo_server().await;
    let gw = start_gateway(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: local
    rules: [{ipv4: 127.0.0.0/8}]
"#,
    )
    .await;

    // Head and tunneled payload in a single write: the bytes past the head
    // must reach the upstream once the tunnel is established.
    let payload = b"pipelined \r\n\r\n \x00\xff bytes";
    let mut request = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo.port()).into_bytes();
    request.extend_from_slice(payload);
    let mut stream = TcpStream::connect(gw.addr).await.unwrap();
    stream.write_all(&request).await.unwrap();

    let expected = b"HTTP/1.1 200 Connection established\r\n\r\n";
    let mut response = vec![0u8; expected.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, expected);

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn chains_through_upstream_connect_proxy() {
    let echo = spawn_echo_server().await;
    let (proxy, authorities) = spawn_connect_proxy(echo).await;
    let gw = start_gateway(&format!(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: via-proxy
    rules: [{{hostname: "artifactory.corp.example"}}]
    upstream_proxy:
      addr: "{proxy}"
"#
    ))
    .await;

    let (status, mut stream) = connect(gw.addr, "artifactory.corp.example:8081").await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    assert_echo_roundtrip(&mut stream).await;

    // The original hostname must be preserved in the chained CONNECT.
    assert_eq!(
        authorities.lock().unwrap().as_slice(),
        ["artifactory.corp.example:8081"]
    );
}

#[tokio::test]
async fn abandoned_connect_cancels_stalled_upstream_proxy_dial() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let gw = start_gateway(&format!(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: via-proxy
    rules: [{{hostname: "artifactory.corp.example"}}]
    upstream_proxy:
      addr: "{proxy_addr}"
"#
    ))
    .await;

    let mut client = TcpStream::connect(gw.addr).await.unwrap();
    client
        .write_all(b"CONNECT artifactory.corp.example:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let (mut upstream, _) = proxy.accept().await.unwrap();
    let mut request = [0u8; 1024];
    assert!(upstream.read(&mut request).await.unwrap() > 0);

    #[allow(deprecated)]
    client.set_linger(Some(std::time::Duration::ZERO)).unwrap();
    drop(client);
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        upstream.read(&mut request),
    )
    .await
    .expect("abandoned dial should not wait for the full dial timeout")
    .unwrap();
    assert_eq!(closed, 0);
}

#[tokio::test]
async fn delayed_proxy_preserves_large_optimistic_connect_payload() {
    delayed_proxy_preserves_optimistic_payload(vec![0x5a; 32 * 1024], false).await;
}

#[tokio::test]
async fn delayed_proxy_preserves_write_half_closed_connect_payload() {
    delayed_proxy_preserves_optimistic_payload(b"request".to_vec(), true).await;
}

async fn delayed_proxy_preserves_optimistic_payload(payload: Vec<u8>, half_close: bool) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let expected_payload = payload.clone();
    let proxy_task = tokio::spawn(async move {
        let (mut upstream, _) = proxy.accept().await.unwrap();
        let mut request = [0u8; 1024];
        assert!(upstream.read(&mut request).await.unwrap() > 0);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        upstream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let mut received = vec![0u8; expected_payload.len()];
        upstream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected_payload);
        upstream.write_all(b"response").await.unwrap();
    });
    let gw = start_gateway(&format!(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: via-proxy
    rules: [{{hostname: "artifactory.corp.example"}}]
    upstream_proxy:
      addr: "{proxy_addr}"
"#
    ))
    .await;

    let mut client = TcpStream::connect(gw.addr).await.unwrap();
    client
        .write_all(b"CONNECT artifactory.corp.example:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    client.write_all(&payload).await.unwrap();
    if half_close {
        client.shutdown().await.unwrap();
    }

    let expected_response = b"HTTP/1.1 200 Connection established\r\n\r\nresponse";
    let mut response = vec![0u8; expected_response.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_exact(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response, expected_response);
    proxy_task.await.unwrap();
}

#[tokio::test]
async fn refuses_proxy_hostname_resolutions_to_loopback_by_default() {
    let echo = spawn_echo_server().await;
    let (proxy, authorities) = spawn_connect_proxy(echo).await;
    let dns = spawn_dns_server([127, 0, 0, 1]).await;
    let gw = start_gateway(&format!(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
dns:
  nameservers: ["{dns}"]
routes:
  - name: via-proxy
    rules: [{{hostname: "artifactory.corp.example"}}]
    upstream_proxy:
      addr: "{proxy}"
"#
    ))
    .await;

    let (status, _stream) = connect(gw.addr, "artifactory.corp.example:8081").await;
    assert_eq!(status, "HTTP/1.1 502 Bad Gateway");
    assert!(authorities.lock().unwrap().is_empty());
    assert_eq!(gw.metrics.dial_errors_total.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn rejects_non_connect_requests() {
    let gw = start_gateway(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
"#,
    )
    .await;
    let mut stream = TcpStream::connect(gw.addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 400 Bad Request"), "{head}");
    assert_eq!(gw.metrics.bad_requests_total.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn reaps_half_closed_connection_when_peer_never_closes() {
    let silent = spawn_silent_server().await;
    let gw = start_gateway(
        r#"
schema_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
half_close_timeout: 200ms
routes:
  - name: local
    rules: [{ipv4: 127.0.0.0/8}]
"#,
    )
    .await;

    let (status, mut stream) = connect(gw.addr, &format!("127.0.0.1:{}", silent.port())).await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");
    stream.write_all(b"ping").await.unwrap();
    // The client ends its write side; the silent peer never answers the
    // FIN the splice then sends it.
    stream.shutdown().await.unwrap();

    let eof = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut buf = [0u8; 16];
        stream.read(&mut buf).await.unwrap()
    })
    .await
    .expect("half-closed connection should be reaped");
    assert_eq!(eof, 0);
    assert_eq!(
        gw.metrics.connections_reaped_total.load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn reload_applies_to_new_connections_and_keeps_last_good() {
    let echo = spawn_echo_server().await;
    let allow = r#"
schema_version: 1
config_version: 1
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: local
    rules: [{ipv4: 127.0.0.0/8}]
"#;
    let mut gw = start_gateway(allow).await;
    let authority = format!("127.0.0.1:{}", echo.port());

    let (status, _stream) = connect(gw.addr, &authority).await;
    assert_eq!(status, "HTTP/1.1 200 Connection established");

    // Swap to a config that no longer allows it.
    std::fs::write(
        &gw.config_path,
        r#"
schema_version: 1
config_version: 2
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:1
routes:
  - name: other
    rules: [{hostname: "other.corp.example"}]
"#,
    )
    .unwrap();
    assert!(gw.handle.reload().await.unwrap());
    let (status, _stream) = connect(gw.addr, &authority).await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");

    // A broken config is rejected; the last-known-good (deny) config stays.
    std::fs::write(&gw.config_path, "schema_version: 99\n").unwrap();
    assert!(gw.handle.reload().await.is_err());
    let (status, _stream) = connect(gw.addr, &authority).await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    assert_eq!(gw.metrics.config_version.load(Ordering::Relaxed), 2);
}
