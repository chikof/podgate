//! A backend that is never the limiter, for `scripts/bench-proxies.sh`.
//!
//! `fast_upstream <addr>` answers `GET /` with 100 bytes, `GET /16k` with 16 KiB and
//! `GET /__stats` with the number of connections accepted and requests served so far, so a
//! benchmark can prove that a proxy kept its upstream connections alive. Anything else is `404`.
//! Every response is preformatted, keep-alive HTTP/1.1, `application/octet-stream` (a type no
//! proxy compresses), and answered without any per-request allocation.

use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static REQUESTS: AtomicU64 = AtomicU64::new(0);

const SMALL_LEN: usize = 100;
const LARGE_LEN: usize = 16 * 1024;
const HEAD_END: &[u8] = b"\r\n\r\n";

fn response(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// The request target of the request line that starts `head`.
fn target(head: &[u8]) -> &[u8] {
    let line = head.split(|&byte| byte == b'\r').next().unwrap_or_default();
    line.split(|&byte| byte == b' ').nth(1).unwrap_or_default()
}

async fn serve(mut stream: TcpStream, small: &'static [u8], large: &'static [u8]) {
    CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    if stream.set_nodelay(true).is_err() {
        return;
    }
    let mut seen = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        while let Some(end) = seen.windows(HEAD_END.len()).position(|w| w == HEAD_END) {
            let reply = match target(&seen[..end]) {
                b"/" => small.to_vec(),
                b"/16k" => large.to_vec(),
                b"/__stats" => response(
                    format!(
                        "{} {}\n",
                        CONNECTIONS.load(Ordering::Relaxed),
                        REQUESTS.load(Ordering::Relaxed)
                    )
                    .as_bytes(),
                ),
                _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            };
            seen.drain(..end + HEAD_END.len());
            REQUESTS.fetch_add(1, Ordering::Relaxed);
            if stream.write_all(&reply).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let Some(addr) = std::env::args().nth(1) else {
        eprintln!("usage: fast_upstream <addr>");
        std::process::exit(2);
    };
    // Leaked once at startup: the responses live as long as the process.
    let small: &'static [u8] = Box::leak(response(&[b'x'; SMALL_LEN]).into_boxed_slice());
    let large: &'static [u8] = Box::leak(response(&[b'x'; LARGE_LEN]).into_boxed_slice());
    let listener = TcpListener::bind(&addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve(stream, small, large));
    }
}
