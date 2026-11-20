//! A backend with a fixed latency and a fixed capacity, for `scripts/load-fairness.sh`.
//!
//! `slow_upstream <addr> <latency_ms> <capacity>` answers every `GET` with `200 ok` after
//! `latency_ms`, serving at most `capacity` requests at once; the rest wait their turn, so its
//! latency grows once the offered concurrency passes `capacity`, like a real saturated backend.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";

async fn serve(mut stream: TcpStream, latency: Duration, capacity: Arc<Semaphore>) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
            let Ok(permit) = capacity.acquire().await else {
                return;
            };
            tokio::time::sleep(latency).await;
            drop(permit);
            if stream.write_all(RESPONSE).await.is_err() {
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
    let mut args = std::env::args().skip(1);
    let (Some(addr), Some(latency_ms), Some(capacity)) = (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: slow_upstream <addr> <latency_ms> <capacity>");
        std::process::exit(2);
    };
    let (Ok(latency_ms), Ok(capacity)) = (latency_ms.parse::<u64>(), capacity.parse::<usize>())
    else {
        eprintln!("latency_ms and capacity must be integers");
        std::process::exit(2);
    };
    let latency = Duration::from_millis(latency_ms);
    let capacity = Arc::new(Semaphore::new(capacity));
    let listener = TcpListener::bind(&addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve(stream, latency, Arc::clone(&capacity)));
    }
}
