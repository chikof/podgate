//! The test harness itself: a port taken by another process must not fool `Podgate::start`.
//!
//! Tests run in parallel and pick ports with a probe that releases them again, so another test's
//! proxy can end up on a port a `podgate` was told to use. Pingora retries the bind while the
//! port is busy, and a plain connect succeeds against the squatter, which once let an ACME test
//! read a `503 tenant is over its in-flight limit` from a different test's proxy.

mod common;

use std::net::TcpListener;

use common::{Podgate, Upstream, simple_snapshot};

#[tokio::test]
async fn harness_start_ignores_a_squatted_port() {
    // Plays the other test's proxy: accepts and answers like an over-limit tenant.
    let squatter = TcpListener::bind("127.0.0.1:0").expect("bind squatter");
    let taken = squatter.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in squatter.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0_u8; 512];
            drop(stream.read(&mut buf));
            drop(stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 36\r\n\r\n{\"error\":\"tenant is over its in-flig\"}",
            ));
        }
    });

    let podgate = Podgate::start_on(&[], Some(taken)).await;
    assert_ne!(
        podgate.proxy_addr.port(),
        taken,
        "the harness must move off a port somebody else listens on"
    );
    let upstream = Upstream::start("upstream body").await;
    let pushed = simple_snapshot(1, &[("a.test", upstream.addr)]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "upstream body");
}
