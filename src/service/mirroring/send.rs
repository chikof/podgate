//! The one HTTP/1.1 exchange of a mirrored request: dial, write, read the head of the answer,
//! close.
//!
//! The copy dials through Pingora's `TransportConnector`, the connect path of the proxy, so an
//! `https://` shadow is reached with the transport of its own service (`Upstream::peer`), and it
//! asks the upstream address policy about the exact IP it is about to dial, every time. It speaks
//! HTTP/1.1 by hand with `Connection: close`: every size in the exchange is a number in this
//! file. What the shadow answers is read only as far as the end of its head (at most
//! [`HEAD_LIMIT`] bytes), so it can finish what it was doing, and then dropped with the
//! connection: status and body are never looked at. The whole exchange runs under one timeout.

use std::net::SocketAddr;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use pingora::connectors::TransportConnector;
use pingora::http::RequestHeader;
use pingora::protocols::ALPN;
use pingora::upstreams::peer::HttpPeer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::run::{Dropped, MARKER, Sent, dropped, sent};
use crate::budget::BackgroundSlot;
use crate::fairq::Permit;
use crate::service::Lease;
use crate::service::upstream_policy::UpstreamPolicy;

/// The most copies the process runs at once; the rest are shed.
pub(super) const MAX_IN_FLIGHT: usize = 256;
/// The most bytes of the shadow's answer that are read.
const HEAD_LIMIT: usize = 8 * 1024;

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// Copies running now.
pub(super) fn in_flight() -> usize {
    IN_FLIGHT.load(Ordering::Relaxed)
}

/// One of the process's [`MAX_IN_FLIGHT`] places. Dropping it frees the place.
#[derive(Debug)]
pub(super) struct GlobalSlot(());

/// Adds one to `counter` unless it already is `max`.
fn reserve(counter: &AtomicUsize, max: usize) -> bool {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
            (now < max).then_some(now + 1)
        })
        .is_ok()
}

impl GlobalSlot {
    /// Takes a place, or `None` when all are taken.
    pub(super) fn take() -> Option<Self> {
        reserve(&IN_FLIGHT, MAX_IN_FLIGHT).then_some(Self(()))
    }
}

impl Drop for GlobalSlot {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The request every copy of one request shares: its head and body, and the charge for both.
#[derive(Debug)]
pub(super) struct Copy {
    head: RequestHeader,
    body: Vec<Bytes>,
    _charge: super::run::Reservation,
}

impl Copy {
    pub(super) fn new(
        head: RequestHeader,
        body: Vec<Bytes>,
        charge: super::run::Reservation,
    ) -> Self {
        Self {
            head,
            body,
            _charge: charge,
        }
    }

    pub(super) fn head(&self) -> &RequestHeader {
        &self.head
    }

    fn body_len(&self) -> usize {
        self.body.iter().map(Bytes::len).sum()
    }
}

/// What one copy holds while it runs: its place, its tenant place, its server and its limiter
/// slot. All are given back when the task ends.
pub(super) type Hold = (GlobalSlot, BackgroundSlot, Lease, Permit);

/// One copy of a request, for one mirror.
pub(super) struct Job {
    pub(super) peer: HttpPeer,
    pub(super) copy: std::sync::Arc<Copy>,
    pub(super) timeout: Duration,
    pub(super) policy: UpstreamPolicy,
    pub(super) tenant: Box<str>,
    pub(super) _hold: Hold,
}

static CONNECTOR: LazyLock<TransportConnector> = LazyLock::new(|| TransportConnector::new(None));

/// Runs one copy to its end and counts how it ended. Never fails: there is nobody to tell.
pub(super) async fn run(job: Job) {
    let Job {
        mut peer,
        copy,
        timeout: limit,
        policy,
        tenant,
        _hold,
    } = job;
    let Some(ip) = peer._address.as_inet().map(SocketAddr::ip) else {
        dropped(Dropped::NoServer, 1);
        return;
    };
    // The exact address about to be dialled, every time.
    if policy.check(&tenant, ip).is_err() {
        dropped(Dropped::Policy, 1);
        return;
    }
    peer.options.connection_timeout = Some(limit);
    peer.options.read_timeout = Some(limit);
    peer.options.write_timeout = Some(limit);
    // The exchange below is HTTP/1.1, whatever the service's transport would negotiate for
    // proxied traffic.
    peer.options.alpn = ALPN::H1;
    let exchange = async {
        let mut stream = Box::pin(CONNECTOR.new_stream(&peer))
            .await
            .map_err(|_| ())?;
        talk(&mut stream, &copy).await.map_err(|_| ())
    };
    sent(match timeout(limit, exchange).await {
        Ok(Ok(())) => Sent::Ok,
        Ok(Err(())) => Sent::Error,
        Err(_) => Sent::Timeout,
    });
}

/// The request head as bytes: the copy's own headers, then the marker, the length and
/// `Connection: close`.
fn head_bytes(copy: &Copy) -> Vec<u8> {
    let request = &copy.head;
    let target = request
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(request.method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in &request.headers {
        if name.as_str() == MARKER {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let length = copy.body_len();
    out.extend_from_slice(format!("{MARKER}: 1\r\nConnection: close\r\n").as_bytes());
    if length > 0 || matches!(request.method.as_str(), "POST" | "PUT" | "PATCH") {
        out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Writes the copy to `stream`, then reads the shadow's answer up to the end of its head.
async fn talk<S>(stream: &mut S, copy: &Copy) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&head_bytes(copy)).await?;
    for block in &copy.body {
        stream.write_all(block).await?;
    }
    stream.flush().await?;
    let mut buffer = [0_u8; 1024];
    let mut seen = 0_usize;
    let mut tail = [0_u8; 4];
    while seen < HEAD_LIMIT {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return if seen > 0 {
                Ok(())
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            };
        }
        for byte in &buffer[..read] {
            tail.rotate_left(1);
            tail[3] = *byte;
            if tail == *b"\r\n\r\n" {
                return Ok(());
            }
        }
        seen += read;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, AtomicUsize};

    use tokio::net::TcpListener;

    use super::*;
    use crate::budget::Budgets;
    use crate::fairq::Backends;
    use crate::service::Service;
    use podgate_model::{Budget, Declared};

    fn copy(method: &str, headers: &[(&str, &str)], body: &[&[u8]]) -> Copy {
        let mut head = RequestHeader::build(method, b"/x?y=1", None).expect("request");
        for (name, value) in headers {
            head.insert_header(name.to_string(), *value)
                .expect("header");
        }
        let tenant = Budgets::new().tenant(
            "t",
            Budget {
                max_inflight: 1,
                max_buffer_bytes: 1 << 20,
            },
        );
        let charge = super::super::run::Reservation::new(&tenant, 1).expect("charge");
        Copy::new(
            head,
            body.iter()
                .map(|part| Bytes::copy_from_slice(part))
                .collect(),
            charge,
        )
    }

    #[test]
    fn mirror_marker_header_is_written_once_with_the_length_and_connection_close() {
        let bytes = head_bytes(&copy("POST", &[("host", "a.test")], &[b"ab", b"cde"]));
        let text = String::from_utf8(bytes).expect("utf-8");
        assert_eq!(
            text,
            "POST /x?y=1 HTTP/1.1\r\nhost: a.test\r\nx-podgate-mirrored: 1\r\nConnection: close\r\nContent-Length: 5\r\n\r\n"
        );
        let bodyless = head_bytes(&copy("GET", &[], &[]));
        let text = String::from_utf8(bodyless).expect("utf-8");
        assert!(!text.contains("Content-Length"), "{text}");
        let empty_post = String::from_utf8(head_bytes(&copy("POST", &[], &[]))).expect("utf-8");
        assert!(empty_post.contains("Content-Length: 0\r\n"), "{empty_post}");
        let spoofed = copy("GET", &[(MARKER, "spoofed")], &[]);
        let text = String::from_utf8(head_bytes(&spoofed)).expect("utf-8");
        assert_eq!(text.matches(MARKER).count(), 1, "{text}");
    }

    #[tokio::test]
    async fn mirror_exchange_stops_at_the_end_of_the_answer_head() {
        let (mut near, mut far) = tokio::io::duplex(64 * 1024);
        let shadow = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut chunk = [0_u8; 256];
            let end = loop {
                if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
                let read = far.read(&mut chunk).await.expect("read");
                seen.extend_from_slice(&chunk[..read]);
            };
            // The body follows the head, possibly in the same read.
            while seen.len() < end + 5 {
                let read = far.read(&mut chunk).await.expect("body");
                seen.extend_from_slice(&chunk[..read]);
            }
            far.write_all(b"HTTP/1.1 500 X\r\nContent-Length: 1000\r\n\r\npartial")
                .await
                .expect("answer");
            let body: [u8; 5] = seen[end..end + 5].try_into().expect("five bytes");
            (
                String::from_utf8(seen[..end].to_vec()).expect("utf-8"),
                body,
            )
        });
        let request = copy("POST", &[("host", "a.test")], &[b"ab", b"cde"]);
        talk(&mut near, &request)
            .await
            .expect("a 500 is still an answer");
        let (head, body) = shadow.await.expect("shadow");
        assert!(head.starts_with("POST /x?y=1 HTTP/1.1\r\n"), "{head}");
        assert_eq!(&body, b"abcde");
    }

    #[tokio::test]
    async fn mirror_exchange_without_an_answer_is_an_error() {
        let (mut near, far) = tokio::io::duplex(1024);
        drop(far);
        assert!(talk(&mut near, &copy("GET", &[], &[])).await.is_err());
    }

    fn peer_of(addr: SocketAddr) -> HttpPeer {
        let balancer = Service::compile(
            &serde_json::from_value::<Declared>(serde_json::json!({
                "name": "s", "type": "loadbalancer", "servers": [{"url": format!("http://{addr}")}],
            }))
            .expect("declared"),
            &[],
            None,
            "t",
            &crate::service::resolve::Resolver::default(),
        )
        .expect("service");
        balancer
            .with_upstream(addr, |upstream| upstream.peer())
            .expect("server")
    }

    fn job(addr: SocketAddr, policy: UpstreamPolicy, limit: Duration) -> Job {
        let tenant = Budgets::new().tenant(
            "t",
            Budget {
                max_inflight: 10,
                max_buffer_bytes: 1 << 20,
            },
        );
        let service = Service::compile(
            &serde_json::from_value::<Declared>(serde_json::json!({
                "name": "s", "type": "loadbalancer", "servers": [{"url": format!("http://{addr}")}],
            }))
            .expect("declared"),
            &[],
            None,
            "t",
            &crate::service::resolve::Resolver::default(),
        )
        .expect("service");
        let request = RequestHeader::build("GET", b"/", None).expect("request");
        let (_, lease) = service
            .pick(crate::service::PickCx::new(&request))
            .expect("a server");
        let limiter = Backends::new();
        let table = crate::table::RoutingTable::default();
        Job {
            peer: peer_of(addr),
            copy: Arc::new(copy("GET", &[("host", "a.test")], &[])),
            timeout: limit,
            policy,
            tenant: "t".into(),
            _hold: (
                GlobalSlot::take().expect("a place"),
                tenant.admit_background().expect("a slot"),
                lease,
                limiter.try_admit(&table, addr).expect("a permit"),
            ),
        }
    }

    #[tokio::test]
    async fn mirror_obeys_upstream_policy_before_anything_is_dialled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let dialled = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&dialled);
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        });
        let before = super::super::run::dropped_total(Dropped::Policy);
        let denying = UpstreamPolicy::parse(r#"{"deny": ["127.0.0.0/8"]}"#).expect("policy");
        run(job(addr, denying, Duration::from_secs(2))).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            dialled.load(Ordering::SeqCst),
            0,
            "a refused address is never dialled"
        );
        assert!(super::super::run::dropped_total(Dropped::Policy) > before);
        let allowing = UpstreamPolicy::parse(r#"{"deny": ["10.0.0.0/8"]}"#).expect("policy");
        run(job(addr, allowing, Duration::from_millis(300))).await;
        assert_eq!(
            dialled.load(Ordering::SeqCst),
            1,
            "an allowed address is dialled"
        );
    }

    #[tokio::test]
    async fn mirror_never_slows_primary_a_silent_shadow_ends_at_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let held = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&held);
        tokio::spawn(async move {
            let mut streams = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                streams.push(stream);
            }
        });
        let before = super::super::run::sent_total(Sent::Timeout);
        let started = std::time::Instant::now();
        let policy = UpstreamPolicy::parse(r#"{"deny": ["10.0.0.0/8"]}"#).expect("policy");
        run(job(addr, policy, Duration::from_millis(300))).await;
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(held.load(Ordering::SeqCst), 1);
        assert!(super::super::run::sent_total(Sent::Timeout) > before);
    }

    #[test]
    fn mirror_places_are_bounded() {
        let counter = AtomicUsize::new(0);
        assert!((0..3).all(|_| reserve(&counter, 3)));
        assert!(!reserve(&counter, 3));
        counter.fetch_sub(1, Ordering::SeqCst);
        assert!(reserve(&counter, 3));
    }
}
