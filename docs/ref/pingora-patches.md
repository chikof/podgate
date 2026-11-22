# Upstream issues for cloudflare/pingora

podgate carries patched copies of two Pingora 0.9.1 crates, wired by `[patch.crates-io]` in `Cargo.toml`: `pingora-proxy` in `vendor/pingora-proxy/` (sections 1 to 3) and `pingora-core` in `vendor/pingora-core/` (sections 4 and 5). Each copy can be dropped only when a Pingora release covers every change in it, so file them together (one issue each, linked).

Reproduce each against the registry crate: `diff -ru ~/.cargo/registry/src/*/pingora-proxy-0.9.1/src vendor/pingora-proxy/src`, and the same for `pingora-core-0.9.1` and `vendor/pingora-core/src`.

---

## 1. HTTP/1 upgrade: a `101` read before the request's end-of-body task closes the tunnel

Found by podgate change 0063, fixed by change 0114 (`vendor/pingora-proxy/src/proxy_h1.rs`).

Version: pingora-proxy 0.9.1. An upgrade `GET` (WebSocket) has no body, so `proxy_handle_downstream` sends `HttpTask::Body(None, true)` before its loop (`proxy_h1.rs`, "retry, send buffer if it exists or body empty"). `proxy_handle_upstream` waits on `read_response_task()` and `rx.recv()` in one `tokio::select!`, which picks a ready arm at random.

If the end task is taken first, `request_done = true` and the `101` resets it to `false`. If an upstream that answers within microseconds makes the `101` be taken first, `request_done` is already `false`; the end task then arrives with `was_upgraded()` true and `if request_done && client_session.was_upgraded() { response_done = true }` ends the loop. The tunnel closes before the first client frame is forwarded. With a local echo server this loses about 10% of connections.

Fix: only `HttpTask::UpgradedBody` (or a dropped sender) should end an upgraded connection; a plain `HttpTask::Body` after the upgrade is the original request's end and should keep `request_done = false`:

```rust
let pre_upgrade_end = matches!(body, Some(HttpTask::Body(..)));
match send_body_to1(client_session, body).await {
    Ok(send_done) => {
        request_done = send_done;
        if request_done && client_session.was_upgraded() {
            if pre_upgrade_end { request_done = false } else { response_done = true }
        }
    }
```

---

## 2. No way to set an upgraded tunnel's read timeout or end it from the application

Added by podgate change 0098 (`proxy_trait.rs`, `proxy_h1.rs`, `lib.rs`).

After a `101`, the upstream read timeout of an HTTP/1 tunnel stays the peer's `read_timeout`, which was chosen for the wait for the response head. A proxy that wants a separate idle timeout for tunnels (WebSockets idle for minutes), a maximum tunnel lifetime, or to close a tunnel whose server was removed has no hook: `client_session.read_timeout` is a field of the upstream session inside `proxy_handle_upstream`, and no `ProxyHttp` callback can reach it or interrupt the loop.

Proposal: an optional callback, called once for an upgrade request, returning the tunnel's limits:

```rust
fn tunnel(&self, session: &Session, ctx: &mut Self::CTX) -> Option<Tunnel> { None }

pub struct Tunnel {
    /// Upstream read timeout once the upgrade succeeded; `None` is no timeout.
    pub read_timeout: Option<Duration>,
    /// `notify_one` ends the upgraded connection.
    pub cancel: Arc<tokio::sync::Notify>,
}
```

`proxy_h1.rs` calls it before the upstream join, switches `client_session.read_timeout` when `was_upgraded()` first becomes true, and adds a `select!` arm on `cancel.notified()` (only while upgraded) that ends the tunnel with a failed upstream task. Default `None` keeps today's behaviour.

---

## 3. HTTP/2: a response that ends in trailers never gives the body filter its end of stream

Added by podgate's fix of task 0052 (`proxy_trait.rs`, `proxy_h2.rs`); found by change 0064.

When an HTTP/2 upstream response ends with a TRAILERS frame, the last DATA frame does not carry END_STREAM, so `response_body_filter` is never called with `end_of_stream = true`. A filter that holds body bytes until the end (a buffering middleware), or an encoder that must be finished (response compression), loses its tail. `response_trailer_filter` cannot help: it can only turn the trailers into body bytes, which drops the trailers (`proxy_h2.rs:993-1021` in 0.9.1).

Proposal: an optional callback called once, before `response_trailer_filter`, when an HTTP/2 upstream response ends in non-empty trailers; what it returns is written as body data ahead of the trailers, which are still sent as trailers:

```rust
fn response_body_before_trailers(
    &self,
    session: &mut Session,
    ctx: &mut Self::CTX,
) -> Result<Option<Bytes>> { Ok(None) }
```

`proxy_h2.rs` (`process_upstream_tasks_h2`): before pushing a `HttpTask::Trailer(Some(_))`, call it and push `HttpTask::Body(Some(body), false)` if it returns bytes. Default `None` keeps today's behaviour. (A cleaner alternative is to call `response_body_filter` with `end_of_stream = true` and an empty chunk before the trailers.)

---

## 4. rustls: no per-peer server certificate verifier

Added by podgate change 0104 (`vendor/pingora-core`: `upstreams/peer.rs`, `connectors/tls/rustls/mod.rs`).

SPIFFE upstreams are identified by a URI SAN (`spiffe://trust-domain/path`), not a DNS name, so the rustls connector's verifier (chain plus hostname, or neither) cannot judge them. With OpenSSL a caller can check the peer after the handshake through `upstream_tls_handshake_complete_hook`, but that hook exists only under `openssl_derived`; the rustls build has no way for a peer to bring its own verification.

Proposal: an optional field on `PeerOptions`, used by the rustls connector in place of the chosen verifier:

```rust
#[cfg(feature = "rustls")]
pub server_cert_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
```

In `connectors/tls/rustls/mod.rs`, after the per-peer config is built: if the peer has a verifier, clone the config (or take the per-peer one) and call `dangerous().set_certificate_verifier(verifier)`. `verify_cert` and `verify_hostname` are then not consulted. Because the connection reuse hash does not cover the verifier, the docs should tell callers to put what the verifier decides on into `group_key` (podgate mixes the trust domain and allowed IDs into it). Default `None` keeps today's behaviour.

---

## 5. Services cannot share a runtime

Added by podgate change 0116 (`vendor/pingora-core`: `server/mod.rs`, `services/mod.rs`, `services/listening.rs`).

`Server::run_forever` builds one tokio runtime per service, with `ServerConf.threads` workers each. A proxy with several listeners that need their own application (podgate: one per entry point, each with its own name, policy and PROXY protocol gate) therefore runs `n` pools of workers. Under load only the pools that have traffic take CPU, but all of them exist, and podgate measured the idle one costing throughput: with an `http` and an `https` entry point on 4 CPUs, 5 of 7 fresh starts made 2 to 3 times as many voluntary context switches per request and ran 12% slower than the same process with the `http` entry point alone (`docs/benchmarks.md`, "One pool for the HTTP entry points").

Proposal: an optional method on `Service` and `ServiceWithDependents`, and a field on `listening::Service`:

```rust
fn runtime_group(&self) -> Option<&str> { None }
```

Services that name the same group run on one runtime, built from the first member's thread count, name and options. `Server::run_forever` keeps a map from group name to the runtime it built and builds a runtime only for a service whose group has none yet; `run_service` takes the runtime instead of building it. Default `None` keeps today's behaviour (a runtime per service). The alternative, one service with many listeners, needs the application to find each connection's listener, and `HttpServerApp::h2_options` and `server_options` do not receive the connection.
