# Middleware `content_guard`

Reference for the kind in `src/middleware/content_guard.rs` (rule engine in `content_guard/rules.rs` and `json.rs`, the operator's classifiers in `content_guard/classifier.rs`). What it shares with `llm_guard` is in `src/middleware/guard.rs`; the held response is vendored Pingora patch 6 (`docs/ref/pingora-patches.md`). The model it plugs into is in `docs/architecture.md` (`### Middlewares`).

A route can scan request and response bodies for sensitive content with **regex rules** that run inside podgate and with an **NLP classifier** the operator names, and for each match block the exchange or redact the match. A body that cannot be scanned is **refused**, never passed on: skipping it would be a bypass.

```json
{
  "name": "pii",
  "type": "content_guard",
  "rules": [
    { "name": "email", "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", "phase": "both", "action": "redact", "category": "pii" },
    { "name": "ssn", "pattern": "\\d{3}-\\d{2}-\\d{4}", "action": "block", "category": "ssn" }
  ],
  "classifier": { "name": "toxicity", "phase": "request", "on_error": "deny" },
  "max_body_bytes": 65536
}
```

| Field | Meaning |
|---|---|
| `rules` | At most 64, run in declaration order. At least one rule or a `classifier` is required. |
| `rules[].name` | `a-z`, `0-9`, `_`, `-`, 32 bytes at most, unique. It is printed in `[redacted:<name>]`. |
| `rules[].pattern` | A [`regex` crate](https://docs.rs/regex) pattern, at most 1024 bytes, under a compiled-size limit. A pattern that matches the empty string is refused. |
| `rules[].phase` | `request`, `response` or `both` (default). |
| `rules[].action` | `block` or `redact`. No default: a typo never weakens a rule. |
| `rules[].category` | The label a `block` shows the client: `a-z`, `0-9`, `_`, `-`, `.`, 64 bytes at most. Default: the rule's name. |
| `classifier.name` | An entry of the operator's `CONTENT_CLASSIFIERS_FILE` that lists the app's tenant. |
| `classifier.phase` | `request`, `response` or `both` (default). |
| `classifier.on_error` | `deny` (default): a classifier that cannot answer is `503`. `allow`: the exchange goes on. `allow` is a posture change (`guard_fail_open`). |
| `max_body_bytes` | The most body bytes that are held and scanned. 1 to 65536, default 65536: a held request body reaches the upstream through Pingora's 64 KiB replay buffer (`buffering` has the same cap). A larger request is `413`, a larger response `502`. |

Unknown fields are `invalid_middleware`: a setting is never ignored.

## What is scanned

The **string values** of a JSON body. Everything else in the document (keys, numbers, whitespace, key order, number spellings such as `1e400` or a 25 digit integer, escapes in untouched strings) is copied byte for byte, so a redaction keeps the JSON valid and changes only the redacted values. A rule sees one value at a time, after JSON escapes are decoded.

- A **key** or a **number** that a rule matches **blocks**, even for a `redact` rule: rewriting it would change the shape or the type of the document.
- A `block` rule always sees the text as it came, so a redaction cannot hide a value from a `block` rule, and one `block` hit anywhere in the body wins over every redaction before it.
- `redact` rules run in declaration order, each on the text the one before left, and only the rules that match the original value run.
- A secret split over two values, or encoded (base64, JSON escaped inside a string), is not found. Run a classifier for what a pattern cannot say.

## Request phase

Before the upstream is chosen or dialled, in this order, each step closing the door:

| Step | Refusal |
|---|---|
| An `Upgrade` or `CONNECT` request (a tunnel carries bytes no scan can see) | `415` |
| No body: nothing to scan | passes |
| `Content-Type` not `application/json` or `+json`, a `charset` other than UTF-8, any `Content-Encoding` other than `identity` | `415` |
| `Content-Length` over `max_body_bytes` | `413` (`417` for `Expect: 100-continue`) |
| The tenant's `max_buffer_bytes` has no room (3 times the body plus 4 KiB, charged before the first byte) | `503` with `retry-after: 1` |
| Slower than 30 seconds to send the body | `408` |
| A chunked body over `max_body_bytes` | `413` |
| Not valid JSON, or not UTF-8 | `400` |
| A rule or the classifier blocks | `403` |

The body is held whole in Pingora's replay buffer, scanned on the blocking pool (a hostile body cannot stall a proxy worker), and then either blocked, passed untouched, or **rewritten**: the upstream gets the redacted body with its exact `Content-Length` (any `Transfer-Encoding` is removed), on a retry too.

A `block` answers `403 {"error":"blocked by content guard","category":"<category>"}` before the upstream is dialled. The body never says what matched, and a matched value is never logged.

## Response phase

The proxy holds the upstream's whole response, raw, before the client sees a byte of it, and before any response hook ran on it (compression, the cache, the failed-request recorder). The stage then:

| Case | Answer |
|---|---|
| `HEAD`, `1xx` other than `101`, `204`, `304`, `Content-Length: 0` | not held, passes |
| `101`, a `Content-Type` that is not JSON, any `Content-Encoding` | `502 {"error":"upstream response cannot be scanned"}` |
| `Content-Length` over `max_body_bytes`, or a chunked body that passes it | `502` |
| The tenant's `max_buffer_bytes` has no room | `503` with `retry-after: 1` |
| Not valid JSON | `502` |
| A rule or the classifier blocks | `403`, the same body as above; **no** byte of the upstream's response, head included, reaches the client |
| Redactions | the redacted body, with an exact `Content-Length` (a chunked response stays chunked) |

An upstream `5xx` is held and scanned like any other answer: an error page can carry the same data. So a route with a response rule turns an upstream error page that is not JSON into `502`; scope the guard to the routes that speak JSON. The upstream is sent no `Accept-Encoding` when a response is scanned, so it answers in the clear; the client's own `Accept-Encoding` is untouched and `compress` still runs, after the scan. Streaming is lost on a guarded route: the response is held until it ends. A response that ends in HTTP/2 trailers is held up to them.

## Classifier

`classifier` names an entry of `CONTENT_CLASSIFIERS_FILE`, read once at startup:

```json
{ "toxicity": { "url": "http://10.0.0.9:8080/classify", "timeout_ms": 2000,
                "tenants": ["acme"], "max_concurrent": 64 } }
```

| Field | Meaning |
|---|---|
| `url` | Required. An absolute `http://` or `https://` URL, at most 512 bytes, no credentials. |
| `timeout_ms` | 1 to 10000, default 2000. |
| `tenants` | Required, 1 to 4096 tenant ids. Only these tenants' apps may name the entry. |
| `max_concurrent` | 1 to 4096, default 64: calls in flight at once, per `content_guard` stage. |

A bad file, or a bad entry, **stops startup** and the message names `CONTENT_CLASSIFIERS_FILE`, the entry and the field. Nothing is contacted at startup. A snapshot names a classifier and never an address, so a tenant cannot aim the proxy at an address of its choosing. An unknown name and a name whose entry does not list the app's tenant are both `invalid_middleware`, with the same message, so a tenant cannot tell which.

No model runs inside podgate: a model brings a runtime, native libraries and memory no budget covers. The classifier is an HTTP service that speaks the **guard wire** of `llm_guard` (`docs/ref/mw-llm-guard.md`, "The guard wire"):

```
POST <path of url> HTTP/1.1
Content-Type: application/json

{"phase": "request", "text": "<the text>"}
```

answered with `200 {"verdict": "allow" | "block", "category"?: "...", "reason"?: "..."}`. The `text` is the string values of the body **after the rules ran** (so redacted text stays redacted), joined with a newline, once per phase, and only when it is not empty. Keys and numbers are not sent. A `block` answers the same `403` as a rule, with the verdict's category (or the classifier's name when it gave none); the `reason` is for the operator's log line of the shared guard code, which carries the category only, and never reaches the client.

The call is the one `llm_guard` makes: dialled through the upstream address policy for the calling tenant on every call (a classifier on a private address needs the operator's `tenants.<id>.allow` entry), one fresh connection, one permit of `max_concurrent`, a circuit (5 failures, 5 seconds, one probe) per stage, and charged to the tenant's `max_buffer_bytes` before a byte is sent. Down, too slow, refused by the policy, circuit open, an answer over 4 KiB, a status other than `200`, anything that is not exactly a verdict, no budget, no permit: `503 {"error":"guard unavailable"}` (with `retry-after: 1` when the cause is capacity). `on_error: "allow"` lets the exchange go on when the call failed; it never turns a `block` verdict into a pass, and it does not apply to a body that cannot be scanned.

## Bounds and safety

- At most 64 rules of at most 1 KiB. Each pattern compiles under a 64 KiB size limit, each set of patterns under 4 MiB, nesting at most 32, and the lazy DFA of a pattern is capped, so a tenant cannot spend memory with a pattern. The engine is linear in the input and has no backtracking: `(a+)+$` on a 64 KiB body costs one pass (`content_guard_pattern_linear_time`). Look-around and back-references do not exist in the `regex` crate and are refused. A Unicode class costs program size: `\d{15}` is over the limit, `[0-9]{15}` is not, so write ASCII classes for long repeats.
- Input is bounded by `max_body_bytes`, output by twice that plus 4 KiB (every match may grow: `[redacted:<name>]` is up to 41 bytes). A rewrite over the output limit is `413` (request) or `502` (response).
- The hold is charged to the tenant's `max_buffer_bytes` before a byte is read: 3 times the body (the held copy, the copy the scan reads and the one it writes) plus 4 KiB. `POST /v1/snapshot` refuses a stage the tenant's whole budget could never hold, naming the numbers; a budget that is only full right now is `503`. The classifier text can be larger than the body when it has many JSON escapes; the compile check judges ordinary text and a call that does not fit is `503`.
- A matched value reaches **no** log line, metric label, recorded failure, mirror copy, cache entry or explain output. Rule names and categories are the only words that do. A failed-request recorder and a mirror copy a guarded request body **after** the chain rewrote it (every other request is copied as the client sent it, as before); a recorder, the compressor and the cache see a response only after the stage let it through. `POST /v1/apps/{app}/failures/{id}/replay` sends the recorded (redacted) body straight to the upstream, never through the guard.

## Plan and explain

`POST /v1/snapshot/plan` lists these `posture_changes`:

| Kind | When |
|---|---|
| `content_guard_removed` | The middleware is gone: bodies are no longer scanned. |
| `content_guard_rule_weakened` | A rule is gone, has another pattern, redacts where it blocked, or runs in fewer phases. A rule that is added or tightened is not listed. |
| `guard_dropped` | The classifier is gone, or judges fewer phases. |
| `guard_moved` | The classifier's address changed. |
| `guard_fail_open` | `on_error` went from `deny` to `allow`. |

Explain shows the rule names, phases, actions and categories, the classifier's name, phase and `on_error`, and `max_body_bytes`. It never shows a pattern.

## Not here

- Streaming: a guarded response is held until it ends.
- Bodies that are not JSON (forms, multipart, XML, gRPC): refused, not scanned. Put the guard on the routes that speak JSON.
- Secrets split across values, encoded, or in keys and numbers beyond what a block can say (see What is scanned).
- A private CA for an `https://` classifier: the default trust anchors are used.
- A model inside podgate.
