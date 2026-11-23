# Middleware `llm_guard`

Reference for the kind in `src/middleware/llm_guard.rs`, with what every guard-calling kind shares in `src/middleware/guard.rs`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`).

A route in front of an LLM can send each prompt, and optionally each answer, to one or more **guard models** in parallel and block the exchange when any guard says so. A blocked request gets `403` and never reaches the model; a blocked answer is replaced by the same `403` and no byte of it reaches the client. A guard that cannot answer **closes the door** unless the author chose otherwise for that guard. This is the guardrail step of an AI gateway (calls to a guard model such as Llama Guard) with a failure that never opens by accident.

```json
{
  "name": "safety",
  "type": "llm_guard",
  "guards": [
    { "name": "llama-guard", "address": "http://10.0.0.9:8080/check", "phases": ["request", "response"] },
    { "name": "pii", "address": "http://10.0.0.10:8080/check", "on_error": "allow" }
  ],
  "timeout_ms": 2000,
  "max_prompt_bytes": 65536,
  "max_response_bytes": 262144
}
```

| Field | Meaning |
|---|---|
| `guards` | Required, one to eight. Each: `name` (`a-z`, `0-9`, `_`, `-`, 32 bytes at most, unique in the middleware), `address`, `phases`, `on_error`, `transport`. |
| `guards[].address` | An absolute `http://` or `https://` URL with an IP literal or a host name, at most 512 bytes, no credentials, no `h2c://`. The path and query are sent as written. Fixed configuration: never derived from the request. Dialled through the upstream address policy on **every** call (see Operator and tenant). |
| `guards[].phases` | What the guard judges: `["request"]` (default), `["response"]` or both. No repeats, not empty. |
| `guards[].on_error` | `deny` (default): a guard that cannot answer is `503`. `allow`: the exchange goes on. `allow` is a posture change (`guard_fail_open`), listed by the plan. |
| `guards[].transport` | Name of a `servers_transport` of the app: CA, server name and client certificate of an `https://` address. The call is HTTP/1.1. A transport with TLS options on an `http://` address is `invalid_middleware`; an undeclared name is `unknown_transport`. |
| `timeout_ms` | One bound for every call of a phase, in milliseconds. Default 2000, 1 to 10000; a call also never runs past `REQUEST_TIMEOUT_SECS`. The guards of a phase run together, so the phase takes about as long as the slowest. |
| `max_prompt_bytes` | The most bytes of request body that are held and judged. Default and maximum 65536. A larger prompt is `413`, never forwarded and never scanned in part. The limit is Pingora's 64 KiB replay buffer, which carries the held body to the model; `buffering` has the same cap. |
| `max_response_bytes` | The most bytes of answer that are held and judged. Default 262144, at most 1048576; needs a guard with the `response` phase. A larger answer is `502`. |
| `max_concurrent` | Calls in flight at once, per guard. Default 64, at most 4096. |

Unknown fields are `invalid_middleware`: a setting is never ignored.

## The guard wire

podgate sends one request per guard per phase:

```
POST <path and query of address> HTTP/1.1
Host: <authority of address>
Connection: close
Content-Type: application/json
Accept: application/json
Content-Length: <n>

{"phase": "request", "text": "<extracted text>"}
```

`phase` is `request` or `response`. `text` is what the guards read:

- **Request.** Every `messages[].content` of the OpenAI chat body that is a string, or the `text` parts of an array, joined with a newline, in message order (every role, the system prompt and tool messages too). `null` or absent content is skipped; image and other non-text parts are ignored. Other fields (`tools`, `functions`, `tool_calls[].function.arguments`, `prompt`, `input`) are **not** read.
- **Response.** Every `choices[].message.content` of the answer, joined per choice with a newline. For an event stream (`Content-Type: text/event-stream`) the `choices[].delta.content` of every `data:` event, joined per choice; `[DONE]` is ignored.

The guard answers `200` and **exactly** one JSON object:

```json
{ "verdict": "allow" }
{ "verdict": "block", "category": "violence", "reason": "rule 7: instructions for harm" }
```

| Field | Rule |
|---|---|
| `verdict` | Required, exactly `allow` or `block` (lower case). |
| `category` | Optional. A short label `[a-z0-9][a-z0-9_.:-]{0,63}`; it is the only thing of the verdict a client sees. Anything else is a failure. |
| `reason` | Optional, at most 1 KiB. For the log only; never sent to the client. |

Anything else is a failure: another status, a redirect, an answer over 4 KiB, a body that is not exactly this object (an unknown field, a repeated field, trailing bytes, an unknown verdict such as `maybe` or `ALLOW`), a head that is not clean HTTP/1.x (two `Content-Length` headers, a content coding, a folded header).

An adapter for guard models that only speak the OpenAI chat API is out of scope; run a thin shim in front. A complete one for a Llama Guard served by an OpenAI-compatible endpoint:

```python
# shim.py: python3 shim.py  (needs no packages)
import json, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

MODEL = "http://127.0.0.1:8000/v1/chat/completions"  # the guard model, OpenAI chat API

class Check(BaseHTTPRequestHandler):
    def do_POST(self):
        asked = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        role = "User" if asked["phase"] == "request" else "Agent"
        chat = {"model": "llama-guard", "temperature": 0,
                "messages": [{"role": "user", "content": f"[{role}] {asked['text']}"}]}
        call = urllib.request.Request(MODEL, json.dumps(chat).encode(),
                                      {"Content-Type": "application/json"})
        with urllib.request.urlopen(call, timeout=1.5) as reply:
            said = json.load(reply)["choices"][0]["message"]["content"].strip()
        # Llama Guard answers "safe", or "unsafe" and a category code on the next line.
        if said.startswith("unsafe"):
            category = said.split("\n")[1].strip().lower() if "\n" in said else "unsafe"
            out = {"verdict": "block", "category": category, "reason": said}
        else:
            out = {"verdict": "allow"}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 8080), Check).serve_forever()
```

Try it by hand: `curl -s -d '{"phase":"request","text":"hello"}' http://127.0.0.1:8080/check`.

## What the client gets

| Case | Answer |
|---|---|
| Every guard allows | The request goes on (the model gets the held body untouched); the answer comes back as it would without the middleware. |
| A guard says `block` | `403 {"error":"blocked by guard","category":"violence"}` (no `category` key when the guard gave none). The other guards of the phase are cancelled: their connections are closed. The reason goes to the log. |
| A guard cannot answer, `on_error: deny` | `503 {"error":"guard unavailable"}`. |
| No room for the call (the guard is at `max_concurrent`, or the tenant's buffer budget is full right now) | `503 {"error":"guard unavailable"}` with `retry-after: 1`; a capacity refusal, which auto-revert does not count. |
| A guard cannot answer, `on_error: allow` | The exchange goes on; a warning names the guard in the log. |
| The request body is not a chat body (not JSON, no `messages` array, a `content` that is not a string or an array of parts, a `Content-Encoding`) | `400 {"error":"unreadable request"}`. A body the guard cannot read is never passed. A request with no body (a `GET`) has nothing to judge and goes on. |
| The prompt is over `max_prompt_bytes` | `413`. |
| The answer is over `max_response_bytes`, or is `2xx` with a body that is not a chat completion, or is encoded | `502` (`{"error":"upstream response too large"}` or `{"error":"unreadable response"}`). Nothing of the answer is sent. |

A block is always `403` and a failure never is, so an operator can tell a verdict from an outage. The access log's `reason` is `guard_blocked`, `guard_unavailable`, `guard_saturated` or `guard_unreadable_response`.

All guards of a phase are asked at the same time. The first refusal, a `block` or a failure of a `deny` guard, is the answer and cancels the rest; waiting for a slower guard to turn a `503` into a `403` would only add latency. A `block` from one guard wins over a failure of an `allow` guard.

## The response phase

An answer can only be judged whole, so a route with a guard on the `response` phase **holds the answer** until it has ended, and the client sees nothing until the guards have answered. Two consequences are on you:

- **Streaming latency is lost.** A `stream: true` answer (an event stream) is held until the stream ends, then sent in one piece. Put the middleware on routes where that is acceptable, or leave `response` off.
- **Only chat routes.** A `2xx` answer without `choices` is `502`. Put the middleware on the chat completions route, not on `/v1/models` or `/v1/embeddings`.

Only a `2xx` that is not a tunnel, to a request that is not a `HEAD`, with a body, is held. An upstream error, a redirect or a `204` passes untouched. The model is asked for an identity-encoded answer (`Accept-Encoding` is removed from the upstream request) so the guard reads what the model said; an answer that is encoded anyway is `502`.

The held answer is judged **raw**: no response hook has run on it. After an allow, the usual hooks run on exactly what was let through, in their usual order: the failed-request recorder, `compress`, `cache`. So compression and the cache work on a guarded route, and a blocked or refused answer is never stored, recorded or compressed. The vendored Pingora hook that makes this possible is section 6 of `docs/ref/pingora-patches.md`.

What is held is bounded and charged: a declared `Content-Length` over `max_response_bytes` is `502` before anything is held; the proxy counts every body chunk before keeping it, and a chunked answer that passes the cap ends with one clean `502`, nothing written, and the charge released at once. The tenant is charged twice the held size (the held chunks and the one copy the guard reads) before the first byte is held.

## Operator and tenant

Guard addresses are tenant configuration, so podgate treats them as untrusted:

- **The upstream address policy** (`docs/ref/upstream-policy.md`) is checked for the calling tenant on the exact IP dialled, on every call. A host name is resolved once per call and never again within it, so the answer cannot change between the check and the dial. Loopback and link-local addresses are denied unless the operator allows them for that tenant; that is also what stops one tenant from naming another tenant's guard: the other tenant's policy does not list it. A refusal counts in `podgate_upstream_refused_total{tenant}` and is a failure of that guard (`on_error`), but it is not counted against the guard's circuit.
- **`max_concurrent`** bounds the calls a guard has in flight.
- **A circuit** per guard: after 5 failed calls in a row the guard is not called for 5 seconds (every request then fails by its `on_error`), then one probe goes through. Calls cancelled because another guard blocked first do not count.
- **The tenant's buffer budget.** Every call is charged before it is made: its own bytes plus 20 KiB for the answer head, the read buffers and the answer. The held prompt (up to `max_prompt_bytes`) is charged before the body is read. A tenant whose `max_buffer_bytes` could never hold one exchange (the held prompt plus a call, or twice the held answer plus a call) has its snapshot refused with `invalid_middleware` naming the tenant and the bytes needed; a budget that is only full right now is a `503` with `retry-after: 1`.

## Logs, metrics, explain, the recorder

podgate never writes a prompt, an answer or extracted text to a log line, a metric label, the failed-request recorder or explain. The log names the app, the guard, the phase and the category. A guard's `reason` is written to the log (at `info`, control characters removed, 200 bytes at most): **a guard that echoes the prompt in its reason puts the prompt in your log.** Keep reasons to rule names.

The prompt is read by the middleware and never reaches the body hooks of the proxy unless every guard allowed it, so a blocked or failed-closed prompt is never fed to the recorder or to a mirror. Explain shows each guard's name, address, phases, `on_error` and limits.

## Plan, posture

The plan (`POST /v1/snapshot/plan`) lists under `posture_changes`:

| `kind` | When |
|---|---|
| `guard_fail_open` | A guard's `on_error` went from `deny` to `allow`. |
| `guard_dropped` | The middleware, a guard, or one of its phases is gone. |
| `guard_moved` | A guard's server or path changed: another decision-maker answers. |
| `upstream_tls_verification_disabled` | A guard's `https://` address is now reached without verifying its certificate. |

A new middleware or a new guard is stricter and lists nothing. Guards are matched by name across a push.

## Not built

- No adapter for guard models that only speak the OpenAI chat API: run a shim like the one above.
- Only the text of `messages[].content` and `choices[].message.content` is judged; tool arguments, `prompt` and `input` are not.
- A prompt over 64 KiB (about 16000 tokens) is refused, not judged.
