# The `ai_token_limit` middleware

Reference for `src/middleware/ai_token_limit.rs` and its helpers `ai_token_limit/{usage,sse,request}.rs`. A route in front of an OpenAI-compatible model can limit each key by tokens over a calendar minute, hour, day or month, counted from what the model reports it used, streaming responses included. A key whose budget is spent gets `429` before its request reaches the model. It matches the token rate limits of Traefik Hub's AI Gateway. The counter is the one of `quota` (`docs/ref/mw-quota.md`): fixed UTC calendar windows in the shared store, so every node counts one budget.

```json
{
  "name": "tokens", "type": "ai_token_limit",
  "limits": [ { "limit": 100000, "period": "minute" }, { "limit": 5000000, "period": "month" } ],
  "source": { "header": "authorization" },
  "store": "main",
  "on_store_error": "deny",
  "store_timeout_ms": 20,
  "max_prompt_bytes": 65536
}
```

|Field|Meaning|
|---|---|
|`limits`|Required. One to four windows, each `{limit, period}`: `limit` is 1 to 2^40 tokens, `period` is `minute`, `hour`, `day` or `month`, a fixed UTC calendar window. One window per period. A key is refused when any window is spent.|
|`source`|Required. What a request is counted by: `{"ip": {...}}`, `{"header": "<name>"}`, `{"host": true}` or `{"jwt_claim": "<claim>"}`, exactly as for `quota` (`docs/ref/mw-quota.md`, the claim rules included).|
|`store`|Required. The name of a store in the operator's `RATE_LIMIT_STORES_FILE` that the app's tenant may use (`docs/ref/ratelimit-cluster.md`).|
|`on_store_error`|Required: `"allow"` or `"deny"`. There is no default, and absence is `invalid_middleware`.|
|`store_timeout_ms`|Optional, 1 to 200. How long one store call may take. Default: the store entry's `timeout_ms`.|
|`max_prompt_bytes`|Optional, 1 to 65536 (the default). The largest JSON request body the middleware reads. A longer one is `413`.|

There is no node scope and no per-request token cost: a budget that resets when the process restarts is not a budget, and a request is never sized by a guess. A field the middleware does not know is `invalid_middleware`. A chain holds at most one `ai_token_limit` (two would both need the usage chunk the first removes): put several windows in `limits`.

## What is counted, and from where

Tokens come from the model's answer, not from a guess about the request. After the answer ends, the middleware charges the amount to the key's counter in every window.

- A `2xx` answer with a usable `usage` is charged that usage. The chat completions shape has `prompt_tokens`, `completion_tokens` and `total_tokens`; the Responses API shape has `input_tokens`, `output_tokens` and `total_tokens`. A streamed answer is Server-Sent Events: the last data chunk before `[DONE]` carries `usage` (the `response.completed` event carries it under `response` for the Responses API). The largest total any event reports is the one that counts, so a model cannot lower its own count by repeating a smaller one.
- A `usage` is usable when it is an object and the fields in it that are present are integers from 0 to 2^40. A negative number, a fraction, a string, a `null` or a number over 2^40 makes that field unusable. It is never clamped to zero, and a model cannot refund itself by reporting a negative total. With both parts usable the charge is `max(total, prompt + completion)`, so a total below its own parts is raised. With only a usable total it is that total. A charge of 0 is not usable either.
- Anything else on a `2xx` answer (no `usage`, none usable, an answer that is not JSON or events, an answer too long to read, an answer that is encoded) is charged an **estimate**: one token per 4 bytes of the exchange (the request body plus the response body, rounded up, at least 1). `podgate_ai_tokens_estimated_total` counts those answers.
- An answer that is not `2xx` (the model refused or failed) is charged nothing, and so is a request that never reached the model.
- The charge is made when the request ends, whatever ended it: a client that leaves mid-stream is charged what the model had sent.

A concurrent burst can overspend by what is in flight: the check before the model sees only what earlier requests have been charged. Put an `in_flight_req` on the same route to bound it. A client that sends its next request the instant the last answer ends may also see the old remaining count for one store round trip, since the charge is a task of its own.

## Before the model

|Case|Answer|
|---|---|
|Any window has nothing left for the key|`429 {"error":"token budget exceeded"}` with `retry-after` (seconds until every spent window has reset), `x-ratelimit-remaining-tokens: 0`, `x-ratelimit-limit-tokens` and `x-ratelimit-reset-tokens`. No upstream is contacted. It is a capacity refusal, so auto-revert does not count it as a broken deploy.|
|A JSON body over `max_prompt_bytes`|`413` before the store is asked (`417` for `Expect: 100-continue`).|
|The tenant's `max_buffer_bytes` cannot hold the prompt|`503` with `retry-after: 1`. A tenant whose `max_buffer_bytes` is under `max_prompt_bytes` plus 16 KiB can never hold one, and the snapshot is refused with `invalid_middleware`.|
|The store fails|`on_store_error`, below.|

The check takes nothing: it asks whether the key has anything left. Every answer the stage touches says what is left, in the names OpenAI's own limits use: `x-ratelimit-limit-tokens`, `x-ratelimit-remaining-tokens` and `x-ratelimit-reset-tokens`, taken from the window with the least left, as of before this request. An upstream's own `x-ratelimit-*-tokens` headers are replaced.

A JSON request body (`application/json` or `+json`) is held in memory before the model is dialled: it is read whole, charged to the tenant's `max_buffer_bytes` first, and goes to the model through Pingora's 64 KiB replay buffer, which is why `max_prompt_bytes` stops at 65536. A body of another type is not held and not capped; its bytes are counted for the estimate. `Upgrade` and `CONNECT` requests are ignored.

## Streaming

A streamed chat completion reports `usage` only when the request has `stream_options.include_usage: true`. When the request has `"stream": true` and the client did not set it, podgate adds it:

- The edit is surgical. The body is never parsed into a value and written back: only the bytes of `stream_options` change, or `,"stream_options":{"include_usage":true}` goes in before the closing `}`. Key order, number text and every other byte reach the model as the client wrote them. `Content-Length` is fixed.
- The body is left as it is when it is not one JSON object, when it repeats `stream`, `stream_options`, `messages`, `prompt` or `input` (a duplicate could make podgate's view differ from the model's), when it has `input` (the Responses API, which always reports usage in `response.completed`), when `stream_options` is not an object, or when `include_usage` is already `true`.
- The model then sends a final chunk with an empty `choices` and the `usage`. The client did not ask for it, so podgate **removes it** from the answer as it passes. The client sees exactly the chunks it would have seen without podgate. When the client set `include_usage` itself, nothing is removed.
- The scanner reads the stream as it passes, unbuffered. A chunk that ends on an event boundary is forwarded as the same bytes, with no delay. Only a trailing partial event is held until its end, and only when podgate added the option. An event over 16 KiB is forwarded as it is and never the one removed. Other chunks keep the `"usage":null` fields the model gives them when `include_usage` is on: podgate does not re-serialise every event.
- A scanner reads one event only when it holds `"usage"` followed by `{`. A model's text cannot forge one: a quote inside a JSON string is escaped.

A response with a `Content-Length` loses it when the usage chunk may be removed, since the length the model declared is no longer the length sent.

## Compression

The model is asked for `Accept-Encoding: identity`, so it answers plain text that can be counted. The count reads the model's bytes before podgate's compressor (`Kind::response_body_raw`, which runs ahead of the compressor and of every `response_body` hook), and the compressor then encodes for the client from the client's own `Accept-Encoding`. A client that asks for gzip gets a gzip answer that was counted.

A model that answers encoded anyway (`Content-Encoding` other than `identity`) is not inflated: its bytes are counted for the estimate, and if podgate had added `include_usage` the usage chunk reaches the client, because nothing reads that stream. Keep `identity` working on the model.

An `errors` middleware page that replaces a model error never reaches the counting hooks, which matches "a non-`2xx` answer is charged nothing".

## When the store fails

A store error (down, slow, saturated, circuit open, an error reply) is not a verdict:

|`on_store_error`|A request that meets a store error|
|---|---|
|`allow`|Is admitted without the `x-ratelimit-*-tokens` headers, is not counted, and is counted in `podgate_quota_unmetered_total`. A budget that fails open lets a key past its limit while the store is down: alert on that series.|
|`deny`|Is answered `503 {"error":"token budget unavailable"}` with `retry-after: 1`.|

A failure to charge after the answer (the response is already served) counts in `podgate_quota_store_errors_total` and `podgate_quota_unmetered_total` and logs at debug. It cannot deny anything. The store's circuit opens after five errors and probes after five seconds, as for `quota`.

## Together with `llm_guard`

`llm_guard` (`docs/ref/mw-llm-guard.md`) holds the request body before the model and holds the whole answer before the client. The two compose in one chain:

- **Declare `ai_token_limit` first.** A spent key is then refused with `429` before any guard call is paid for (a guard may itself be an LLM). The budget check does not read the body.
- **The request.** Whichever of the two runs second finds the body already held and reads the same replay buffer, which holds the body as the client sent it. The `include_usage` rewrite is made later, as the buffer is sent to the model, so a guard always judges the client's own prompt and never sees `stream_options` podgate added. Each charges the tenant for its view of the held body.
- **The answer.** The guard holds the raw answer. Before it judges, every stage of the chain is shown the complete raw answer through a hook that cannot refuse (`Kind::response_held_seen`), and `ai_token_limit` counts it there. A held answer is therefore charged from its complete body whatever the verdict is: allowed, blocked, the guard unavailable, an answer over `max_response_bytes` (charged the estimate of what the model had sent) or an upstream that died mid-answer. A client that keeps provoking answers the guard blocks cannot use the model without its budget going down. The order of the two stages does not change what is charged, and an answer that is released afterwards is not charged twice.
- A guarded route loses streaming latency: the answer reaches the client in one burst once the guard allows it. `ai_token_limit` itself never asks for a held response.

## Who sets what

The tenant names a store and sets `limits`, `source`, `on_store_error`, `store_timeout_ms` and `max_prompt_bytes`. The store's address, credentials, TLS and the tenants that may use it are the operator's (`RATE_LIMIT_STORES_FILE`); nothing in a snapshot can carry an address. A snapshot that names a store that does not exist, or one the app's tenant is not listed for, is refused with `invalid_middleware` and the same message in both cases. The keys are those of `quota` (`podgate:q:<tenant>:<app>:<middleware>:<fingerprint>:<window id>:<source>`), under the tenant's own prefix; the source is hashed, so no key, address or claim reaches the store. A changed limit applies to the counts already used.

## Metrics

|Series|Meaning|
|---|---|
|`podgate_ai_tokens_total{tenant,app,kind}`|Tokens charged to keys. `kind` is `prompt`, `completion`, `other` (a total the model did not split, or that its parts do not account for) or `estimated`; the four add up to what was charged.|
|`podgate_ai_tokens_estimated_total{tenant,app}`|Answers charged the estimate.|
|`podgate_ai_tokens_refused_total{tenant,app}`|Requests refused with `429` because a key's budget was spent.|

There is no key, model or route label, so an app has six series however many keys call, and a tenant stays under `METRICS_SERIES_PER_TENANT`. The store series of `quota` (`podgate_quota_store_up`, `podgate_quota_store_errors_total`, `podgate_quota_unmetered_total`) count this kind too.

## Posture

`POST /v1/snapshot/plan` lists these under `posture_changes`:

|Kind|When|
|---|---|
|`ai_tokens_removed`|The middleware is gone: nothing counts the route's tokens.|
|`ai_tokens_loosened`|An old window is no longer bounded by some new window of at most its rate (a higher limit, a window gone, a longer period at the same limit; a month counts 31 days).|
|`ai_tokens_source_changed`|Keys are counted by another source, which can let a client leave its count.|
|`ai_tokens_fail_open`|A budget that did not admit requests when its store fails now does (`on_store_error: "allow"`).|

`GET /v1/explain` shows the windows, source, store, `on_store_error`, timeout and `max_prompt_bytes` of the stage.
