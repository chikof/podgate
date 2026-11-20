# Middleware `ip_allow_list`

Reference for `src/middleware/ip_allow_list.rs` and `src/client_ip/set.rs`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`). Matches Traefik's `ipAllowList {sourceRange, ipStrategy {depth, excludedIPs, ipv6Subnet}}` (`ipWhiteList`, its deprecated name, is not offered). Caddy spells it as the `remote_ip` and `client_ip` matchers with `not` and `respond 403`.

```json
{
  "name": "office",
  "type": "ip_allow_list",
  "source_range": ["203.0.113.0/24", "198.51.100.7", "2001:db8::/32"],
  "ip_strategy": { "depth": 2, "excluded": ["10.0.0.0/8"], "ipv6_subnet_bits": 64 }
}
```

|Field|Meaning|
|---|---|
|`source_range`|Required, 1 to 4096 CIDR blocks or bare addresses, IPv4 and IPv6 mixed. A bare address is a block as long as the address. An empty list is `invalid_middleware`: an allow list that admits nobody is a mistake, use `respond` for a closed route.|
|`ip_strategy.depth`|Optional, at least 1. Which address of the forwarded chain is the client, counted from the right after `excluded` addresses are removed (`1` is the last).|
|`ip_strategy.excluded`|Optional, at most 64 blocks or addresses. Skipped while walking the chain from the right.|
|`ip_strategy.ipv6_subnet_bits`|Optional, 1 to 128. An IPv6 client is replaced by the first address of its `/bits` subnet before the comparison. IPv4 clients are not touched.|

Unknown fields, a bad CIDR, `depth: 0` and `ipv6_subnet_bits` outside 1 to 128 are `invalid_middleware`, so a typo never leaves a route open or closed by accident.

## Which address is checked

The address is `ClientIp::resolve(view, strategy)` over the request's `ForwardedView` (`docs/ref/client-ip.md`). The middleware never reads `X-Forwarded-For` itself.

- **No `ip_strategy`.** The entry point's own decision: the connection's peer, or, when the entry point's `forwarded_headers` trusts that peer, the first untrusted address from the right of the chain it sent.
- **`depth` and `excluded`.** They pick an address from the chain a trusted peer sent. A peer the entry point does not trust has no chain: its `X-Forwarded-For`, `X-Real-IP` and `Forwarded` were removed before routing, so the checked address is the peer's own whatever the strategy says. A chain that runs out gives the connection's peer.
- **IPv4-mapped IPv6.** `::ffff:203.0.113.9` is `203.0.113.9` on both sides of the comparison: a block `203.0.113.0/24` admits the mapped form, and a block written `::ffff:203.0.113.0/120` is read as the IPv4 block.
- **No IP peer** (a unix socket) means no address, and the request is refused even by `0.0.0.0/0` and `::/0`.

## The refusal

`403` with `{"error":"forbidden"}` and `content-type: application/json`. It names no range and no address. The check runs in the middleware chain, ahead of revision and server selection and ahead of every admission, so a refused request reaches no upstream and takes no tenant slot, no queue place and no budget.

A deny list is not a second middleware: express it with the `not` matcher and a `respond` middleware.

## Posture changes

`POST /v1/snapshot/plan` lists, under `posture_changes`, for a host that exists on both sides:

|Kind|When|
|---|---|
|`ip_allow_list_removed`|The middleware is no longer used by the app (removed, renamed or replaced by another kind): everyone is admitted.|
|`ip_allow_list_widened`|The new `source_range` contains an address the old one did not: a new block, or a wider one. Splitting or merging blocks that cover the same addresses is not a change.|
|`ip_allow_list_strategy_changed`|`depth`, `excluded` or `ipv6_subnet_bits` differs: another address of the request is checked, which can admit clients the old strategy refused.|

Narrowing a range lists nothing.

## `CidrSet`

`client_ip::set::CidrSet` is the shared type for allow lists, here and in the L4 middleware. It holds blocks as sorted, merged ranges per address family, so a lookup is one binary search. It uses no HTTP type.

|Call|Meaning|
|---|---|
|`CidrSet::new(blocks)`|Builds the set from `Cidr` values (`Cidr::from_str` or serde).|
|`contains(addr)`|Whether `addr` is in some block; an IPv4-mapped IPv6 address is looked up as IPv4.|
|`covers(&Cidr)`|Whether every address of a block is in the set, however many blocks it takes.|
|`covers_all(&CidrSet)`|Whether the other set lets in nothing this one does not (the widening test).|
|`blocks()`, `is_empty()`|The blocks as given.|
