# The Amazon ECS source

Reference for `crates/podgate-provider/src/ecs/`: the provider source that turns running Amazon ECS tasks, whose task definition is labelled for podgate, into apps. The server of each app is the task's own network interface address, and the source follows task changes by polling. It matches Traefik's ECS provider (`clusters`, `autoDiscoverClusters`, `exposedByDefault`, `refreshSeconds`, `region`, labels from the task definition's `dockerLabels`). Caddy has no first-party equivalent.

The labels are the Docker labels of the container definition (`dockerLabels`): they go through the same parser ([`docker::labels::parse`](provider-docker.md#labels) and `assemble`), so every `podgate.*` key means what it means in [the Docker source](provider-docker.md), and the `traefik.*` keys are read too ([Traefik labels](provider-traefik.md)). Only what is ECS's differs: where the server comes from, how the tenant is chosen, and how changes arrive.

## Configuration

```toml
[[source]]
kind = "ecs"
name = "ecs-prod"
region = "eu-west-1"
clusters = ["prod-acme", "prod-globex"]
refresh_secs = 15
tenant_from = "cluster"
cluster_tenants = { prod-acme = "acme", prod-globex = "globex" }
exposed_by_default = false
```

| Key | Default | Meaning |
|---|---|---|
| `region` | `AWS_REGION`, else `AWS_DEFAULT_REGION` | The AWS region. Lowercase letters, digits and `-`; it becomes part of the endpoint's host name and of every signature's scope. |
| `clusters` | `["default"]` | The clusters to read, by name or ARN. |
| `auto_discover` | `false` | Read every cluster of the account and region instead (`ListClusters` on every poll). Excludes `clusters`. |
| `refresh_secs` | `15` | The time between polls. At least `5`: ECS throttles the account's API calls, and a poll makes several. |
| `tenant_from` | `"fixed"` | `"fixed"`, `"cluster"` or `"tag"`: see [Tenants](#tenants). |
| `tenant` | `default` | Under `fixed`, the tenant of every app. Under `cluster`, the tenant of a cluster that `cluster_tenants` does not list (required when `clusters` has such a cluster). Under `tag`, the tenant of a task that names none. |
| `cluster_tenants` | none | `{ prod-acme = "acme" }`: the tenant of a cluster, by name. Only under `tenant_from = "cluster"`, where it is required. With `clusters`, every key must be one of them. |
| `exposed_by_default` | `false` | Whether a container without a `podgate.enable` or `traefik.enable` label counts. `false` in either label always excludes. |
| `network` | `"awsvpc"` | The only value. Tasks reach the proxy over their own network interface; `bridge` and `host` tasks need `ec2 = true`. |
| `ec2` | `false` | Also serve `bridge` and `host` mode tasks, from their container instance's address: see [The address rule](#the-address-rule). |
| `endpoint` | `https://ecs.<region>.amazonaws.com` | The origin of the ECS API: an `http(s)` URL without a path, a query or credentials. For a VPC endpoint or a local test double. China regions (`cn-*`) default to `amazonaws.com.cn`. |
| `ec2_endpoint` | `https://ec2.<region>.amazonaws.com` | The same for the EC2 API; only with `ec2 = true`. |

Unknown keys are errors, so a misspelt `cluster_tenants` cannot move the source's apps to another tenant. **There is no key for credentials**: `access_key_id` and `secret_access_key` are unknown keys and the source refuses to start (the error names the key, never its value). Credentials come from the AWS chain, below, and nowhere in the provider's configuration file.

## Credentials

The source finds credentials the way the AWS SDKs do, in this order, and uses the first step that is set up:

1. **Environment**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, with `AWS_SESSION_TOKEN` for temporary ones. One without the other is an error.
2. **Shared credentials file**: `AWS_SHARED_CREDENTIALS_FILE`, else `~/.aws/credentials`, profile `AWS_PROFILE`, else `default`. A missing file is skipped (an explicit `AWS_PROFILE` makes it an error). It is read again every 15 minutes, so a rotated file is picked up. `~/.aws/config`, `credential_process` and `role_arn` profiles are not read.
3. **Web identity** (EKS, GitHub Actions and the like): `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN` (`AWS_ROLE_SESSION_NAME`, default `podgate`), exchanged at STS `AssumeRoleWithWebIdentity` (`AWS_ENDPOINT_URL_STS` overrides the endpoint).
4. **The ECS task role**: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (read from `169.254.170.2`) or `AWS_CONTAINER_CREDENTIALS_FULL_URI`, with `AWS_CONTAINER_AUTHORIZATION_TOKEN` or `..._TOKEN_FILE` as the `Authorization` header. A full URI over `http` must be a loopback or one of AWS's container credential addresses; anything else must be `https`.
5. **The EC2 instance profile**, over IMDSv2 (a session token first). `AWS_EC2_METADATA_SERVICE_ENDPOINT` overrides the address and `AWS_EC2_METADATA_DISABLED=true` skips the step. IMDSv1 is never used.

A step that is set up but fails (a task role endpoint that answers `403`) ends the chain with that error, so a broken task role is not hidden behind an instance profile. Temporary credentials are fetched again five minutes before they expire. With no step set up, the outage text says where the source looked.

Nothing of a credential is ever in a log line, an outage text, a `Debug` print or an error: the types that hold them print `[redacted]`, and the text of an error answer from AWS (which quotes the canonical request, session token included, when a signature does not match) has every credential of the request replaced by `[redacted]` before it is shortened and shown. The test `ecs_secrets_never_logged` runs every step of the chain and every failure above against a recording logger.

## The IAM policy

The source only reads. This policy is enough:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:ListClusters",
        "ecs:ListTasks",
        "ecs:DescribeTasks",
        "ecs:DescribeTaskDefinition",
        "ecs:DescribeServices"
      ],
      "Resource": "*"
    }
  ]
}
```

`ecs:ListClusters` is needed only for `auto_discover`. With `ec2 = true`, add `ecs:DescribeContainerInstances` and `ec2:DescribeInstances`. (`ecs:DescribeTaskDefinition` and `ecs:ListClusters` do not support resource-level permissions; scope the others to the clusters with `"Resource": "arn:aws:ecs:<region>:<account>:*/<cluster>*"` or a `ecs:cluster` condition if you want to.) A missing permission is an error answer (`AccessDeniedException`), which is an [outage](#polling-reports-and-outages), never an empty cluster.

The client has no way to ask for anything else: `client.rs` has an `Operation` enum with the six ECS calls above, and the EC2 call is `DescribeInstances`. It cannot run, stop or change a task.

## Labels

A container is read when it is exposed: `podgate.enable` (or `traefik.enable`) is not `false`, and either it is `true` or `exposed_by_default` is on. Then its `dockerLabels` are parsed with the Docker labels' rules: any other `podgate.*` key, a value that does not parse, a router without `match`, a name that no label defines: the container is rejected and reported. The daemon behaves the same on unknown fields, so a misspelt label cannot silently turn a rule off.

Differences from Docker:

- `podgate.port` is the container's port. Without it, the one TCP port mapping of the container definition is used; none or several is a rejection with a report.
- `podgate.app` defaults to the ECS service name, else the task definition family (a task started with `RunTask` has no service). In the snapshot the app is called `<source name>-<cluster>.<app>` (`ecs-prod-acme.shop`), so the same service name in two clusters is two apps. The id, without the source prefix, is at most 63 characters of letters, digits, `-`, `_` and `.`.
- `podgate.tenant` is only read under `tenant_from = "tag"`; see [Tenants](#tenants).

## The address rule

A server is `http://<ip>:<port>`, never a value from a label.

- **`awsvpc` mode (Fargate, and EC2 tasks with their own interface).** The IP is the task's `ElasticNetworkInterface` attachment's `privateIPv4Address` (else the container's `networkInterfaces`), the port is the container port. An address that is not IPv4, or no address at all, rejects the container with a report naming the task. A label that names an address, a URL or a `host:port` rejects the container too ([the Docker source](provider-docker.md#the-address-rule) lists what counts).
- **`bridge` and `host` mode.** Such a task has no routable address of its own. By default it is skipped with a report that says so. With `ec2 = true` the server is the private IPv4 address of the container instance's EC2 instance (`DescribeContainerInstances` then EC2 `DescribeInstances`; ECS Anywhere instances have none and are reported) with, in `host` mode, the container port, and in `bridge` mode, the host port the task published the container port on (`networkBindings`; a container port that is not published is a rejection).
- **Serving.** Only tasks whose `lastStatus` and `desiredStatus` are `RUNNING` (`ListTasks` is asked for `RUNNING` only) and whose task `healthStatus` is not `UNHEALTHY` serve. A labelled container serves when it is `RUNNING` and, if its container definition has a `healthCheck`, its `healthStatus` is `HEALTHY`: a task that is starting or failing its check has no server yet and is not reported, because that is the normal course of a deploy. All tasks of one app and revision form its service.

**A task decides nothing about its address, but the account can put it anywhere.** An interface in the VPC can be in any subnet the task's configuration names. The protection is the operator's upstream address policy: the provider checks every server of every app against it in the merge (`upstream_forbidden`, `docs/ref/upstream-policy.md`), per tenant, and the daemon checks every connection it opens. For a cluster per tenant, allow each tenant the subnets of its cluster:

```json
{
  "tenants": {
    "acme":   { "allow": ["10.4.0.0/16"] },
    "globex": { "allow": ["10.5.0.0/16"] }
  }
}
```

## Revisions

One revision `default`. ECS's rolling deployments remove tasks that fail their health checks from the list, so no revision states are produced. A task definition that wants explicit revisions uses `podgate.revision` and `podgate.revision.state` labels, exactly as with Docker labels. The containers of one app and revision must agree on their routing, services and revision state; the oldest task (by `createdAt`, then ARN) is the reference, and one that differs is left out and reported.

`first_seen` of an app is the ECS service's `createdAt` in unix seconds (`DescribeServices`), else the oldest task's `createdAt`; the first value seen stays for as long as the app exists, so a rolling deployment that replaces the oldest task does not make the app younger. It is the backend's own time, never the time of the poll, so a conflict between two apps over one host is decided the same way after every restart of the provider.

## Tenants

- **`fixed`**: every app belongs to `tenant`.
- **`cluster`**: the tenant of a cluster is `cluster_tenants[cluster]`, else `tenant`. That is the operator's decision. A task cannot change it.
- **`tag`**: the app belongs to `tenant` (if set), and the task's `podgate.tenant` resource tag (else its container's `podgate.tenant` label) is only a claim, which the core honours under its trust rule (`docs/ref/provider.md`): only for a tenant whose `label_sources` list this source. The tag is read from `DescribeTasks` with tags included; set `propagateTags` on the service so that the tags of the service reach its tasks.

Whatever the tenant, an app may claim only the hosts the tenant may claim (`foreign_host_claim`), so a label cannot take another tenant's host, and a catch-all follows the core's rule (`catch_all`, `docs/ref/provider.md`).

## Polling, reports and outages

ECS has no event stream, so the source polls every `refresh_secs`. A poll is:

1. `ListClusters` (with `auto_discover`), then per cluster `ListTasks` (`desiredStatus = RUNNING`, in pages of 100) and `DescribeTasks` (in batches of 100, with tags).
2. `DescribeTaskDefinition` for each task definition revision not seen before. A revision never changes, so it is described once while a task uses it.
3. `DescribeServices` (in batches of 10) for the services of the tasks, for the apps' age.
4. With `ec2 = true`, `DescribeContainerInstances` and EC2 `DescribeInstances` for the instances of host and bridge tasks.

The first state is sent after the first complete poll. A new state is sent only when it differs from the last one.

**Rate limit.** Calls are spaced at least 100 ms apart, however many clusters there are. A throttled call (`ThrottlingException`, `429`) or a server error is tried up to four times in all, after delays growing from 200 ms with jitter, before the poll fails.

**A failed poll keeps the last state.** If any call fails (the API is unreachable, answers an error, sends something unparsable, or no credentials can be had), the source sends an outage text and keeps the previous state in force: an outage of the ECS API never deletes routes. It then retries after `refresh_secs`, doubling up to one minute while it keeps failing. `print` and `check` run one pass and fail on an outage.

A container that is exposed but cannot be used is named in an outage text sent after the state, and logged:

```
task 4f2a91c0 (cluster prod, container web): unknown label podgate.hots: ...; task 77b1e2aa (cluster prod, container web): no address: the task has no network interface with a private IPv4 address
```

A task that stopped between the list and its description (`MISSING`) is not reported.

## Dependencies

No AWS SDK. Requests are signed by `ring` (already in the build for TLS) through a few dozen lines of Signature Version 4, checked against the published AWS test vector `get-vanilla` and, in the tests, by a fake API that recomputes every signature. `aws-sigv4` was measured and rejected; the figures are in the spec's Decisions.
