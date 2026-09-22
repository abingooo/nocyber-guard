# NoCyber Guard

NoCyber Guard is a small, transparent instruction-audit gateway for
Sub2API, New API, and other OpenAI-compatible gateways. It sits in front of an
upstream and forwards requests unchanged after the audit decision. The v0.5
default is permissive: only an explicit risk decision blocks a request;
unknown clients, parse failures, and reviewer outages are recorded and passed
through. Three independent asynchronous reviewers can now vote after a
request finishes in parallel. A high-confidence 2/3 reject vote automatically
promotes the prompt hash to the risk library; a high-confidence 2/3 pass vote
promotes it to the trusted library. The first same-kind quorum completes the
job and cancels outstanding calls. Timeout, error, uncertain, low-confidence,
or conflicting votes are non-votes and never promote a rule. Promotions affect
subsequent requests and do not require manual approval.

## Key traceability and rule plaintext

Every observed request records an instance-local HMAC-SHA-256 fingerprint of
its API credential plus a masked hint such as `sk-…A7F2`. The raw credential is
never written to SQLite, logs, responses, or the administrator API. Because the
HMAC uses the instance master key, the same API key can be searched and grouped
inside one Guard installation without becoming a portable cross-instance
identifier. Trusted and risk rules retain the first request-key trace that led
to or later matched the rule; legacy rules fill this metadata on their next
exact match. The normal authenticated administration UI displays the hint and
short fingerprint and supports searching events by either value.

Every rule created since v0.4 stores both the SHA-256 digest and the exact selected
instruction text. The server computes or verifies the digest before writing the
rule. Trusted and risk library pages return and display that plaintext to a
normally signed-in administrator; there is no second administrator key,
password prompt, or separate unlock step.

Databases upgraded from an older release can contain historical hash-only rows
because a SHA-256 digest cannot be reversed. Those rows are visibly marked in
the library and accept a one-time plaintext backfill. Guard also fills the row
automatically when the exact instruction is encountered again and its digest
matches. Request traffic never overwrites plaintext that is already present.
Plaintext is intentionally excluded from ordinary event rows and application
logs.

## Quick start

```sh
# Choose a verified server profile (this example is for ZeusA).
cp deploy/zeusa.env.example .env
# Use deploy/tianliyun.env.example on tianliyun instead.
# Set NCG_UPSTREAM_URL and choose direct values or the documented file mode
# for NCG_MASTER_KEY and NCG_INITIAL_ADMIN_PASSWORD.
mkdir -p /opt/nocyber-guard-main/data
docker compose --env-file .env up -d
curl -fsS http://127.0.0.1:18087/_nocyber/readyz
```

The proxy and administrator ports are controlled by `NCG_PROXY_PORT` and
`NCG_ADMIN_PORT` (the tianliyun example uses `18087` and `19090`). The
container runs as UID/GID `65532`, has
no Linux capabilities, and uses a read-only root filesystem. Persist only the
mounted data directory. Pin a release tag or image digest in production.

`NCG_MASTER_KEY` is used to encrypt local secrets. Generate it outside the
shell history where possible, for example with `openssl rand -hex 32`, and do
not commit the value. `NCG_MASTER_KEY_FILE` and
`NCG_INITIAL_ADMIN_PASSWORD_FILE` are supported for container-mounted secret
files; do not define the corresponding direct variable, even as an empty
string, when using file mode. Local Compose file secrets are bind mounts, so
make their host files owned by UID/GID `65532` with mode `0400`. The initial
administrator password is consumed on first initialization. v0.5 does not
expose a password-change endpoint; changing it later requires a separately
controlled offline administration procedure.

## Put it in front of a gateway

The simplest setup changes the public reverse proxy's upstream from the
gateway to Guard. Keep the gateway's own port reachable only from localhost or
an internal Docker network. See:

- `deploy/nginx-modelport.conf.example` for the existing ModelPort/tianliyun
  layout;
- `deploy/nginx-generic.conf.example` for a generic Sub2API/New API host;
- `deploy/nginx-connect-failover.conf.example` for an optional direct-upstream
  fallback when Guard fails before a request has been sent;
- `deploy/nginx-http-common.conf.example` for the single shared WebSocket map
  that must be included once from Nginx's `http {}` context;
- `deploy/tianliyun.env.example` and `deploy/zeusa.env.example` for verified
  network/port examples.

The strict Nginx examples set `proxy_next_upstream off`. The optional
connect-fallback example uses only `error timeout`: nginx may reach the direct
backup when connecting to Guard fails before it sends the request, but its
default non-idempotent protection prevents a POST from being replayed after
any request bytes were sent. Do not add `non_idempotent` or HTTP response
status codes to that retry policy.

Keep `Upgrade`, `Connection`, `X-Forwarded-*`, request buffering, and long read
timeouts as shown so SSE and WebSocket handshakes remain compatible. v0.5
audits the OpenAI Responses HTTP paths listed in `compatibility.json`; it does
not inspect WebSocket frames or Chat Completions/Messages bodies.

The ModelPort image-site bridge accepts `/image/api-proxy/`; the example
intentionally strips that prefix before forwarding to Guard. It rejects the
invalid no-trailing-slash form so it cannot fall through to the static image
UI or trigger a redirect/replay of a generation POST.

## Docker network modes

For a Compose-managed upstream, put Guard and the gateway on one dedicated
external network and set `NCG_UPSTREAM_URL` to the gateway service name. For
the current tianliyun rehearsal, the upstream is `http://app:8080` on
`modelport-next-egress`; Guard must not join the internal PostgreSQL/Redis
network. Verify the network name and gateway alias before deployment:

```sh
docker network inspect modelport-next-egress
docker inspect modelport-next --format '{{json .NetworkSettings.Networks}}'
```

For a host-loopback upstream, set `NCG_UPSTREAM_URL=http://host.docker.internal:18085`
and add `extra_hosts: ["host.docker.internal:host-gateway"]` to a local override;
do not assume that name is available on every Docker installation.

## Health and failover

The data listener exposes `/_nocyber/healthz` (process liveness) and
`/_nocyber/readyz` (configuration/storage readiness). The admin listener
exposes the same paths. These endpoints are Guard-local and are not forwarded.
Use the readiness endpoint for container orchestration and keep the public
gateway health check separate while testing a cutover.

The authenticated administration event page supports deleting one event or
bulk-cleaning all events/events older than a selected date. Linked blocking
evidence is deleted in the same operation. Trusted and risk rules, AI nodes,
review jobs, and Guard configuration are never part of event cleanup.

There is no automatic bypass from Guard to the upstream. If Guard is down,
Nginx returns an error rather than silently bypassing the audit. To recover,
stop new writes, verify the reason, and manually switch the public proxy back
to the pinned upstream configuration. After Guard has accepted writes, do not
blindly switch databases or replay POSTs; reconcile the audit records first.

## Migrating legacy ModelPort V2 rules

v0.5 intentionally does **not** import ModelPort's PostgreSQL schema, evidence
vault, AI-node credentials, users, or events. The old V2 implementation uses
platform-specific group/profile scopes and encrypted evidence that cannot be
copied safely into an independent product.

`deploy/migrate-modelport-v2.sh` is an optional helper for an operator who has
already created an administrator session. It exports a repeatable-read,
read-only snapshot containing global trusted/risk SHA-256 rows, the three
enabled Codex profiles, and one synchronous AI-node configuration. Scoped
rules are counted and skipped. With an explicit `NCG_ADMIN_COOKIE_FILE`, its
idempotent import and dry-run modes compare that data with Guard; they never
accept, print, or store a password or API key. Review and validate the export
before import, and repeat it immediately before a production cutover.

Because the ModelPort hash tables do not contain reversible instruction text,
v0.5 skips hash-only migration rows instead of creating new incomplete rules.
An operator may add an exact `content` value to a reviewed migration row; the
Guard API verifies it against `sha256` before import. Rules already present in
an upgraded Guard database remain available and can be backfilled as described
above.

The selected AI endpoint URL, model, timeout, and concurrency are transferable;
its credential must be entered separately in Guard. The three asynchronous
nodes are configured through the authenticated `PUT /api/v1/ai-nodes` API;
each node needs a distinct slot (`async_1`, `async_2`, `async_3`), endpoint,
model, and API key. Do not copy
`raw_ciphertext`, `api_key_ciphertext`, evidence vault rows, or foreign-key IDs
from ModelPort.

## Releases and provenance

The GitHub Actions workflow publishes provenance/SBOM metadata for
`linux/amd64` and `linux/arm64` images to GHCR on version tags. Use a tag or
digest from a release, not `latest`. `NOTICE`, `SOURCE_MANIFEST.json`, and the
repository `LICENSE` describe the ModelPort/Sub2API provenance and LGPL terms.
