# Deployment runbook

## Prepare

1. Choose a pinned GHCR release tag or digest and copy the matching environment
   example. Do not put a populated `.env` in Git.
2. Verify the upstream container alias and external network with
   `docker inspect` and `docker network inspect`.
3. Create the data directory for container UID/GID 65532. On tianliyun:

   ```sh
   install -d -m 0700 -o 65532 -g 65532 /data/nocyber-guard/data
   cp deploy/tianliyun.env.example /data/nocyber-guard/.env
   ```

4. Set a stable `NCG_MASTER_KEY` and a one-time administrator password in the
   server-local `.env`, then validate and start:

   ```sh
   docker compose --env-file /data/nocyber-guard/.env config --quiet
   docker compose --env-file /data/nocyber-guard/.env pull
   docker compose --env-file /data/nocyber-guard/.env up -d
   curl -fsS http://127.0.0.1:18087/_nocyber/readyz
   ```

   To keep secrets out of the environment, delete the `NCG_MASTER_KEY` and
   `NCG_INITIAL_ADMIN_PASSWORD` lines entirely, set
   `NCG_MASTER_KEY_HOST_FILE` and `NCG_INITIAL_ADMIN_PASSWORD_HOST_FILE`, and
   add the supplied override. Compose implements local file secrets as bind
   mounts, so the host files must be readable by the container's UID/GID
   `65532` without being world-readable:

   ```sh
   chown 65532:65532 /path/to/ncg_master_key /path/to/ncg_initial_admin_password
   chmod 0400 /path/to/ncg_master_key /path/to/ncg_initial_admin_password
   docker compose -f docker-compose.yml \
     -f deploy/docker-compose.secrets.yml.example \
     --env-file .env up -d
   ```

   The direct and file forms are mutually exclusive. An empty direct value
   still takes precedence inside the application, so never leave `KEY=` or
   `PASSWORD=` placeholders in a file-mode environment.

The current tianliyun values are proxy `127.0.0.1:18087`, admin
`127.0.0.1:19090`, upstream `http://app:8080`, and external network
`modelport-next-egress`. When Nginx reaches the published Guard port, its
peer as seen inside the container is the network gateway `172.21.0.1`; keep
that CIDR exact rather than trusting the whole subnet. Port `18086` is currently assigned to
`modelport-batch-patch`, so it must not be reused. Re-check all values at
deployment time. The admin UI stays
local; reach it with `ssh -L 19090:127.0.0.1:19090 tianliyun`.

On ZeusA, use `zeusa.env.example`. Its verified non-database network is
`zeuszs_upstreams`, where the native Sub2API alias is `zeus-sub2api`. If Caddy
connects directly to Guard over that network, replace the trusted proxy CIDR
with Caddy's current single container address rather than trusting the subnet.

## Nginx cutover

Keep the existing config and checksum before editing. Install the shared
`nginx-http-common.conf.example` once from Nginx's `http {}` context, then
install either the strict transparent example or the optional
connect-fallback example. Do not duplicate the shared map. Then run:

```sh
nginx -t
systemctl reload nginx
curl -fsS https://YOUR_DOMAIN/_nocyber/healthz
```

Both `/image/api-proxy` and `/image/api-proxy/` must be handled before the
static `/image/` location. The invalid no-slash form returns `404` rather than
redirecting and replaying a POST; the upstream `proxy_pass` keeps its trailing
`/` so Guard sees `/v1/...`.
The strict example disables upstream retry. The connect-fallback example uses
only `error timeout`, allowing the direct backup before a request is sent.
Never add `non_idempotent` or HTTP status codes: after any POST bytes reach
Guard, nginx must return the resulting failure without replaying the request.

## Legacy rule transfer

First export a fresh, consistent, read-only snapshot on the ModelPort host:

```sh
sh deploy/migrate-modelport-v2.sh export \
  --source-container modelport-standalone-postgres \
  --source-db modelport --source-user modelport \
  --output /data/nocyber-guard/modelport-v2-rules.json
```

Review the metadata and counts, then run the helper's `validate` mode against
the exported file. Scoped trusted rules are counted and skipped because an
upstream-agnostic Guard cannot preserve a Sub2API group ID before upstream
authentication; historical scoped rows do not abort the export. The file
contains global active trusted hashes, all active risk hashes, the three
enabled Codex profiles, one synchronous AI-node configuration, and the three
asynchronous quorum-node configurations without keys. Evidence, credentials,
users, events, and foreign IDs are never exported.

Log into the local admin UI first. To create a curl cookie jar without putting
the password in shell history, read it silently and send it over stdin:

```sh
umask 077
read -r -s NCG_LOGIN_PASSWORD
printf '%s' "$NCG_LOGIN_PASSWORD" | jq -Rs '{username:"admin",password:.}' | \
  curl -fsS -c /data/nocyber-guard/admin.cookies \
  -H 'Content-Type: application/json' --data-binary @- \
  http://127.0.0.1:19090/api/v1/auth/login >/dev/null
unset NCG_LOGIN_PASSWORD
```

Run an idempotent dry-run against the current Guard state first by appending
`--dry-run` to the following command. The real import creates missing hashes,
creates or updates the three named profiles, and applies the synchronous and
asynchronous AI-node metadata while preserving any keys already entered in
Guard. Enter all four AI credentials separately before enabling review:

```sh
NCG_ADMIN_COOKIE_FILE=/data/nocyber-guard/admin.cookies \
  sh deploy/migrate-modelport-v2.sh import \
  --input /data/nocyber-guard/modelport-v2-rules.json \
  --guard-url http://127.0.0.1:19090
```

Delete the cookie jar after verification. Re-enter AI endpoint URLs/models and
keys in the UI; no encrypted key is portable from ModelPort.

## Upgrade and rollback

Before an image change, stop Guard and copy its data directory to a timestamped
backup on the same data disk. Update only `NCG_IMAGE`, pull, recreate, and wait
for readiness. Never run `docker compose down -v` against production data.

To roll back an image, restore the previous pinned image reference and run
`docker compose up -d`. Do not use an older binary against a database that it
cannot read; restore the matching stopped-state data backup when required.

For an emergency traffic rollback, restore the previously checksummed Nginx
file so it points at the official upstream (`18085` on the current tianliyun
layout), run `nginx -t`, and reload. Do not automatically replay failed model
POSTs. Keep Guard and its data stopped for diagnosis rather than deleting them.
