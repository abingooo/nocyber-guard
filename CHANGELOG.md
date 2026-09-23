# Changelog

## v0.8.3 - 2026-09-23

- Disabled provider-side thinking on the JSON-object fallback so reasoning tokens cannot consume the verdict output budget.
- Increased the reviewer output budget from 300 to 4,096 tokens for compatible gateways that cannot disable thinking.
- Added a third standards-only JSON-object fallback when a strict OpenAI-compatible provider rejects the optional thinking control.
- Reproduced the original `ai_invalid` against the configured DeepSeek node and verified that the corrected request returns a complete four-field verdict.

## v0.8.2 - 2026-09-23

- Added a compatibility parser for common OpenAI-compatible reviewer deviations while preserving the exact four-field JSON parser as the preferred path.
- Accepted a single JSON verdict inside Markdown fences or explanatory text, OpenAI text content blocks, case variations, numeric confidence strings, and non-conflicting extra metadata.
- Kept ambiguous, incomplete, duplicate, invalid-result, non-finite, and out-of-range verdicts fail-open as `ai_invalid`.
- Added regression coverage for both accepted provider formats and rejected ambiguous responses.

## v0.8.1 - 2026-09-23

- Added a hot-reloadable system setting for exact HTTPS origins that may embed the administration console in an iframe.
- Kept clickjacking protection enabled by default; an empty allowlist continues to emit `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- When origins are configured, the CSP lists only those origins and omits the incompatible legacy frame header so modern browsers can enforce the scoped policy.
- Added validation against HTTP origins, wildcards, paths, duplicates, and header-control injection, plus backend and frontend regression coverage.

## v0.8.0 - 2026-09-23

- Added a guarded interactive Linux installer for fresh single-instance deployments with Docker and Compose detection, upstream/network selection, port checks, release resolution, digest pinning, and readiness verification.
- Moved installer-created master keys and administrator passwords to root-managed bind-mounted secret files and kept both Guard listeners on host loopback.
- Added optional verified installation of the restricted host updater and conflict-safe Caddy/Nginx configuration generation or application.
- Added a non-interactive automation contract, installer syntax/contract tests, and public onboarding documentation.

## v0.7.2 - 2026-09-22

- Replaced route-wide overview verification with a lightweight, cached session check so navigation no longer waits for dashboard aggregation.
- Reduced overview database work to one all-time aggregate scan and removed the redundant event count used for recent activity.
- Changed rule-library lists to return metadata only; plaintext is loaded on demand from an authenticated detail endpoint.
- Added event decision/evidence indexes and stale-response guards for event and rule-library navigation.
- Updated the real-container contract test to verify summary-only rule lists and authenticated on-demand plaintext details.

## v0.7.0 - 2026-09-22

- Replaced the desktop sidebar with a compact responsive top navigation and added the NoCyber shield favicon.
- Rebuilt the overview from real SQLite data: twelve-hour request/block trends, audit and AI latency samples, latest activity, configured nodes, and asynchronous rule promotions.
- Made the upstream service URL editable and hot-reloadable for new requests while preserving optimistic concurrency and self-listener validation.
- Fixed stale trusted/risk rows when switching routes and stabilized rule status controls at narrow table widths.
- Removed internal configuration version badges from the administration UI.
- Added an in-console update center backed by a restricted host Unix-socket agent, pinned official image digests, health verification, automatic failed-update rollback, and manual one-click rollback.

## v0.6.0 - 2026-09-22

- Added authenticated deletion for individual audit events and bulk cleanup for all events or events before a selected date.
- Event cleanup atomically removes linked blocking evidence while preserving trusted/risk rules, AI nodes, review jobs, and configuration.
- Added an administration UI cleanup dialog with explicit scope, irreversible-action warning, deletion counts, and a per-event delete action.
- Enabled secure SQLite cleanup with a best-effort truncating WAL checkpoint and regression coverage for storage, API, CSRF, and frontend request contracts.

## v0.5.1 - 2026-09-22

- Reworded the client-facing blocked-request message to: `Your activity may violate our usage policies. Please contact the administrator.`
- Kept the HTTP 403 status, OpenAI-compatible error envelope, and stable `nocyber_guard_blocked` code unchanged.

## v0.5.0 - 2026-09-21

- Added an instance-local HMAC fingerprint and strictly masked hint for request API keys without persisting raw credentials.
- Added key traces to audited and bypass events, event search, event details, review-job recovery, and asynchronous rule promotion.
- Trusted and risk rules now retain their first observed source-key trace; legacy rows are filled on the next exact match.
- Added schema-v5 migration, administration UI columns, copy/search controls, and secret-leak regression coverage.

## v0.4.0 - 2026-09-21

- Added exact plaintext retention to trusted and risk rules, with SHA-256 verification and direct viewing through the normal authenticated administration UI.
- Required plaintext for all newly created manual rules and carried the complete selected field through asynchronous AI promotion without exposing it in ordinary event records or logs.
- Added automatic first-hit backfill and manual backfill for legacy hash-only rules; existing plaintext is never overwritten by request traffic.
- Added schema-v4 upgrades, encrypted in-flight job recovery, API/UI regression coverage, and real-container checks for plaintext persistence.

## v0.3.3 - 2026-09-21

- Fixed synchronous and asynchronous AI node saves by allowlisting only fields accepted by the strict management APIs.
- Changed asynchronous connection tests to use the current form values, including unsaved nodes, while safely reusing a stored API key when the key field is left blank.
- Added frontend request-contract coverage and real-container E2E checks for synchronous save/test, all three asynchronous node saves, unsaved-node tests, and stored-key preservation.

## v0.3.2 - 2026-09-21

- Fixed Guard configuration updates being rejected because response-only asynchronous quorum metadata was sent back to the strict update endpoint.
- Added an explicit editable-field allowlist for configuration writes and regression coverage for all response-only metadata.

## v0.3.1 - 2026-09-17

- Rebuilt the login screen as a responsive NoCyber security-console experience.
- Added a consistent visual system for navigation, status, metrics, charts, forms, tables, drawers, and notifications.
- Restored the missing login, overview, and toast styles that previously caused browser-default rendering.
- Improved desktop, tablet, and mobile layouts without changing proxy, audit, storage, or API behavior.

## v0.3.0 - 2026-09-17

- Changed asynchronous quorum to symmetric `2/3` high-confidence pass or reject promotion.
- Quorum decisions are made as soon as two same-kind valid votes arrive; outstanding calls are cancelled.
- Added encrypted persistent review samples, atomic job claiming, retry backoff, stale-job recovery, and terminal task states.
- Conflicting valid votes never promote a rule; failed, uncertain, low-confidence, and timed-out votes are non-votes.

## v0.2.0 - 2026-09-15

- Added three independently configurable asynchronous OpenAI-compatible review nodes.
- Added concurrent quorum review with automatic `2/3 reject` risk promotion and `3/3 pass` trusted promotion.
- Added durable review jobs, per-node votes, promotion records, idempotency, and hot rule reloads.
- Added authenticated node configuration, connection tests, review-job and vote APIs, and the settings UI.
- Extended the ModelPort migration helper to carry synchronous and asynchronous node metadata without credentials or evidence.
- Preserved the permissive fail-open proxy behavior: asynchronous review never changes the request already in flight.
