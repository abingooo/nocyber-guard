# Changelog

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
