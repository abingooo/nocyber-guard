# Changelog

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
