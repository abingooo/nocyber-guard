# Changelog

## v0.2.0 - 2026-09-15

- Added three independently configurable asynchronous OpenAI-compatible review nodes.
- Added concurrent quorum review with automatic `2/3 reject` risk promotion and `3/3 pass` trusted promotion.
- Added durable review jobs, per-node votes, promotion records, idempotency, and hot rule reloads.
- Added authenticated node configuration, connection tests, review-job and vote APIs, and the settings UI.
- Extended the ModelPort migration helper to carry synchronous and asynchronous node metadata without credentials or evidence.
- Preserved the permissive fail-open proxy behavior: asynchronous review never changes the request already in flight.
