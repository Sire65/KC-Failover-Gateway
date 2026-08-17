# Security Sprint 1 – Gateway Boundary

Acceptance criteria:

- Sync, restore and reconciliation routes fail closed without configured device keys.
- Device requests use HMAC-SHA-256 over method, full path/query, timestamp, nonce and SHA-256 body digest.
- Requests outside the clock-skew window are rejected.
- Replayed nonces are rejected within the active worker isolate; durable cross-isolate replay storage remains a later hardening item.
- Browser origins are allowlisted; wildcard CORS is not emitted by the secure boundary.
- Health and safe Super-GAU diagnostic endpoints remain readable without device credentials.
- No production device secret is committed to Git.
- CI must pass 50+ unit/attack cases, Wrangler dry-run, npm vulnerability audit and CodeQL before merge.
