# KC Failover Gateway Security Baseline

The gateway is a privileged boundary between untrusted clients and cloud databases.

## Mandatory production properties

- Sync, reconcile and restore endpoints are authenticated; a client label is never authentication.
- No database credential, Cloudflare token, Supabase secret/service-role key, recovery key or device private key is committed to this repository.
- Per-device credentials are independently revocable.
- Authenticated requests include method, path, body digest, timestamp and unique nonce/request ID in the signed/MACed canonical request.
- Server rejects stale timestamps and replayed nonces.
- Authorization binds a device to its permitted register(s); a caller cannot select another register by changing JSON/query parameters.
- Restore/reconciliation privileges are narrower than normal write privileges.
- Request size/batch limits and rate controls fail closed.
- CORS is allowlisted for browser origins used in production; CORS is not an authentication mechanism.
- Database access uses least-privilege roles and TLS.
- Sensitive payloads should be application-encrypted when confidentiality from storage/database compromise is required.
- Audit logs must not contain secrets, raw authentication material or recovery keys.

## Superadmin recovery

Superadmin recovery credentials are separate from device credentials and are never distributed to POS clients. Recovery supports revocation, replacement-device authorization, key rotation and historical backup decryption by key version. There is no undocumented bypass/backdoor.

## Release gate

Production is not security-green while an unauthenticated caller can write, reconcile, or restore POS journal data.
