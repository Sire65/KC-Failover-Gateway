# KC Failover Gateway

Dual-provider failover gateway for the KC Supabase -> Neon path.

## Provider A - Cloudflare
- Shared gateway entrypoint: `src/worker.js`
- Cloudflare Hyperdrive binding: `HYPERDRIVE`
- Current production URL: `https://kc-failover-gateway.ha-joko.workers.dev`

## Provider B - Netlify
- Adapter: `netlify/functions/gateway.mjs`
- Deployment configuration: `netlify.toml`
- The adapter reuses the same `src/worker.js`, so both providers expose the same API contract.
- Required Netlify environment variables:
  - `SUPABASE_URL`
  - `SUPABASE_PUBLISHABLE_KEY`
  - `NEON_DATABASE_URL` (Neon connection string; keep TLS/SSL enabled in the connection string)
- Intended site name: `kc-failover-gateway-b` when available.

## Failover behavior
The POS normally uses provider A. A client-side circuit breaker automatically retries against provider B if A is unavailable. If both gateways are unavailable, the encrypted local IndexedDB queue remains authoritative until one provider returns, after which replay and reconciliation run automatically.

## Server scenarios
1. Supabase simulated down -> Neon read/write probe -> Supabase recovery.
2. Neon simulated down -> Supabase remains active.
3. Supabase and Neon simulated down -> gateway routes to `LOCAL_QUEUE` requirement.

## Regression
GitHub Actions checks the shared Cloudflare/Netlify module contract and syntax. Client/device scenarios (offline POS, replacement device, power loss and reconciliation) are validated separately against the KC MarktKasse implementation. The gateway does not claim real hardware tests as passed by itself.
