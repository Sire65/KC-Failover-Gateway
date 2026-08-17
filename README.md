# KC Failover Gateway

Cloudflare Worker repository for the KC Supabase -> Neon failover path.

Current state:
- Worker entrypoint: `src/worker.js`
- Production branch: `main`
- Cloudflare Hyperdrive binding: `HYPERDRIVE`
- Primary health target: Supabase
- Fallback database: Neon via Hyperdrive
- Safe non-destructive Super-GAU routing tests are executed in GitHub Actions.

Automated server scenarios:
1. Supabase simulated down -> Neon read/write probe -> Supabase recovery.
2. Neon simulated down -> Supabase remains active.
3. Supabase and Neon simulated down -> gateway routes to `LOCAL_QUEUE` requirement.

Client/device scenarios (offline POS, two registers, replacement device, power loss and reconciliation) are validated separately against the KC MarktKasse implementation. The gateway does not claim those client/hardware tests as passed by itself.
