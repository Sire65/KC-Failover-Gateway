# KC Failover Gateway

Cloudflare Worker repository for the KC Supabase -> Neon failover path.

Current bootstrap state:
- Worker entrypoint: `src/worker.js`
- Production branch: `main`
- Cloudflare Hyperdrive binding expected at runtime as `HYPERDRIVE`
- First deployment is a non-destructive binding/health test only

The initial Worker performs no database writes. It only reports whether the Hyperdrive binding is available.
