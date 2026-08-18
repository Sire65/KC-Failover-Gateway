import pg from 'pg';
const { Client } = pg;

async function withClient(env, fn) {
  if (!env.HYPERDRIVE?.connectionString) throw new Error('SECURITY_STORE_UNAVAILABLE');
  const client = new Client({ connectionString: env.HYPERDRIVE.connectionString });
  try { await client.connect(); return await fn(client); }
  finally { try { await client.end(); } catch {} }
}

export async function resolveDeviceFromStore(env, deviceId) {
  return withClient(env, async client => {
    const r = await client.query(
      `SELECT device_id, register_id, public_jwk, key_version, status
       FROM public.kc_security_devices
       WHERE device_id=$1
       LIMIT 1`, [deviceId]
    );
    if (!r.rows[0]) return null;
    const row = r.rows[0];
    return {
      deviceId: row.device_id,
      registerId: row.register_id,
      publicJwk: row.public_jwk,
      keyVersion: Number(row.key_version),
      status: row.status
    };
  });
}

export async function reserveNonceInStore(env, { deviceId, nonce, timestamp, ttlSeconds=125 }) {
  return withClient(env, async client => {
    const requestDate = new Date(Number(timestamp) * 1000);
    if (!Number.isFinite(requestDate.getTime())) throw new Error('INVALID_TIMESTAMP');
    const expiresDate = new Date(requestDate.getTime() + Number(ttlSeconds) * 1000);
    const r = await client.query(
      `INSERT INTO public.kc_security_nonces(device_id,nonce,request_ts,expires_at)
       VALUES($1,$2,$3,$4)
       ON CONFLICT (device_id,nonce) DO NOTHING
       RETURNING nonce`,
      [deviceId, nonce, requestDate.toISOString(), expiresDate.toISOString()]
    );
    return r.rowCount === 1;
  });
}

export async function consumeRateLimitInStore(env, { deviceId, windowSeconds=60, limit=120 }) {
  const safeWindow = Math.max(10, Math.min(3600, Number(windowSeconds)||60));
  const safeLimit = Math.max(10, Math.min(10000, Number(limit)||120));
  return withClient(env, async client => {
    const r = await client.query(
      `INSERT INTO public.kc_security_rate_limits(device_id, window_start, request_count, updated_at)
       VALUES($1, now(), 1, now())
       ON CONFLICT (device_id) DO UPDATE SET
         window_start = CASE
           WHEN public.kc_security_rate_limits.window_start <= now() - ($2::text || ' seconds')::interval THEN now()
           ELSE public.kc_security_rate_limits.window_start
         END,
         request_count = CASE
           WHEN public.kc_security_rate_limits.window_start <= now() - ($2::text || ' seconds')::interval THEN 1
           ELSE public.kc_security_rate_limits.request_count + 1
         END,
         updated_at = now()
       RETURNING request_count,
         GREATEST(1, CEIL(EXTRACT(EPOCH FROM ((window_start + ($2::text || ' seconds')::interval) - now()))))::int AS retry_after`,
      [deviceId, safeWindow]
    );
    const count = Number(r.rows[0]?.request_count || 0);
    return { ok: count <= safeLimit, count, remaining: Math.max(0, safeLimit-count), retryAfter: Number(r.rows[0]?.retry_after || safeWindow) };
  });
}

export async function purgeExpiredNonces(env, { limit=1000 }={}) {
  const safeLimit = Math.max(1, Math.min(10000, Number(limit)||1000));
  return withClient(env, async client => {
    const r = await client.query(
      `DELETE FROM public.kc_security_nonces
       WHERE ctid IN (
         SELECT ctid FROM public.kc_security_nonces
         WHERE expires_at < now()
         ORDER BY expires_at
         LIMIT $1
       )`, [safeLimit]
    );
    return r.rowCount;
  });
}

export async function purgeStaleRateLimits(env, { olderThanSeconds=3600, limit=1000 }={}) {
  const safeAge = Math.max(120, Math.min(86400, Number(olderThanSeconds)||3600));
  const safeLimit = Math.max(1, Math.min(10000, Number(limit)||1000));
  return withClient(env, async client => {
    const r = await client.query(
      `DELETE FROM public.kc_security_rate_limits
       WHERE ctid IN (
         SELECT ctid FROM public.kc_security_rate_limits
         WHERE updated_at < now() - ($1::text || ' seconds')::interval
         ORDER BY updated_at
         LIMIT $2
       )`, [safeAge, safeLimit]
    );
    return r.rowCount;
  });
}
