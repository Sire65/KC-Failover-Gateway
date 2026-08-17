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
