import pg from 'pg';

const { Client } = pg;
const GATEWAY = 'https://kc-failover-gateway.netlify.app';

function response(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*'
    }
  });
}

async function post(path, body) {
  const r = await fetch(GATEWAY + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  const json = await r.json();
  if (!r.ok) throw new Error(`${path} HTTP ${r.status}: ${JSON.stringify(json)}`);
  return json;
}

async function cleanup(connectionString, ids) {
  if (!connectionString || !ids.length) return;
  const c = new Client({ connectionString });
  await c.connect();
  try {
    await c.query('DELETE FROM public.kc_failover_transactions WHERE transaction_id = ANY($1::text[])', [ids]);
  } finally {
    await c.end();
  }
}

export default async () => {
  const run = crypto.randomUUID();
  const registerId = `SUPERGAU_TEST3_${run.slice(0, 8)}`;
  const ids = [1, 2, 3].map(i => `supergau-test3-${run}-${i}`);
  const fakeLocalOnly = `supergau-test3-local-only-${run}`;
  const rows = ids.map((transactionId, i) => ({
    transactionId,
    registerId,
    registerName: 'SUPERGAU_TEST3',
    time: new Date(Date.now() + i).toISOString(),
    recordHash: `hash-${transactionId}`,
    amount: i + 1,
    test: true
  }));
  const connectionString = process.env.NEON_DATABASE_URL || process.env.DATABASE_URL || '';

  try {
    const stored = await post('/sync/batch', { transactions: rows });
    const storedOk = Array.isArray(stored.results) && stored.results.length === 3 && stored.results.every(x => x.status === 'STORED');

    const localIds = [ids[0], ids[1], fakeLocalOnly];
    const reconcile = await post('/sync/reconcile', { registerId, transactionIds: localIds });

    const expectedMissingRemote = reconcile.missingRemote?.length === 1 && reconcile.missingRemote[0] === fakeLocalOnly;
    const expectedMissingLocal = reconcile.missingLocal?.length === 1 && reconcile.missingLocal[0] === ids[2];
    const countsOk = reconcile.remoteCount === 3 && reconcile.localCount === 3;
    const pass = storedOk && expectedMissingRemote && expectedMissingLocal && countsOk;

    return response({
      service: 'KC Failover Gateway',
      test: 'SUPER-GAU-TEST-3-RECONCILIATION-INTEGRITY',
      status: pass ? 'PASS' : 'FAIL',
      registerId,
      checks: {
        threeTransactionsStored: storedOk,
        remoteMissingDetected: expectedMissingRemote,
        localMissingDetected: expectedMissingLocal,
        countsConsistent: countsOk
      },
      reconcile,
      cleanup: 'test transactions removed after execution',
      timestamp: new Date().toISOString()
    }, pass ? 200 : 503);
  } catch (e) {
    return response({
      service: 'KC Failover Gateway',
      test: 'SUPER-GAU-TEST-3-RECONCILIATION-INTEGRITY',
      status: 'FAIL',
      error: e instanceof Error ? e.message : String(e),
      timestamp: new Date().toISOString()
    }, 500);
  } finally {
    try { await cleanup(connectionString, ids); } catch {}
  }
};
