import pg from 'pg';

const { Client } = pg;
const GATEWAY = 'https://kc-failover-gateway.netlify.app';
const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'access-control-allow-origin': '*'
};

async function jfetch(path, options = {}) {
  const res = await fetch(GATEWAY + path, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) }
  });
  const body = await res.json();
  return { res, body };
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
  const registerId = `SUPERGAU_TEST5_${run.slice(0,8)}`;
  const now = Date.now();
  const ids = [1,2,3].map(i => `supergau-test5-${run}-${i}`);
  const times = [now - 180000, now - 120000, now - 60000].map(t => new Date(t).toISOString());
  const cutoff = new Date(now - 150000).toISOString();
  const rows = ids.map((transactionId, i) => ({
    transactionId,
    registerId,
    registerName: 'SUPERGAU_TEST5',
    time: times[i],
    recordHash: `hash-${transactionId}`,
    amount: i + 1,
    test: true
  }));
  const connectionString = process.env.NEON_DATABASE_URL || process.env.DATABASE_URL || '';

  const out = {
    service: 'KC Failover Gateway',
    test: 'SUPER-GAU-TEST-5-INCREMENTAL-RESTORE-WINDOW',
    status: 'FAIL',
    registerId,
    cutoff,
    checks: {},
    details: {},
    timestamp: new Date().toISOString()
  };

  try {
    const store = await jfetch('/sync/batch', {
      method: 'POST',
      body: JSON.stringify({ transactions: rows })
    });
    out.details.store = store.body;
    out.checks.allStored = store.res.ok && store.body?.results?.length === 3 && store.body.results.every(x => x.status === 'STORED');

    const full = await jfetch('/sync/transactions?register_id=' + encodeURIComponent(registerId));
    const fullRows = full.body?.transactions || [];
    out.details.fullRestoreCount = full.body?.count;
    out.checks.fullRestoreThree = full.res.ok && full.body?.count === 3;
    out.checks.fullRestoreOrderCorrect = fullRows.length === 3 && fullRows.map(x => x.transactionId).join('|') === ids.join('|');

    const incremental = await jfetch('/sync/transactions?register_id=' + encodeURIComponent(registerId) + '&since=' + encodeURIComponent(cutoff));
    const incRows = incremental.body?.transactions || [];
    out.details.incrementalRestoreCount = incremental.body?.count;
    out.details.incrementalIds = incRows.map(x => x.transactionId);
    out.checks.incrementalReturnsTwo = incremental.res.ok && incremental.body?.count === 2;
    out.checks.oldestExcluded = !incRows.some(x => x.transactionId === ids[0]);
    out.checks.newerTwoPresent = ids.slice(1).every(id => incRows.some(x => x.transactionId === id));
    out.checks.noUnexpectedRows = incRows.every(x => ids.slice(1).includes(x.transactionId));

    const replay = await jfetch('/sync/batch', {
      method: 'POST',
      body: JSON.stringify({ transactions: rows })
    });
    out.details.replay = replay.body;
    out.checks.replayIdempotent = replay.res.ok && replay.body?.results?.length === 3 && replay.body.results.every(x => x.status === 'ALREADY_STORED');

    out.status = Object.values(out.checks).every(Boolean) ? 'PASS' : 'FAIL';
    return new Response(JSON.stringify(out, null, 2), {
      status: out.status === 'PASS' ? 200 : 503,
      headers: JSON_HEADERS
    });
  } catch (e) {
    out.error = e instanceof Error ? e.message : String(e);
    return new Response(JSON.stringify(out, null, 2), { status: 500, headers: JSON_HEADERS });
  } finally {
    try { await cleanup(connectionString, ids); } catch {}
  }
};
