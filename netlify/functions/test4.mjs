const GATEWAY = 'https://kc-failover-gateway.netlify.app';
const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };

async function jfetch(path, options = {}) {
  const res = await fetch(GATEWAY + path, { ...options, headers: { 'content-type': 'application/json', ...(options.headers || {}) } });
  let body = {};
  try { body = await res.json(); } catch {}
  return { res, body };
}

export default async () => {
  const run = crypto.randomUUID();
  const registerId = `SUPERGAU_TEST4_${run.slice(0,8)}`;
  const baseId = `supergau-test4-base-${run}`;
  const newId1 = `supergau-test4-new1-${run}`;
  const newId2 = `supergau-test4-new2-${run}`;
  const now = new Date().toISOString();
  const base = { transactionId: baseId, registerId, registerName: 'SUPERGAU_TEST4', time: now, recordHash: `hash-base-${run}`, amount: 10, test: true };
  const conflict = { ...base, recordHash: `hash-conflict-${run}`, amount: 99 };
  const fresh1 = { transactionId: newId1, registerId, registerName: 'SUPERGAU_TEST4', time: now, recordHash: `hash-new1-${run}`, amount: 20, test: true };
  const fresh2 = { transactionId: newId2, registerId, registerName: 'SUPERGAU_TEST4', time: now, recordHash: `hash-new2-${run}`, amount: 30, test: true };

  const out = {
    service: 'KC Failover Gateway',
    test: 'SUPER-GAU-TEST-4-MIXED-BATCH-CONFLICT-RECOVERY',
    status: 'FAIL',
    registerId,
    checks: {},
    details: {},
    timestamp: new Date().toISOString()
  };

  try {
    const seed = await jfetch('/sync/batch', { method: 'POST', body: JSON.stringify({ transactions: [base] }) });
    out.details.seed = seed.body;
    out.checks.seedStored = seed.res.ok && seed.body?.results?.[0]?.status === 'STORED';

    const mixed = await jfetch('/sync/batch', { method: 'POST', body: JSON.stringify({ transactions: [conflict, fresh1, fresh2] }) });
    out.details.mixedBatch = mixed.body;
    const statuses = Object.fromEntries((mixed.body?.results || []).map(x => [x.transactionId, x.status]));
    out.checks.partialResponse = mixed.res.status === 207 && mixed.body?.status === 'PARTIAL';
    out.checks.conflictDetected = statuses[baseId] === 'CONFLICT';
    out.checks.newRowsStored = statuses[newId1] === 'STORED' && statuses[newId2] === 'STORED';

    const replay = await jfetch('/sync/batch', { method: 'POST', body: JSON.stringify({ transactions: [conflict, fresh1, fresh2] }) });
    out.details.replay = replay.body;
    const replayStatuses = Object.fromEntries((replay.body?.results || []).map(x => [x.transactionId, x.status]));
    out.checks.replayStillConflictsOriginal = replayStatuses[baseId] === 'CONFLICT';
    out.checks.replayIdempotentForNewRows = replayStatuses[newId1] === 'ALREADY_STORED' && replayStatuses[newId2] === 'ALREADY_STORED';

    const restore = await jfetch('/sync/transactions?register_id=' + encodeURIComponent(registerId));
    out.details.restoreCount = restore.body?.count;
    const rows = restore.body?.transactions || [];
    const byId = new Map(rows.map(x => [x.transactionId, x]));
    out.checks.allThreePresent = [baseId, newId1, newId2].every(id => byId.has(id));
    out.checks.originalProtected = byId.get(baseId)?.amount === 10 && byId.get(baseId)?.recordHash === base.recordHash;
    out.checks.noDuplicateCopies = rows.filter(x => [baseId, newId1, newId2].includes(x.transactionId)).length === 3;

    out.status = Object.values(out.checks).every(Boolean) ? 'PASS' : 'FAIL';
    return new Response(JSON.stringify(out, null, 2), { status: out.status === 'PASS' ? 200 : 503, headers: JSON_HEADERS });
  } catch (e) {
    out.error = e instanceof Error ? e.message : String(e);
    return new Response(JSON.stringify(out, null, 2), { status: 500, headers: JSON_HEADERS });
  }
};
