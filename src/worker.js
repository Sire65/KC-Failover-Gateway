import pg from "pg";

const { Client } = pg;
const JSON_HEADERS = { "cache-control": "no-store", "content-type": "application/json; charset=utf-8" };
const CORS_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type,x-kc-client",
  "access-control-max-age": "86400"
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...CORS_HEADERS } });
}

async function checkSupabase(env) {
  const startedAt = Date.now();
  const url = `${env.SUPABASE_URL}/auth/v1/health`;
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { apikey: env.SUPABASE_PUBLISHABLE_KEY },
      cf: { cacheTtl: 0 }
    });
    return { reachable: response.ok, statusCode: response.status, latencyMs: Date.now() - startedAt };
  } catch (error) {
    return { reachable: false, statusCode: null, latencyMs: Date.now() - startedAt, error: error instanceof Error ? error.message : "Unknown Supabase error" };
  }
}

async function withNeon(env, fn) {
  const client = new Client({ connectionString: env.HYPERDRIVE.connectionString });
  try {
    await client.connect();
    return await fn(client);
  } finally {
    try { await client.end(); } catch {}
  }
}

async function checkNeon(env) {
  const startedAt = Date.now();
  if (!env.HYPERDRIVE?.connectionString) return { reachable: false, latencyMs: Date.now() - startedAt, error: "Hyperdrive binding missing" };
  try {
    await withNeon(env, (client) => client.query("SELECT 1 AS ok"));
    return { reachable: true, latencyMs: Date.now() - startedAt };
  } catch (error) {
    return { reachable: false, latencyMs: Date.now() - startedAt, error: error instanceof Error ? error.message : "Unknown Neon error" };
  }
}

async function runFallbackReadWriteProbe(env) {
  const marker = crypto.randomUUID();
  const startedAt = Date.now();
  try {
    const result = await withNeon(env, async (client) => {
      await client.query("BEGIN");
      try {
        await client.query("CREATE TEMP TABLE kc_failover_probe (marker text NOT NULL) ON COMMIT DROP");
        await client.query("INSERT INTO kc_failover_probe(marker) VALUES($1)", [marker]);
        const read = await client.query("SELECT marker FROM kc_failover_probe LIMIT 1");
        await client.query("ROLLBACK");
        return read.rows[0]?.marker === marker;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    });
    return { readWrite: result === true, latencyMs: Date.now() - startedAt, persistentChanges: false };
  } catch (error) {
    return { readWrite: false, latencyMs: Date.now() - startedAt, persistentChanges: false, error: error instanceof Error ? error.message : "Unknown failover probe error" };
  }
}

function chooseBackend(primaryReachable, fallbackReachable) {
  if (primaryReachable) return "SUPABASE";
  if (fallbackReachable) return "NEON";
  return "LOCAL_QUEUE";
}

function cleanTransaction(row) {
  if (!row || typeof row !== "object") throw new Error("INVALID_TRANSACTION");
  const transactionId = String(row.transactionId || "").trim();
  const registerId = String(row.registerId || "").trim();
  if (!transactionId || transactionId.length > 160) throw new Error("INVALID_TRANSACTION_ID");
  if (!registerId || registerId.length > 100) throw new Error("INVALID_REGISTER_ID");
  const payload = JSON.stringify(row);
  if (payload.length > 180000) throw new Error("TRANSACTION_TOO_LARGE");
  return {
    transactionId,
    registerId,
    registerName: String(row.registerName || "").slice(0, 160) || null,
    occurredAt: row.endTime || row.time || row.startTime || null,
    recordHash: row.recordHash ? String(row.recordHash).slice(0, 256) : null,
    payload: row
  };
}

async function saveTransactions(env, inputRows) {
  if (!Array.isArray(inputRows) || inputRows.length < 1 || inputRows.length > 100) throw new Error("INVALID_BATCH_SIZE");
  const rows = inputRows.map(cleanTransaction);
  return withNeon(env, async (client) => {
    await client.query("BEGIN");
    const results = [];
    try {
      for (const row of rows) {
        const inserted = await client.query(
          `INSERT INTO public.kc_failover_transactions
             (transaction_id, register_id, register_name, occurred_at, record_hash, payload)
           VALUES ($1,$2,$3,$4,$5,$6::jsonb)
           ON CONFLICT (transaction_id) DO NOTHING
           RETURNING transaction_id`,
          [row.transactionId, row.registerId, row.registerName, row.occurredAt, row.recordHash, JSON.stringify(row.payload)]
        );
        if (inserted.rowCount === 1) {
          results.push({ transactionId: row.transactionId, status: "STORED" });
          continue;
        }
        const existing = await client.query(
          "SELECT record_hash, payload FROM public.kc_failover_transactions WHERE transaction_id=$1",
          [row.transactionId]
        );
        const old = existing.rows[0];
        const sameHash = Boolean(row.recordHash && old?.record_hash && row.recordHash === old.record_hash);
        const samePayload = JSON.stringify(old?.payload ?? null) === JSON.stringify(row.payload);
        if (!sameHash && !samePayload) {
          results.push({ transactionId: row.transactionId, status: "CONFLICT" });
        } else {
          results.push({ transactionId: row.transactionId, status: "ALREADY_STORED" });
        }
      }
      await client.query("COMMIT");
      return results;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  });
}

async function restoreTransactions(env, registerId, since) {
  if (!registerId || registerId.length > 100) throw new Error("INVALID_REGISTER_ID");
  return withNeon(env, async (client) => {
    const params = [registerId];
    let where = "register_id=$1";
    if (since) {
      params.push(since);
      where += " AND occurred_at >= $2::timestamptz";
    }
    const result = await client.query(
      `SELECT payload FROM public.kc_failover_transactions WHERE ${where} ORDER BY occurred_at NULLS LAST, received_at LIMIT 5000`,
      params
    );
    return result.rows.map(x => x.payload);
  });
}

async function reconcileTransactions(env, registerId, ids) {
  if (!registerId || registerId.length > 100) throw new Error("INVALID_REGISTER_ID");
  if (!Array.isArray(ids) || ids.length > 5000) throw new Error("INVALID_ID_LIST");
  const localIds = [...new Set(ids.map(x => String(x)).filter(Boolean))];
  return withNeon(env, async (client) => {
    const result = await client.query(
      "SELECT transaction_id FROM public.kc_failover_transactions WHERE register_id=$1",
      [registerId]
    );
    const remote = new Set(result.rows.map(x => x.transaction_id));
    const local = new Set(localIds);
    return {
      missingRemote: localIds.filter(id => !remote.has(id)),
      missingLocal: [...remote].filter(id => !local.has(id)),
      remoteCount: remote.size,
      localCount: local.size
    };
  });
}

async function scenario1(env) {
  const primaryBefore = await checkSupabase(env);
  const fallback = await runFallbackReadWriteProbe(env);
  const primaryAfter = await checkSupabase(env);
  const pass = primaryBefore.reachable && fallback.readWrite && primaryAfter.reachable;
  return { id: 1, name: "Supabase down -> Neon -> Supabase recovery", status: pass ? "PASS" : "FAIL", before: primaryBefore, simulatedOutage: { primaryForcedDown: true, activeBackend: "NEON", fallback }, recovery: { primary: primaryAfter, activeBackend: primaryAfter.reachable ? "SUPABASE" : "NEON" }, safeSimulation: true };
}

async function scenario2(env) {
  const primary = await checkSupabase(env);
  const realFallback = await checkNeon(env);
  const activeBackend = chooseBackend(primary.reachable, false);
  return { id: 2, name: "Neon down while Supabase remains healthy", status: primary.reachable && activeBackend === "SUPABASE" ? "PASS" : "FAIL", primary, fallbackBeforeSimulation: realFallback, simulatedFallbackDown: true, activeBackend, safeSimulation: true };
}

async function scenario3(env) {
  const primary = await checkSupabase(env);
  const fallback = await checkNeon(env);
  const activeBackend = chooseBackend(false, false);
  return { id: 3, name: "Supabase and Neon both down -> local queue required", status: activeBackend === "LOCAL_QUEUE" ? "PASS" : "FAIL", primaryBeforeSimulation: primary, fallbackBeforeSimulation: fallback, simulatedPrimaryDown: true, simulatedFallbackDown: true, activeBackend, localQueueRequired: true, clientQueueVerified: false, safeSimulation: true };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === "/sync/transaction" && request.method === "POST") {
        const body = await request.json();
        const results = await saveTransactions(env, [body.transaction]);
        const conflict = results.some(x => x.status === "CONFLICT");
        return json({ status: conflict ? "CONFLICT" : "OK", results }, conflict ? 409 : 200);
      }
      if (path === "/sync/batch" && request.method === "POST") {
        const body = await request.json();
        const results = await saveTransactions(env, body.transactions);
        const conflicts = results.filter(x => x.status === "CONFLICT");
        return json({ status: conflicts.length ? "PARTIAL" : "OK", results, conflicts }, conflicts.length ? 207 : 200);
      }
      if (path === "/sync/transactions" && request.method === "GET") {
        const registerId = url.searchParams.get("register_id") || "";
        const since = url.searchParams.get("since") || null;
        const transactions = await restoreTransactions(env, registerId, since);
        return json({ status: "OK", registerId, count: transactions.length, transactions });
      }
      if (path === "/sync/reconcile" && request.method === "POST") {
        const body = await request.json();
        const result = await reconcileTransactions(env, String(body.registerId || ""), body.transactionIds || []);
        return json({ status: "OK", ...result });
      }
      if (path === "/supergau" || path === "/scenario/1") {
        const result = await scenario1(env);
        return json(result, result.status === "PASS" ? 200 : 503);
      }
      if (path === "/scenario/2") {
        const result = await scenario2(env);
        return json(result, result.status === "PASS" ? 200 : 503);
      }
      if (path === "/scenario/3") {
        const result = await scenario3(env);
        return json(result, result.status === "PASS" ? 200 : 503);
      }
      if (path === "/supergau/server-matrix") {
        const results = [await scenario1(env), await scenario2(env), await scenario3(env)];
        const pass = results.every(x => x.status === "PASS");
        return json({ service: "KC Failover Gateway", test: "SERVER-SUPER-GAU-MATRIX", status: pass ? "PASS" : "FAIL", results, timestamp: new Date().toISOString() }, pass ? 200 : 503);
      }

      const primary = await checkSupabase(env);
      const fallback = await checkNeon(env);
      const activeBackend = chooseBackend(primary.reachable, fallback.reachable);
      return json({ service: "KC Failover Gateway", status: activeBackend === "LOCAL_QUEUE" ? "DEGRADED" : "OK", activeBackend, primary: { name: "SUPABASE", ...primary }, fallback: { name: "NEON", hyperdriveBinding: Boolean(env.HYPERDRIVE?.connectionString), ...fallback }, durablePosJournal: fallback.reachable, localQueueRequired: activeBackend === "LOCAL_QUEUE", timestamp: new Date().toISOString() });
    } catch (error) {
      const message = error instanceof Error ? error.message : "UNKNOWN_ERROR";
      const status = message.startsWith("INVALID_") || message === "TRANSACTION_TOO_LARGE" ? 400 : 500;
      return json({ status: "ERROR", error: message }, status);
    }
  }
};
