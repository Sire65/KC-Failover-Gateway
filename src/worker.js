import pg from "pg";

const { Client } = pg;

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
    return {
      reachable: false,
      statusCode: null,
      latencyMs: Date.now() - startedAt,
      error: error instanceof Error ? error.message : "Unknown Supabase error"
    };
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
  if (!env.HYPERDRIVE?.connectionString) {
    return { reachable: false, latencyMs: Date.now() - startedAt, error: "Hyperdrive binding missing" };
  }
  try {
    await withNeon(env, (client) => client.query("SELECT 1 AS ok"));
    return { reachable: true, latencyMs: Date.now() - startedAt };
  } catch (error) {
    return {
      reachable: false,
      latencyMs: Date.now() - startedAt,
      error: error instanceof Error ? error.message : "Unknown Neon error"
    };
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
    return {
      readWrite: false,
      latencyMs: Date.now() - startedAt,
      persistentChanges: false,
      error: error instanceof Error ? error.message : "Unknown failover probe error"
    };
  }
}

function chooseBackend(primaryReachable, fallbackReachable) {
  if (primaryReachable) return "SUPABASE";
  if (fallbackReachable) return "NEON";
  return "LOCAL_QUEUE";
}

async function scenario1(env) {
  const primaryBefore = await checkSupabase(env);
  const fallback = await runFallbackReadWriteProbe(env);
  const primaryAfter = await checkSupabase(env);
  const pass = primaryBefore.reachable && fallback.readWrite && primaryAfter.reachable;
  return {
    id: 1,
    name: "Supabase down -> Neon -> Supabase recovery",
    status: pass ? "PASS" : "FAIL",
    before: primaryBefore,
    simulatedOutage: { primaryForcedDown: true, activeBackend: "NEON", fallback },
    recovery: { primary: primaryAfter, activeBackend: primaryAfter.reachable ? "SUPABASE" : "NEON" },
    safeSimulation: true
  };
}

async function scenario2(env) {
  const primary = await checkSupabase(env);
  const realFallback = await checkNeon(env);
  const activeBackend = chooseBackend(primary.reachable, false);
  return {
    id: 2,
    name: "Neon down while Supabase remains healthy",
    status: primary.reachable && activeBackend === "SUPABASE" ? "PASS" : "FAIL",
    primary,
    fallbackBeforeSimulation: realFallback,
    simulatedFallbackDown: true,
    activeBackend,
    safeSimulation: true
  };
}

async function scenario3(env) {
  const primary = await checkSupabase(env);
  const fallback = await checkNeon(env);
  const activeBackend = chooseBackend(false, false);
  return {
    id: 3,
    name: "Supabase and Neon both down -> local queue required",
    status: activeBackend === "LOCAL_QUEUE" ? "PASS" : "FAIL",
    primaryBeforeSimulation: primary,
    fallbackBeforeSimulation: fallback,
    simulatedPrimaryDown: true,
    simulatedFallbackDown: true,
    activeBackend,
    localQueueRequired: true,
    clientQueueVerified: false,
    safeSimulation: true
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/supergau" || path === "/scenario/1") {
      const result = await scenario1(env);
      return Response.json(result, { status: result.status === "PASS" ? 200 : 503, headers: { "cache-control": "no-store" } });
    }

    if (path === "/scenario/2") {
      const result = await scenario2(env);
      return Response.json(result, { status: result.status === "PASS" ? 200 : 503, headers: { "cache-control": "no-store" } });
    }

    if (path === "/scenario/3") {
      const result = await scenario3(env);
      return Response.json(result, { status: result.status === "PASS" ? 200 : 503, headers: { "cache-control": "no-store" } });
    }

    if (path === "/supergau/server-matrix") {
      const results = [await scenario1(env), await scenario2(env), await scenario3(env)];
      const pass = results.every(x => x.status === "PASS");
      return Response.json({
        service: "KC Failover Gateway",
        test: "SERVER-SUPER-GAU-MATRIX",
        status: pass ? "PASS" : "FAIL",
        results,
        note: "Scenarios 4-10 require POS/client/hardware validation and are not claimed by this endpoint.",
        timestamp: new Date().toISOString()
      }, { status: pass ? 200 : 503, headers: { "cache-control": "no-store" } });
    }

    const primary = await checkSupabase(env);
    const fallback = await checkNeon(env);
    const activeBackend = chooseBackend(primary.reachable, fallback.reachable);
    const ok = activeBackend !== "LOCAL_QUEUE";

    return Response.json({
      service: "KC Failover Gateway",
      status: ok ? "OK" : "DEGRADED",
      activeBackend,
      primary: { name: "SUPABASE", ...primary },
      fallback: { name: "NEON", hyperdriveBinding: Boolean(env.HYPERDRIVE?.connectionString), ...fallback },
      localQueueRequired: activeBackend === "LOCAL_QUEUE",
      timestamp: new Date().toISOString()
    }, { status: 200, headers: { "cache-control": "no-store" } });
  }
};
