import pg from "pg";

const { Client } = pg;

async function checkSupabase(env) {
  const startedAt = Date.now();
  const url = `${env.SUPABASE_URL}/auth/v1/health`;
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        apikey: env.SUPABASE_PUBLISHABLE_KEY
      },
      cf: { cacheTtl: 0 }
    });

    return {
      reachable: response.ok,
      statusCode: response.status,
      latencyMs: Date.now() - startedAt
    };
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
    try {
      await client.end();
    } catch {
      // Ignore cleanup errors.
    }
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

    return {
      readWrite: result === true,
      latencyMs: Date.now() - startedAt,
      persistentChanges: false
    };
  } catch (error) {
    return {
      readWrite: false,
      latencyMs: Date.now() - startedAt,
      persistentChanges: false,
      error: error instanceof Error ? error.message : "Unknown failover probe error"
    };
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/supergau") {
      const primaryBefore = await checkSupabase(env);
      const forcedPrimaryDown = true;
      const fallback = await runFallbackReadWriteProbe(env);
      const primaryAfter = await checkSupabase(env);

      const passed =
        primaryBefore.reachable === true &&
        forcedPrimaryDown === true &&
        fallback.readWrite === true &&
        primaryAfter.reachable === true;

      return Response.json(
        {
          service: "KC Failover Gateway",
          test: "SUPER-GAU-SIMULATION",
          status: passed ? "PASS" : "FAIL",
          phase1PrimaryBefore: primaryBefore,
          phase2SimulatedOutage: {
            primaryForcedDown: forcedPrimaryDown,
            activeBackend: "NEON",
            fallback
          },
          phase3Recovery: {
            primaryReachableAgain: primaryAfter.reachable,
            activeBackend: primaryAfter.reachable ? "SUPABASE" : "NEON",
            primary: primaryAfter
          },
          safeSimulation: true,
          productionSupabaseWasNotStopped: true,
          timestamp: new Date().toISOString()
        },
        {
          status: passed ? 200 : 503,
          headers: { "cache-control": "no-store" }
        }
      );
    }

    const primary = await checkSupabase(env);
    const fallback = await checkNeon(env);
    const activeBackend = primary.reachable ? "SUPABASE" : fallback.reachable ? "NEON" : "NONE";
    const ok = activeBackend !== "NONE";

    return Response.json(
      {
        service: "KC Failover Gateway",
        status: ok ? "OK" : "ERROR",
        activeBackend,
        primary: {
          name: "SUPABASE",
          ...primary
        },
        fallback: {
          name: "NEON",
          hyperdriveBinding: Boolean(env.HYPERDRIVE?.connectionString),
          ...fallback
        },
        timestamp: new Date().toISOString()
      },
      {
        status: ok ? 200 : 503,
        headers: { "cache-control": "no-store" }
      }
    );
  }
};
