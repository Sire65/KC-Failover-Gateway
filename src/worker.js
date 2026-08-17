import pg from "pg";

const { Client } = pg;

export default {
  async fetch(request, env) {
    const startedAt = Date.now();
    const hasHyperdrive = Boolean(env.HYPERDRIVE?.connectionString);

    if (!hasHyperdrive) {
      return Response.json(
        {
          service: "KC Failover Gateway",
          status: "ERROR",
          hyperdriveBinding: false,
          databaseReachable: false,
          timestamp: new Date().toISOString()
        },
        {
          status: 500,
          headers: { "cache-control": "no-store" }
        }
      );
    }

    const client = new Client({
      connectionString: env.HYPERDRIVE.connectionString
    });

    try {
      await client.connect();
      await client.query("SELECT 1 AS ok");

      return Response.json(
        {
          service: "KC Failover Gateway",
          status: "OK",
          hyperdriveBinding: true,
          databaseReachable: true,
          latencyMs: Date.now() - startedAt,
          timestamp: new Date().toISOString()
        },
        {
          status: 200,
          headers: { "cache-control": "no-store" }
        }
      );
    } catch (error) {
      console.error("Hyperdrive database health check failed", error);

      return Response.json(
        {
          service: "KC Failover Gateway",
          status: "ERROR",
          hyperdriveBinding: true,
          databaseReachable: false,
          error: error instanceof Error ? error.message : "Unknown database error",
          latencyMs: Date.now() - startedAt,
          timestamp: new Date().toISOString()
        },
        {
          status: 503,
          headers: { "cache-control": "no-store" }
        }
      );
    } finally {
      try {
        await client.end();
      } catch {
        // Ignore connection cleanup errors in the health endpoint.
      }
    }
  }
};
