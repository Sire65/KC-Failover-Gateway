export default {
  async fetch(request, env) {
    const hasHyperdrive = Boolean(env.HYPERDRIVE);

    const body = {
      service: "KC Failover Gateway",
      status: hasHyperdrive ? "OK" : "ERROR",
      hyperdriveBinding: hasHyperdrive,
      timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(body, null, 2), {
      status: hasHyperdrive ? 200 : 500,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store"
      }
    });
  }
};
