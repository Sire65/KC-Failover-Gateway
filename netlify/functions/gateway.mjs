import worker from '../../src/worker.js';

function envShim() {
  const neon = process.env.NEON_DATABASE_URL || process.env.DATABASE_URL || '';
  const supabaseKey = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || '';
  return {
    SUPABASE_URL: process.env.SUPABASE_URL || '',
    SUPABASE_PUBLISHABLE_KEY: supabaseKey,
    HYPERDRIVE: neon ? { connectionString: neon } : null
  };
}

function restoreGatewayPath(request) {
  const url = new URL(request.url);
  const routedPath = url.searchParams.get('kc_path');
  if (!routedPath) return request;

  url.pathname = routedPath;
  url.searchParams.delete('kc_path');
  return new Request(url.toString(), request);
}

export default async (request) => {
  return worker.fetch(restoreGatewayPath(request), envShim());
};
