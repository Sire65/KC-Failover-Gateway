import worker from '../../src/worker.js';

function envShim() {
  const neon = process.env.NEON_DATABASE_URL || process.env.DATABASE_URL || '';
  // Netlify production uses SUPABASE_ANON_KEY. Prefer it here as well so
  // Deploy Previews do not accidentally pick up an unrelated/invalid
  // publishable-key variable when both names exist.
  const supabaseKey = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || '';
  return {
    SUPABASE_URL: process.env.SUPABASE_URL || '',
    SUPABASE_PUBLISHABLE_KEY: supabaseKey,
    HYPERDRIVE: neon ? { connectionString: neon } : null
  };
}

export default async (request) => {
  return worker.fetch(request, envShim());
};
