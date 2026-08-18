import worker from '../../src/worker.js';

function envShim() {
  const neon = process.env.NEON_DATABASE_URL || process.env.DATABASE_URL || '';
  return {
    SUPABASE_URL: process.env.SUPABASE_URL || '',
    SUPABASE_PUBLISHABLE_KEY: process.env.SUPABASE_PUBLISHABLE_KEY || '',
    HYPERDRIVE: neon ? { connectionString: neon } : null
  };
}

export default async (request) => {
  return worker.fetch(request, envShim());
};
