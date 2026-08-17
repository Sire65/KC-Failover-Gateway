import worker from './worker.js';
import { authenticateRequest, allowedOrigin, corsHeaders } from './security.js';

const PROTECTED_PREFIXES = ['/sync/'];

function isProtected(pathname) {
  return PROTECTED_PREFIXES.some(prefix => pathname.startsWith(prefix));
}

function securityJson(request, env, body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...corsHeaders(request, env)
    }
  });
}

function secureResponse(request, env, response) {
  const headers = new Headers(response.headers);
  headers.delete('access-control-allow-origin');
  headers.delete('access-control-allow-credentials');
  headers.set('vary', 'Origin');
  const origin = allowedOrigin(request, env);
  if (origin) headers.set('access-control-allow-origin', origin);
  headers.set('x-content-type-options', 'nosniff');
  headers.set('referrer-policy', 'no-referrer');
  headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  headers.set('content-security-policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('origin');

    if (request.method === 'OPTIONS') {
      if (origin && !allowedOrigin(request, env)) {
        return securityJson(request, env, { status: 'ERROR', error: 'ORIGIN_NOT_ALLOWED' }, 403);
      }
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    if (origin && !allowedOrigin(request, env)) {
      return securityJson(request, env, { status: 'ERROR', error: 'ORIGIN_NOT_ALLOWED' }, 403);
    }

    if (isProtected(url.pathname)) {
      const auth = await authenticateRequest(request, env);
      if (!auth.ok) {
        return securityJson(request, env, { status: 'ERROR', error: auth.code }, auth.status);
      }
    }

    const response = await worker.fetch(request, env, ctx);
    return secureResponse(request, env, response);
  }
};
