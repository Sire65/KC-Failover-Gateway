const encoder = new TextEncoder();
const replayCache = new Map();
const MAX_SKEW_SECONDS = 120;
const MAX_NONCE_CACHE = 20000;

function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromB64url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const bin = atob(padded);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function sha256Base64Url(text) {
  return b64url(await crypto.subtle.digest('SHA-256', encoder.encode(text)));
}

function parseDeviceKeys(env) {
  if (!env.KC_DEVICE_KEYS_JSON) return null;
  let parsed;
  try { parsed = JSON.parse(env.KC_DEVICE_KEYS_JSON); } catch { return null; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  return parsed;
}

function cleanupReplayCache(nowSeconds) {
  for (const [key, expires] of replayCache) if (expires <= nowSeconds) replayCache.delete(key);
  if (replayCache.size <= MAX_NONCE_CACHE) return;
  const overflow = replayCache.size - MAX_NONCE_CACHE;
  let removed = 0;
  for (const key of replayCache.keys()) {
    replayCache.delete(key);
    if (++removed >= overflow) break;
  }
}

export function allowedOrigin(request, env) {
  const origin = request.headers.get('origin');
  if (!origin) return null;
  const allowed = String(env.KC_ALLOWED_ORIGINS || '')
    .split(',').map(x => x.trim()).filter(Boolean);
  return allowed.includes(origin) ? origin : null;
}

export function corsHeaders(request, env) {
  const origin = allowedOrigin(request, env);
  const headers = {
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type,x-kc-client,x-kc-device-id,x-kc-timestamp,x-kc-nonce,x-kc-signature',
    'access-control-max-age': '600',
    'vary': 'Origin'
  };
  if (origin) headers['access-control-allow-origin'] = origin;
  return headers;
}

export async function buildCanonicalRequest(method, url, timestamp, nonce, bodyText) {
  const parsed = new URL(url);
  const bodyHash = await sha256Base64Url(bodyText || '');
  return [method.toUpperCase(), `${parsed.pathname}${parsed.search}`, String(timestamp), nonce, bodyHash].join('\n');
}

export async function signCanonical(secretB64url, canonical) {
  const key = await crypto.subtle.importKey('raw', fromB64url(secretB64url), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, encoder.encode(canonical)));
}

export async function authenticateRequest(request, env, { nowSeconds = Math.floor(Date.now() / 1000), enforceReplay = true } = {}) {
  const keys = parseDeviceKeys(env);
  if (!keys) return { ok: false, status: 503, code: 'SECURITY_NOT_CONFIGURED' };

  const deviceId = String(request.headers.get('x-kc-device-id') || '');
  const timestampRaw = String(request.headers.get('x-kc-timestamp') || '');
  const nonce = String(request.headers.get('x-kc-nonce') || '');
  const signature = String(request.headers.get('x-kc-signature') || '');

  if (!/^[A-Za-z0-9._:-]{3,100}$/.test(deviceId)) return { ok: false, status: 401, code: 'INVALID_DEVICE_ID' };
  if (!/^\d{10}$/.test(timestampRaw)) return { ok: false, status: 401, code: 'INVALID_TIMESTAMP' };
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) return { ok: false, status: 401, code: 'INVALID_NONCE' };
  if (!/^[A-Za-z0-9_-]{40,128}$/.test(signature)) return { ok: false, status: 401, code: 'INVALID_SIGNATURE' };

  const timestamp = Number(timestampRaw);
  if (Math.abs(nowSeconds - timestamp) > MAX_SKEW_SECONDS) return { ok: false, status: 401, code: 'STALE_REQUEST' };

  const secret = keys[deviceId];
  if (typeof secret !== 'string' || secret.length < 43) return { ok: false, status: 401, code: 'UNKNOWN_DEVICE' };

  const bodyText = request.method === 'GET' || request.method === 'HEAD' ? '' : await request.clone().text();
  const canonical = await buildCanonicalRequest(request.method, request.url, timestampRaw, nonce, bodyText);
  const key = await crypto.subtle.importKey('raw', fromB64url(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  let supplied;
  try { supplied = fromB64url(signature); } catch { return { ok: false, status: 401, code: 'INVALID_SIGNATURE' }; }
  const verified = await crypto.subtle.verify('HMAC', key, supplied, encoder.encode(canonical));
  if (!verified) return { ok: false, status: 401, code: 'BAD_SIGNATURE' };

  cleanupReplayCache(nowSeconds);
  const replayKey = `${deviceId}:${nonce}`;
  if (enforceReplay && replayCache.has(replayKey)) return { ok: false, status: 409, code: 'REPLAY_DETECTED' };
  if (enforceReplay) replayCache.set(replayKey, nowSeconds + MAX_SKEW_SECONDS + 5);

  return { ok: true, deviceId, bodyText, timestamp, nonce };
}

export const securityConstants = Object.freeze({ MAX_SKEW_SECONDS });
