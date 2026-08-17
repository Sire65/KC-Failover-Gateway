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
  const normalized = String(value).replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const bin = atob(padded);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function sha256Base64Url(text) {
  return b64url(await crypto.subtle.digest('SHA-256', encoder.encode(String(text ?? ''))));
}

function parseJsonObject(value) {
  if (!value) return null;
  let parsed;
  try { parsed = JSON.parse(value); } catch { return null; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  return parsed;
}

function parseDeviceKeys(env) { return parseJsonObject(env.KC_DEVICE_KEYS_JSON); }
function parseDevicePublicKeys(env) { return parseJsonObject(env.KC_DEVICE_PUBLIC_KEYS_JSON); }

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
    'access-control-allow-headers': 'content-type,x-kc-client,x-kc-device-id,x-kc-key-version,x-kc-timestamp,x-kc-nonce,x-kc-signature',
    'access-control-max-age': '600',
    'vary': 'Origin'
  };
  if (origin) headers['access-control-allow-origin'] = origin;
  return headers;
}

export async function buildCanonicalRequest(method, url, timestamp, nonce, bodyText) {
  const parsed = new URL(url);
  const bodyHash = await sha256Base64Url(bodyText || '');
  return [String(method).toUpperCase(), `${parsed.pathname}${parsed.search}`, String(timestamp), String(nonce), bodyHash].join('\n');
}

export async function signCanonical(secretB64url, canonical) {
  const key = await crypto.subtle.importKey('raw', fromB64url(secretB64url), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, encoder.encode(canonical)));
}

export async function verifyEcdsaCanonical(publicJwk, canonical, signature) {
  if (!publicJwk || publicJwk.kty !== 'EC' || publicJwk.crv !== 'P-256' || !publicJwk.x || !publicJwk.y || publicJwk.d) return false;
  let supplied;
  try { supplied = fromB64url(signature); } catch { return false; }
  try {
    const key = await crypto.subtle.importKey('jwk', { kty:'EC', crv:'P-256', x:publicJwk.x, y:publicJwk.y, ext:true, key_ops:['verify'] }, { name:'ECDSA', namedCurve:'P-256' }, false, ['verify']);
    return crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, key, supplied, encoder.encode(canonical));
  } catch { return false; }
}

function basicHeaders(request) {
  return {
    deviceId: String(request.headers.get('x-kc-device-id') || ''),
    keyVersionRaw: String(request.headers.get('x-kc-key-version') || '1'),
    timestampRaw: String(request.headers.get('x-kc-timestamp') || ''),
    nonce: String(request.headers.get('x-kc-nonce') || ''),
    signature: String(request.headers.get('x-kc-signature') || '')
  };
}

function validateHeaders(h, nowSeconds) {
  if (!/^[A-Za-z0-9._:-]{3,100}$/.test(h.deviceId)) return { ok:false,status:401,code:'INVALID_DEVICE_ID' };
  if (!/^\d{1,9}$/.test(h.keyVersionRaw) || Number(h.keyVersionRaw) < 1) return { ok:false,status:401,code:'INVALID_KEY_VERSION' };
  if (!/^\d{10}$/.test(h.timestampRaw)) return { ok:false,status:401,code:'INVALID_TIMESTAMP' };
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(h.nonce)) return { ok:false,status:401,code:'INVALID_NONCE' };
  if (!/^[A-Za-z0-9_-]{40,200}$/.test(h.signature)) return { ok:false,status:401,code:'INVALID_SIGNATURE' };
  const timestamp = Number(h.timestampRaw);
  if (Math.abs(nowSeconds - timestamp) > MAX_SKEW_SECONDS) return { ok:false,status:401,code:'STALE_REQUEST' };
  return { ok:true,timestamp,keyVersion:Number(h.keyVersionRaw) };
}

async function verifyAsymmetric(request, registry, h, canonical, keyVersion) {
  const entry = registry[h.deviceId];
  if (!entry || typeof entry !== 'object') return { ok:false,status:401,code:'UNKNOWN_DEVICE' };
  if (String(entry.status || 'active').toLowerCase() !== 'active') return { ok:false,status:403,code:'DEVICE_REVOKED' };
  if (Number(entry.keyVersion || 1) !== keyVersion) return { ok:false,status:401,code:'KEY_VERSION_MISMATCH' };
  if (entry.registerId && !/^[A-Za-z0-9._:-]{3,100}$/.test(String(entry.registerId))) return { ok:false,status:503,code:'INVALID_DEVICE_REGISTRY' };
  const verified = await verifyEcdsaCanonical(entry.publicJwk, canonical, h.signature);
  if (!verified) return { ok:false,status:401,code:'BAD_SIGNATURE' };
  return { ok:true,authMode:'ECDSA-P256',registerId:entry.registerId || null };
}

async function verifyLegacyHmac(env, keys, h, canonical) {
  const secret = keys[h.deviceId];
  if (typeof secret !== 'string' || secret.length < 43) return { ok:false,status:401,code:'UNKNOWN_DEVICE' };
  const key = await crypto.subtle.importKey('raw', fromB64url(secret), { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
  let supplied;
  try { supplied = fromB64url(h.signature); } catch { return { ok:false,status:401,code:'INVALID_SIGNATURE' }; }
  const verified = await crypto.subtle.verify('HMAC', key, supplied, encoder.encode(canonical));
  if (!verified) return { ok:false,status:401,code:'BAD_SIGNATURE' };
  return { ok:true,authMode:'HMAC-SHA256',registerId:null };
}

export async function authenticateRequest(request, env, { nowSeconds = Math.floor(Date.now() / 1000), enforceReplay = true } = {}) {
  const publicRegistry = parseDevicePublicKeys(env);
  const legacyKeys = parseDeviceKeys(env);
  if (!publicRegistry && !legacyKeys) return { ok:false,status:503,code:'SECURITY_NOT_CONFIGURED' };

  const h = basicHeaders(request);
  const valid = validateHeaders(h, nowSeconds);
  if (!valid.ok) return valid;

  const bodyText = request.method === 'GET' || request.method === 'HEAD' ? '' : await request.clone().text();
  const canonical = await buildCanonicalRequest(request.method, request.url, h.timestampRaw, h.nonce, bodyText);
  const verified = publicRegistry
    ? await verifyAsymmetric(request, publicRegistry, h, canonical, valid.keyVersion)
    : await verifyLegacyHmac(env, legacyKeys, h, canonical);
  if (!verified.ok) return verified;

  cleanupReplayCache(nowSeconds);
  const replayKey = `${h.deviceId}:${h.nonce}`;
  if (enforceReplay && replayCache.has(replayKey)) return { ok:false,status:409,code:'REPLAY_DETECTED' };
  if (enforceReplay) replayCache.set(replayKey, nowSeconds + MAX_SKEW_SECONDS + 5);

  return { ok:true,deviceId:h.deviceId,bodyText,timestamp:valid.timestamp,nonce:h.nonce,keyVersion:valid.keyVersion,...verified };
}

export const securityConstants = Object.freeze({ MAX_SKEW_SECONDS, MAX_NONCE_CACHE });
