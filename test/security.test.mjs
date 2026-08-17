import test from 'node:test';
import assert from 'node:assert/strict';
import { authenticateRequest, buildCanonicalRequest, signCanonical, allowedOrigin, corsHeaders, securityConstants } from '../src/security.js';

const secret = Buffer.alloc(32, 7).toString('base64url');
const otherSecret = Buffer.alloc(32, 9).toString('base64url');
const env = {
  KC_DEVICE_KEYS_JSON: JSON.stringify({ 'register-1': secret, 'register-2': otherSecret }),
  KC_ALLOWED_ORIGINS: 'https://sire65.github.io,http://localhost:8000'
};
const now = 1787000000;
let seq = 0;

async function signedRequest({ method='POST', url='https://gateway.example/sync/batch', body='{"transactions":[]}', device='register-1', key=secret, timestamp=now, nonce }={}) {
  const n = nonce || `nonce_${String(++seq).padStart(20,'0')}`;
  const canonical = await buildCanonicalRequest(method, url, String(timestamp), n, method === 'GET' || method === 'HEAD' ? '' : body);
  const signature = await signCanonical(key, canonical);
  return new Request(url, {
    method,
    headers: {
      'content-type':'application/json',
      'x-kc-device-id': device,
      'x-kc-timestamp': String(timestamp),
      'x-kc-nonce': n,
      'x-kc-signature': signature
    },
    body: method === 'GET' || method === 'HEAD' ? undefined : body
  });
}

test('valid signed POST authenticates', async () => {
  const req = await signedRequest();
  const result = await authenticateRequest(req, env, { nowSeconds: now });
  assert.equal(result.ok, true);
  assert.equal(result.deviceId, 'register-1');
});

test('valid signed GET with query authenticates', async () => {
  const req = await signedRequest({ method:'GET', url:'https://gateway.example/sync/transactions?register_id=abc&since=2026-01-01' });
  const result = await authenticateRequest(req, env, { nowSeconds: now });
  assert.equal(result.ok, true);
});

test('missing security configuration fails closed', async () => {
  const req = await signedRequest();
  const result = await authenticateRequest(req, {}, { nowSeconds: now });
  assert.deepEqual({ok:result.ok,status:result.status,code:result.code},{ok:false,status:503,code:'SECURITY_NOT_CONFIGURED'});
});

test('malformed key JSON fails closed', async () => {
  const req = await signedRequest();
  const result = await authenticateRequest(req, {KC_DEVICE_KEYS_JSON:'{'}, { nowSeconds: now });
  assert.equal(result.code, 'SECURITY_NOT_CONFIGURED');
});

for (const badDevice of ['', 'a', 'x y', '<script>', 'a'.repeat(101), 'ä-device']) {
  test(`invalid device id rejected: ${JSON.stringify(badDevice)}`, async () => {
    const req = await signedRequest();
    req.headers.set('x-kc-device-id', badDevice);
    const result = await authenticateRequest(req, env, { nowSeconds: now });
    assert.equal(result.code, 'INVALID_DEVICE_ID');
  });
}

for (const offset of [-121, 121, -3600, 3600, -86400, 86400]) {
  test(`stale timestamp rejected at offset ${offset}`, async () => {
    const req = await signedRequest({ timestamp: now + offset });
    const result = await authenticateRequest(req, env, { nowSeconds: now });
    assert.equal(result.code, 'STALE_REQUEST');
  });
}

for (const offset of [-120, -60, -1, 0, 1, 60, 120]) {
  test(`timestamp accepted within skew ${offset}`, async () => {
    const req = await signedRequest({ timestamp: now + offset });
    const result = await authenticateRequest(req, env, { nowSeconds: now, enforceReplay:false });
    assert.equal(result.ok, true);
  });
}

for (const badNonce of ['', 'short', 'has space 123456789', 'bad!nonce_1234567890', 'x'.repeat(129)]) {
  test(`invalid nonce rejected: ${badNonce.slice(0,20)}`, async () => {
    const req = await signedRequest();
    req.headers.set('x-kc-nonce', badNonce);
    const result = await authenticateRequest(req, env, { nowSeconds: now });
    assert.equal(result.code, 'INVALID_NONCE');
  });
}

test('unknown device rejected', async () => {
  const req = await signedRequest({ device:'register-404' });
  const result = await authenticateRequest(req, env, { nowSeconds: now });
  assert.equal(result.code, 'UNKNOWN_DEVICE');
});

test('signature made with another device key rejected', async () => {
  const req = await signedRequest({ key:otherSecret });
  const result = await authenticateRequest(req, env, { nowSeconds: now });
  assert.equal(result.code, 'BAD_SIGNATURE');
});

test('replayed nonce rejected', async () => {
  const nonce = 'replay_nonce_1234567890123456';
  const req1 = await signedRequest({ nonce });
  const req2 = await signedRequest({ nonce });
  const first = await authenticateRequest(req1, env, { nowSeconds: now });
  const second = await authenticateRequest(req2, env, { nowSeconds: now });
  assert.equal(first.ok, true);
  assert.equal(second.code, 'REPLAY_DETECTED');
});

const tamperCases = [
  ['body', async req => new Request(req.url,{method:req.method,headers:req.headers,body:'{"transactions":[{"x":1}]}'} )],
  ['path', async req => new Request('https://gateway.example/sync/reconcile',{method:req.method,headers:req.headers,body:'{"transactions":[]}'} )],
  ['query', async req => new Request(req.url+'?x=1',{method:req.method,headers:req.headers,body:'{"transactions":[]}'} )],
  ['method', async req => new Request(req.url,{method:'PUT',headers:req.headers,body:'{"transactions":[]}'} )],
];
for (const [name, mutate] of tamperCases) {
  test(`tampered ${name} invalidates signature`, async () => {
    const req = await signedRequest();
    const changed = await mutate(req);
    const result = await authenticateRequest(changed, env, { nowSeconds: now, enforceReplay:false });
    assert.equal(result.code, 'BAD_SIGNATURE');
  });
}

for (let i=0;i<20;i++) {
  test(`unique request ${i+1} cannot be forged by changing payload`, async () => {
    const body = JSON.stringify({transactions:[{transactionId:`tx-${i}`,amount:i+0.25}]});
    const req = await signedRequest({body});
    const forgedBody = JSON.stringify({transactions:[{transactionId:`tx-${i}`,amount:99999}]});
    const forged = new Request(req.url,{method:'POST',headers:req.headers,body:forgedBody});
    const result = await authenticateRequest(forged, env, { nowSeconds:now, enforceReplay:false });
    assert.equal(result.code,'BAD_SIGNATURE');
  });
}

for (let i=0;i<10;i++) {
  test(`independent valid nonce ${i+1} authenticates`, async () => {
    const req = await signedRequest({nonce:`valid_nonce_${String(i).padStart(20,'0')}`});
    const result = await authenticateRequest(req, env, {nowSeconds:now});
    assert.equal(result.ok,true);
  });
}

test('allowed production origin is reflected', () => {
  const req = new Request('https://gateway.example/',{headers:{origin:'https://sire65.github.io'}});
  assert.equal(allowedOrigin(req,env),'https://sire65.github.io');
  assert.equal(corsHeaders(req,env)['access-control-allow-origin'],'https://sire65.github.io');
});

test('allowed localhost origin is reflected', () => {
  const req = new Request('https://gateway.example/',{headers:{origin:'http://localhost:8000'}});
  assert.equal(allowedOrigin(req,env),'http://localhost:8000');
});

test('unknown origin is not allowed', () => {
  const req = new Request('https://gateway.example/',{headers:{origin:'https://evil.example'}});
  assert.equal(allowedOrigin(req,env),null);
  assert.equal(corsHeaders(req,env)['access-control-allow-origin'],undefined);
});

test('request without Origin is permitted for server-to-server use', () => {
  const req = new Request('https://gateway.example/');
  assert.equal(allowedOrigin(req,env),null);
});

test('CORS never emits wildcard', () => {
  const req = new Request('https://gateway.example/',{headers:{origin:'https://sire65.github.io'}});
  assert.notEqual(corsHeaders(req,env)['access-control-allow-origin'],'*');
});

test('canonical request binds full path and query', async () => {
  const a = await buildCanonicalRequest('GET','https://x.example/sync/transactions?a=1&b=2','1787000000','abcdefghijklmnop','');
  const b = await buildCanonicalRequest('GET','https://x.example/sync/transactions?a=1&b=3','1787000000','abcdefghijklmnop','');
  assert.notEqual(a,b);
});

test('canonical request binds body hash', async () => {
  const a = await buildCanonicalRequest('POST','https://x.example/sync/batch','1787000000','abcdefghijklmnop','{"a":1}');
  const b = await buildCanonicalRequest('POST','https://x.example/sync/batch','1787000000','abcdefghijklmnop','{"a":2}');
  assert.notEqual(a,b);
});

test('security skew constant stays bounded', () => {
  assert.ok(securityConstants.MAX_SKEW_SECONDS <= 120);
  assert.ok(securityConstants.MAX_SKEW_SECONDS >= 30);
});
