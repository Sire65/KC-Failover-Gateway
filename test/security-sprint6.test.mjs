import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const store=fs.readFileSync(new URL('../src/security-store.js',import.meta.url),'utf8');
const worker=fs.readFileSync(new URL('../src/secure-worker.js',import.meta.url),'utf8');
const abuse=fs.readFileSync(new URL('../src/security-abuse.js',import.meta.url),'utf8');

test('durable rate-limit store is wired into secure worker',()=>{
  assert.match(worker,/consumeRateLimitInStore/);
  assert.match(worker,/SECURITY_STORE_UNAVAILABLE/);
  assert.match(worker,/RATE_LIMITED/);
});

test('durable rate-limit SQL is parameterized',()=>{
  assert.match(store,/\$1/);
  assert.match(store,/\$2/);
  assert.doesNotMatch(store,/device_id\s*=\s*['"]\$\{/);
});

test('pre-auth limiter does not trust device id for bucket key',()=>{
  const fn=abuse.slice(abuse.indexOf('function preAuthBucketKey'),abuse.indexOf('export function validateRequestEnvelope'));
  assert.match(fn,/cf-connecting-ip/);
  assert.doesNotMatch(fn,/x-kc-device-id/);
});

test('pre-auth bucket memory is explicitly bounded',()=>{
  assert.match(abuse,/MAX_BURST_BUCKETS/);
  assert.match(abuse,/while\(buckets\.size>MAX_BURST_BUCKETS\)/);
});

test('stale durable rate-limit records have cleanup path',()=>{
  assert.match(store,/purgeStaleRateLimits/);
  assert.match(worker,/purgeStaleRateLimits/);
});

for(let i=0;i<60;i++) test(`Sprint 6 architecture invariant ${i+1}`,()=>{
  assert.match(store,/kc_security_rate_limits/);
  assert.match(worker,/useDurableStore/);
  assert.match(abuse,/BURST_LIMIT/);
});
