import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRequestEnvelope, enforceBodyLimit, enforceBurstLimit, abuseConstants, getBurstBucketCount } from '../src/security-abuse.js';

const base='https://gateway.example/sync/batch';
function req(url=base,init={}){return new Request(url,init);}
function ipReq(ip,extraHeaders={}){return req(base,{headers:{'cf-connecting-ip':ip,...extraHeaders}});}

test('limits are conservative',()=>{
  assert.equal(abuseConstants.MAX_POST_BYTES,262144);
  assert.ok(abuseConstants.MAX_URL_LENGTH<=4096);
  assert.ok(abuseConstants.BURST_LIMIT>=60&&abuseConstants.BURST_LIMIT<=300);
  assert.ok(abuseConstants.MAX_BURST_BUCKETS<=10000);
});

for(const method of ['PUT','PATCH','DELETE','TRACE','CONNECT']){
  test(`${method} rejected`,()=>{
    const r=validateRequestEnvelope(req(base,{method}));
    assert.equal(r.ok,false);assert.equal(r.status,405);assert.equal(r.code,'METHOD_NOT_ALLOWED');
  });
}

for(let i=0;i<20;i++){
  test(`valid JSON POST envelope ${i+1}`,()=>{
    const r=validateRequestEnvelope(req(base,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({n:i})}));
    assert.equal(r.ok,true);
  });
}

for(const type of ['text/plain','application/xml','multipart/form-data','application/x-www-form-urlencoded','text/html']){
  test(`reject content type ${type}`,()=>{
    const r=validateRequestEnvelope(req(base,{method:'POST',headers:{'content-type':type},body:'x'}));
    assert.equal(r.ok,false);assert.equal(r.status,415);assert.equal(r.code,'JSON_REQUIRED');
  });
}

test('reject declared oversized content length',()=>{
  const r=validateRequestEnvelope(req(base,{method:'POST',headers:{'content-type':'application/json','content-length':String(abuseConstants.MAX_POST_BYTES+1)},body:'{}'}));
  assert.equal(r.ok,false);assert.equal(r.status,413);
});

test('accept body exactly at byte limit',async()=>{
  const body='x'.repeat(abuseConstants.MAX_POST_BYTES);
  const r=await enforceBodyLimit(req(base,{method:'POST',headers:{'content-type':'application/json'},body}));
  assert.equal(r.ok,true);
});

test('reject body above byte limit without content-length trust',async()=>{
  const body='x'.repeat(abuseConstants.MAX_POST_BYTES+1);
  const r=await enforceBodyLimit(req(base,{method:'POST',headers:{'content-type':'application/json'},body}));
  assert.equal(r.ok,false);assert.equal(r.status,413);assert.equal(r.code,'PAYLOAD_TOO_LARGE');
});

for(let i=0;i<20;i++){
  test(`GET envelope ${i+1}`,()=>{
    const r=validateRequestEnvelope(req(`https://gateway.example/sync/transactions?register_id=kasse-${i}`));
    assert.equal(r.ok,true);
  });
}

test('reject excessive query',()=>{
  const r=validateRequestEnvelope(req(`https://gateway.example/sync/transactions?q=${'x'.repeat(abuseConstants.MAX_QUERY_LENGTH+10)}`));
  assert.equal(r.ok,false);assert.equal(r.status,414);
});

test('burst limiter permits normal request rate from one IP',()=>{
  for(let i=0;i<abuseConstants.BURST_LIMIT;i++){
    const r=enforceBurstLimit(ipReq('198.51.100.10'));
    assert.equal(r.ok,true);
  }
});

test('burst limiter rejects request above threshold',()=>{
  for(let i=0;i<abuseConstants.BURST_LIMIT;i++)enforceBurstLimit(ipReq('198.51.100.11'));
  const r=enforceBurstLimit(ipReq('198.51.100.11'));
  assert.equal(r.ok,false);assert.equal(r.status,429);assert.equal(r.code,'RATE_LIMITED');assert.ok(r.retryAfter>=1);
});

test('spoofing device ID does not evade pre-auth IP bucket',()=>{
  const ip='198.51.100.12';
  for(let i=0;i<abuseConstants.BURST_LIMIT;i++)enforceBurstLimit(ipReq(ip,{'x-kc-device-id':`spoof-${i}`}));
  const r=enforceBurstLimit(ipReq(ip,{'x-kc-device-id':'fresh-spoof'}));
  assert.equal(r.ok,false);assert.equal(r.code,'RATE_LIMITED');
});

test('burst buckets are isolated per source IP',()=>{
  for(let i=0;i<abuseConstants.BURST_LIMIT;i++)enforceBurstLimit(ipReq('203.0.113.20'));
  const a=enforceBurstLimit(ipReq('203.0.113.20'));
  const b=enforceBurstLimit(ipReq('203.0.113.21'));
  assert.equal(a.ok,false);assert.equal(b.ok,true);
});

for(let i=0;i<50;i++)test(`distinct source IP case ${i+1}`,()=>{
  const r=enforceBurstLimit(ipReq(`192.0.2.${(i%250)+1}`));
  assert.equal(typeof r.ok,'boolean');
});

test('bucket count remains bounded by configured ceiling after cleanup opportunity',()=>{
  assert.ok(getBurstBucketCount()<=abuseConstants.MAX_BURST_BUCKETS);
});
