import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRequestEnvelope, enforceBodyLimit, enforceBurstLimit, abuseConstants } from '../src/security-abuse.js';

const base='https://gateway.example/sync/batch';
function req(url=base,init={}){return new Request(url,init);}

test('limits are conservative',()=>{
  assert.equal(abuseConstants.MAX_POST_BYTES,262144);
  assert.ok(abuseConstants.MAX_URL_LENGTH<=4096);
  assert.ok(abuseConstants.BURST_LIMIT>=60&&abuseConstants.BURST_LIMIT<=300);
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

test('burst limiter permits normal request rate',()=>{
  for(let i=0;i<abuseConstants.BURST_LIMIT;i++){
    const r=enforceBurstLimit(req(base,{headers:{'x-kc-device-id':'burst-normal'}}));
    assert.equal(r.ok,true);
  }
});

test('burst limiter rejects request above threshold',()=>{
  for(let i=0;i<abuseConstants.BURST_LIMIT;i++)enforceBurstLimit(req(base,{headers:{'x-kc-device-id':'burst-block'}}));
  const r=enforceBurstLimit(req(base,{headers:{'x-kc-device-id':'burst-block'}}));
  assert.equal(r.ok,false);assert.equal(r.status,429);assert.equal(r.code,'RATE_LIMITED');assert.ok(r.retryAfter>=1);
});

test('burst buckets are isolated per device',()=>{
  for(let i=0;i<abuseConstants.BURST_LIMIT;i++)enforceBurstLimit(req(base,{headers:{'x-kc-device-id':'device-A'}}));
  const a=enforceBurstLimit(req(base,{headers:{'x-kc-device-id':'device-A'}}));
  const b=enforceBurstLimit(req(base,{headers:{'x-kc-device-id':'device-B'}}));
  assert.equal(a.ok,false);assert.equal(b.ok,true);
});
