import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
if(!globalThis.btoa)globalThis.btoa=s=>Buffer.from(s,'binary').toString('base64');
if(!globalThis.atob)globalThis.atob=s=>Buffer.from(s,'base64').toString('binary');
const {authenticateRequest,buildCanonicalRequest}=await import('../src/security.js');
const enc=new TextEncoder();
const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
const jwk=await crypto.subtle.exportKey('jwk',pair.publicKey);
const now=1787000000;let seq=0;
const active={deviceId:'KASSE-01',registerId:'REGISTER-01',status:'active',keyVersion:4,publicJwk:{kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y}};
const b64url=b=>Buffer.from(new Uint8Array(b)).toString('base64url');
async function req({body='{"transactions":[]}',nonce=`durable_${String(++seq).padStart(20,'0')}`,timestamp=now,version=4}={}){
 const url='https://gateway.example/sync/batch';const c=await buildCanonicalRequest('POST',url,String(timestamp),nonce,body);const s=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,enc.encode(c));
 return new Request(url,{method:'POST',headers:{'content-type':'application/json','x-kc-device-id':'KASSE-01','x-kc-key-version':String(version),'x-kc-timestamp':String(timestamp),'x-kc-nonce':nonce,'x-kc-signature':b64url(s)},body});
}

test('durable resolver authenticates known active device',async()=>{let seen='';const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async id=>(seen=id,active),replayStore:async()=>true});assert.equal(r.ok,true);assert.equal(seen,'KASSE-01');assert.equal(r.authMode,'ECDSA-P256')});
test('durable resolver unknown device rejected',async()=>{const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async()=>null,replayStore:async()=>true});assert.equal(r.code,'UNKNOWN_DEVICE')});
test('durable resolver revoked device rejected',async()=>{const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async()=>({...active,status:'revoked'}),replayStore:async()=>true});assert.equal(r.code,'DEVICE_REVOKED')});
test('resolver error fails closed',async()=>{const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async()=>{throw new Error('db')},replayStore:async()=>true});assert.equal(r.code,'SECURITY_STORE_UNAVAILABLE');assert.equal(r.status,503)});
test('replay store rejection becomes replay detected',async()=>{const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async()=>active,replayStore:async()=>false});assert.equal(r.code,'REPLAY_DETECTED');assert.equal(r.status,409)});
test('replay store error fails closed',async()=>{const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async()=>active,replayStore:async()=>{throw new Error('db')}});assert.equal(r.code,'SECURITY_STORE_UNAVAILABLE');assert.equal(r.status,503)});

test('durable replay store receives signed device nonce timestamp',async()=>{let captured;const q=await req({nonce:'durable_capture_1234567890'});const r=await authenticateRequest(q,{}, {nowSeconds:now,deviceResolver:async()=>active,replayStore:async x=>(captured=x,true)});assert.equal(r.ok,true);assert.equal(captured.deviceId,'KASSE-01');assert.equal(captured.nonce,'durable_capture_1234567890');assert.equal(captured.timestamp,now);assert.ok(captured.ttlSeconds>=120)});

for(let i=0;i<25;i++)test(`durable nonce uniqueness case ${i+1}`,async()=>{const used=new Set();const store=async x=>{if(used.has(x.nonce))return false;used.add(x.nonce);return true};const nonce=`durable_unique_${String(i).padStart(18,'0')}`;const a=await authenticateRequest(await req({nonce}),{}, {nowSeconds:now,deviceResolver:async()=>active,replayStore:store});const b=await authenticateRequest(await req({nonce}),{}, {nowSeconds:now,deviceResolver:async()=>active,replayStore:store});assert.equal(a.ok,true);assert.equal(b.code,'REPLAY_DETECTED')});

for(let i=0;i<20;i++)test(`registry key-version mismatch case ${i+1}`,async()=>{const requested=i+1===4?5:i+1;const r=await authenticateRequest(await req({version:requested}),{}, {nowSeconds:now,deviceResolver:async()=>active,replayStore:async()=>true});if(requested===4)assert.equal(r.ok,true);else assert.equal(r.code,'KEY_VERSION_MISMATCH')});

test('bad registry public key fails signature',async()=>{const bad={...active,publicJwk:{...active.publicJwk,x:'bad'}};const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async()=>bad,replayStore:async()=>true});assert.equal(r.code,'BAD_SIGNATURE')});
test('private component in registry rejected',async()=>{const bad={...active,publicJwk:{...active.publicJwk,d:'should-never-exist'}};const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async()=>bad,replayStore:async()=>true});assert.equal(r.code,'BAD_SIGNATURE')});
test('invalid register id in DB fails closed',async()=>{const bad={...active,registerId:'bad register'};const r=await authenticateRequest(await req(),{}, {nowSeconds:now,deviceResolver:async()=>bad,replayStore:async()=>true});assert.equal(r.code,'INVALID_DEVICE_REGISTRY')});
