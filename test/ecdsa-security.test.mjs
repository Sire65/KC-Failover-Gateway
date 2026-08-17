import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
if(!globalThis.btoa)globalThis.btoa=s=>Buffer.from(s,'binary').toString('base64');
if(!globalThis.atob)globalThis.atob=s=>Buffer.from(s,'base64').toString('binary');

const { authenticateRequest, buildCanonicalRequest } = await import('../src/security.js');
const enc=new TextEncoder();
const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
const other=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
const jwk=await crypto.subtle.exportKey('jwk',pair.publicKey);
const otherJwk=await crypto.subtle.exportKey('jwk',other.publicKey);
const b64url=bytes=>Buffer.from(new Uint8Array(bytes)).toString('base64url');
const now=1787000000;
let seq=0;
const registry={
  'KASSE-01':{status:'active',registerId:'REGISTER-01',keyVersion:3,publicJwk:{kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y}},
  'KASSE-02':{status:'revoked',registerId:'REGISTER-02',keyVersion:1,publicJwk:{kty:'EC',crv:'P-256',x:otherJwk.x,y:otherJwk.y}}
};
const env={KC_DEVICE_PUBLIC_KEYS_JSON:JSON.stringify(registry),KC_ALLOWED_ORIGINS:'https://sire65.github.io'};

async function makeReq({method='POST',url='https://gateway.example/sync/batch',body='{"transactions":[]}',device='KASSE-01',version=3,timestamp=now,nonce,key=pair.privateKey}={}){
  const n=nonce||`ecdsa_nonce_${String(++seq).padStart(20,'0')}`;
  const canonical=await buildCanonicalRequest(method,url,String(timestamp),n,method==='GET'||method==='HEAD'?'':body);
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,enc.encode(canonical));
  return new Request(url,{method,headers:{'content-type':'application/json','x-kc-device-id':device,'x-kc-key-version':String(version),'x-kc-timestamp':String(timestamp),'x-kc-nonce':n,'x-kc-signature':b64url(sig)},body:method==='GET'||method==='HEAD'?undefined:body});
}

test('valid P-256 signed request authenticates',async()=>{const r=await authenticateRequest(await makeReq(),env,{nowSeconds:now});assert.equal(r.ok,true);assert.equal(r.authMode,'ECDSA-P256');assert.equal(r.registerId,'REGISTER-01')});
test('revoked device is rejected',async()=>{const r=await authenticateRequest(await makeReq({device:'KASSE-02',version:1,key:other.privateKey}),env,{nowSeconds:now});assert.equal(r.code,'DEVICE_REVOKED')});
test('wrong key version rejected',async()=>{const r=await authenticateRequest(await makeReq({version:2}),env,{nowSeconds:now});assert.equal(r.code,'KEY_VERSION_MISMATCH')});
test('unknown device rejected',async()=>{const r=await authenticateRequest(await makeReq({device:'KASSE-99'}),env,{nowSeconds:now});assert.equal(r.code,'UNKNOWN_DEVICE')});
test('other private key cannot impersonate device',async()=>{const r=await authenticateRequest(await makeReq({key:other.privateKey}),env,{nowSeconds:now});assert.equal(r.code,'BAD_SIGNATURE')});
test('malformed registry fails closed',async()=>{const r=await authenticateRequest(await makeReq(),{KC_DEVICE_PUBLIC_KEYS_JSON:'{'},{nowSeconds:now});assert.equal(r.code,'SECURITY_NOT_CONFIGURED')});

for(const version of ['0','-1','x','1.5','9999999999'])test(`invalid key version ${version}`,async()=>{const req=await makeReq();req.headers.set('x-kc-key-version',version);const r=await authenticateRequest(req,env,{nowSeconds:now});assert.equal(r.code,'INVALID_KEY_VERSION')});
for(const offset of [-121,121,-1000,1000])test(`ECDSA stale timestamp ${offset}`,async()=>{const r=await authenticateRequest(await makeReq({timestamp:now+offset}),env,{nowSeconds:now});assert.equal(r.code,'STALE_REQUEST')});
for(const offset of [-120,-60,-1,0,1,60,120])test(`ECDSA allowed timestamp ${offset}`,async()=>{const r=await authenticateRequest(await makeReq({timestamp:now+offset}),env,{nowSeconds:now,enforceReplay:false});assert.equal(r.ok,true)});

test('ECDSA replay detected',async()=>{const nonce='ecdsa_replay_123456789012345';const a=await makeReq({nonce});const b=await makeReq({nonce});assert.equal((await authenticateRequest(a,env,{nowSeconds:now})).ok,true);assert.equal((await authenticateRequest(b,env,{nowSeconds:now})).code,'REPLAY_DETECTED')});

const tamper=[
 ['body',r=>new Request(r.url,{method:'POST',headers:r.headers,body:'{"transactions":[{"amount":9999}]}'} )],
 ['path',r=>new Request('https://gateway.example/sync/reconcile',{method:'POST',headers:r.headers,body:'{"transactions":[]}'} )],
 ['query',r=>new Request(r.url+'?admin=true',{method:'POST',headers:r.headers,body:'{"transactions":[]}'} )],
 ['method',r=>new Request(r.url,{method:'PUT',headers:r.headers,body:'{"transactions":[]}'} )]
];
for(const [name,mutate] of tamper)test(`ECDSA tampered ${name} rejected`,async()=>{const r=await makeReq();const f=mutate(r);const x=await authenticateRequest(f,env,{nowSeconds:now,enforceReplay:false});assert.equal(x.code,'BAD_SIGNATURE')});

for(let i=0;i<30;i++)test(`ECDSA transaction forgery ${i+1}`,async()=>{const body=JSON.stringify({transactions:[{transactionId:`t-${i}`,total:i+0.25}]});const req=await makeReq({body});const forged=JSON.stringify({transactions:[{transactionId:`t-${i}`,total:1000000}]});const f=new Request(req.url,{method:'POST',headers:req.headers,body:forged});const r=await authenticateRequest(f,env,{nowSeconds:now,enforceReplay:false});assert.equal(r.code,'BAD_SIGNATURE')});

for(let i=0;i<10;i++)test(`ECDSA unique valid request ${i+1}`,async()=>{const r=await authenticateRequest(await makeReq({nonce:`ecdsa_valid_${String(i).padStart(20,'0')}`}),env,{nowSeconds:now});assert.equal(r.ok,true)});

test('registry entry containing private coordinate is rejected',async()=>{const bad={...registry,'KASSE-01':{...registry['KASSE-01'],publicJwk:{...registry['KASSE-01'].publicJwk,d:'secret'}}};const r=await authenticateRequest(await makeReq(),{KC_DEVICE_PUBLIC_KEYS_JSON:JSON.stringify(bad)},{nowSeconds:now,enforceReplay:false});assert.equal(r.code,'BAD_SIGNATURE')});
test('non P-256 registry key rejected',async()=>{const bad={...registry,'KASSE-01':{...registry['KASSE-01'],publicJwk:{...registry['KASSE-01'].publicJwk,crv:'P-384'}}};const r=await authenticateRequest(await makeReq(),{KC_DEVICE_PUBLIC_KEYS_JSON:JSON.stringify(bad)},{nowSeconds:now,enforceReplay:false});assert.equal(r.code,'BAD_SIGNATURE')});
test('invalid registry register id fails closed',async()=>{const bad={...registry,'KASSE-01':{...registry['KASSE-01'],registerId:'bad register'}};const r=await authenticateRequest(await makeReq(),{KC_DEVICE_PUBLIC_KEYS_JSON:JSON.stringify(bad)},{nowSeconds:now,enforceReplay:false});assert.equal(r.code,'INVALID_DEVICE_REGISTRY')});
