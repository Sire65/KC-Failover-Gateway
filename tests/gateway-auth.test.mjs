import assert from 'node:assert/strict';
import worker,{signaturePayload,verifyDeviceRequest} from '../src/worker.js';

const secret='0123456789abcdef0123456789abcdef0123456789abcdef';
const env={
  KC_ALLOWED_ORIGINS:'https://pos.example.test',
  KC_DEVICE_KEYS_JSON:JSON.stringify({
    'DEVICE-1':{secret,registerIds:['KASSE-01'],allowDiagnostics:false}
  })
};
const hex=bytes=>[...bytes].map(x=>x.toString(16).padStart(2,'0')).join('');
async function signRequest({nonce=crypto.randomUUID(),timestamp=Date.now(),body='{"registerId":"KASSE-01","transactionIds":[]}',origin='https://pos.example.test'}={}){
  const headers=new Headers({'content-type':'application/json','origin':origin,'x-kc-device':'DEVICE-1','x-kc-timestamp':String(timestamp),'x-kc-nonce':nonce});
  let request=new Request('https://gateway.example.test/sync/reconcile',{method:'POST',headers,body});
  const payload=await signaturePayload(request,body),key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']),signature=hex(new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(payload))));
  headers.set('x-kc-signature',signature);
  request=new Request('https://gateway.example.test/sync/reconcile',{method:'POST',headers,body});
  return {request,body,nonce};
}

const signed=await signRequest();
let auth=await verifyDeviceRequest(signed.request,env,signed.body);
assert.equal(auth.ok,true);
assert.deepEqual(auth.registerIds,['KASSE-01']);

auth=await verifyDeviceRequest(signed.request,env,signed.body);
assert.equal(auth.ok,false);
assert.equal(auth.code,'REPLAY_DETECTED');

const stale=await signRequest({timestamp:Date.now()-10*60*1000});
auth=await verifyDeviceRequest(stale.request,env,stale.body);
assert.equal(auth.ok,false);
assert.equal(auth.code,'TIMESTAMP_INVALID');

const bad=await signRequest();
bad.request.headers.set('x-kc-signature','0'.repeat(64));
auth=await verifyDeviceRequest(bad.request,env,bad.body);
assert.equal(auth.ok,false);
assert.equal(auth.code,'SIGNATURE_INVALID');

let response=await worker.fetch(new Request('https://gateway.example.test/sync/reconcile',{method:'POST',headers:{'content-type':'application/json','origin':'https://pos.example.test'},body:'{"registerId":"KASSE-01","transactionIds":[]}'}),env);
assert.equal(response.status,401,'Geschützte Sync-Route muss ohne Geräteauthentifizierung fail-closed sein.');

response=await worker.fetch(new Request('https://gateway.example.test/',{method:'OPTIONS',headers:{origin:'https://pos.example.test'}}),env);
assert.equal(response.status,204);
assert.equal(response.headers.get('access-control-allow-origin'),'https://pos.example.test');

response=await worker.fetch(new Request('https://gateway.example.test/',{method:'OPTIONS',headers:{origin:'https://evil.example.test'}}),env);
assert.equal(response.status,403);
assert.equal(response.headers.get('access-control-allow-origin'),null);

console.log('PASS Gateway HMAC auth, replay window and CORS allowlist');
