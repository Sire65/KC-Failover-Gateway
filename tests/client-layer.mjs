import assert from 'node:assert/strict';
import { KCFailoverClient, KC_FAILOVER_VERSION } from '../sdk/kc-failover-client.js';

assert.equal(KC_FAILOVER_VERSION,'1.0.0');
const client=new KCFailoverClient({programId:'kc-dp2',instanceId:'test'});
assert.equal(client.programId,'kc-dp2');
assert.equal(await client.queueDepth(),0);
const tx=await client.envelope('shift','shift-1','UPSERT',{name:'test'},{operationId:'op-1',occurredAt:'2026-08-28T00:00:00.000Z'});
assert.equal(tx.transactionId,'op-1');
assert.equal(tx.registerId,'kc-dp2');
assert.equal(tx.payload.programId,'kc-dp2');
assert.equal(tx.payload.entityType,'shift');
assert.equal(tx.payload.entityId,'shift-1');
assert.equal(tx.payload.operation,'UPSERT');
assert.equal(tx.payload.payload.name,'test');
assert.match(tx.recordHash,/^[a-f0-9]{64}$/);
let invalid=false;try{new KCFailoverClient({programId:'x'});}catch(e){invalid=String(e.message)==='INVALID_PROGRAM_ID';}
assert.equal(invalid,true);
console.log('PASS KC shared failover client layer');
