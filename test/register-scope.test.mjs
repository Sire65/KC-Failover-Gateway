import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeDeviceScope } from '../src/security-scope.js';

const auth=(registerId='KASSE-01',bodyText='')=>({ok:true,registerId,bodyText});
const req=(path,{method='GET'}={})=>new Request(`https://gateway.example${path}`,{method});

for(let i=0;i<20;i++)test(`restore scope allow ${i+1}`,()=>{
  const r=authorizeDeviceScope(auth('KASSE-01'),req(`/sync/transactions?register_id=KASSE-01&n=${i}`));
  assert.equal(r.ok,true);
});

for(let i=0;i<20;i++)test(`restore scope reject cross-register ${i+1}`,()=>{
  const r=authorizeDeviceScope(auth('KASSE-01'),req(`/sync/transactions?register_id=KASSE-02&n=${i}`));
  assert.equal(r.ok,false);assert.equal(r.code,'REGISTER_SCOPE_VIOLATION');assert.equal(r.status,403);
});

for(let i=0;i<20;i++)test(`batch scope allow ${i+1}`,()=>{
  const body=JSON.stringify({transactions:[{transactionId:`T-${i}-A`,registerId:'KASSE-01'},{transactionId:`T-${i}-B`,registerId:'KASSE-01'}]});
  const r=authorizeDeviceScope(auth('KASSE-01',body),req('/sync/batch',{method:'POST'}));assert.equal(r.ok,true);
});

for(let i=0;i<20;i++)test(`batch scope reject mixed register ${i+1}`,()=>{
  const body=JSON.stringify({transactions:[{transactionId:`T-${i}-A`,registerId:'KASSE-01'},{transactionId:`T-${i}-B`,registerId:'KASSE-02'}]});
  const r=authorizeDeviceScope(auth('KASSE-01',body),req('/sync/batch',{method:'POST'}));assert.equal(r.ok,false);assert.equal(r.code,'REGISTER_SCOPE_VIOLATION');
});

for(let i=0;i<10;i++)test(`single transaction scope ${i+1}`,()=>{
  const good=JSON.stringify({transaction:{transactionId:`S-${i}`,registerId:'KASSE-01'}});
  const bad=JSON.stringify({transaction:{transactionId:`X-${i}`,registerId:'KASSE-02'}});
  assert.equal(authorizeDeviceScope(auth('KASSE-01',good),req('/sync/transaction',{method:'POST'})).ok,true);
  assert.equal(authorizeDeviceScope(auth('KASSE-01',bad),req('/sync/transaction',{method:'POST'})).code,'REGISTER_SCOPE_VIOLATION');
});

for(let i=0;i<10;i++)test(`reconcile scope ${i+1}`,()=>{
  const good=JSON.stringify({registerId:'KASSE-01',transactionIds:[`R-${i}`]});
  const bad=JSON.stringify({registerId:'KASSE-02',transactionIds:[`R-${i}`]});
  assert.equal(authorizeDeviceScope(auth('KASSE-01',good),req('/sync/reconcile',{method:'POST'})).ok,true);
  assert.equal(authorizeDeviceScope(auth('KASSE-01',bad),req('/sync/reconcile',{method:'POST'})).code,'REGISTER_SCOPE_VIOLATION');
});

test('unbound device is denied',()=>assert.equal(authorizeDeviceScope(auth('',JSON.stringify({registerId:'KASSE-01'})),req('/sync/reconcile',{method:'POST'})).code,'DEVICE_REGISTER_UNBOUND'));
test('invalid json is rejected',()=>assert.equal(authorizeDeviceScope(auth('KASSE-01','{'),req('/sync/reconcile',{method:'POST'})).code,'INVALID_JSON'));
test('empty batch rejected',()=>assert.equal(authorizeDeviceScope(auth('KASSE-01','{"transactions":[]}'),req('/sync/batch',{method:'POST'})).code,'INVALID_BATCH_SIZE'));
test('missing restore register rejected',()=>assert.equal(authorizeDeviceScope(auth('KASSE-01'),req('/sync/transactions')).code,'INVALID_REGISTER_ID'));
test('missing transaction register rejected',()=>assert.equal(authorizeDeviceScope(auth('KASSE-01','{"transaction":{}}'),req('/sync/transaction',{method:'POST'})).code,'INVALID_REGISTER_ID'));
