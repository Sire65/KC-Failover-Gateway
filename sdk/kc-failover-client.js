const DEFAULT_PRIMARY = 'https://kc-failover-gateway.ha-joko.workers.dev';
const DEFAULT_SECONDARY = 'https://kc-failover-gateway.netlify.app/.netlify/functions/gateway';
const DB_NAME = 'kc-failover-client';
const STORE = 'outbox';

function sleep(ms){return new Promise(resolve=>setTimeout(resolve,ms));}
function uuid(){return globalThis.crypto?.randomUUID?.() || `kc-${Date.now()}-${Math.random().toString(16).slice(2)}`;}
function nowIso(){return new Date().toISOString();}
function normalizeBase(v){return String(v||'').replace(/\/+$/,'');}
function assertProgramId(v){const s=String(v||'').trim();if(!/^[a-z0-9][a-z0-9._-]{1,79}$/i.test(s))throw new Error('INVALID_PROGRAM_ID');return s;}
function stableStringify(value){if(value===null||typeof value!=='object')return JSON.stringify(value);if(Array.isArray(value))return `[${value.map(stableStringify).join(',')}]`;return `{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;}
async function sha256(value){const bytes=new TextEncoder().encode(typeof value==='string'?value:stableStringify(value));const hash=await crypto.subtle.digest('SHA-256',bytes);return Array.from(new Uint8Array(hash)).map(x=>x.toString(16).padStart(2,'0')).join('');}

function openDb(){
  if(!globalThis.indexedDB) return Promise.resolve(null);
  return new Promise((resolve,reject)=>{
    const req=indexedDB.open(DB_NAME,1);
    req.onupgradeneeded=()=>{const db=req.result;if(!db.objectStoreNames.contains(STORE)){const s=db.createObjectStore(STORE,{keyPath:'id'});s.createIndex('programId','programId');s.createIndex('createdAt','createdAt');}};
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
}
async function idbPut(row){const db=await openDb();if(!db)return false;return new Promise((resolve,reject)=>{const tx=db.transaction(STORE,'readwrite');tx.objectStore(STORE).put(row);tx.oncomplete=()=>resolve(true);tx.onerror=()=>reject(tx.error);});}
async function idbDelete(id){const db=await openDb();if(!db)return false;return new Promise((resolve,reject)=>{const tx=db.transaction(STORE,'readwrite');tx.objectStore(STORE).delete(id);tx.oncomplete=()=>resolve(true);tx.onerror=()=>reject(tx.error);});}
async function idbList(programId){const db=await openDb();if(!db)return [];return new Promise((resolve,reject)=>{const tx=db.transaction(STORE,'readonly');const req=tx.objectStore(STORE).index('programId').getAll(programId);req.onsuccess=()=>resolve((req.result||[]).sort((a,b)=>String(a.createdAt).localeCompare(String(b.createdAt))));req.onerror=()=>reject(req.error);});}

export class KCFailoverClient {
  constructor(options={}){
    this.programId=assertProgramId(options.programId);
    this.instanceId=String(options.instanceId||'browser').slice(0,100);
    this.primary=normalizeBase(options.primaryGateway||DEFAULT_PRIMARY);
    this.secondary=normalizeBase(options.secondaryGateway||DEFAULT_SECONDARY);
    this.timeoutMs=Math.max(1000,Number(options.timeoutMs||7000));
    this.failureThreshold=Math.max(1,Number(options.failureThreshold||2));
    this.cooldownMs=Math.max(1000,Number(options.cooldownMs||15000));
    this.failures={primary:0,secondary:0};
    this.openUntil={primary:0,secondary:0};
    this.listeners=new Set();
    this.lastStatus={state:'UNKNOWN',backend:null,queueDepth:null,changedAt:nowIso()};
  }
  onStatus(fn){this.listeners.add(fn);return()=>this.listeners.delete(fn);}
  emit(status){this.lastStatus={...this.lastStatus,...status,changedAt:nowIso()};for(const fn of this.listeners){try{fn(this.lastStatus);}catch{}}}
  async fetchWithTimeout(url,init={}){const ctrl=new AbortController();const t=setTimeout(()=>ctrl.abort(),this.timeoutMs);try{return await fetch(url,{...init,signal:ctrl.signal,headers:{'content-type':'application/json','x-kc-client':`${this.programId}/${this.instanceId}`,...(init.headers||{})}});}finally{clearTimeout(t);}}
  endpointCandidates(){const now=Date.now();return [['primary',this.primary],['secondary',this.secondary]].filter(([name])=>this.openUntil[name]<=now);}
  mark(name,ok){if(ok){this.failures[name]=0;this.openUntil[name]=0;return;}this.failures[name]=(this.failures[name]||0)+1;if(this.failures[name]>=this.failureThreshold)this.openUntil[name]=Date.now()+this.cooldownMs;}
  async request(path,init={}){
    let lastError=null;
    const candidates=this.endpointCandidates();
    if(!candidates.length){await sleep(20);candidates.push(['primary',this.primary],['secondary',this.secondary]);}
    for(const [name,base] of candidates){
      try{const res=await this.fetchWithTimeout(`${base}${path}`,init);if(res.ok||res.status===207||res.status===409){this.mark(name,true);const body=await res.json().catch(()=>({}));this.emit({state:'ONLINE',backend:name.toUpperCase(),httpStatus:res.status});return{ok:res.ok,status:res.status,body,provider:name};}this.mark(name,false);lastError=new Error(`HTTP_${res.status}`);}catch(e){this.mark(name,false);lastError=e;}
    }
    this.emit({state:'OFFLINE',backend:'LOCAL_QUEUE'});throw lastError||new Error('ALL_GATEWAYS_UNAVAILABLE');
  }
  async health(){
    try{const r=await this.request('/',{method:'GET'});return{ok:true,provider:r.provider,...r.body};}catch(error){return{ok:false,activeBackend:'LOCAL_QUEUE',error:String(error?.message||error)};}
  }
  async envelope(entityType,entityId,operation,payload,meta={}){
    const id=String(meta.operationId||uuid());
    const cleanPayload={kcFailover:true,schema:'kc.failover.record.v1',programId:this.programId,instanceId:this.instanceId,entityType:String(entityType||'entity').slice(0,100),entityId:String(entityId||id).slice(0,160),operation:String(operation||'UPSERT').toUpperCase().slice(0,20),occurredAt:meta.occurredAt||nowIso(),payload,meta:{...meta,operationId:id}};
    const recordHash=await sha256(cleanPayload);
    return{transactionId:id,registerId:this.programId,registerName:this.instanceId,time:cleanPayload.occurredAt,recordHash,payload:cleanPayload};
  }
  async write({entityType,entityId,operation='UPSERT',payload,meta={}}){
    const transaction=await this.envelope(entityType,entityId,operation,payload,meta);
    try{
      const r=await this.request('/sync/transaction',{method:'POST',body:JSON.stringify({transaction})});
      if(r.status===409||r.body?.status==='CONFLICT')return{status:'CONFLICT',operationId:transaction.transactionId,provider:r.provider,result:r.body};
      return{status:'SYNCED',operationId:transaction.transactionId,provider:r.provider,result:r.body};
    }catch(error){
      await idbPut({id:transaction.transactionId,programId:this.programId,createdAt:nowIso(),attempts:0,transaction});
      const queue=await idbList(this.programId);this.emit({state:'QUEUED',backend:'LOCAL_QUEUE',queueDepth:queue.length});
      return{status:'QUEUED',operationId:transaction.transactionId,error:String(error?.message||error)};
    }
  }
  async replay(){
    const queued=await idbList(this.programId);if(!queued.length){this.emit({queueDepth:0});return{status:'EMPTY',sent:0,remaining:0,conflicts:[]};}
    const conflicts=[];let sent=0;
    for(let i=0;i<queued.length;i+=100){
      const batch=queued.slice(i,i+100);
      try{
        const r=await this.request('/sync/batch',{method:'POST',body:JSON.stringify({transactions:batch.map(x=>x.transaction)})});
        const results=Array.isArray(r.body?.results)?r.body.results:[];
        for(const row of batch){const rr=results.find(x=>x.transactionId===row.id);if(rr?.status==='CONFLICT'){conflicts.push(row.id);continue;}if(rr&&['STORED','ALREADY_STORED'].includes(rr.status)){await idbDelete(row.id);sent++;}}
      }catch{break;}
    }
    const remaining=(await idbList(this.programId)).length;this.emit({state:remaining?'DEGRADED':'ONLINE',queueDepth:remaining});
    return{status:remaining?'PARTIAL':'OK',sent,remaining,conflicts};
  }
  async restore({since=null}={}){
    const q=new URLSearchParams({register_id:this.programId});if(since)q.set('since',since);
    const r=await this.request(`/sync/transactions?${q.toString()}`,{method:'GET'});
    const rows=Array.isArray(r.body?.transactions)?r.body.transactions:[];
    return rows.filter(x=>x?.payload?.kcFailover===true||x?.kcFailover===true).map(x=>x?.payload?.kcFailover===true?x.payload:x);
  }
  async reconcile(localOperationIds=[]){
    const r=await this.request('/sync/reconcile',{method:'POST',body:JSON.stringify({registerId:this.programId,transactionIds:[...new Set(localOperationIds.map(String))]})});
    return r.body;
  }
  async queueDepth(){return (await idbList(this.programId)).length;}
  async startAutoReplay({intervalMs=15000}={}){if(this._timer)return this._timer;const tick=async()=>{try{await this.replay();}catch{}};await tick();this._timer=setInterval(tick,Math.max(5000,intervalMs));return this._timer;}
  stopAutoReplay(){if(this._timer){clearInterval(this._timer);this._timer=null;}}
}

export function createKCFailoverClient(options){return new KCFailoverClient(options);}
export const KC_FAILOVER_VERSION='1.0.0';
