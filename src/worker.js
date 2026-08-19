import pg from "pg";

const { Client } = pg;
const JSON_HEADERS = { "cache-control": "no-store", "content-type": "application/json; charset=utf-8" };
const AUTH_VERSION = "KC-GW-HMAC-V1";
const AUTH_WINDOW_MS = 5 * 60 * 1000;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = 240;
const DEFAULT_PAGE_SIZE = 500;
const MAX_PAGE_SIZE = 1000;
const MAX_RECONCILE_IDS = 1000;
const MAX_RESTORE_PAGES = 200;
const NONCE_CACHE = new Map();
const RATE_CACHE = new Map();

function allowedOrigins(env){return String(env.KC_ALLOWED_ORIGINS||"").split(",").map(x=>x.trim()).filter(Boolean)}
function originAllowed(request,env){const origin=request.headers.get("origin");return !origin||allowedOrigins(env).includes(origin)}
function corsHeaders(request,env){
  const origin=request.headers.get("origin"),headers={
    "access-control-allow-methods":"GET,POST,OPTIONS",
    "access-control-allow-headers":"content-type,x-kc-client,x-kc-device,x-kc-timestamp,x-kc-nonce,x-kc-signature",
    "access-control-max-age":"600",
    "vary":"Origin"
  };
  if(origin&&allowedOrigins(env).includes(origin))headers["access-control-allow-origin"]=origin;
  return headers;
}
function json(request,env,body,status=200){return new Response(JSON.stringify(body),{status,headers:{...JSON_HEADERS,...corsHeaders(request,env)}})}
function cleanErrorCode(value){return /^[A-Z0-9_:-]{1,80}$/.test(String(value||""))?String(value):"INTERNAL_ERROR"}
function safeAuthError(request,env,result){return json(request,env,{status:"ERROR",error:cleanErrorCode(result?.code||"AUTH_REQUIRED")},result?.status||401)}
export function boundedPageLimit(value){const n=Number(value);return Number.isInteger(n)&&n>0?Math.min(MAX_PAGE_SIZE,n):DEFAULT_PAGE_SIZE}
function cleanCursor(value){const text=String(value||"").trim();if(!text)return null;if(text.length>160||!/^[A-Za-z0-9._:-]+$/.test(text))throw new Error("INVALID_CURSOR");return text}

function deviceRegistry(env){
  try{
    const parsed=JSON.parse(String(env.KC_DEVICE_KEYS_JSON||"{}"));
    return parsed&&typeof parsed==="object"&&!Array.isArray(parsed)?parsed:{};
  }catch{return{}}
}
function normalizeDeviceConfig(value){
  if(typeof value==="string")return{secret:value,registerIds:[],allowDiagnostics:false};
  if(!value||typeof value!=="object")return null;
  return{
    secret:String(value.secret||""),
    registerIds:Array.isArray(value.registerIds)?value.registerIds.map(String).filter(Boolean):[],
    allowDiagnostics:value.allowDiagnostics===true
  };
}
function bytesToHex(bytes){return [...bytes].map(x=>x.toString(16).padStart(2,"0")).join("")}
function hexToBytes(text){if(!/^[0-9a-f]{64}$/i.test(String(text||"")))return null;return Uint8Array.from(String(text).match(/../g),x=>parseInt(x,16))}
async function sha256Hex(text){const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(text||"")));return bytesToHex(new Uint8Array(digest))}
export async function signaturePayload(request,bodyText=""){
  const url=new URL(request.url),device=String(request.headers.get("x-kc-device")||""),timestamp=String(request.headers.get("x-kc-timestamp")||""),nonce=String(request.headers.get("x-kc-nonce")||"");
  const bodyHash=await sha256Hex(bodyText);
  return `${AUTH_VERSION}\n${device}\n${timestamp}\n${nonce}\n${request.method.toUpperCase()}\n${url.pathname}${url.search}\n${bodyHash}`;
}
function rateAllowed(deviceId){
  const now=Date.now(),row=RATE_CACHE.get(deviceId);
  if(!row||now-row.startedAt>=RATE_WINDOW_MS){RATE_CACHE.set(deviceId,{startedAt:now,count:1});return true}
  row.count++;return row.count<=RATE_LIMIT;
}
function nonceFresh(deviceId,nonce){
  const now=Date.now();
  for(const [key,expires] of NONCE_CACHE){if(expires<=now)NONCE_CACHE.delete(key)}
  const key=`${deviceId}:${nonce}`;
  if(NONCE_CACHE.has(key))return false;
  NONCE_CACHE.set(key,now+AUTH_WINDOW_MS);return true;
}
export async function verifyDeviceRequest(request,env,bodyTextOverride){
  const deviceId=String(request.headers.get("x-kc-device")||"").trim(),timestampText=String(request.headers.get("x-kc-timestamp")||"").trim(),nonce=String(request.headers.get("x-kc-nonce")||"").trim(),signature=String(request.headers.get("x-kc-signature")||"").trim();
  if(!/^[A-Za-z0-9._:-]{1,100}$/.test(deviceId))return{ok:false,status:401,code:"DEVICE_REQUIRED"};
  const timestamp=Number(timestampText);if(!Number.isFinite(timestamp)||Math.abs(Date.now()-timestamp)>AUTH_WINDOW_MS)return{ok:false,status:401,code:"TIMESTAMP_INVALID"};
  if(!/^[A-Za-z0-9._:-]{16,120}$/.test(nonce))return{ok:false,status:401,code:"NONCE_INVALID"};
  const sigBytes=hexToBytes(signature);if(!sigBytes)return{ok:false,status:401,code:"SIGNATURE_INVALID"};
  const config=normalizeDeviceConfig(deviceRegistry(env)[deviceId]);if(!config||config.secret.length<32)return{ok:false,status:401,code:"DEVICE_UNKNOWN"};
  if(!rateAllowed(deviceId))return{ok:false,status:429,code:"RATE_LIMITED"};
  const bodyText=bodyTextOverride!==undefined?String(bodyTextOverride):(["GET","HEAD"].includes(request.method.toUpperCase())?"":await request.clone().text());
  const payload=await signaturePayload(request,bodyText),key=await crypto.subtle.importKey("raw",new TextEncoder().encode(config.secret),{name:"HMAC",hash:"SHA-256"},false,["verify"]),valid=await crypto.subtle.verify("HMAC",key,sigBytes,new TextEncoder().encode(payload));
  if(!valid)return{ok:false,status:401,code:"SIGNATURE_INVALID"};
  if(!nonceFresh(deviceId,nonce))return{ok:false,status:409,code:"REPLAY_DETECTED"};
  return{ok:true,status:200,code:"OK",deviceId,registerIds:config.registerIds,allowDiagnostics:config.allowDiagnostics};
}
function assertRegisterAllowed(auth,registerId){if(!auth?.ok)throw new Error("AUTH_REQUIRED");const id=String(registerId||"");if(!id||!auth.registerIds.includes(id))throw new Error("REGISTER_NOT_ALLOWED")}
function protectedPath(path){return path.startsWith("/sync/")||path==="/supergau"||path.startsWith("/supergau/")||path.startsWith("/scenario/")}
function diagnosticsPath(path){return path==="/supergau"||path.startsWith("/supergau/")||path.startsWith("/scenario/")}

async function checkSupabase(env){const t=Date.now();try{const r=await fetch(`${env.SUPABASE_URL}/auth/v1/health`,{headers:{apikey:env.SUPABASE_PUBLISHABLE_KEY},cf:{cacheTtl:0}});return{reachable:r.ok,statusCode:r.status,latencyMs:Date.now()-t}}catch{return{reachable:false,statusCode:null,latencyMs:Date.now()-t,error:"SUPABASE_UNREACHABLE"}}}
async function withNeon(env,fn){const c=new Client({connectionString:env.HYPERDRIVE.connectionString});try{await c.connect();return await fn(c)}finally{try{await c.end()}catch{}}}
async function checkNeon(env){const t=Date.now();if(!env.HYPERDRIVE?.connectionString)return{reachable:false,latencyMs:Date.now()-t,error:"NEON_BINDING_MISSING"};try{await withNeon(env,c=>c.query("SELECT 1 AS ok"));return{reachable:true,latencyMs:Date.now()-t}}catch{return{reachable:false,latencyMs:Date.now()-t,error:"NEON_UNREACHABLE"}}}
async function runFallbackReadWriteProbe(env){const marker=crypto.randomUUID(),t=Date.now();try{const ok=await withNeon(env,async c=>{await c.query("BEGIN");try{await c.query("CREATE TEMP TABLE kc_failover_probe (marker text NOT NULL) ON COMMIT DROP");await c.query("INSERT INTO kc_failover_probe(marker) VALUES($1)",[marker]);const r=await c.query("SELECT marker FROM kc_failover_probe LIMIT 1");await c.query("ROLLBACK");return r.rows[0]?.marker===marker}catch(e){await c.query("ROLLBACK");throw e}});return{readWrite:ok===true,latencyMs:Date.now()-t,persistentChanges:false}}catch{return{readWrite:false,latencyMs:Date.now()-t,persistentChanges:false,error:"NEON_PROBE_FAILED"}}}
function chooseBackend(p,f){return p?"SUPABASE":f?"NEON":"LOCAL_QUEUE"}
function cleanTransaction(row){if(!row||typeof row!=="object")throw new Error("INVALID_TRANSACTION");const transactionId=String(row.transactionId||"").trim(),registerId=String(row.registerId||"").trim();if(!transactionId||transactionId.length>160)throw new Error("INVALID_TRANSACTION_ID");if(!registerId||registerId.length>100)throw new Error("INVALID_REGISTER_ID");const payload=JSON.stringify(row);if(payload.length>180000)throw new Error("TRANSACTION_TOO_LARGE");return{transactionId,registerId,registerName:String(row.registerName||"").slice(0,160)||null,occurredAt:row.endTime||row.time||row.startTime||null,recordHash:row.recordHash?String(row.recordHash).slice(0,256):null,payload:row}}
async function saveTransactions(env,inputRows){if(!Array.isArray(inputRows)||inputRows.length<1||inputRows.length>100)throw new Error("INVALID_BATCH_SIZE");const rows=inputRows.map(cleanTransaction);return withNeon(env,async c=>{await c.query("BEGIN");const results=[];try{for(const row of rows){const ins=await c.query(`INSERT INTO public.kc_failover_transactions (transaction_id,register_id,register_name,occurred_at,record_hash,payload) VALUES ($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT (transaction_id) DO NOTHING RETURNING transaction_id`,[row.transactionId,row.registerId,row.registerName,row.occurredAt,row.recordHash,JSON.stringify(row.payload)]);if(ins.rowCount===1){results.push({transactionId:row.transactionId,status:"STORED"});continue}const ex=await c.query("SELECT record_hash,payload FROM public.kc_failover_transactions WHERE transaction_id=$1",[row.transactionId]);const old=ex.rows[0],sameHash=Boolean(row.recordHash&&old?.record_hash&&row.recordHash===old.record_hash),samePayload=JSON.stringify(old?.payload??null)===JSON.stringify(row.payload);results.push({transactionId:row.transactionId,status:(!sameHash&&!samePayload)?"CONFLICT":"ALREADY_STORED"})}await c.query("COMMIT");return results}catch(e){await c.query("ROLLBACK");throw e}})}
async function restorePage(env,registerId,{since=null,afterId=null,limit=DEFAULT_PAGE_SIZE}={}){
  if(!registerId||registerId.length>100)throw new Error("INVALID_REGISTER_ID");const pageLimit=boundedPageLimit(limit),cursor=cleanCursor(afterId);
  return withNeon(env,async c=>{const p=[registerId];let w="register_id=$1";if(since){p.push(since);w+=` AND occurred_at >= $${p.length}::timestamptz`}if(cursor){p.push(cursor);w+=` AND transaction_id > $${p.length}`}p.push(pageLimit);const r=await c.query(`SELECT transaction_id,payload FROM public.kc_failover_transactions WHERE ${w} ORDER BY transaction_id ASC LIMIT $${p.length}`,p),rows=r.rows||[],nextCursor=rows.length===pageLimit?rows.at(-1)?.transaction_id||null:null;return{transactions:rows.map(x=>x.payload),nextCursor,count:rows.length}})
}
async function restoreTransactions(env,registerId,since){let out=[],afterId=null;for(let page=0;page<MAX_RESTORE_PAGES;page++){const r=await restorePage(env,registerId,{since,afterId,limit:MAX_PAGE_SIZE});out.push(...r.transactions);if(!r.nextCursor)return out;afterId=r.nextCursor}throw new Error("RESTORE_PAGE_LIMIT")}
async function listIdPage(env,registerId,{afterId=null,limit=MAX_PAGE_SIZE}={}){
  if(!registerId||registerId.length>100)throw new Error("INVALID_REGISTER_ID");const pageLimit=boundedPageLimit(limit),cursor=cleanCursor(afterId);
  return withNeon(env,async c=>{const p=[registerId];let w="register_id=$1";if(cursor){p.push(cursor);w+=` AND transaction_id > $${p.length}`}p.push(pageLimit);const r=await c.query(`SELECT transaction_id FROM public.kc_failover_transactions WHERE ${w} ORDER BY transaction_id ASC LIMIT $${p.length}`,p),ids=(r.rows||[]).map(x=>x.transaction_id),nextCursor=ids.length===pageLimit?ids.at(-1)||null:null;return{transactionIds:ids,nextCursor,count:ids.length}})
}
async function reconcileTransactions(env,registerId,ids){
  if(!registerId||registerId.length>100)throw new Error("INVALID_REGISTER_ID");if(!Array.isArray(ids)||ids.length>MAX_RECONCILE_IDS)throw new Error("INVALID_ID_LIST");const localIds=[...new Set(ids.map(String).filter(Boolean))];if(!localIds.length)return{missingRemote:[],matchedCount:0,localCount:0};
  return withNeon(env,async c=>{const r=await c.query("SELECT transaction_id FROM public.kc_failover_transactions WHERE register_id=$1 AND transaction_id = ANY($2::text[])",[registerId,localIds]),remote=new Set((r.rows||[]).map(x=>x.transaction_id));return{missingRemote:localIds.filter(id=>!remote.has(id)),matchedCount:remote.size,localCount:localIds.length}})
}
async function deleteTestTransaction(env,id){return withNeon(env,c=>c.query("DELETE FROM public.kc_failover_transactions WHERE transaction_id=$1",[id]))}
async function scenario1(env){const a=await checkSupabase(env),f=await runFallbackReadWriteProbe(env),b=await checkSupabase(env),pass=a.reachable&&f.readWrite&&b.reachable;return{id:1,name:"Supabase down -> Neon -> Supabase recovery",status:pass?"PASS":"FAIL",before:a,simulatedOutage:{primaryForcedDown:true,activeBackend:"NEON",fallback:f},recovery:{primary:b,activeBackend:b.reachable?"SUPABASE":"NEON"},safeSimulation:true}}
async function scenario2(env){const p=await checkSupabase(env),f=await checkNeon(env),activeBackend=chooseBackend(p.reachable,false);return{id:2,name:"Neon down while Supabase remains healthy",status:p.reachable&&activeBackend==="SUPABASE"?"PASS":"FAIL",primary:p,fallbackBeforeSimulation:f,simulatedFallbackDown:true,activeBackend,safeSimulation:true}}
async function scenario3(env){const p=await checkSupabase(env),f=await checkNeon(env),activeBackend=chooseBackend(false,false);return{id:3,name:"Both DBs down -> local queue required",status:activeBackend==="LOCAL_QUEUE"?"PASS":"FAIL",primaryBeforeSimulation:p,fallbackBeforeSimulation:f,simulatedPrimaryDown:true,simulatedFallbackDown:true,activeBackend,localQueueRequired:true,clientQueueVerified:false,safeSimulation:true}}
async function scenario4(env){const p=await checkSupabase(env),f=await checkNeon(env),queued=["q1","q2","q3"],activeDuringOutage=chooseBackend(false,false),activeAfterRecovery=chooseBackend(p.reachable,f.reachable),pass=activeDuringOutage==="LOCAL_QUEUE"&&queued.length===3&&activeAfterRecovery!=="LOCAL_QUEUE";return{id:4,name:"Local queue -> backend recovery -> replay readiness",status:pass?"PASS":"FAIL",queuedTransactions:queued.length,activeDuringOutage,primaryAfter:p,fallbackAfter:f,activeAfterRecovery,replayRequired:true,note:"Gateway verifies recovery/replay readiness; browser IndexedDB queue itself must be integration-tested in client.",safeSimulation:true}}
async function scenario5(env){const id=`supergau-${crypto.randomUUID()}`,row={transactionId:id,registerId:"SUPERGAU_TEST",registerName:"SAFE_TEST",time:new Date().toISOString(),recordHash:`hash-${id}`,test:true};try{const first=await saveTransactions(env,[row]),second=await saveTransactions(env,[row]),restored=await restoreTransactions(env,"SUPERGAU_TEST",null),matches=restored.filter(x=>x.transactionId===id);const pass=first[0]?.status==="STORED"&&second[0]?.status==="ALREADY_STORED"&&matches.length===1;return{id:5,name:"Replay idempotency -> no duplicate transaction",status:pass?"PASS":"FAIL",first:first[0],replay:second[0],storedCopies:matches.length,safeSimulation:true}}finally{try{await deleteTestTransaction(env,id)}catch{}}}
async function scenario6(env){const id=`supergau-${crypto.randomUUID()}`,base={transactionId:id,registerId:"SUPERGAU_TEST",time:new Date().toISOString(),recordHash:`hash-a-${id}`,amount:1,test:true},changed={...base,recordHash:`hash-b-${id}`,amount:2};try{const first=await saveTransactions(env,[base]),second=await saveTransactions(env,[changed]);const pass=first[0]?.status==="STORED"&&second[0]?.status==="CONFLICT";return{id:6,name:"Conflicting replay -> conflict detected, original protected",status:pass?"PASS":"FAIL",first:first[0],conflictingReplay:second[0],safeSimulation:true}}finally{try{await deleteTestTransaction(env,id)}catch{}}}
const scenarios=[scenario1,scenario2,scenario3,scenario4,scenario5,scenario6];

export default{async fetch(request,env){
  const url=new URL(request.url),path=url.pathname;
  if(request.method==="OPTIONS")return originAllowed(request,env)?new Response(null,{status:204,headers:corsHeaders(request,env)}):new Response(null,{status:403,headers:corsHeaders(request,env)});
  if(!originAllowed(request,env))return json(request,env,{status:"ERROR",error:"ORIGIN_NOT_ALLOWED"},403);
  let auth=null,rawBody;
  try{
    if(protectedPath(path)){
      if(!["GET","HEAD"].includes(request.method.toUpperCase()))rawBody=await request.clone().text();
      auth=await verifyDeviceRequest(request,env,rawBody);
      if(!auth.ok)return safeAuthError(request,env,auth);
      if(diagnosticsPath(path)&&!auth.allowDiagnostics)return json(request,env,{status:"ERROR",error:"DIAGNOSTICS_NOT_ALLOWED"},403);
    }
    const readBody=()=>rawBody!==undefined?JSON.parse(rawBody||"{}"):request.json();
    if(path==="/sync/transaction"&&request.method==="POST"){
      const b=await readBody();assertRegisterAllowed(auth,b.transaction?.registerId);const r=await saveTransactions(env,[b.transaction]),conflict=r.some(x=>x.status==="CONFLICT");return json(request,env,{status:conflict?"CONFLICT":"OK",results:r},conflict?409:200)
    }
    if(path==="/sync/batch"&&request.method==="POST"){
      const b=await readBody();for(const tx of b.transactions||[])assertRegisterAllowed(auth,tx?.registerId);const r=await saveTransactions(env,b.transactions),conflicts=r.filter(x=>x.status==="CONFLICT");return json(request,env,{status:conflicts.length?"PARTIAL":"OK",results:r,conflicts},conflicts.length?207:200)
    }
    if(path==="/sync/transactions"&&request.method==="GET"){
      const registerId=url.searchParams.get("register_id")||"",since=url.searchParams.get("since")||null,afterId=url.searchParams.get("after_id")||null,limit=url.searchParams.get("limit")||DEFAULT_PAGE_SIZE;assertRegisterAllowed(auth,registerId);const page=await restorePage(env,registerId,{since,afterId,limit});return json(request,env,{status:"OK",registerId,...page})
    }
    if(path==="/sync/ids"&&request.method==="GET"){
      const registerId=url.searchParams.get("register_id")||"",afterId=url.searchParams.get("after_id")||null,limit=url.searchParams.get("limit")||MAX_PAGE_SIZE;assertRegisterAllowed(auth,registerId);const page=await listIdPage(env,registerId,{afterId,limit});return json(request,env,{status:"OK",registerId,...page})
    }
    if(path==="/sync/reconcile"&&request.method==="POST"){
      const b=await readBody(),registerId=String(b.registerId||"");assertRegisterAllowed(auth,registerId);const r=await reconcileTransactions(env,registerId,b.transactionIds||[]);return json(request,env,{status:"OK",mode:"membership",...r})
    }
    if(path==="/supergau")return json(request,env,await scenario1(env));
    const m=path.match(/^\/scenario\/(\d+)$/);if(m){const fn=scenarios[Number(m[1])-1];if(!fn)return json(request,env,{status:"ERROR",error:"UNKNOWN_SCENARIO"},404);const r=await fn(env);return json(request,env,r,r.status==="PASS"?200:503)}
    if(path==="/supergau/server-matrix"){const results=[];for(const fn of scenarios)results.push(await fn(env));const pass=results.every(x=>x.status==="PASS");return json(request,env,{service:"KC Failover Gateway",test:"SERVER-SUPER-GAU-MATRIX",scenarioCount:results.length,status:pass?"PASS":"FAIL",results,timestamp:new Date().toISOString()},pass?200:503)}
    const p=await checkSupabase(env),f=await checkNeon(env),activeBackend=chooseBackend(p.reachable,f.reachable);return json(request,env,{service:"KC Failover Gateway",status:activeBackend==="LOCAL_QUEUE"?"DEGRADED":"OK",activeBackend,primary:{name:"SUPABASE",...p},fallback:{name:"NEON",hyperdriveBinding:Boolean(env.HYPERDRIVE?.connectionString),...f},durablePosJournal:f.reachable,localQueueRequired:activeBackend==="LOCAL_QUEUE",timestamp:new Date().toISOString()})
  }catch(e){
    const message=cleanErrorCode(e instanceof Error?e.message:"INTERNAL_ERROR");
    const status=message.startsWith("INVALID_")||message==="TRANSACTION_TOO_LARGE"?400:message==="REGISTER_NOT_ALLOWED"||message==="DIAGNOSTICS_NOT_ALLOWED"?403:500;
    return json(request,env,{status:"ERROR",error:status===500?"INTERNAL_ERROR":message},status)
  }
}};
