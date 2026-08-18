const MAX_POST_BYTES = 256 * 1024;
const MAX_URL_LENGTH = 2048;
const MAX_QUERY_LENGTH = 1500;
const BURST_WINDOW_MS = 60_000;
const BURST_LIMIT = 120;
const MAX_BURST_BUCKETS = 5000;
const buckets = new Map();

function nowMs(){ return Date.now(); }
function cleanup(now){
  for(const [key,b] of buckets){ if(now-b.startedAt>BURST_WINDOW_MS*2) buckets.delete(key); }
  while(buckets.size>MAX_BURST_BUCKETS){ const oldest=buckets.keys().next().value; if(oldest===undefined)break; buckets.delete(oldest); }
}
function headerLength(request,name){
  const raw=request.headers.get(name);
  if(raw==null) return null;
  const n=Number(raw);
  return Number.isFinite(n)&&n>=0?n:null;
}
function preAuthBucketKey(request){
  const ip=String(request.headers.get('cf-connecting-ip')||request.headers.get('x-forwarded-for')||'unknown').split(',')[0].trim();
  return `ip:${ip.slice(0,128)}`;
}
export function validateRequestEnvelope(request){
  const url=new URL(request.url);
  if(request.url.length>MAX_URL_LENGTH) return {ok:false,status:414,code:'URI_TOO_LONG'};
  if(url.search.length>MAX_QUERY_LENGTH) return {ok:false,status:414,code:'QUERY_TOO_LONG'};
  const allowedMethods=new Set(['GET','POST','OPTIONS']);
  if(!allowedMethods.has(request.method)) return {ok:false,status:405,code:'METHOD_NOT_ALLOWED'};
  if(request.method==='POST'){
    const type=(request.headers.get('content-type')||'').toLowerCase();
    if(!type.startsWith('application/json')) return {ok:false,status:415,code:'JSON_REQUIRED'};
    const len=headerLength(request,'content-length');
    if(len!==null&&len>MAX_POST_BYTES) return {ok:false,status:413,code:'PAYLOAD_TOO_LARGE'};
  }
  return {ok:true};
}
export async function enforceBodyLimit(request){
  if(request.method!=='POST') return {ok:true};
  const buf=await request.clone().arrayBuffer();
  if(buf.byteLength>MAX_POST_BYTES) return {ok:false,status:413,code:'PAYLOAD_TOO_LARGE'};
  return {ok:true};
}
export function enforceBurstLimit(request){
  const now=nowMs(); cleanup(now);
  const key=preAuthBucketKey(request);
  let bucket=buckets.get(key);
  if(!bucket||now-bucket.startedAt>=BURST_WINDOW_MS){bucket={startedAt:now,count:0};buckets.set(key,bucket);}
  bucket.count+=1;
  if(bucket.count>BURST_LIMIT) return {ok:false,status:429,code:'RATE_LIMITED',retryAfter:Math.max(1,Math.ceil((BURST_WINDOW_MS-(now-bucket.startedAt))/1000))};
  return {ok:true,remaining:Math.max(0,BURST_LIMIT-bucket.count)};
}
export function getBurstBucketCount(){ return buckets.size; }
export const abuseConstants=Object.freeze({MAX_POST_BYTES,MAX_URL_LENGTH,MAX_QUERY_LENGTH,BURST_WINDOW_MS,BURST_LIMIT,MAX_BURST_BUCKETS});
