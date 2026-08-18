import worker from './worker.js';
import { authenticateRequest, allowedOrigin, corsHeaders } from './security.js';
import { resolveDeviceFromStore, reserveNonceInStore, purgeExpiredNonces, consumeRateLimitInStore, purgeStaleRateLimits } from './security-store.js';
import { authorizeDeviceScope } from './security-scope.js';
import { validateRequestEnvelope, enforceBodyLimit, enforceBurstLimit } from './security-abuse.js';

const PROTECTED_PREFIXES=['/sync/'];
function isProtected(pathname){return PROTECTED_PREFIXES.some(prefix=>pathname.startsWith(prefix));}
function securityJson(request,env,body,status,extraHeaders={}){return new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...corsHeaders(request,env),...extraHeaders}});}
function secureResponse(request,env,response){
  const headers=new Headers(response.headers);headers.delete('access-control-allow-origin');headers.delete('access-control-allow-credentials');headers.set('vary','Origin');
  const origin=allowedOrigin(request,env);if(origin)headers.set('access-control-allow-origin',origin);
  headers.set('x-content-type-options','nosniff');headers.set('referrer-policy','no-referrer');headers.set('permissions-policy','camera=(), microphone=(), geolocation=()');headers.set('content-security-policy',"default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  headers.set('cross-origin-resource-policy','same-site');
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
}

export default {
  async fetch(request,env,ctx){
    const url=new URL(request.url);const origin=request.headers.get('origin');
    const envelope=validateRequestEnvelope(request);
    if(!envelope.ok)return securityJson(request,env,{status:'ERROR',error:envelope.code},envelope.status,envelope.status===405?{'allow':'GET, POST, OPTIONS'}:{});
    if(request.method==='OPTIONS'){
      if(origin&&!allowedOrigin(request,env))return securityJson(request,env,{status:'ERROR',error:'ORIGIN_NOT_ALLOWED'},403);
      return new Response(null,{status:204,headers:corsHeaders(request,env)});
    }
    if(origin&&!allowedOrigin(request,env))return securityJson(request,env,{status:'ERROR',error:'ORIGIN_NOT_ALLOWED'},403);

    if(isProtected(url.pathname)){
      const bodyLimit=await enforceBodyLimit(request);
      if(!bodyLimit.ok)return securityJson(request,env,{status:'ERROR',error:bodyLimit.code},bodyLimit.status);
      const burst=enforceBurstLimit(request);
      if(!burst.ok)return securityJson(request,env,{status:'ERROR',error:burst.code},burst.status,{'retry-after':String(burst.retryAfter||60)});
      const useDurableStore=String(env.KC_SECURITY_STORE_MODE||'durable').toLowerCase()==='durable';
      const auth=await authenticateRequest(request,env,useDurableStore?{
        deviceResolver:(deviceId)=>resolveDeviceFromStore(env,deviceId),
        replayStore:(nonce)=>reserveNonceInStore(env,nonce)
      }:{});
      if(!auth.ok)return securityJson(request,env,{status:'ERROR',error:auth.code},auth.status);
      if(useDurableStore){
        let durableRate;
        try{durableRate=await consumeRateLimitInStore(env,{deviceId:auth.deviceId,windowSeconds:60,limit:120});}
        catch{return securityJson(request,env,{status:'ERROR',error:'SECURITY_STORE_UNAVAILABLE'},503);}
        if(!durableRate.ok)return securityJson(request,env,{status:'ERROR',error:'RATE_LIMITED'},429,{'retry-after':String(durableRate.retryAfter||60)});
      }
      const scope=authorizeDeviceScope(auth,request);
      if(!scope.ok)return securityJson(request,env,{status:'ERROR',error:scope.code},scope.status);
      if(Math.random()<0.01 && ctx?.waitUntil){
        ctx.waitUntil(Promise.allSettled([
          purgeExpiredNonces(env,{limit:500}),
          purgeStaleRateLimits(env,{olderThanSeconds:3600,limit:500})
        ]));
      }
    }
    const response=await worker.fetch(request,env,ctx);return secureResponse(request,env,response);
  }
};
