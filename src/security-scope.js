function validRegisterId(value){return /^[A-Za-z0-9._:-]{3,100}$/.test(String(value||''));}
function deny(code,status=403){return {ok:false,status,code};}
function allow(){return {ok:true};}
function parseBody(bodyText){try{return JSON.parse(bodyText||'{}')}catch{return null}}

export function authorizeDeviceScope(auth,request){
  if(!auth?.ok)return deny('AUTH_REQUIRED',401);
  const registerId=String(auth.registerId||'');
  if(!validRegisterId(registerId))return deny('DEVICE_REGISTER_UNBOUND');
  const url=new URL(request.url);
  const path=url.pathname;

  if(path==='/sync/transactions'&&request.method==='GET'){
    const requested=String(url.searchParams.get('register_id')||'');
    if(!validRegisterId(requested))return deny('INVALID_REGISTER_ID',400);
    return requested===registerId?allow():deny('REGISTER_SCOPE_VIOLATION');
  }

  if(request.method==='POST'){
    const body=parseBody(auth.bodyText);
    if(!body)return deny('INVALID_JSON',400);
    if(path==='/sync/transaction'){
      const requested=String(body.transaction?.registerId||'');
      if(!validRegisterId(requested))return deny('INVALID_REGISTER_ID',400);
      return requested===registerId?allow():deny('REGISTER_SCOPE_VIOLATION');
    }
    if(path==='/sync/batch'){
      if(!Array.isArray(body.transactions)||!body.transactions.length)return deny('INVALID_BATCH_SIZE',400);
      for(const row of body.transactions){
        const requested=String(row?.registerId||'');
        if(!validRegisterId(requested))return deny('INVALID_REGISTER_ID',400);
        if(requested!==registerId)return deny('REGISTER_SCOPE_VIOLATION');
      }
      return allow();
    }
    if(path==='/sync/reconcile'){
      const requested=String(body.registerId||'');
      if(!validRegisterId(requested))return deny('INVALID_REGISTER_ID',400);
      return requested===registerId?allow():deny('REGISTER_SCOPE_VIOLATION');
    }
  }
  return allow();
}

export const scopeConstants=Object.freeze({registerIdPattern:'^[A-Za-z0-9._:-]{3,100}$'});
