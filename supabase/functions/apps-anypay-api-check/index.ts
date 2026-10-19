// Apple Inside Apps — read-only AnyPay API authorization probe.
// Never exposes credentials, transaction identifiers, balances, or payment records.
// Requests are capped to one provider call per five minutes (DB atomic limit).
const MERCHANT_ID="18580";
function json(x:unknown,status=200){return new Response(JSON.stringify(x),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}})}
async function digest(x:string){
 const v=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(x));
 return Array.from(new Uint8Array(v),b=>b.toString(16).padStart(2,"0")).join("");
}
Deno.serve(async(req:Request)=>{
 if(req.method!=="GET")return json({error:"METHOD_NOT_ALLOWED"},405);
 const apiId=Deno.env.get("ANYPAY_API_ID")?.trim(),apiKey=Deno.env.get("ANYPAY_API_KEY")?.trim();
 if(!apiId||!apiKey)return json({ok:false,api_configured:false,api_authenticated:false,error:"API_CREDENTIALS_MISSING",missing_secret_names:[...(!apiId?["ANYPAY_API_ID"]:[]),...(!apiKey?["ANYPAY_API_KEY"]:[])]},503);
 if(!/^[a-zA-Z0-9_-]{8,96}$/.test(apiId))return json({ok:false,api_configured:true,api_authenticated:false,error:"INVALID_API_ID_FORMAT"},503);
 // Detect accidental copying of masked stars from AnyPay's readonly password field.
 // This examines secret bytes locally; neither key values nor lengths are disclosed.
 if(/[\u002a\u2022\u25cf\u00b7\u2026]/.test(apiKey))
  return json({ok:false,api_configured:true,api_authenticated:false,error:"MASKED_API_KEY_SAVED_IN_SUPABASE"},503);
 if(apiKey.length<16||apiKey.length>512)
  return json({ok:false,api_configured:true,api_authenticated:false,error:"API_KEY_FORMAT_SUSPICIOUS"},503);

 const serviceKey=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),base=Deno.env.get("SUPABASE_URL");
 if(!serviceKey||!base)return json({error:"SERVER_UNAVAILABLE"},503);
 try{
  const claim=await fetch(base+"/rest/v1/rpc/web_app_claim_provider_api_check",{
   method:"POST",headers:{"Content-Type":"application/json","apikey":serviceKey,"Authorization":"Bearer "+serviceKey},
   body:"{}",signal:AbortSignal.timeout(4000)
  });
  if(!claim.ok)return json({error:"PROBE_LOCK_UNAVAILABLE"},503);
  if(await claim.json()!==true)return json({ok:false,api_configured:true,rate_limited:true,message:"Повторная проверка доступна не чаще одного раза в 5 минут."},429);
  // Authentication health check uses AnyPay's dedicated READ-ONLY balance API.
  // An empty payment list is legitimate and must not be mistaken for bad credentials.
  // SHA256("balance" + API_ID + API_KEY) is the published API scheme.
  const sign=await digest("balance"+apiId+apiKey);
  const url=new URL("https://anypay.io/api/balance/"+encodeURIComponent(apiId));
  url.searchParams.set("sign",sign);
  const remote=await fetch(url.toString(),{method:"GET",redirect:"error",signal:AbortSignal.timeout(7000),
    headers:{"accept":"application/json"},cache:"no-store"});
  if(!remote.ok)return json({ok:false,api_configured:true,api_authenticated:false,provider_http_status:remote.status,error:"PROVIDER_HTTP_ERROR"},502);
  const raw=await remote.text();
  if(raw.length>100000)return json({ok:false,api_configured:true,api_authenticated:false,error:"UNEXPECTED_PROVIDER_RESPONSE"},502);
  let parsed:any;try{parsed=JSON.parse(raw)}catch(_){return json({ok:false,api_configured:true,api_authenticated:false,error:"PROVIDER_NOT_JSON"},502)}
  // Return only a limited, allow-listed error code and response structure.
  // Never forward account balance, payment records, error messages, API keys.
  const errorCode=parsed?.error&&typeof parsed.error==="object"?parsed.error.code:null;
  const sanitizedCode=typeof errorCode==="number"&&Number.isInteger(errorCode)&&errorCode>=1&&errorCode<=99999?errorCode:
    typeof errorCode==="string"&&/^[0-9]{1,5}$/.test(errorCode)?errorCode:null;
  if(parsed?.error!=null)return json({ok:false,api_configured:true,api_authenticated:false,
    error:"PROVIDER_REJECTED_CREDENTIALS_OR_REQUEST",...(sanitizedCode!=null?{provider_error_code:sanitizedCode}:{})},502);
  const result=parsed?.result;
  // An account may have zero funds; zero is still a valid response.
  const balance=(result&&typeof result==="object"&&!Array.isArray(result))?result.balance:undefined;
  const balanceIsValid=
    (typeof balance==="number"&&Number.isFinite(balance)&&balance>=0)||
    (typeof balance==="string"&&/^\d+(?:\.\d{1,8})?$/.test(balance))||
    (balance&&typeof balance==="object"&&!Array.isArray(balance)&&Object.keys(balance).length<=100);
  if(!balanceIsValid)return json({ok:false,api_configured:true,api_authenticated:false,
    error:"BALANCE_RESPONSE_SCHEMA_UNEXPECTED",
    response_structure:{
      top_level_result_type:result===null?"null":Array.isArray(result)?"array":typeof result,
      result_has_balance:balance!==undefined,
      balance_type:balance===null?"null":Array.isArray(balance)?"array":typeof balance
    }},502);
  return json({ok:true,merchant_id:MERCHANT_ID,api_configured:true,api_authenticated:true,
    verification_method:"signed_read_only_balance",read_only:true,payments_enabled:false});
 }catch(_){return json({ok:false,api_configured:true,api_authenticated:false,error:"PROVIDER_UNREACHABLE"},503)}
});