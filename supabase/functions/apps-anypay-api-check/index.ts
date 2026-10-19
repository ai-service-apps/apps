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
 const serviceKey=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),base=Deno.env.get("SUPABASE_URL");
 if(!serviceKey||!base)return json({error:"SERVER_UNAVAILABLE"},503);
 try{
  const claim=await fetch(base+"/rest/v1/rpc/web_app_claim_provider_api_check",{
   method:"POST",headers:{"Content-Type":"application/json","apikey":serviceKey,"Authorization":"Bearer "+serviceKey},
   body:"{}",signal:AbortSignal.timeout(4000)
  });
  if(!claim.ok)return json({error:"PROBE_LOCK_UNAVAILABLE"},503);
  if(await claim.json()!==true)return json({ok:false,api_configured:true,rate_limited:true,message:"Повторная проверка доступна не чаще одного раза в 5 минут."},429);
  const sign=await digest("payments"+apiId+MERCHANT_ID+apiKey);
  const url=new URL("https://anypay.io/api/payments/"+encodeURIComponent(apiId));
  url.searchParams.set("project_id",MERCHANT_ID);
  url.searchParams.set("sign",sign);
  const remote=await fetch(url.toString(),{method:"GET",redirect:"error",signal:AbortSignal.timeout(7000),
   headers:{"accept":"application/json"},cache:"no-store"});
  if(!remote.ok)return json({ok:false,api_configured:true,api_authenticated:false,provider_http_status:remote.status,error:"PROVIDER_HTTP_ERROR"},502);
  const raw=await remote.text();
  if(raw.length>500000)return json({ok:false,api_configured:true,api_authenticated:false,error:"UNEXPECTED_PROVIDER_RESPONSE"},502);
  let parsed:any;try{parsed=JSON.parse(raw)}catch(_){return json({ok:false,api_configured:true,api_authenticated:false,error:"PROVIDER_NOT_JSON"},502)}
  const data=parsed?.result;
  const valid=parsed?.error==null&&data&&typeof data==="object"&&!Array.isArray(data)&&
    (Array.isArray(data.payments)||(data.payments!==null&&typeof data.payments==="object"));
  // No data from the provider is ever forwarded to the public requester.
  if(!valid)return json({ok:false,api_configured:true,api_authenticated:false,error:"PROVIDER_REJECTED_OR_UNEXPECTED_SCHEMA"},502);
  return json({ok:true,merchant_id:MERCHANT_ID,api_configured:true,api_authenticated:true,read_only:true,payments_enabled:false});
 }catch(_){return json({ok:false,api_configured:true,api_authenticated:false,error:"PROVIDER_UNREACHABLE"},503)}
});