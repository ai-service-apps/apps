// Apple Inside Apps: read-only provider transactions API diagnostic.
// Returns response shape only. NEVER returns payment records, sums, contacts, or credentials.
// Independent of checkout. Does not mark orders paid or grant delivery.
const MERCHANT_ID="18580";
const BASE="https://anypay.io/api/payments/";
const te=new TextEncoder();
function json(value:unknown,status=200) {
  return new Response(JSON.stringify(value),{status,headers:{
    "Content-Type":"application/json; charset=utf-8",
    "Cache-Control":"no-store",
    "X-Content-Type-Options":"nosniff"
  }});
}
async function digest(x:string) {
  const bytes=await crypto.subtle.digest("SHA-256",te.encode(x));
  return Array.from(new Uint8Array(bytes),v=>v.toString(16).padStart(2,"0")).join("");
}
Deno.serve(async(req:Request)=>{
  if(req.method!=="GET")return json({error:"METHOD_NOT_ALLOWED"},405);
  const apiId=Deno.env.get("ANYPAY_API_ID")?.trim();
  const apiKey=Deno.env.get("ANYPAY_API_KEY")?.trim();
  if(!apiId||!apiKey||!/^[a-zA-Z0-9_-]{8,96}$/.test(apiId))
    return json({ok:false,api_authenticated:false,error:"API_CREDENTIALS_UNAVAILABLE"},503);
  const serviceKey=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const dbUrl=Deno.env.get("SUPABASE_URL");
  if(!serviceKey||!dbUrl)return json({error:"SERVER_UNAVAILABLE"},503);
  try {
    const claim=await fetch(dbUrl+"/rest/v1/rpc/web_app_claim_provider_api_check",{
      method:"POST",headers:{"Content-Type":"application/json",
        apikey:serviceKey,Authorization:"Bearer "+serviceKey},
      body:"{}",signal:AbortSignal.timeout(5000)
    });
    if(!claim.ok)return json({error:"API_CHECK_LIMIT_UNAVAILABLE"},503);
    if(await claim.json()!==true)return json({ok:false,rate_limited:true,
      message:"Provider API checks are limited to one per 5 minutes"},429);

    const sign=await digest("payments"+apiId+MERCHANT_ID+apiKey);
    const endpoint=new URL(BASE+encodeURIComponent(apiId));
    endpoint.searchParams.set("project_id",MERCHANT_ID);
    endpoint.searchParams.set("sign",sign);
    const response=await fetch(endpoint.toString(),{
      method:"GET",redirect:"error",
      headers:{"Accept":"application/json"},
      cache:"no-store",signal:AbortSignal.timeout(7000)
    });
    if(!response.ok)return json({ok:false,provider_http_status:response.status,
      error:"PROVIDER_HTTP_ERROR"},502);
    const raw=await response.text();
    if(raw.length>500000)return json({ok:false,error:"RESPONSE_TOO_LARGE"},503);
    let payload:any;
    try{payload=JSON.parse(raw)}catch(_){return json({ok:false,error:"PROVIDER_NOT_JSON"},502)}
    if(payload?.error!=null) {
      const providerCode=payload.error?.code;
      const safeCode=typeof providerCode==="number"&&Number.isInteger(providerCode)&&providerCode>=0&&providerCode<=9999?providerCode:
        typeof providerCode==="string"&&/^\d{1,4}$/.test(providerCode)?providerCode:null;
      return json({ok:false,error:"PROVIDER_REJECTED_PAYMENT_QUERY",
        ...(safeCode!==null?{provider_error_code:safeCode}:{})},502);
    }
    const data=payload?.result;
    if(data==null||typeof data!=="object"||Array.isArray(data)||!("payments" in data))
      return json({ok:false,error:"PAYMENTS_RESULT_SCHEMA_UNKNOWN",
        result_kind:data===null?"null":Array.isArray(data)?"array":typeof data},502);
    const records=data.payments;
    const shape=records===null?"empty":Array.isArray(records)?"array":
      typeof records==="object"&&!Array.isArray(records)?"object":"unknown";
    if(shape==="unknown")return json({ok:false,error:"PAYMENTS_LIST_SCHEMA_UNKNOWN"},502);
    // No transaction data and no count are returned.
    return json({ok:true,merchant_id:MERCHANT_ID,api_authenticated:true,
      payments_list_accessible:true,records_shape:shape,
      read_only:true,real_payment_settlement_enabled:false});
  }catch(_){return json({ok:false,error:"PROVIDER_UNAVAILABLE"},503)}
});