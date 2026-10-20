// Apple Inside Apps — single invitation-only owner pilot for 500 RUB.
// Payment link is signed server-side from a pre-created order. Never marks paid,
// publishes IPA files, or exposes Apple Account credentials.
// Real public checkout remains disabled and does not use this endpoint.
const PROJECT_ID="18580";
const T_ORIGIN="https://serene-cannoli-abc049.netlify.app";
const BASE="https://anypay.io/merchant";
const enc=new TextEncoder();
function j(body:unknown,status=200){return new Response(JSON.stringify(body),{status,headers:{
 "Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",
 "Access-Control-Allow-Origin":T_ORIGIN,"Access-Control-Allow-Methods":"POST,OPTIONS",
 "Access-Control-Allow-Headers":"Content-Type","X-Content-Type-Options":"nosniff",
 "Referrer-Policy":"no-referrer","Vary":"Origin"
}})}
async function digest(x:string){const d=await crypto.subtle.digest("SHA-256",enc.encode(x));
 return Array.from(new Uint8Array(d),v=>v.toString(16).padStart(2,"0")).join("")}
async function db(path:string){
 const u=Deno.env.get("SUPABASE_URL");
 const k=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 if(!u||!k)throw Error("SERVER_CONFIG_MISSING");
 const r=await fetch(u+"/rest/v1/"+path,{method:"GET",signal:AbortSignal.timeout(5500),
   headers:{apikey:k,Authorization:"Bearer "+k,Accept:"application/json"}});
 if(!r.ok)throw Error("DB_UNAVAILABLE");
 return await r.json();
}
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:{
  "Access-Control-Allow-Origin":T_ORIGIN,"Access-Control-Allow-Methods":"POST,OPTIONS",
  "Access-Control-Allow-Headers":"Content-Type","Vary":"Origin"
 }});
 if(req.method!=="POST")return j({error:"METHOD_NOT_ALLOWED"},405);
 if(req.headers.get("Origin")!==T_ORIGIN)return j({error:"ORIGIN_FORBIDDEN"},403);
 if(Number(req.headers.get("content-length")||0)>1024)return j({error:"TOO_LARGE"},413);
 let b:any;
 try{b=await req.json()}catch(_){return j({error:"INVALID_JSON"},400)}
 const token=b?.token,action=b?.action;
 if(typeof token!=="string"||!/^[a-f0-9]{64}$/.test(token)||
   !["start","status","invoice"].includes(action))return j({error:"INVALID_REQUEST"},400);
 try{
  // The invitation is created by the owner in Supabase Secrets.
  // Neither the token nor the expected secret is ever returned to the browser.
  const expected=Deno.env.get("ANYPAY_PILOT_PASSPHRASE")?.trim();
  if(!expected||!/^[a-f0-9]{64}$/.test(expected))
    return j({error:"PILOT_INVITATION_NOT_CONFIGURED"},503);
  const hash=await digest(token);
  const expectedHash=await digest(expected);
  let mismatch=0;
  for(let i=0;i<64;i++)mismatch|=hash.charCodeAt(i)^expectedHash.charCodeAt(i);
  if(mismatch!==0)return j({error:"INVALID_INVITATION"},403);
  if(action==="start"){
    const key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),base=Deno.env.get("SUPABASE_URL");
    if(!key||!base)return j({error:"SERVER_CONFIG_MISSING"},503);
    const response=await fetch(base+"/rest/v1/rpc/web_app_start_owner_pilot",{
      method:"POST",signal:AbortSignal.timeout(7000),
      headers:{apikey:key,Authorization:"Bearer "+key,"Content-Type":"application/json"},
      body:JSON.stringify({p_token_sha256:hash})
    });
    if(!response.ok)return j({error:"PILOT_START_UNAVAILABLE"},503);
    const rows=await response.json();
    if(!Array.isArray(rows)||rows.length!==1||rows[0].total_rub!==500)
      return j({error:"PILOT_START_UNEXPECTED"},503);
    return j({ok:true,merchant_order_no:rows[0].merchant_order_no,
      total_rub:500,currency:"RUB",delivery_enabled:false});
  }
  const p=await db("web_app_payment_pilot?select=order_id,expires_at,is_active&pilot_id=eq.1&token_sha256=eq."+hash);
  if(!Array.isArray(p)||p.length!==1||!p[0].is_active||
     Date.parse(p[0].expires_at)<=Date.now())return j({error:"INVITATION_EXPIRED"},403);
  const os=await db("web_app_orders?select=id,merchant_order_no,total_rub,currency,status,paid_at,expires_at,provider&"+
    "id=eq."+encodeURIComponent(p[0].order_id)+"&limit=1");
  const o=os?.[0];
  if(!o||o.total_rub!==500||o.currency!=="RUB"||
      o.provider!=="anypay"||Date.parse(o.expires_at)<=Date.now())
     return j({error:"PILOT_ORDER_INVALID"},409);
  const result={ok:true,merchant_order_no:o.merchant_order_no,total_rub:500,currency:"RUB",
    payment_verified:o.status==="paid"&&Boolean(o.paid_at),
    delivery_enabled:false,public_checkout_enabled:false};
  if(action==="status")return j(result);
  if(o.status!=="awaiting_payment"||o.paid_at!==null)
     return j({error:"PILOT_NOT_PAYABLE"},409);
  const secret=Deno.env.get("ANYPAY_PROJECT_SECRET")?.trim();
  if(!secret)return j({error:"PROJECT_SECRET_MISSING"},503);
  // AnyPay project's SHA256 SCI setting, separate from its API key:
  // SHA256(currency:amount:project_secret:merchant_id:pay_id)
  const amount="500.00";
  const sign=await digest(["RUB",amount,secret,PROJECT_ID,String(o.merchant_order_no)].join(":"));
  const checkout=new URL(BASE);
  checkout.searchParams.set("merchant_id",PROJECT_ID);
  checkout.searchParams.set("pay_id",String(o.merchant_order_no));
  checkout.searchParams.set("amount",amount);
  checkout.searchParams.set("currency","RUB");
  checkout.searchParams.set("desc","Контрольная оплата услуги Apple Inside Apps");
  checkout.searchParams.set("sign",sign);
  return j({...result,payment_url:checkout.toString(),note:"Это реальная оплата 500 рублей. Возврат к пилоту не подтверждает оплату автоматически."});
 }catch(_){return j({error:"PILOT_SERVICE_UNAVAILABLE"},503)}
});