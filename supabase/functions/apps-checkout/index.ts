// Apple Inside Apps — server-priced checkout draft API.
// FAIL-CLOSED: no payment URL or delivery is ever released by this function.
// Live checkout requires BOTH a later reviewed DB migration and independently verified
// distribution permissions for every app.
// Protected by strict origin validation plus Supabase's service-only RPC grants.
const MERCHANT_ID = 18580;
const ORIGIN = "https://serene-cannoli-abc049.netlify.app";
const textEncoder = new TextEncoder();
function heads(){return{
  "Content-Type":"application/json; charset=utf-8",
  "Cache-Control":"no-store",
  "Access-Control-Allow-Origin":ORIGIN,
  "Access-Control-Allow-Methods":"GET,POST,OPTIONS",
  "Access-Control-Allow-Headers":"Content-Type",
  "X-Content-Type-Options":"nosniff",
  "Referrer-Policy":"no-referrer",
  "Vary":"Origin",
}}
function json(x:unknown,status=200){
  return new Response(JSON.stringify(x),{status,headers:heads()});
}
function dbHeaders(){
 const key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 if(!key)throw Error("Missing database service credentials");
 return {"apikey":key,"Authorization":"Bearer "+key};
}
async function db(path:string,init:RequestInit={}) {
 const url=Deno.env.get("SUPABASE_URL");
 if(!url)throw Error("Missing database URL");
 const h={...dbHeaders(),...((init.headers||{}) as Record<string,string>)};
 const r=await fetch(url+"/rest/v1/"+path,{...init,headers:h});
 if(!r.ok)throw Error("Database API "+r.status);
 return r.json();
}
async function sha256(x:string){
 const digest=await crypto.subtle.digest("SHA-256",textEncoder.encode(x));
 return Array.from(new Uint8Array(digest),v=>v.toString(16).padStart(2,"0")).join("");
}
Deno.serve(async (req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:heads()});
 if(req.headers.get("Origin")&&req.headers.get("Origin")!==ORIGIN)
   return json({error:"ORIGIN_NOT_ALLOWED"},403);
 if(req.method==="GET")return json({
   ok:true,service:"apps-checkout",merchant_id:MERCHANT_ID,
   checkout_enabled:false,real_payments_enabled:false
 });
 if(req.method!=="POST")return json({error:"METHOD_NOT_ALLOWED"},405);
 if(Number(req.headers.get("content-length")||0)>2048)
   return json({error:"REQUEST_TOO_LARGE"},413);
 let body;
 try{body=await req.json()}catch(_){return json({error:"INVALID_JSON"},400)}
 const apps=body?.slugs;
 if(!Array.isArray(apps) || apps.length<1 || apps.length>5 ||
    apps.some(x=>typeof x!=="string" || !/^[a-z0-9_-]{2,40}$/.test(x)) ||
    new Set(apps).size!==apps.length) return json({error:"INVALID_SELECTION"},400);
 try {
   // This must be checked on the server, not based on disabled site buttons.
   const gates=await db("web_app_payment_controls?select=checkout_enabled,real_payments_enabled&merchant_id=eq."+MERCHANT_ID);
   if(gates?.length!==1 || !gates[0].checkout_enabled || !gates[0].real_payments_enabled)
     return json({error:"CHECKOUT_NOT_ENABLED",message:"Оплата пока недоступна."},409);

   // No cost or title is ever accepted from the browser; the RPC calculates
   // full price from catalog and individually approved distribution rights.
   const token=Array.from(crypto.getRandomValues(new Uint8Array(32)),
     x=>x.toString(16).padStart(2,"0")).join("");
   const hash=await sha256(token);
   const rows=await db("rpc/web_app_create_draft",{
     method:"POST",headers:{"Content-Type":"application/json"},
     body:JSON.stringify({p_slugs:apps,p_access_token_sha256:hash})
   });
   if(!Array.isArray(rows)||rows.length!==1)throw Error("ORDER_CREATION_FAILED");
   const order=rows[0];
   // No payment link is issued until provider API credentials & status
   // re-verification are implemented and the gate is unlocked.
   return json({ok:true,order_id:order.order_id,
      merchant_order_no:order.merchant_order_no,
      total_rub:order.total_rub,currency:"RUB",
      private_access_token:token,
      payment_url:null,payment_ready:false});
 }catch(_){return json({error:"CHECKOUT_UNAVAILABLE"},503)}
});
