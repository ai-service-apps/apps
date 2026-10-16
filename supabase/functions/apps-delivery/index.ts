// Apple Inside Apps — protected web delivery and order completion.
// Authorization: 256-bit random bearer token in a private checkout link.
// Tokens are stored ONLY as SHA256 hashes in Postgres and never logged.
// This service never creates or marks payments as paid; AnyPay webhook must
// independently verify the original checkout, amount, currency, and status.
const ORIGIN = "https://ai-service-apps.github.io";
const enc = new TextEncoder();
function head(){
  return {
    "Access-Control-Allow-Origin":ORIGIN,
    "Access-Control-Allow-Methods":"GET,POST,OPTIONS",
    "Access-Control-Allow-Headers":"Content-Type",
    "Content-Type":"application/json; charset=utf-8",
    "Cache-Control":"no-store",
    "X-Content-Type-Options":"nosniff",
    "Referrer-Policy":"no-referrer",
    "Vary":"Origin"
  };
}
function json(x:unknown,status=200){return new Response(JSON.stringify(x),{status,headers:head()})}
function dbHeaders(extra:Record<string,string>={}){
  const key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if(!key)throw Error("Server DB key unavailable");
  return {apikey:key,Authorization:"Bearer "+key,...extra};
}
async function db(path:string,init?:RequestInit){
  const endpoint=Deno.env.get("SUPABASE_URL");
  if(!endpoint)throw Error("Server DB endpoint unavailable");
  const result=await fetch(endpoint+"/rest/v1/"+path,{
    ...init,headers:dbHeaders((init?.headers||{}) as Record<string,string>)
  });
  if(!result.ok){console.error("App delivery DB failure",{status:result.status});throw Error("DB_FAILED")}
  const body=await result.text();
  return body.trim()?JSON.parse(body):null;
}
async function sha256(x:string){
  const buffer=await crypto.subtle.digest("SHA-256",enc.encode(x));
  return Array.from(new Uint8Array(buffer),b=>b.toString(16).padStart(2,"0")).join("");
}
function cleanManifest(x:unknown):string|null{
  if(typeof x!=="string")return null;
  try{
    const url=new URL(x);
    if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash) return null;
    // The list is intentionally narrow. Add new hosts only after individual vetting.
    if(url.hostname!=="raw.githubusercontent.com" &&
       url.hostname!=="ai-service-apps.github.io")return null;
    if(url.hostname==="raw.githubusercontent.com" &&
       !url.pathname.startsWith("/ai-service-apps/apps/"))return null;
    return url.toString();
  }catch(_){return null}
}
type AppItem={app_id:string,marked_installed_at:string|null,app_catalog:{
 slug:string,title:string,is_available:boolean,requires_activation:boolean,install_manifest_url:string|null
}};
function allowedToDeliver(order:any,app:AppItem,approvals:Map<string,any>){
  if(!["paid","installing"].includes(order.status))return false;
  if(!order.paid_at)return false;
  if(!app.app_catalog?.is_available)return false;
  const license=approvals.get(app.app_id);
  if(!license?.enabled)return false;
  if(license.valid_until && Date.parse(license.valid_until)<=Date.now())return false;
  return Boolean(cleanManifest(app.app_catalog.install_manifest_url));
}
Deno.serve(async(req:Request)=>{
  if(req.method==="OPTIONS")return new Response(null,{status:204,headers:head()});
  if(req.headers.get("Origin")&&req.headers.get("Origin")!==ORIGIN)
    return json({error:"ORIGIN_NOT_ALLOWED"},403);
  if(req.method==="GET")return json({ok:true,service:"apps-delivery",payments_enabled:false,delivery_enabled:false});
  if(req.method!=="POST")return json({error:"METHOD_NOT_ALLOWED"},405);
  if(Number(req.headers.get("content-length")||"0")>4096)return json({error:"REQUEST_TOO_LARGE"},413);
  try{
    const b=await req.json();
    const token=b?.access_token;
    const action=b?.action;
    if(typeof token!=="string" || !/^[a-f0-9]{64}$/i.test(token) ||
      !["status","mark_installed","complete"].includes(action))return json({error:"INVALID_REQUEST"},400);
    const digest=await sha256(token);
    const rows=await db("web_app_orders?select=id,status,total_rub,currency,paid_at,expires_at,created_at&access_token_sha256=eq."+digest+"&limit=1");
    const order=rows?.[0];
    if(!order || Date.parse(order.expires_at)<=Date.now())return json({error:"ORDER_NOT_FOUND"},404);

    const items=(await db("web_app_order_items?select=app_id,marked_installed_at,app_catalog(slug,title,is_available,requires_activation,install_manifest_url)&order_id=eq."+order.id)) as AppItem[];
    const ids=items.map(x=>x.app_id).filter(x=>/^[0-9a-f-]{36}$/i.test(x));
    const licenses=ids.length?await db("app_distribution_approvals?select=app_id,enabled,valid_until&app_id=in.("+ids.join(",")+")"):[];
    const approvals=new Map((licenses||[]).map((x:any)=>[x.app_id,x]));
    const allReviewed=items.length>0 && items.every(item=>allowedToDeliver(order,item,approvals));
    const paid=Boolean(order.paid_at)&&["paid","installing","completed"].includes(order.status);
    if(action==="mark_installed"){
      if(!paid||!allReviewed||typeof b.app_id!=="string"||
        !items.some(x=>x.app_id===b.app_id))return json({error:"INSTALL_NOT_AVAILABLE"},409);
      const changed=await db("web_app_order_items?order_id=eq."+order.id+"&app_id=eq."+b.app_id+
        "&marked_installed_at=is.null&select=order_id",{
        method:"PATCH",
        headers:{"Content-Type":"application/json","Prefer":"return=representation"},
        body:JSON.stringify({marked_installed_at:new Date().toISOString()})
      });
      if(changed?.length){
        await db("web_app_order_events",{
          method:"POST",headers:{"Content-Type":"application/json","Prefer":"return=minimal"},
          body:JSON.stringify({order_id:order.id,event_type:"marked_installed",app_id:b.app_id})
        });
      }
    }
    if(action==="complete"){
      if(!paid||!allReviewed)return json({error:"INSTALL_NOT_AVAILABLE"},409);
      const latest=await db("web_app_order_items?select=marked_installed_at&order_id=eq."+order.id);
      if(!latest?.length||latest.some((x:any)=>!x.marked_installed_at))return json({error:"INSTALL_NOT_FINISHED"},409);
      const changed=await db("web_app_orders?select=id&status=in.(paid,installing)&id=eq."+order.id,{
        method:"PATCH",headers:{"Content-Type":"application/json","Prefer":"return=representation"},
        body:JSON.stringify({status:"completed",completed_at:new Date().toISOString()})
      });
      if(changed?.length)await db("web_app_order_events",{
        method:"POST",headers:{"Content-Type":"application/json","Prefer":"return=minimal"},
        body:JSON.stringify({order_id:order.id,event_type:"completed"})
      });
    }

    const finalOrder=(await db("web_app_orders?select=id,status,total_rub,currency,paid_at,created_at&access_token_sha256=eq."+digest+"&limit=1"))[0];
    const finalItems=(await db("web_app_order_items?select=app_id,marked_installed_at,app_catalog(slug,title,is_available,requires_activation,install_manifest_url)&order_id=eq."+order.id)) as AppItem[];
    // Completed orders do not need to reveal additional files; refresh before completion.
    const output=finalItems.map(item=>{
      const ok=allowedToDeliver(finalOrder,item,approvals);
      const manifest=ok?cleanManifest(item.app_catalog.install_manifest_url):null;
      return {
        id:item.app_id,slug:item.app_catalog.slug,title:item.app_catalog.title,
        installed:Boolean(item.marked_installed_at),
        needs_activation:Boolean(item.app_catalog.requires_activation),
        download_available:Boolean(manifest),
        install_url:manifest? "itms-services://?action=download-manifest&url="+encodeURIComponent(manifest):null
      };
    });
    return json({
      ok:true,
      order:{id:finalOrder.id,status:finalOrder.status,total_rub:finalOrder.total_rub,currency:finalOrder.currency},
      payment_confirmed:paid,
      download_available:paid&&allReviewed&&output.length>0,
      apps:output
    });
  }catch(_){
    console.error("App delivery processing failed");
    return json({error:"SERVICE_UNAVAILABLE"},503);
  }
});