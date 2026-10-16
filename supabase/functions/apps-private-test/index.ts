// Apple Inside Apps — short-lived owner-only installation link test.
// This endpoint does NOT confirm payment and must never activate normal catalog delivery.
const ORIGIN="https://ai-service-apps.github.io";
const MANIFEST="https://raw.githubusercontent.com/ai-service-apps/apps/main/AppleID1-Karen/online.plist";
function headers(){return{"Content-Type":"application/json;charset=utf-8","Access-Control-Allow-Origin":ORIGIN,"Access-Control-Allow-Methods":"POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type","Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","Vary":"Origin"}}
function result(obj:unknown,code=200){return new Response(JSON.stringify(obj),{status:code,headers:headers()})}
async function hash(token:string){const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(token));return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("")}
async function query(path:string,init?:RequestInit){
 const u=Deno.env.get("SUPABASE_URL"),key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 if(!u||!key)throw new Error("CONFIG");
 const h={apikey:key,Authorization:"Bearer "+key,...((init?.headers||{}) as Record<string,string>)};
 const r=await fetch(u+"/rest/v1/"+path,{...init,headers:h});
 if(!r.ok)throw new Error("DB");
 const value=await r.text();return value?JSON.parse(value):null;
}
Deno.serve(async req=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:headers()});
 if(req.method!=="POST")return result({error:"METHOD_NOT_ALLOWED"},405);
 if(req.headers.get("Origin")&&req.headers.get("Origin")!==ORIGIN)return result({error:"ORIGIN_NOT_ALLOWED"},403);
 if(Number(req.headers.get("content-length")||"0")>1024)return result({error:"TOO_LARGE"},413);
 try{
  const b=await req.json();
  const token=b?.access_token;
  if(typeof token!=="string"|| !/^[0-9a-f]{64}$/.test(token) || b?.app_slug!=="sber")return result({error:"BAD_REQUEST"},400);
  const digest=await hash(token);
  const rows=await query("web_app_test_access?select=token_sha256,allowed_slug,expires_at,revoked,uses,max_uses&token_sha256=eq."+digest+"&limit=1");
  const permit=rows?.[0];
  if(!permit||permit.revoked||permit.allowed_slug!=="sber"||Date.parse(permit.expires_at)<=Date.now()||permit.uses>=permit.max_uses)return result({error:"TEST_ACCESS_EXPIRED"},403);
  const appRows=await query("app_catalog?select=slug,install_manifest_url&slug=eq.sber&limit=1");
  if(appRows?.[0]?.install_manifest_url!==MANIFEST)return result({error:"MANIFEST_NOT_APPROVED_FOR_TEST"},409);
  const nextCount=permit.uses+1;
  const changed=await query("web_app_test_access?token_sha256=eq."+digest+"&uses=eq."+permit.uses+"&select=token_sha256",{
    method:"PATCH",headers:{"Content-Type":"application/json","Prefer":"return=representation"},
    body:JSON.stringify({uses:nextCount})
  });
  if(!changed?.length)return result({error:"RETRY"},409);
  return result({ok:true,app_slug:"sber",title:"СберБанк Онлайн",install_url:"itms-services://?action=download-manifest&url="+encodeURIComponent(MANIFEST),test_only:true,expires_at:permit.expires_at});
 }catch(_){return result({error:"TEST_UNAVAILABLE"},503)}
});
