// CardLink callback URLs for the external Apple Inside Apps checkout.
// Fail-closed bootstrap: receives payment notifications but never grants access
// until an order-binding / reconciliation flow has been reviewed and enabled.
// User browser redirects are not proof of payment.
import { createHash, timingSafeEqual } from "node:crypto";

const CHECKOUT = "https://ai-service-apps.github.io/apps/docs/checkout/";
const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
};
const asJson = (data: unknown, code=200) => new Response(JSON.stringify(data), {status:code,headers:JSON_HEADERS});

function constantTimeMatch(expected: string, received: string): boolean {
  if (!/^[A-F0-9]{32}$/i.test(expected) || !/^[A-F0-9]{32}$/i.test(received)) return false;
  const a = Buffer.from(expected.toUpperCase(), "ascii");
  const b = Buffer.from(received.toUpperCase(), "ascii");
  return a.length === b.length && timingSafeEqual(a,b);
}

Deno.serve(async(req:Request)=>{
  const url = new URL(req.url);
  const mode = url.searchParams.get("mode");
  if (mode === "success" || mode === "fail") {
    if (req.method !== "GET" && req.method !== "POST") return asJson({error:"METHOD_NOT_ALLOWED"},405);
    // POST redirects use 303, forcing browser navigation via GET.
    // The success page explicitly DOES NOT grant access based on redirect.
    return new Response(null,{status:303,headers:{
      Location: CHECKOUT + (mode==="success"?"success.html":"fail.html"),
      "Cache-Control":"no-store",
      "Referrer-Policy":"no-referrer"
    }});
  }
  if(mode === "health" && req.method === "GET") return asJson({ok:true,accepting_payments:false});
  if(mode !== "result") return asJson({error:"UNKNOWN_MODE"},404);
  if(req.method !== "POST") return asJson({error:"METHOD_NOT_ALLOWED"},405);

  const token = Deno.env.get("CARDLINK_API_TOKEN");
  if(!token) return asJson({error:"INTEGRATION_NOT_CONFIGURED"},503);
  const contentType=(req.headers.get("content-type")||"").split(";")[0].trim().toLowerCase();
  if(contentType!=="application/x-www-form-urlencoded") return asJson({error:"UNSUPPORTED_MEDIA_TYPE"},415);
  const raw=await req.text();
  if(raw.length>8192) return asJson({error:"PAYLOAD_TOO_LARGE"},413);
  const fields=new URLSearchParams(raw);
  if(new Set(fields.keys()).size!==Array.from(fields.keys()).length) return asJson({error:"INVALID_PAYLOAD"},400);
  const amount=fields.get("OutSum")||"", invoice=fields.get("InvId")||"", signature=fields.get("SignatureValue")||"";
  if(!amount||!invoice||!signature||!/^\\d+(?:\\.\\d+)?$/.test(amount)||invoice.length>128) return asJson({error:"INVALID_PAYLOAD"},400);
  const expected=createHash("md5").update(amount+":"+invoice+":"+token).digest("hex").toUpperCase();
  if(!constantTimeMatch(expected,signature)) return asJson({error:"INVALID_SIGNATURE"},401);

  // No order or money change here: never trust signed callback alone without
  // matching a server-created invoice, amount, currency, shop, status and unique transaction.
  // Return 503 so CardLink can retry while the integration is under construction.
  return asJson({error:"PAYMENT_PROCESSING_NOT_ENABLED"},503);
});
