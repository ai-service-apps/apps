// AnyPay callback endpoint: bootstrap only, intentionally fails closed.
// Project: Apple Inside Apps (merchant_id 18580).
// This endpoint MUST NOT mark orders paid or release IPA manifests, credentials,
// or Apple Account data until an authenticated payment-intent ledger is deployed.
// Docs: https://anypay.io/doc/sci/notification
const PROJECT_ID = "18580";
const encoder = new TextEncoder();

const headers = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
};

function json(body: Record<string, unknown>, code = 200) {
  return new Response(JSON.stringify(body), { status: code, headers });
}

async function sha256Hex(value: string): Promise<string> {
  const hashed = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(hashed), x => x.toString(16).padStart(2, "0")).join("");
}

function constantTimeSame(a: string, b: string): boolean {
  if (!/^[a-f0-9]{64}$/i.test(a) || !/^[a-f0-9]{64}$/i.test(b)) return false;
  let diff = 0;
  const left = a.toLowerCase();
  const right = b.toLowerCase();
  for (let i = 0; i < 64; i++) diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return diff === 0;
}

async function fieldsFromRequest(req: Request): Promise<Map<string, string>> {
  const ct = (req.headers.get("content-type") ?? "").split(";")[0].toLowerCase().trim();
  const result = new Map<string,string>();
  if (ct === "application/json") {
    const body = await req.json();
    if (!body || Array.isArray(body) || typeof body !== "object")
      throw Error("INVALID_PAYLOAD");
    for (const [name, value] of Object.entries(body)) {
      if (typeof value !== "string" && typeof value !== "number") continue;
      result.set(name, String(value));
    }
    return result;
  }
  if (ct === "application/x-www-form-urlencoded" || ct === "") {
    const raw = await req.text();
    if (raw.length > 8192) throw Error("PAYLOAD_TOO_LARGE");
    const p = new URLSearchParams(raw);
    for (const [k,v] of p.entries()) {
      if (result.has(k)) throw Error("DUPLICATE_PARAMETER");
      result.set(k,v);
    }
    return result;
  }
  if (ct === "multipart/form-data") {
    const form = await req.formData();
    for (const [k,v] of form.entries()) {
      if (result.has(k) || typeof v !== "string") throw Error("INVALID_FORM_FIELD");
      result.set(k,v);
    }
    return result;
  }
  throw Error("UNSUPPORTED_MEDIA_TYPE");
}

Deno.serve(async (req: Request) => {
  if (req.method === "GET") return json({
    ok: true,
    service: "AnyPay callback",
    merchant_id: PROJECT_ID,
    configured: Boolean(Deno.env.get("ANYPAY_PROJECT_SECRET")),
    payments_enabled: false,
  });
  if (req.method !== "POST") return json({error:"METHOD_NOT_ALLOWED"},405);
  const contentLength = Number(req.headers.get("content-length") || "0");
  if (contentLength > 8192) return json({error:"PAYLOAD_TOO_LARGE"},413);

  const secret = Deno.env.get("ANYPAY_PROJECT_SECRET")?.trim();
  if (!secret) return json({error:"NOT_CONFIGURED"},503);

  let p: Map<string,string>;
  try { p = await fieldsFromRequest(req); }
  catch (_) { return json({error:"INVALID_PAYLOAD"},400); }

  const merchantId = p.get("merchant_id") ?? "";
  const currency = p.get("currency") ?? "";
  const amount = p.get("amount") ?? "";
  const payId = p.get("pay_id") ?? "";
  const status = p.get("status") ?? "";
  const signature = p.get("sign") ?? "";
  const test = p.get("test") ?? "";

  if (merchantId !== PROJECT_ID || currency !== "RUB" ||
    !/^\d+(?:\.\d{1,2})?$/.test(amount) ||
    !/^[0-9]{1,15}$/.test(payId) ||
    !/^[a-z-]{2,24}$/.test(status) ||
    !/^[0-9a-f]{64}$/i.test(signature)) {
    return json({error:"INVALID_NOTIFICATION"},400);
  }

  // The SHA256 recipe must match the toggle in AnyPay project settings.
  const expected = await sha256Hex([
    currency, amount, payId, merchantId, status, secret
  ].join(":"));
  if (!constantTimeSame(expected, signature)) return json({error:"INVALID_SIGNATURE"},401);

  // This is NOT enough to credit an order: do not trust callback alone.
  // Next stage must confirm payId belongs to a server-created intent,
  // exact price and currency match, status === "paid", test === "0",
  // transaction_id is unique, and payment belongs to this project.
  // Then perform an idempotent transaction BEFORE replying with "OK".
  // AnyPay test tool sends signed `test=1` notifications. Acknowledge only a
  // correctly signed, paid-status simulation with plain "OK" as AnyPay requires.
  // NEVER create an order, set paid_at, or release app files for test traffic.
  if (test === "1" && status === "paid") {
    // Record the signed AnyPay simulation exactly once. It is never a paid order.
    // The test flag is NOT covered by the AnyPay signature, so we do not use
    // this audit as evidence for a real payment.
    const dbUrl = Deno.env.get("SUPABASE_URL");
    const dbKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!dbUrl || !dbKey) return json({error:"AUDIT_NOT_CONFIGURED"},503);
    const fingerprint = await sha256Hex([
      merchantId,currency,Number(amount).toFixed(2),payId,status,
      signature.toLowerCase(),"test=1"
    ].join("|"));
    try {
      const response = await fetch(dbUrl+
        "/rest/v1/web_app_payment_events?on_conflict=notification_fingerprint",{
        method:"POST",
        headers:{
          apikey:dbKey,Authorization:"Bearer "+dbKey,
          "Content-Type":"application/json",
          Prefer:"resolution=ignore-duplicates,return=minimal"
        },
        body:JSON.stringify({
          merchant_id:Number(merchantId),
          merchant_order_no:Number(payId),
          currency,amount_rub:Number(amount),provider_status:status,
          is_test:true,signature_valid:true,confirmed_with_provider:false,
          notification_fingerprint:fingerprint
        })
      });
      if(!response.ok)return json({error:"TEST_AUDIT_UNAVAILABLE"},503);
    }catch(_){return json({error:"TEST_AUDIT_UNAVAILABLE"},503)}
    return new Response("OK", {
      status: 200,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }
  if (status !== "paid" || test !== "0")
    return json({error:"NOT_REAL_COMPLETED_PAYMENT"},409);
  // A real callback is NEVER sufficient to credit an order. Independently
  // check a server-created unpaid order against AnyPay's read-only payments API.
  // Unknown provider schema, missing transaction ID, or conflicting records
  // => fail closed. This code has NO database payment-write path.
  const apiId=Deno.env.get("ANYPAY_API_ID")?.trim();
  const apiKey=Deno.env.get("ANYPAY_API_KEY")?.trim();
  const dbUrl=Deno.env.get("SUPABASE_URL");
  const dbKey=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if(!apiId||!apiKey||!dbUrl||!dbKey)
    return json({error:"INDEPENDENT_VERIFICATION_NOT_CONFIGURED"},503);
  if(!/^[A-Za-z0-9_-]{8,96}$/.test(apiId))
    return json({error:"API_ID_INVALID"},503);
  const dbHeaders={
    apikey:dbKey,Authorization:"Bearer "+dbKey,"Accept":"application/json"
  };
  const numericId=Number(payId);
  if(!Number.isSafeInteger(numericId)||numericId<1)return json({error:"INVALID_ORDER_ID"},400);
  const cents=(s:string):bigint|null=>{
    if(!/^\d{1,10}(?:\.\d{1,2})?$/.test(s))return null;
    const [a,b=""]=s.split(".");
    return BigInt(a)*100n+BigInt((b+"00").slice(0,2));
  };
  const expectedCents=cents(amount);
  if(expectedCents===null)return json({error:"INVALID_AMOUNT"},400);

  let internalOrder:any;
  try{
    const rowsRes=await fetch(dbUrl+"/rest/v1/web_app_orders?select=id,merchant_order_no,total_rub,currency,status,provider,paid_at,expires_at&merchant_order_no=eq."+numericId+"&limit=1",{
      method:"GET",headers:dbHeaders,signal:AbortSignal.timeout(6000)
    });
    if(!rowsRes.ok)return json({error:"ORDER_LOOKUP_UNAVAILABLE"},503);
    const rows=await rowsRes.json();
    internalOrder=rows?.[0];
  }catch(_){return json({error:"ORDER_LOOKUP_UNAVAILABLE"},503)}
  if(!internalOrder||internalOrder.status!=="awaiting_payment"
    ||internalOrder.provider!=="anypay"||internalOrder.paid_at!==null
    ||Date.parse(internalOrder.expires_at)<=Date.now()
    ||internalOrder.currency!=="RUB"
    ||BigInt(internalOrder.total_rub)*100n!==expectedCents)
    return json({error:"ORDER_NOT_PAYABLE_OR_AMOUNT_MISMATCH"},409);

  const verifiedSign=await sha256Hex("payments"+apiId+PROJECT_ID+apiKey);
  const providerURL=new URL("https://anypay.io/api/payments/"+encodeURIComponent(apiId));
  providerURL.searchParams.set("project_id",PROJECT_ID);
  providerURL.searchParams.set("sign",verifiedSign);
  let providerRows:any[];
  try{
    const res=await fetch(providerURL.toString(),{
      method:"GET",redirect:"error",signal:AbortSignal.timeout(7000),
      cache:"no-store",headers:{"Accept":"application/json"}
    });
    if(!res.ok)return json({error:"PROVIDER_VERIFICATION_UNAVAILABLE"},503);
    const raw=await res.text();
    if(raw.length>500000)return json({error:"PROVIDER_RESPONSE_TOO_LARGE"},503);
    const decoded=JSON.parse(raw);
    const collection=decoded?.result?.payments;
    if(decoded?.error!=null||!collection||typeof collection!=="object")
      return json({error:"PROVIDER_SCHEMA_UNCONFIRMED"},503);
    providerRows=Array.isArray(collection)?collection:Object.values(collection);
    if(providerRows.length>10000)return json({error:"PROVIDER_RESULT_TOO_LARGE"},503);
  }catch(_){return json({error:"PROVIDER_VERIFICATION_UNAVAILABLE"},503)}
  const matches=providerRows.filter(v=>
    v&&typeof v==="object"&&String(v.pay_id)===String(numericId));
  if(matches.length!==1)return json({error:"PAYMENT_NOT_CONFIRMED_IN_PROVIDER"},503);
  const payment=matches[0];
  // Require all critical fields, including a stable unique provider record ID.
  // If AnyPay changes its API schema, this deliberately rejects the event.
  const txn=String(payment.id??"");
  const txnMoney=cents(String(payment.amount??""));
  if(!/^[A-Za-z0-9_-]{1,96}$/.test(txn)
    || payment.status!=="paid"
    || payment.currency!=="RUB"
    || txnMoney===null||txnMoney!==expectedCents
    || (payment.project_id!=null&&String(payment.project_id)!==PROJECT_ID)
    || (payment.test!=null&&String(payment.test)!=="0"))
    return json({error:"PROVIDER_PAYMENT_MISMATCH"},503);
  // Confirm items sum too; the internal server must have priced this order.
  try{
    const ir=await fetch(dbUrl+"/rest/v1/web_app_order_items?select=unit_price_rub&order_id=eq."+internalOrder.id,{
      headers:dbHeaders,signal:AbortSignal.timeout(6000)
    });
    if(!ir.ok)return json({error:"ORDER_LINES_UNAVAILABLE"},503);
    const items=await ir.json();
    const total=items.reduce((s:number,x:any)=>s+Number(x.unit_price_rub),0);
    if(!items.length||!Number.isSafeInteger(total)||total!==internalOrder.total_rub)
      return json({error:"ORDER_LINES_MISMATCH"},409);
  }catch(_){return json({error:"ORDER_LINES_UNAVAILABLE"},503)}
  // Independent verification exists; atomic real settlement remains locked
  // pending provider test, rights review, and controlled production enablement.
  return json({error:"REAL_PAYMENT_SETTLEMENT_DISABLED"},503);
});
