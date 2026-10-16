// AnyPay callback endpoint: bootstrap only, intentionally fails closed.
// Project: Apple Inside Apps (merchant_id 18554).
// This endpoint MUST NOT mark orders paid or release IPA manifests, credentials,
// or Apple Account data until an authenticated payment-intent ledger is deployed.
// Docs: https://anypay.io/doc/sci/notification
const PROJECT_ID = "18554";
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
  if (status !== "paid" || test !== "0") return json({error:"NOT_REAL_COMPLETED_PAYMENT"},409);
  return json({error:"ORDER_LEDGER_NOT_CONFIGURED"},503);
});
