// Apple Inside Apps — server-only order API.
// Authenticates Telegram WebApp.initData using the official HMAC-SHA256 algorithm.
// No Apple Account credentials, payment details or activation codes are handled here.
const ALLOWED_ORIGIN = "https://ai-service-apps.github.io";
const encoder = new TextEncoder();

function headers() {
  return {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, apikey, Authorization",
    "Cache-Control": "no-store",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff"
  };
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: headers() });
}

async function hmac(keyBytes: Uint8Array, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function equalHex(a: string, b: string): boolean {
  if (!/^[0-9a-f]{64}$/i.test(a) || !/^[0-9a-f]{64}$/i.test(b)) return false;
  let diff = 0;
  for (let i = 0; i < 64; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function authenticate(initData: unknown): Promise<number | null> {
  const token = Deno.env.get("TELEGRAM_BOT_TOKEN");
  if (!token || typeof initData !== "string" || initData.length === 0 || initData.length > 8192) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get("hash") || "";
  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(authDate) || authDate > now + 60 || now - authDate > 86400) return null;
  const userRaw = params.get("user");
  if (!userRaw) return null;
  // The hash is excluded; Telegram's signature field is included when present.
  const dataCheck = Array.from(params.entries()).filter(([key]) => key !== "hash")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => key + "=" + value).join("\n");
  const secret = await hmac(encoder.encode("WebAppData"), token);
  const computed = hex(await hmac(secret, dataCheck));
  if (!equalHex(computed, hash.toLowerCase())) return null;
  try {
    const u = JSON.parse(userRaw);
    const id = Number(u.id);
    return Number.isSafeInteger(id) && id > 0 ? id : null;
  } catch (_) {
    return null;
  }
}

function dbHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!key) throw new Error("Server DB key unavailable");
  return { "apikey": key, "Authorization": "Bearer " + key, ...extra };
}

async function db(path: string, init?: RequestInit) {
  const url = Deno.env.get("SUPABASE_URL");
  if (!url) throw new Error("Project URL unavailable");
  const request = { ...(init || {}), headers: dbHeaders((init?.headers || {}) as Record<string, string>) };
  const res = await fetch(url + "/rest/v1/" + path, request);
  if (!res.ok) throw new Error("Database operation failed: " + res.status);
  return res.status === 204 ? null : await res.json();
}

function responseOrder(row: any) {
  const items = Array.isArray(row.app_order_items) ? row.app_order_items : [];
  return {
    id: row.id,
    status: row.status,
    created_at: row.created_at,
    apps: items.map((i: any) => i?.app_catalog?.title).filter((x: unknown) => typeof x === "string")
  };
}

async function listOrders(userId: number) {
  const data = await db("app_orders?select=id,status,created_at,app_order_items(app_catalog(title))&telegram_user_id=eq." +
    userId + "&order=created_at.desc&limit=30");
  return (data || []).map(responseOrder);
}

async function notify(order: any, titles: string[], userId: number) {
  const token = Deno.env.get("TELEGRAM_BOT_TOKEN");
  if (!token) return;
  const adminChatId = Deno.env.get("TELEGRAM_ADMIN_CHAT_ID");
  const messages: Array<{ chat_id: string | number; text: string }> = [
    { chat_id: userId, text: "Apple Inside Apps\n\nЗаявка принята: " + order.id.slice(0, 8).toUpperCase() +
      "\n" + titles.join(", ") + "\n\nСтоимость и доступность уточняются. Оплата пока не требуется." }
  ];
  if (adminChatId && /^-?\d+$/.test(adminChatId)) {
    messages.push({ chat_id: adminChatId, text: "Новая заявка Apple Inside Apps\n" + order.id +
      "\nTelegram ID: " + userId + "\nПриложения: " + titles.join(", ") });
  }
  for (const message of messages) {
    try {
      await fetch("https://api.telegram.org/bot" + token + "/sendMessage", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(message), signal: AbortSignal.timeout(5000)
      });
    } catch (_) { /* Notifications are best-effort; orders remain saved. */ }
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: headers() });
  if (req.method !== "GET" && req.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED" }, 405);
  // Restrict browser origins; Telegram HMAC validates the actual user identity.
  const origin = req.headers.get("Origin");
  if (origin && origin !== ALLOWED_ORIGIN) return json({ error: "ORIGIN_NOT_ALLOWED" }, 403);
  try {
    if (req.method === "GET") {
      const apps = await db("app_catalog?select=slug,title,category,description,is_available&order=title.asc");
      return json({ ok: true, apps, configured: Boolean(Deno.env.get("TELEGRAM_BOT_TOKEN")) });
    }
    const body = await req.json().catch(() => null);
    if (!body || typeof body !== "object") return json({ error: "INVALID_JSON" }, 400);
    const botToken = Deno.env.get("TELEGRAM_BOT_TOKEN");
    if (!botToken) return json({ error: "BOT_TOKEN_NOT_CONFIGURED" }, 503);
    const userId = await authenticate(body.init_data);
    if (userId === null) return json({ error: "INVALID_TELEGRAM_AUTH" }, 401);
    if (body.action === "my_orders") return json({ ok: true, orders: await listOrders(userId) });

    if (body.action !== "create_order") return json({ error: "UNKNOWN_ACTION" }, 400);
    const slugs: unknown = body.app_slugs;
    const requestKey: unknown = body.request_key;
    if (!Array.isArray(slugs) || slugs.length < 1 || slugs.length > 12 ||
      slugs.some((x) => typeof x !== "string" || !/^[a-z0-9_-]{2,64}$/.test(x)) ||
      new Set(slugs).size !== slugs.length ||
      typeof requestKey !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestKey))
      return json({ error: "INVALID_ORDER" }, 400);

    // A request identifier prevents duplicate orders when a client retries.
    const existing = await db("app_orders?select=id,status,created_at,app_order_items(app_catalog(title))&telegram_user_id=eq." +
      userId + "&request_key=eq." + requestKey + "&limit=1");
    if (existing?.length) return json({ ok: true, order: responseOrder(existing[0]), duplicate: true });

    const recent = await db("app_orders?select=id&telegram_user_id=eq." + userId +
      "&created_at=gte." + encodeURIComponent(new Date(Date.now() - 3600_000).toISOString()) + "&limit=6");
    if (recent.length >= 5) return json({ error: "RATE_LIMIT" }, 429);

    const catalog = await db("app_catalog?select=id,slug,title&slug=in.(" + (slugs as string[]).join(",") + ")");
    if (catalog.length !== slugs.length) return json({ error: "UNKNOWN_APP" }, 400);
    const titles = catalog.map((x: any) => x.title as string);

    const created = await db("app_orders?select=id,status,created_at", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Prefer": "return=representation" },
      body: JSON.stringify({ telegram_user_id: userId, status: "new", request_key: requestKey })
    });
    const order = created?.[0];
    if (!order?.id) throw new Error("Missing saved order ID");
    try {
      await db("app_order_items", {
        method: "POST", headers: { "Content-Type": "application/json", "Prefer": "return=minimal" },
        body: JSON.stringify(catalog.map((x: any) => ({ order_id: order.id, app_id: x.id })))
      });
    } catch (e) {
      await db("app_orders?id=eq." + order.id, { method: "DELETE" }).catch(() => {});
      throw e;
    }
    await notify(order, titles, userId);
    return json({ ok: true, order: { id: order.id, status: order.status, created_at: order.created_at, apps: titles } }, 201);
  } catch (e) {
    console.error("apps-orders: operation failed", String(e).slice(0, 160));
    return json({ error: "SERVER_ERROR", message: "Не удалось обработать запрос. Попробуйте позже." }, 500);
  }
});
