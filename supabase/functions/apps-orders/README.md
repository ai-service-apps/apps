# apps-orders Edge Function

Path: `/functions/v1/apps-orders`. Custom authentication: Telegram WebApp `initData` HMAC SHA-256 with `TELEGRAM_BOT_TOKEN`.

- `GET` returns a public preview catalog and the boolean `configured`.
- `POST {"action":"create_order","init_data":"...","request_key":"uuid","app_slugs":["sber"]}` checks Telegram signature (24h age), validates catalog IDs, rate-limits to five/hour per Telegram user, inserts a new order and items, and sends confirmation to user.
- `POST {"action":"my_orders","init_data":"..."}` lists only the authenticated user's orders.

The function is deployed with `verify_jwt=false` **because Telegram's own server-verified HMAC is used instead**. Never trust client-supplied Telegram IDs. Database tables are private (RLS enabled, anon/authenticated grants revoked).

## Configuration
In Supabase Apple Inside Apps → Edge Functions → Secrets, add:
- `TELEGRAM_BOT_TOKEN` = token from BotFather. **Never place in GitHub, web files or chat.**
- Optional `TELEGRAM_ADMIN_CHAT_ID` = verified chat ID where new order notices should arrive; admin must have started the bot.

`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected into hosted functions.

Orders are non-paying requests; price/stock are unconfirmed. Do not treat these as paid orders. No Apple Account passwords or 2FA codes handled.

For stronger resilience before production, add database-side atomic order creation and server-side payment verification; account for simultaneous request races in rate limiting.
