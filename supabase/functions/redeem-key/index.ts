// Edge Function: redeem a premium key for a registered device. Rate-limited per IP.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const j = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });
Deno.serve(async (req) => {
  if (req.method !== "POST") return j({ error: "method" }, 405);
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
  const { data: ok } = await db.rpc("rate_limit_hit", { p_bucket: "key:" + ip, p_max: 10, p_window_seconds: 3600 });
  if (!ok) return j({ error: "RATE_LIMITED" }, 429);
  let body: { code?: string; device_id?: string };
  try { body = await req.json(); } catch { return j({ error: "json" }, 400); }
  const { data, error } = await db.rpc("redeem_premium_key", { p_code: (body.code ?? "").slice(0, 64), p_device: body.device_id });
  if (error) return j({ error: error.message }, 403);
  return j({ premium_until: data });
});
