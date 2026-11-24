// Edge Function: register a device. Rate-limited per client IP. Deploy only after owner approval.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const j = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });
Deno.serve(async (req) => {
  if (req.method !== "POST") return j({ error: "method" }, 405);
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
  const { data: ok } = await db.rpc("rate_limit_hit", { p_bucket: "reg:" + ip, p_max: 10, p_window_seconds: 3600 });
  if (!ok) return j({ error: "RATE_LIMITED" }, 429);
  let body: { invite_code?: string; hardware_id_hash?: string };
  try { body = await req.json(); } catch { return j({ error: "json" }, 400); }
  if (!/^[0-9a-f]{64}$/.test(body.hardware_id_hash ?? "")) return j({ error: "hardware_id_hash must be sha256 hex" }, 400);
  const { data, error } = await db.rpc("register_device", { p_invite_code: (body.invite_code ?? "").slice(0, 64), p_hardware_id_hash: body.hardware_id_hash });
  if (error) return j({ error: error.message }, 403);
  return j({ device_id: data });
});
