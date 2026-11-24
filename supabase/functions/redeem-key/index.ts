// Edge Function: redeem a premium key for a registered device. Rate-limited per IP.
// Hardened: F9 (spoof-proof IP), F10 (no internal error leakage), strict contract mapping.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const j = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });

function clientIp(req: Request): string {
  const cf = req.headers.get("cf-connecting-ip");
  if (cf) return cf.trim();
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1];
  }
  return "unknown";
}

const CONTRACT_ERRORS = new Set(["KEY_INVALID", "DEVICE_INVALID"]);
function mapDbError(msg: string | undefined): { code: string; status: number } {
  const m = (msg ?? "").toUpperCase();
  for (const e of CONTRACT_ERRORS) {
    if (m.includes(e)) return { code: e, status: 403 };
  }
  console.error("redeem_db_error", msg);
  return { code: "KEY_INVALID", status: 403 };
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return j({ error: "method" }, 405);

  const ip = clientIp(req);
  const { data: ok, error: rlErr } = await db.rpc("rate_limit_hit", {
    p_bucket: "key:" + ip,
    p_max: 10,
    p_window_seconds: 3600,
  });
  if (rlErr) {
    console.error("rate_limit_error", rlErr.message);
    return j({ error: "RATE_LIMITED" }, 429);
  }
  if (!ok) return j({ error: "RATE_LIMITED" }, 429);

  let body: { code?: string; device_id?: string };
  try {
    body = await req.json();
  } catch {
    return j({ error: "json" }, 400);
  }

  const { data, error } = await db.rpc("redeem_premium_key", {
    p_code: (body.code ?? "").slice(0, 64),
    p_device: body.device_id,
  });
  if (error) {
    const m = mapDbError(error.message);
    return j({ error: m.code }, m.status);
  }
  return j({ premium_until: data });
});
