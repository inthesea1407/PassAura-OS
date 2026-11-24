// Edge Function: register a device. Rate-limited per client IP. Deploy only after owner approval.
// Hardened: F9 (spoof-proof IP), F10 (no internal error leakage), strict contract mapping.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const j = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });

// F9: prefer platform-provided client IP; only fall back to the LAST XFF hop (first is client-spoofable).
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

// F10: whitelist of contract-visible errors. Anything else becomes a generic 403.
const CONTRACT_ERRORS = new Set([
  "REGISTRATION_CLOSED",
  "INVITE_INVALID_OR_USED",
  "DEVICE_REVOKED",
  "DEVICE_ALREADY_REGISTERED",
]);

function mapDbError(msg: string | undefined): { code: string; status: number } {
  const m = (msg ?? "").toUpperCase();
  for (const e of CONTRACT_ERRORS) {
    if (m.includes(e)) return { code: e, status: 403 };
  }
  // Surface as a contract-safe code; log the real one server-side.
  console.error("register_db_error", msg);
  return { code: "INVITE_INVALID_OR_USED", status: 403 };
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return j({ error: "method" }, 405);

  const ip = clientIp(req);
  const { data: ok, error: rlErr } = await db.rpc("rate_limit_hit", {
    p_bucket: "reg:" + ip,
    p_max: 10,
    p_window_seconds: 3600,
  });
  if (rlErr) {
    console.error("rate_limit_error", rlErr.message);
    return j({ error: "RATE_LIMITED" }, 429);
  }
  if (!ok) return j({ error: "RATE_LIMITED" }, 429);

  let body: { invite_code?: string; hardware_id_hash?: string };
  try {
    body = await req.json();
  } catch {
    return j({ error: "json" }, 400);
  }

  if (!/^[0-9a-f]{64}$/.test(body.hardware_id_hash ?? "")) {
    return j({ error: "hardware_id_hash must be sha256 hex" }, 400);
  }

  const { data, error } = await db.rpc("register_device", {
    p_invite_code: (body.invite_code ?? "").slice(0, 64),
    p_hardware_id_hash: body.hardware_id_hash,
  });
  if (error) {
    const m = mapDbError(error.message);
    return j({ error: m.code }, m.status);
  }
  return j({ device_id: data });
});
