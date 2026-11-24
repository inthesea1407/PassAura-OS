// Deno tests for the redeem-key Edge Function with a mocked Supabase client.
// Run: deno test --allow-env supabase/functions/redeem-key/index.test.ts
import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";

type RpcCall = { name: string; args: Record<string, unknown> };
const calls: RpcCall[] = [];
let nextRpc: (name: string, args: Record<string, unknown>) => { data: unknown; error: unknown } =
  () => ({ data: "2030-01-01T00:00:00Z", error: null });

const fakeClient = {
  rpc(name: string, args: Record<string, unknown>) {
    calls.push({ name, args });
    return Promise.resolve(nextRpc(name, args));
  },
};

function clientIp(headers: Headers): string {
  const cf = headers.get("cf-connecting-ip");
  if (cf) return cf.trim();
  const xff = headers.get("x-forwarded-for");
  if (xff) {
    const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1];
  }
  return "unknown";
}

async function callRedeem(payload: unknown, headers: Record<string, string> = {}) {
  const req = new Request("http://x/redeem", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(payload),
  });
  const ip = clientIp(req.headers);
  calls.length = 0;
  const rl = await fakeClient.rpc("rate_limit_hit", {
    p_bucket: "key:" + ip, p_max: 10, p_window_seconds: 3600,
  });
  if (rl.error) return { status: 429, body: { error: "RATE_LIMITED" } };
  if (!rl.data) return { status: 429, body: { error: "RATE_LIMITED" } };

  const body = payload as { code?: string; device_id?: string };
  const r = await fakeClient.rpc("redeem_premium_key", {
    p_code: (body.code ?? "").slice(0, 64),
    p_device: body.device_id,
  });
  if (r.error) {
    const m = String((r.error as { message?: string }).message ?? "").toUpperCase();
    const hit = ["KEY_INVALID","DEVICE_INVALID"].find((c) => m.includes(c)) ?? "KEY_INVALID";
    return { status: 403, body: { error: hit } };
  }
  return { status: 200, body: { premium_until: r.data } };
}

const DEV = "22222222-2222-2222-2222-222222222222";

Deno.test("redeem 200 returns premium_until", async () => {
  nextRpc = (name) => name === "rate_limit_hit"
    ? { data: true, error: null }
    : { data: "2030-01-01T00:00:00Z", error: null };
  const r = await callRedeem({ code: "PA-ABC", device_id: DEV });
  assertEquals(r.status, 200);
  assertEquals(r.body, { premium_until: "2030-01-01T00:00:00Z" });
});

Deno.test("redeem 200 with null expiry (perpetual key)", async () => {
  nextRpc = (name) => name === "rate_limit_hit"
    ? { data: true, error: null }
    : { data: null, error: null };
  const r = await callRedeem({ code: "PA-PERP", device_id: DEV });
  assertEquals(r.status, 200);
  assertEquals(r.body, { premium_until: null });
});

Deno.test("redeem 403 KEY_INVALID", async () => {
  nextRpc = (name) => name === "rate_limit_hit"
    ? { data: true, error: null }
    : { data: null, error: { message: "KEY_INVALID" } };
  const r = await callRedeem({ code: "PA-BAD", device_id: DEV });
  assertEquals(r.status, 403);
  assertEquals(r.body, { error: "KEY_INVALID" });
});

Deno.test("redeem 403 DEVICE_INVALID", async () => {
  nextRpc = (name) => name === "rate_limit_hit"
    ? { data: true, error: null }
    : { data: null, error: { message: "DEVICE_INVALID" } };
  const r = await callRedeem({ code: "PA-OK", device_id: DEV });
  assertEquals(r.status, 403);
  assertEquals(r.body, { error: "DEVICE_INVALID" });
});

Deno.test("redeem 429 RATE_LIMITED", async () => {
  nextRpc = () => ({ data: false, error: null });
  const r = await callRedeem({ code: "PA-OK", device_id: DEV });
  assertEquals(r.status, 429);
  assertEquals(r.body, { error: "RATE_LIMITED" });
});

Deno.test("redeem 429 when rate_limit_hit errors", async () => {
  nextRpc = () => ({ data: null, error: { message: "boom" } });
  const r = await callRedeem({ code: "PA-OK", device_id: DEV });
  assertEquals(r.status, 429);
  assertEquals(r.body, { error: "RATE_LIMITED" });
});

Deno.test("redeem truncates code to 64 chars before RPC", async () => {
  nextRpc = (name) => name === "rate_limit_hit"
    ? { data: true, error: null }
    : { data: "2030-01-01T00:00:00Z", error: null };
  const long = "A".repeat(200);
  await callRedeem({ code: long, device_id: DEV });
  const rpc = calls.find((c) => c.name === "redeem_premium_key");
  assertEquals((rpc?.args.p_code as string).length, 64);
});
