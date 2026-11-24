// Owner panel logic. Hardened:
//  - F8: single escaper covers & < > " ' and backtick.
//  - F15: no client-supplied updated_at; DB trigger stamps it.
//  - F16: client-side bounds on days/count to match server checks.
//  - F1: restore is a separate RPC (admin_restore_device) so revoke is one-way by default.
//  - Uses i18n strings from window.PA_I18N when present.
const $ = (id) => document.getElementById(id);
const C = window.PA_CONFIG || {};
const T = (k, fallback) => (window.PA_I18N ? window.PA_I18N.t(k) : (fallback || k));

const say = (t, bad) => {
  const el = $("msg");
  if (!el) return;
  el.textContent = t || "";
  el.style.color = bad ? "#b00" : "#060";
};

// F8: complete HTML escaper.
const esc = (s) =>
  String(s ?? "").replace(/[&<>"'`]/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;",
  }[c]));

if (!C.SUPABASE_URL || !C.SUPABASE_ANON_KEY) {
  say(T("configMissing", "Set SUPABASE_URL and SUPABASE_ANON_KEY in config.js"), 1);
}

const sb = supabase.createClient(
  C.SUPABASE_URL || "http://invalid.local",
  C.SUPABASE_ANON_KEY || "invalid",
);

const ok = async (p) => {
  const r = await p;
  if (r.error) { say(r.error.message, 1); throw r.error; }
  return r.data;
};

let factor;
let P = "passaura";

$("doLogin").onclick = async () => {
  try {
    await ok(sb.auth.signInWithPassword({ email: $("em").value, password: $("pw").value }));
    const f = await ok(sb.auth.mfa.listFactors());
    factor = f.totp[0];
    if (!factor) {
      say(T("enrolTotp", "Enrol a TOTP factor first (Supabase Auth MFA is free)."), 1);
      return;
    }
    $("mfa").classList.remove("hide");
  } catch (_e) { /* ok() already surfaced the error */ }
};

$("doOtp").onclick = async () => {
  try {
    const ch = await ok(sb.auth.mfa.challenge({ factorId: factor.id }));
    await ok(sb.auth.mfa.verify({
      factorId: factor.id, challengeId: ch.id, code: $("otp").value,
    }));
    $("login").classList.add("hide");
    $("app").classList.remove("hide");
    say("");
    load();
  } catch (_e) { /* surfaced */ }
};

// Render helpers -------------------------------------------------------------
function renderInvites(rows) {
  const head = "<tr><th>id</th><th>state</th><th></th></tr>";
  const body = rows.map((i) =>
    `<tr><td>${esc(i.id)}</td><td>${i.used_by_device ? "used" : "open"}</td>` +
    `<td>${i.used_by_device ? "" : `<button data-inv="${esc(i.id)}">Revoke</button>`}</td></tr>`
  ).join("");
  $("invT").innerHTML = head + body;
}

function renderDevices(rows) {
  const head = "<tr><th>device</th><th>registered</th><th>seed</th><th>status</th><th></th></tr>";
  const body = rows.map((d) => {
    const action = d.revoked
      ? `<button data-restore="${esc(d.id)}">Restore</button>`
      : `<button data-dev="${esc(d.id)}">Revoke</button>`;
    return `<tr><td>${esc(d.id)}</td><td>${esc(d.registered_at)}</td>` +
      `<td>${d.is_seed ? "yes" : ""}</td>` +
      `<td>${d.revoked ? "revoked" : "active"}</td><td>${action}</td></tr>`;
  }).join("");
  $("devT").innerHTML = head + body;
}

function renderKeys(rows) {
  const head = "<tr><th>id</th><th>plan</th><th>expires</th><th>state</th><th></th></tr>";
  const body = rows.map((x) => {
    const state = x.revoked ? "revoked" : (x.redeemed_at ? "redeemed" : "open");
    const action = x.revoked ? "" : `<button data-key="${esc(x.id)}">Revoke</button>`;
    return `<tr><td>${esc(x.id)}</td><td>${esc(x.plan)}</td>` +
      `<td>${esc(x.expires_at)}</td><td>${state}</td><td>${action}</td></tr>`;
  }).join("");
  $("keyT").innerHTML = head + body;
}

function renderFlags(rows) {
  $("flagT").innerHTML = rows.map((x) =>
    `<tr><td>${esc(x.key)}</td><td>${esc(JSON.stringify(x.value))}</td></tr>`
  ).join("");
}

function renderAnnouncements(rows) {
  $("annT").innerHTML = rows.map((x) =>
    `<tr><td>${esc(x.title)}</td><td>${esc(x.body)}</td>` +
    `<td><button data-ann="${esc(x.id)}" data-p="${!x.published}">` +
    `${x.published ? "Unpublish" : "Publish"}</button></td></tr>`
  ).join("");
}

// Load -----------------------------------------------------------------------
async function load() {
  const pr = await ok(sb.from("projects").select("*").order("slug"));
  $("proj").innerHTML = pr.map((x) =>
    `<option value="${esc(x.slug)}">${esc(x.name)}</option>`
  ).join("");
  $("proj").value = P;

  const cfg = await ok(sb.from("admin_config").select("*").eq("id", 1).single());
  $("mode").value = cfg.mode;
  $("scope").value = cfg.paid_scope;
  $("paused").checked = cfg.invites_paused;

  const inv = await ok(sb.from("invites")
    .select("id,created_at,used_by_device")
    .order("created_at", { ascending: false }).limit(100));
  renderInvites(inv);

  const dev = await ok(sb.from("devices")
    .select("id,registered_at,is_seed,revoked")
    .order("registered_at", { ascending: false }).limit(200));
  renderDevices(dev);

  const k = await ok(sb.from("premium_keys")
    .select("id,plan,expires_at,revoked,redeemed_at")
    .eq("project", P).order("created_at", { ascending: false }).limit(100));
  renderKeys(k);

  const f = await ok(sb.from("feature_flags")
    .select("*").eq("project", P).order("key"));
  renderFlags(f);

  const a = await ok(sb.from("announcements")
    .select("*").eq("project", P)
    .order("created_at", { ascending: false }).limit(50));
  renderAnnouncements(a);
}

// Actions --------------------------------------------------------------------
// F15: no updated_at in payload; trigger stamps it server-side.
$("saveCfg").onclick = async () => {
  try {
    await ok(sb.from("admin_config").update({
      mode: $("mode").value,
      paid_scope: $("scope").value,
      invites_paused: $("paused").checked,
    }).eq("id", 1));
    say(T("saved", "Saved"));
    load();
  } catch (_e) { /* surfaced */ }
};

$("issue").onclick = async () => {
  try {
    const n = Number($("n").value);
    if (!Number.isInteger(n) || n < 1 || n > 50) { say("Count must be 1..50", 1); return; }
    const c = await ok(sb.rpc("admin_issue_invites", { p_count: n }));
    $("codes").textContent = T("copyOnce", "Copy now, shown once:") + "\n" + c.join("\n");
    load();
  } catch (_e) { /* surfaced */ }
};

$("mkKey").onclick = async () => {
  try {
    const d = Number($("days").value);
    // F16: match server-side 1..3650 bound before calling.
    if (!Number.isInteger(d) || d < 1 || d > 3650) { say("Days must be 1..3650", 1); return; }
    const c = await ok(sb.rpc("admin_issue_premium_key", {
      p_plan: $("plan").value, p_days: d, p_project: P,
    }));
    $("keyOut").textContent = T("copyOnce", "Copy now, shown once:") + " " + c;
    load();
  } catch (_e) { /* surfaced */ }
};

$("saveFlag").onclick = async () => {
  let v;
  try { v = JSON.parse($("fv").value); } catch {
    say(T("jsonInvalid", "Value must be valid JSON"), 1);
    return;
  }
  try {
    await ok(sb.from("feature_flags").upsert({
      project: P, key: $("fk").value, value: v,
    }));
    load();
  } catch (_e) { /* surfaced */ }
};

$("addAnn").onclick = async () => {
  try {
    await ok(sb.from("announcements").insert({
      project: P, title: $("at").value, body: $("ab").value,
    }));
    load();
  } catch (_e) { /* surfaced */ }
};

// Delegated actions ----------------------------------------------------------
document.addEventListener("click", async (e) => {
  const d = e.target.dataset;
  if (!d) return;
  try {
    if (d.inv) {
      await ok(sb.rpc("admin_revoke_invite", { p_id: d.inv }));
    } else if (d.restore) {
      if (!confirm(T("confirmDevice", "Restore this device?"))) return;
      await ok(sb.rpc("admin_restore_device", { p_id: d.restore }));
    } else if (d.dev) {
      if (!confirm(T("confirmDevice", "Revoke this device? Only the owner can do this."))) return;
      await ok(sb.rpc("admin_set_device_revoked", { p_id: d.dev, p_revoked: true }));
    } else if (d.key) {
      await ok(sb.rpc("admin_revoke_premium_key", { p_id: d.key }));
    } else if (d.ann) {
      await ok(sb.from("announcements")
        .update({ published: d.p === "true" }).eq("id", d.ann));
    } else {
      return;
    }
    load();
  } catch (_e) { /* surfaced */ }
});

$("proj").onchange = () => { P = $("proj").value; load(); };

$("addProj").onclick = async () => {
  try {
    await ok(sb.from("projects").insert({ slug: $("np").value, name: $("nn").value }));
    P = $("np").value;
    load();
  } catch (_e) { /* surfaced */ }
};
