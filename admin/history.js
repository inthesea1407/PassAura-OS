// Audit history page. Same escaper and login/MFA flow as app.js; reads only
// through the owner-gated RPC admin_list_audit_log. No inline secrets.
const $ = (id) => document.getElementById(id);
const C = window.PA_CONFIG || {};
const T = (k, fallback) => (window.PA_I18N ? window.PA_I18N.t(k) : (fallback || k));

const say = (t, bad) => {
  const el = $("msg");
  if (!el) return;
  el.textContent = t || "";
  el.style.color = bad ? "#b00" : "#060";
};

// Same complete escaper as admin/app.js (F8): covers & < > " ' `.
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

$("doLogin").onclick = async () => {
  try {
    await ok(sb.auth.signInWithPassword({ email: $("em").value, password: $("pw").value }));
    const f = await ok(sb.auth.mfa.listFactors());
    factor = f.totp[0];
    if (!factor) {
      say(T("enrolTotp", "Enrol a TOTP factor first."), 1);
      return;
    }
    $("mfa").classList.remove("hide");
  } catch (_e) { /* surfaced */ }
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
    loadHistory();
  } catch (_e) { /* surfaced */ }
};

function renderRows(rows) {
  $("histBody").innerHTML = rows.map((r) =>
    `<tr>` +
      `<td>${esc(r.created_at)}</td>` +
      `<td>${esc(r.actor)}</td>` +
      `<td>${esc(r.action)}</td>` +
      `<td>${esc(r.target)}</td>` +
      `<td><pre>${esc(JSON.stringify(r.details, null, 0))}</pre></td>` +
    `</tr>`
  ).join("");
}

async function loadHistory() {
  try {
    const rows = await ok(sb.rpc("admin_list_audit_log", { p_limit: 100 }));
    renderRows(rows || []);
  } catch (_e) { /* surfaced */ }
}

$("refresh").onclick = () => loadHistory();

// The i18n apply() runs on DOMContentLoaded; history.js is loaded after i18n.js.
