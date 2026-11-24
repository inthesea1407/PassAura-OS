// Premium key batches page. Owner-only RPCs. Keys shown once with copy button;
// never stored in localStorage, sessionStorage, URL, or console. Same escaper
// as app.js. No inline secrets.
const $ = (id) => document.getElementById(id);
const C = window.PA_CONFIG || {};
const T = (k, fallback) => (window.PA_I18N ? window.PA_I18N.t(k) : (fallback || k));

const say = (t, bad) => {
  const el = $("msg");
  if (!el) return;
  el.textContent = t || "";
  el.style.color = bad ? "#b00" : "#060";
};

// Same complete escaper (F8): & < > " ' `
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
let currentKeys = []; // in-memory only; cleared on dismiss / page unload

$("doLogin").onclick = async () => {
  try {
    await ok(sb.auth.signInWithPassword({ email: $("em").value, password: $("pw").value }));
    const f = await ok(sb.auth.mfa.listFactors());
    factor = f.totp[0];
    if (!factor) { say(T("enrolTotp", "Enrol a TOTP factor first."), 1); return; }
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
    loadAll();
  } catch (_e) { /* surfaced */ }
};

// Generate -------------------------------------------------------------------
$("genBtn").onclick = async () => {
  const label = $("label").value.trim();
  const count = Number($("count").value);
  const days = Number($("days").value);
  if (!label || label.length > 80) { say("Label is required (max 80 chars)", 1); return; }
  if (!Number.isInteger(count) || count < 1 || count > 500) { say("Count must be 1..500", 1); return; }
  if (!Number.isInteger(days) || days < 1 || days > 3650) { say("Days must be 1..3650", 1); return; }
  try {
    const codes = await ok(sb.rpc("generate_premium_keys", {
      p_batch_label: label, p_count: count, p_valid_days: days,
    }));
    currentKeys = codes || [];
    renderKeyList(currentKeys);
    $("keyOut").classList.remove("hide");
    loadBatches();
  } catch (_e) { /* surfaced */ }
};

function renderKeyList(codes) {
  $("keyList").innerHTML = codes.map((c) =>
    `<code data-key="${esc(c)}">${esc(c)}</code>`
  ).join("");
}

$("keyList").onclick = async (e) => {
  const code = e.target.dataset.key;
  if (!code) return;
  try { await navigator.clipboard.writeText(code); say("Copied", false); }
  catch { say("Clipboard blocked; select and copy manually", 1); }
};

$("copyAll").onclick = async () => {
  if (!currentKeys.length) return;
  try {
    await navigator.clipboard.writeText(currentKeys.join("\n"));
    say("Copied all", false);
  } catch { say("Clipboard blocked; select and copy manually", 1); }
};

$("dismissKeys").onclick = () => {
  currentKeys = [];
  $("keyList").innerHTML = "";
  $("keyOut").classList.add("hide");
};

// Expiry report --------------------------------------------------------------
async function loadExpiry() {
  const daysAhead = Number($("daysAhead").value) || 30;
  try {
    const rows = await ok(sb.rpc("premium_expiry_report", { p_days_ahead: daysAhead }));
    $("expBody").innerHTML = (rows || []).map((r) =>
      `<tr>` +
        `<td>${esc(r.expires_at)}</td>` +
        `<td>${esc(r.plan)}</td>` +
        `<td>${esc(r.device_id)}</td>` +
        `<td>${r.revoked ? "yes" : ""}${r.device_revoked ? " (device)" : ""}</td>` +
        `<td>${esc(r.batch_id)}</td>` +
      `</tr>`
    ).join("");
  } catch (_e) { /* surfaced */ }
}

$("refreshExpiry").onclick = () => loadExpiry();

// Batches list ---------------------------------------------------------------
async function loadBatches() {
  try {
    const rows = await ok(sb.rpc("admin_list_batches", { p_limit: 50 }));
    $("batchBody").innerHTML = (rows || []).map((b) =>
      `<tr>` +
        `<td>${esc(b.created_at)}</td>` +
        `<td>${esc(b.label)}</td>` +
        `<td>${esc(b.count)}</td>` +
        `<td>${esc(b.valid_days)}</td>` +
      `</tr>`
    ).join("");
  } catch (_e) { /* surfaced */ }
}

function loadAll() {
  loadBatches();
  loadExpiry();
}
