// Tiny i18n: EN/AR dictionary + toggle. No inline secrets, no eval.
// The toggle button (#langBtn) flips document.documentElement.lang/dir and re-renders data-i18n nodes.
(function () {
  const DICT = {
    en: {
      title: "PassAura Owner Panel",
      login: "Owner login",
      signIn: "Sign in",
      verify: "Verify",
      project: "Project",
      addProject: "Add project",
      mode: "POS mode",
      modeLabel: "Mode",
      paidScope: "Paid scope",
      stopInvites: "Stop invites",
      save: "Save",
      invites: "Invites",
      count: "Count",
      issue: "Issue",
      registrations: "Registrations",
      keys: "Premium trial keys",
      plan: "Plan",
      days: "Days",
      flags: "Feature flags / pricing",
      announcements: "Announcements",
      addDraft: "Add (draft)",
      confirmDevice: "Change this member status? Only the owner can do this.",
      saved: "Saved",
      copyOnce: "Copy now, shown once:",
      jsonInvalid: "Value must be valid JSON",
      configMissing: "Set SUPABASE_URL and SUPABASE_ANON_KEY in config.js",
      enrolTotp: "Enrol a TOTP factor first (Supabase Auth MFA is free).",
    },
    ar: {
      title: "لوحة تحكم مالك PassAura",
      login: "تسجيل دخول المالك",
      signIn: "تسجيل الدخول",
      verify: "تحقق",
      project: "المشروع",
      addProject: "إضافة مشروع",
      mode: "وضع POS",
      modeLabel: "الوضع",
      paidScope: "نطاق الاشتراك المدفوع",
      stopInvites: "إيقاف الدعوات",
      save: "حفظ",
      invites: "الدعوات",
      count: "العدد",
      issue: "إصدار",
      registrations: "الأجهزة المسجلة",
      keys: "مفاتيح النسخة التجريبية",
      plan: "الخطة",
      days: "الأيام",
      flags: "أعلام الميزات / التسعير",
      announcements: "الإعلانات",
      addDraft: "إضافة (مسودة)",
      confirmDevice: "تغيير حالة هذا العضو؟ المالك فقط يمكنه ذلك.",
      saved: "تم الحفظ",
      copyOnce: "انسخ الآن، يظهر مرة واحدة:",
      jsonInvalid: "يجب أن تكون القيمة JSON صالحة",
      configMissing: "قم بتعيين SUPABASE_URL و SUPABASE_ANON_KEY في config.js",
      enrolTotp: "قم بتسجيل عامل TOTP أولاً (مصادقة Supabase مجانية).",
    },
  };

  let lang = localStorage.getItem("pa_lang") === "ar" ? "ar" : "en";

  function apply() {
    const d = DICT[lang];
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const key = el.getAttribute("data-i18n");
      if (key && d[key]) el.textContent = d[key];
    });
    const btn = document.getElementById("langBtn");
    if (btn) btn.textContent = lang === "ar" ? "English" : "العربية";
  }

  function toggle() {
    lang = lang === "ar" ? "en" : "ar";
    localStorage.setItem("pa_lang", lang);
    apply();
  }

  window.PA_I18N = {
    t: (key) => (DICT[lang] && DICT[lang][key]) || key,
    toggle,
    apply,
    lang: () => lang,
  };

  document.addEventListener("DOMContentLoaded", () => {
    apply();
    const btn = document.getElementById("langBtn");
    if (btn) btn.addEventListener("click", toggle);
  });
})();
