// Public values only. The anon key is meant to be public; RLS + owner/MFA checks are the protection.
// Never put the service_role key here.
// Fill these in at deploy time; they are not secrets.
window.PA_CONFIG = {
  SUPABASE_URL: "",
  SUPABASE_ANON_KEY: "",
};
