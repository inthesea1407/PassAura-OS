-- Runner: psql "$DATABASE_URL" -f supabase/tests/run.sql
\i supabase/tests/00_setup.sql
\i supabase/tests/10_rls_and_anon.sql
\i supabase/tests/20_register_device.sql
\i supabase/tests/30_redeem_premium_key.sql
\i supabase/tests/40_rate_limit.sql
\i supabase/tests/60_audit.sql
\i supabase/tests/70_premium_batches.sql
