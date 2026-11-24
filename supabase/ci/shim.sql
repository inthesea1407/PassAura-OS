-- CI-only stand-in for the Supabase platform pieces our migrations rely on. Not for production.
create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
create schema extensions; create schema auth;
grant usage on schema public, extensions, auth to anon, authenticated, service_role;
create extension pgcrypto with schema extensions;
create table auth.users (id uuid primary key, email text);
create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claims', true)::jsonb->>'sub','')::uuid $$;
create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true),'')::jsonb,'{}'::jsonb) $$;
grant execute on all functions in schema auth to anon, authenticated, service_role;
