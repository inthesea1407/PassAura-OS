-- 0010_audit_retention.sql — audit log for owner/admin actions, RLS-gated to owner+MFA,
-- with bounded retention cleanup and a pg_cron job (commented out until owner approval).
-- Never edit 0001-0008. This migration is additive.

begin;

-- ---------------------------------------------------------------------------
-- 1) audit_log table.
-- actor: the auth.uid() that performed the action (nullable for system actions).
-- action: short verb string, e.g. 'issue_invite', 'revoke_device', 'redeem_key'.
-- target: the entity acted upon (uuid, slug, or code hash — never plaintext secrets).
-- details: free-form jsonb, capped in the log function.
-- ---------------------------------------------------------------------------
create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  actor uuid references auth.users(id) on delete set null,
  action text not null check (char_length(action) between 1 and 80),
  target text check (target is null or char_length(target) <= 200),
  details jsonb not null default '{}'::jsonb
    check (pg_column_size(details) <= 4096),
  created_at timestamptz not null default now()
);

alter table public.audit_log enable row level security;

-- Only the owner (already MFA-gated via is_owner() from 0002/0005) can read.
-- No INSERT/UPDATE/DELETE policies: writes go through log_admin_action() only.
-- The service_role bypasses RLS and can insert for system actions, but the
-- Edge Functions do not write audit rows directly (they call the RPC via the
-- DB functions that themselves log).
create policy audit_log_owner_select on public.audit_log
  for select to authenticated
  using (public.is_owner());

-- ---------------------------------------------------------------------------
-- 2) log_admin_action() — security definer, callable by authenticated only.
-- It re-checks is_owner() so a non-owner cannot write audit rows even though
-- the function is definer. Returns the new row id.
-- ---------------------------------------------------------------------------
create or replace function public.log_admin_action(
  p_action text,
  p_target text default null,
  p_details jsonb default '{}'::jsonb
)
returns bigint
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_id bigint;
  v_actor uuid := (select auth.uid());
begin
  if not public.is_owner() then
    raise exception 'FORBIDDEN';
  end if;
  if p_action is null or char_length(p_action) < 1 or char_length(p_action) > 80 then
    raise exception 'BAD_ACTION';
  end if;
  if p_target is not null and char_length(p_target) > 200 then
    raise exception 'BAD_TARGET';
  end if;
  if pg_column_size(coalesce(p_details, '{}'::jsonb)) > 4096 then
    raise exception 'DETAILS_TOO_LARGE';
  end if;

  insert into public.audit_log (actor, action, target, details)
  values (v_actor, p_action, p_target, coalesce(p_details, '{}'::jsonb))
  returning id into v_id;
  return v_id;
end $$;

revoke all on function public.log_admin_action(text,text,jsonb)
  from public, anon, authenticated;
grant execute on function public.log_admin_action(text,text,jsonb)
  to authenticated;

-- ---------------------------------------------------------------------------
-- 3) RPC for the admin UI: last N audit rows, owner+MFA only.
-- Returns a bounded, ordered list. N is clamped to 1..500.
-- ---------------------------------------------------------------------------
create or replace function public.admin_list_audit_log(p_limit int default 100)
returns table (
  id bigint,
  actor uuid,
  action text,
  target text,
  details jsonb,
  created_at timestamptz
)
language plpgsql
stable
security definer
set search_path = pg_catalog, public, extensions
as $$
begin
  if not public.is_owner() then
    raise exception 'FORBIDDEN';
  end if;
  return query
    select a.id, a.actor, a.action, a.target, a.details, a.created_at
      from public.audit_log a
     order by a.created_at desc, a.id desc
     limit least(greatest(coalesce(p_limit, 100), 1), 500);
end $$;

revoke all on function public.admin_list_audit_log(int)
  from public, anon, authenticated;
grant execute on function public.admin_list_audit_log(int)
  to authenticated;

-- ---------------------------------------------------------------------------
-- 4) Retention cleanup: delete rows older than p_retention_days in bounded
-- batches. Bounded so it never takes a long lock or bloats WAL in one shot.
-- Returns the number of rows deleted.
-- ---------------------------------------------------------------------------
create or replace function public.cleanup_audit_log(
  p_retention_days int default 90,
  p_limit int default 5000
)
returns int
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_deleted int;
begin
  if p_retention_days is null or p_retention_days < 1 then
    raise exception 'BAD_RETENTION';
  end if;
  if p_limit is null or p_limit < 1 or p_limit > 50000 then
    raise exception 'BAD_LIMIT';
  end if;

  delete from public.audit_log
   where ctid in (
     select ctid from public.audit_log
      where created_at < now() - make_interval(days => p_retention_days)
      order by created_at
      limit p_limit
   );
  get diagnostics v_deleted = row_count;
  return v_deleted;
end $$;

revoke all on function public.cleanup_audit_log(int,int)
  from public, anon, authenticated;
grant execute on function public.cleanup_audit_log(int,int)
  to service_role;

-- ---------------------------------------------------------------------------
-- 5) Index for the cleanup predicate and the admin list order.
-- cleanup_audit_log filters on created_at < cutoff and orders by created_at.
-- admin_list_audit_log orders by created_at desc, id desc.
-- A single btree on (created_at) serves both (the id is a tiebreaker on the
-- PK index, but the order-by can use the created_at index and then sort the
-- tiny result set of 100 rows).
-- ---------------------------------------------------------------------------
create index if not exists audit_log_created_at_idx
  on public.audit_log (created_at);

-- ---------------------------------------------------------------------------
-- 6) pg_cron job: delete audit rows older than 90 days, every 15 minutes,
-- max 5000 per run. COMMENTED OUT until owner approval, per the brief.
--
-- To enable: uncomment the block below and run this migration (or the block
-- alone) in the SQL editor after the owner has approved retention policy.
-- pg_cron is available on the Supabase free tier; jobs run as the postgres
-- role and bypass RLS, which is why cleanup_audit_log is revoked from
-- anon/authenticated and granted only to service_role.
-- ---------------------------------------------------------------------------
-- create extension if not exists pg_cron with schema extensions;
-- select cron.schedule(
--   'passaura-audit-retention',
--   '*/15 * * * *',
--   $$select public.cleanup_audit_log(90, 5000)$$
-- );

commit;
