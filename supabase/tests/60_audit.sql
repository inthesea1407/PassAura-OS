-- 60_audit.sql — plain SQL assertions for audit_log, log_admin_action,
-- admin_list_audit_log, and cleanup_audit_log. No pgTAP; uses DO blocks with
-- RAISE EXCEPTION on failure so any failure aborts the run.
--
-- Run: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/60_audit.sql

begin;

-- Setup: ensure an owner exists for owner-gated calls.
insert into auth.users (id, email) values
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','audit-owner@test') on conflict do nothing;
insert into public.owners (user_id) values
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb') on conflict do nothing;

-- Impersonate the owner with aal2 for the rest of the test.
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","aal":"aal2"}', true);

-- ---------------------------------------------------------------------------
-- A) log_admin_action inserts a row and returns its id.
-- ---------------------------------------------------------------------------
do $$
declare v_id bigint;
begin
  v_id := public.log_admin_action('test_action', 'target-1', '{"k":"v"}'::jsonb);
  if v_id is null then
    raise exception 'A1 FAIL: log_admin_action returned null';
  end if;
  if not exists (select 1 from public.audit_log where id = v_id
                   and action = 'test_action'
                   and target = 'target-1'
                   and details = '{"k":"v"}'::jsonb
                   and actor = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb') then
    raise exception 'A2 FAIL: inserted audit row mismatch';
  end if;
  raise notice 'A PASS: log_admin_action inserted row %', v_id;
end $$;

-- ---------------------------------------------------------------------------
-- B) Non-owner cannot insert via log_admin_action.
-- ---------------------------------------------------------------------------
reset role;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"cccccccc-cccc-cccc-cccc-cccccccccccc","aal":"aal2"}', true);
do $$
begin
  perform public.log_admin_action('should_fail', null, '{}'::jsonb);
  raise exception 'B FAIL: non-owner log_admin_action did not raise';
exception when others then
  if sqlerrm not like '%FORBIDDEN%' then
    raise exception 'B FAIL: wrong error: %', sqlerrm;
  end if;
  raise notice 'B PASS: non-owner blocked';
end $$;

-- ---------------------------------------------------------------------------
-- C) Anon cannot read audit_log directly.
-- ---------------------------------------------------------------------------
reset role;
set local role anon;
do $$
begin
  perform 1 from public.audit_log limit 1;
  raise exception 'C FAIL: anon read audit_log';
exception when insufficient_privilege then
  raise notice 'C PASS: anon blocked from audit_log';
end $$;

-- ---------------------------------------------------------------------------
-- D) Anon cannot call admin_list_audit_log.
-- ---------------------------------------------------------------------------
do $$
begin
  perform public.admin_list_audit_log(10);
  raise exception 'D FAIL: anon called admin_list_audit_log';
exception when others then
  if sqlerrm not like '%FORBIDDEN%' and sqlerrm not like '%permission denied%' then
    raise exception 'D FAIL: wrong error: %', sqlerrm;
  end if;
  raise notice 'D PASS: anon blocked from admin_list_audit_log';
end $$;

-- ---------------------------------------------------------------------------
-- E) Owner can list rows; the limit is clamped.
-- ---------------------------------------------------------------------------
reset role;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","aal":"aal2"}', true);
do $$
declare v_count int;
begin
  select count(*) into v_count from public.admin_list_audit_log(10);
  if v_count < 1 then
    raise exception 'E1 FAIL: owner saw no audit rows';
  end if;
  select count(*) into v_count from public.admin_list_audit_log(0);
  if v_count > 1 then
    raise exception 'E2 FAIL: limit 0 not clamped to 1 (got %)', v_count;
  end if;
  raise notice 'E PASS: owner can list, limit clamped';
end $$;

-- ---------------------------------------------------------------------------
-- F) cleanup_audit_log deletes only rows older than the cutoff, bounded.
-- ---------------------------------------------------------------------------
reset role;
do $$
declare v_deleted int;
begin
  -- Insert one old row directly (service_role-equivalent: reset role = postgres).
  insert into public.audit_log (actor, action, target, created_at)
  values ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'old_action', 'old', now() - interval '100 days');

  v_deleted := public.cleanup_audit_log(90, 100);
  if v_deleted < 1 then
    raise exception 'F1 FAIL: cleanup deleted % rows (expected >= 1)', v_deleted;
  end if;
  if exists (select 1 from public.audit_log where action = 'old_action') then
    raise exception 'F2 FAIL: old row survived cleanup';
  end if;
  raise notice 'F PASS: cleanup deleted % old row(s)', v_deleted;
end $$;

-- ---------------------------------------------------------------------------
-- G) details size cap enforced.
-- ---------------------------------------------------------------------------
reset role;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","aal":"aal2"}', true);
do $$
begin
  perform public.log_admin_action('big', null,
    jsonb_build_object('blob', repeat('x', 5000)));
  raise exception 'G FAIL: oversized details accepted';
exception when others then
  if sqlerrm not like '%DETAILS_TOO_LARGE%' then
    raise exception 'G FAIL: wrong error: %', sqlerrm;
  end if;
  raise notice 'G PASS: oversized details rejected';
end $$;

reset role;
rollback;

-- If execution reaches here with no exception, all assertions passed.
select '60_audit.sql: ALL PASS' as result;
