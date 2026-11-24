-- 70_premium_batches.sql — plain SQL assertions for premium_key_batches,
-- generate_premium_keys, premium_expiry_report, and admin_list_batches.
-- Run: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/70_premium_batches.sql

begin;

-- Setup: owner + project.
insert into auth.users (id, email) values
  ('dddddddd-dddd-dddd-dddd-dddddddddddd','batch-owner@test') on conflict do nothing;
insert into public.owners (user_id) values
  ('dddddddd-dddd-dddd-dddd-dddddddddddd') on conflict do nothing;
insert into public.projects (slug, name) values
  ('passaura','PassAura') on conflict do nothing;

-- Impersonate owner with aal2.
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"dddddddd-dddd-dddd-dddd-dddddddddddd","aal":"aal2"}', true);

-- ---------------------------------------------------------------------------
-- A) generate_premium_keys returns the right count and inserts the batch.
-- ---------------------------------------------------------------------------
do $$
declare v_codes text[]; v_batch_count int; v_key_count int;
begin
  v_codes := public.generate_premium_keys('test-batch-1', 5, 30);
  if array_length(v_codes, 1) <> 5 then
    raise exception 'A1 FAIL: expected 5 keys, got %', array_length(v_codes, 1);
  end if;
  select count(*) into v_batch_count from public.premium_key_batches where label = 'test-batch-1';
  if v_batch_count <> 1 then
    raise exception 'A2 FAIL: expected 1 batch, got %', v_batch_count;
  end if;
  select count(*) into v_key_count from public.premium_keys
   where note like 'batch:%' and plan = 'trial';
  if v_key_count < 5 then
    raise exception 'A3 FAIL: expected >=5 keys, got %', v_key_count;
  end if;
  raise notice 'A PASS: generated % keys', array_length(v_codes, 1);
end $$;

-- ---------------------------------------------------------------------------
-- B) Non-owner cannot call generate_premium_keys.
-- ---------------------------------------------------------------------------
reset role;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee","aal":"aal2"}', true);
do $$
begin
  perform public.generate_premium_keys('should-fail', 1, 30);
  raise exception 'B FAIL: non-owner generated keys';
exception when others then
  if sqlerrm not like '%FORBIDDEN%' then raise exception 'B FAIL: wrong error: %', sqlerrm; end if;
  raise notice 'B PASS: non-owner blocked';
end $$;

-- ---------------------------------------------------------------------------
-- C) Anon cannot call generate_premium_keys or read the table.
-- ---------------------------------------------------------------------------
reset role;
set local role anon;
do $$
begin
  perform public.generate_premium_keys('anon-fail', 1, 30);
  raise exception 'C1 FAIL: anon generated keys';
exception when others then
  if sqlerrm not like '%permission denied%' and sqlerrm not like '%FORBIDDEN%' then
    raise exception 'C1 FAIL: wrong error: %', sqlerrm;
  end if;
  raise notice 'C1 PASS: anon blocked from generate';
end $$;
do $$
begin
  if (select count(*) from public.premium_key_batches) > 0 then
    raise exception 'C2 FAIL: anon read premium_key_batches';
  end if;
  raise notice 'C2 PASS: anon sees no rows (RLS)';
exception when insufficient_privilege then
  raise notice 'C2 PASS: anon blocked from table';
end $$;

-- ---------------------------------------------------------------------------
-- D) admin_list_batches returns batches for owner.
-- ---------------------------------------------------------------------------
reset role;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"dddddddd-dddd-dddd-dddd-dddddddddddd","aal":"aal2"}', true);
do $$
declare v_count int;
begin
  select count(*) into v_count from public.admin_list_batches(10);
  if v_count < 1 then raise exception 'D FAIL: owner saw no batches'; end if;
  raise notice 'D PASS: owner saw % batch(es)', v_count;
end $$;

-- ---------------------------------------------------------------------------
-- E) premium_expiry_report returns keys expiring soon.
-- Insert a key expiring in 5 days and check it appears.
-- ---------------------------------------------------------------------------
reset role;
insert into public.premium_keys (project, key_hash, plan, expires_at)
values ('passaura', encode(digest('EXPIRING-KEY','sha256'),'hex'), 'trial', now() + interval '5 days');

set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"dddddddd-dddd-dddd-dddd-dddddddddddd","aal":"aal2"}', true);
do $$
declare v_found boolean;
begin
  select exists(
    select 1 from public.premium_expiry_report(10)
     where plan = 'trial' and expires_at < now() + interval '10 days'
  ) into v_found;
  if not v_found then raise exception 'E FAIL: expiring key not in report'; end if;
  raise notice 'E PASS: expiry report includes soon-expiring key';
end $$;

-- ---------------------------------------------------------------------------
-- F) Bad inputs rejected.
-- ---------------------------------------------------------------------------
reset role;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"dddddddd-dddd-dddd-dddd-dddddddddddd","aal":"aal2"}', true);
do $$
begin
  perform public.generate_premium_keys('bad', 0, 30);
  raise exception 'F1 FAIL: count 0 accepted';
exception when others then
  if sqlerrm not like '%COUNT_1_TO_500%' then raise exception 'F1 FAIL: wrong error: %', sqlerrm; end if;
  raise notice 'F1 PASS: count 0 rejected';
end $$;
do $$
begin
  perform public.generate_premium_keys('bad', 1, 0);
  raise exception 'F2 FAIL: days 0 accepted';
exception when others then
  if sqlerrm not like '%DAYS_1_TO_3650%' then raise exception 'F2 FAIL: wrong error: %', sqlerrm; end if;
  raise notice 'F2 PASS: days 0 rejected';
end $$;

reset role;
rollback;

select '70_premium_batches.sql: ALL PASS' as result;
