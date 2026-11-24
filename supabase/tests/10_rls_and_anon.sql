begin;
select plan(14);

-- Seed rows as superuser so "anon sees nothing" is meaningful. Supabase grants anon table access by default,
-- so RLS (no policy) must return zero rows / refuse writes.
insert into public.devices(hardware_id_hash) values (repeat('f',64));
insert into public.invites(code_hash) values ('seed-hash');
insert into public.premium_keys(key_hash) values ('seed-key');
insert into public.rate_limits(bucket, window_start, hits) values ('seed', now(), 1);

set local role anon;
select is((select count(*)::int from public.admin_config), 0, 'anon cannot read admin_config');
select is((select count(*)::int from public.devices), 0, 'anon cannot read devices');
select is((select count(*)::int from public.invites), 0, 'anon cannot read invites');
select throws_ok($$select 1 from public.owners$$, '42501', null, 'anon cannot read owners (table grant revoked)');
select is((select count(*)::int from public.premium_keys), 0, 'anon cannot read premium_keys');
select is((select count(*)::int from public.rate_limits), 0, 'anon cannot read rate_limits');
select throws_ok($$insert into public.devices(hardware_id_hash) values (repeat('a',64))$$, '42501', null, 'anon cannot insert devices');
select throws_ok($$insert into public.invites(code_hash) values ('x')$$, '42501', null, 'anon cannot insert invites');
update public.admin_config set mode='paid';
delete from public.premium_keys;
reset role;
select is((select mode from public.admin_config where id=1), 'closed', 'anon update of admin_config changed nothing');
select is((select count(*)::int from public.premium_keys), 1, 'anon delete of premium_keys changed nothing');

insert into public.feature_flags(project,key,value,is_public) values ('passaura','price_monthly','3.99'::jsonb,true);
insert into public.feature_flags(project,key,value,is_public) values ('passaura','secret','"x"'::jsonb,false);
insert into public.announcements(project,title,body,published) values ('passaura','pub','ok',true);
insert into public.announcements(project,title,body,published) values ('passaura','draft','no',false);
set local role anon;
select is((select count(*)::int from public.feature_flags), 1, 'anon sees only public flags');
select is((select count(*)::int from public.announcements), 1, 'anon sees only published announcements');
reset role;

set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000000","aal":"aal2"}', true);
select throws_ok($$select public.admin_issue_invites(1)$$, 'P0001', 'FORBIDDEN', 'non-owner cannot issue invites');
select throws_ok($$select public.admin_issue_premium_key('trial',14)$$, 'P0001', 'FORBIDDEN', 'non-owner cannot issue keys');
reset role;

select * from finish();
rollback;
