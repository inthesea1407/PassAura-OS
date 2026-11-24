begin;
select plan(14);

-- Anon cannot SELECT any table.
set local role anon;
select throws_ok($$select 1 from public.admin_config$$,   '42501', null, 'anon cannot read admin_config');
select throws_ok($$select 1 from public.devices$$,        '42501', null, 'anon cannot read devices');
select throws_ok($$select 1 from public.invites$$,        '42501', null, 'anon cannot read invites');
select throws_ok($$select 1 from public.owners$$,         '42501', null, 'anon cannot read owners');
select throws_ok($$select 1 from public.premium_keys$$,   '42501', null, 'anon cannot read premium_keys');
select throws_ok($$select 1 from public.rate_limits$$,    '42501', null, 'anon cannot read rate_limits');

-- Anon cannot write any table.
select throws_ok($$insert into public.devices(hardware_id_hash) values (repeat('a',64))$$, '42501', null, 'anon cannot insert devices');
select throws_ok($$insert into public.invites(code_hash) values ('x')$$, '42501', null, 'anon cannot insert invites');
select throws_ok($$update public.admin_config set mode='paid'$$, '42501', null, 'anon cannot update admin_config');
select throws_ok($$delete from public.premium_keys$$, '42501', null, 'anon cannot delete premium_keys');
reset role;

-- Anon CAN read only public flags and published announcements.
insert into public.feature_flags(project,key,value,is_public) values ('passaura','price_monthly','3.99'::jsonb,true);
insert into public.feature_flags(project,key,value,is_public) values ('passaura','secret','"x"'::jsonb,false);
insert into public.announcements(project,title,body,published) values ('passaura','pub','ok',true);
insert into public.announcements(project,title,body,published) values ('passaura','draft','no',false);
set local role anon;
select is((select count(*)::int from public.feature_flags), 1, 'anon sees only public flags');
select is((select count(*)::int from public.announcements), 1, 'anon sees only published announcements');
reset role;

-- Authenticated non-owner cannot call admin_*.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"00000000-0000-0000-0000-000000000000","aal":"aal2"}', true);
select throws_ok($$select public.admin_issue_invites(1)$$, 'P0001', 'FORBIDDEN', 'non-owner cannot issue invites');
select throws_ok($$select public.admin_issue_premium_key('trial',14)$$, 'P0001', 'FORBIDDEN', 'non-owner cannot issue keys');
select throws_ok($$select public.admin_set_device_revoked(gen_random_uuid(),true)$$, 'P0001', 'FORBIDDEN', 'non-owner cannot revoke device');
reset role;

select * from finish();
rollback;
