begin;
select plan(9);

-- Owner inserts an owner row so admin_* work.
insert into auth.users(id, email) values ('11111111-1111-1111-1111-111111111111','o@x') on conflict do nothing;
insert into public.owners(user_id) values ('11111111-1111-1111-1111-111111111111');
insert into public.projects(slug,name) values ('passaura','PassAura') on conflict do nothing;

-- Create a device to redeem against.
update public.admin_config set mode='free-invite', seed_limit=1000, invites_paused=false;
select public.register_device('', repeat('a',64));
create temporary table t_dev as select id from public.devices where hardware_id_hash=repeat('a',64);

set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","aal":"aal2"}', true);

-- Issue + redeem.
select isnt(public.admin_issue_premium_key('trial',14), null, 'issue key');

-- Redeem by device.
reset role;
create temporary table t_key as select public.admin_issue_premium_key('trial',14) as code;
select is(public.redeem_premium_key((select code from t_key), (select id from t_dev)) is not null, true, 'redeem succeeds');
select throws_ok(
  $$select public.redeem_premium_key((select code from t_key), (select id from t_dev))$$,
  'P0001', 'KEY_INVALID', 'cannot redeem twice');

-- Revoked key.
select public.admin_issue_premium_key('trial',14);
create temporary table t_key2 as select public.admin_issue_premium_key('trial',14) as code;
select public.admin_revoke_premium_key((select id from public.premium_keys where key_hash=encode(digest((select code from t_key2),'sha256'),'hex')));
select throws_ok(
  $$select public.redeem_premium_key((select code from t_key2), (select id from t_dev))$$,
  'P0001', 'KEY_INVALID', 'revoked key refused');

-- Expired key (issued with p_days now bounded; simulate by direct update).
create temporary table t_key3 as select public.admin_issue_premium_key('trial',1) as code;
update public.premium_keys set expires_at = now() - interval '1 day'
 where key_hash=encode(digest((select code from t_key3),'sha256'),'hex');
select throws_ok(
  $$select public.redeem_premium_key((select code from t_key3), (select id from t_dev))$$,
  'P0001', 'KEY_INVALID', 'expired key refused');

-- Revoked device.
update public.devices set revoked=true where id=(select id from t_dev);
select throws_ok(
  $$select public.redeem_premium_key((select code from t_key), (select id from t_dev))$$,
  'P0001', 'DEVICE_INVALID', 'revoked device refused');

-- Non-owner, non-MFA cannot call admin_*.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","aal":"aal1"}', true);
select throws_ok($$select public.admin_issue_premium_key('trial',1)$$, 'P0001', 'FORBIDDEN', 'aal1 cannot issue keys');
reset role;

select * from finish();
rollback;
