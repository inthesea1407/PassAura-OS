begin;
select plan(10);

-- Closed mode: even during seed window, registration is refused (F2 fix).
update public.admin_config set mode='closed', seed_limit=2 where id=1;
select throws_ok(
  $$select public.register_device('', repeat('a',64))$$,
  'P0001', 'REGISTRATION_CLOSED', 'closed mode refuses registration');

-- Free-invite: seed window registers the first N, then requires an invite.
update public.admin_config set mode='free-invite', seed_limit=2 where id=1;
select is(public.register_device('', repeat('a',64)) is not null, true, 'seed 1 registers');
select is(public.register_device('', repeat('b',64)) is not null, true, 'seed 2 registers');
select throws_ok(
  $$select public.register_device('', repeat('c',64))$$,
  'P0001', 'INVITE_INVALID_OR_USED', 'seed exhausted -> invite required');

-- Invite single use.
insert into public.invites(code_hash) values (encode(digest('CODE1','sha256'),'hex'));
select is(public.register_device('CODE1', repeat('d',64)) is not null, true, 'invite registers once');
select throws_ok(
  $$select public.register_device('CODE1', repeat('e',64))$$,
  'P0001', 'INVITE_INVALID_OR_USED', 'invite cannot be reused');

-- Revoked device cannot re-register.
update public.devices set revoked=true where hardware_id_hash=repeat('d',64);
select throws_ok(
  $$select public.register_device('CODE1', repeat('d',64))$$,
  'P0001', 'DEVICE_REVOKED', 'revoked device refused');

-- Paused invites: seed window is closed too.
update public.admin_config set invites_paused=true;
select throws_ok(
  $$select public.register_device('', repeat('f',64))$$,
  'P0001', 'REGISTRATION_CLOSED', 'paused refuses new devices');

-- Anon cannot call register_device directly (F3 fix).
update public.admin_config set invites_paused=false, seed_limit=2;
set local role anon;
select throws_ok($$select public.register_device('', repeat('9',64))$$, '42501', null, 'anon cannot call register_device directly');
reset role;

-- Bad hash rejected.
select throws_ok($$select public.register_device('', 'nothex')$$, 'P0001', 'BAD_HARDWARE_ID_HASH', 'bad hash refused');

select * from finish();
rollback;
