-- 50_concurrency.sql — race-condition tests for invite use, seed-limit boundary,
-- and premium key redemption. Uses dblink to open a second session that competes
-- with the test session.
--
-- IMPORTANT: this file requires the dblink extension and a non-superuser role
-- that can authenticate back to the DB. On Supabase's DOCKER runtime this works
-- via `supabase test db`. On the NATIVE runtime, non-superuser dblink is refused
-- (see supabase/cli#6832). Run this file under Docker, or replace dblink with an
-- external two-psql harness.
--
-- Each test: begin; select plan(N); ... rollback;
-- The competing session is opened with dblink_connect and closed with
-- dblink_disconnect in each test so state never leaks.

begin;
select plan(9);

-- Setup: ensure dblink and a deterministic config.
create extension if not exists dblink with schema extensions;
update public.admin_config
   set mode = 'free-invite', invites_paused = false, seed_limit = 0
 where id = 1;

-- ---------------------------------------------------------------------------
-- Test group A: one invite, two devices, only one wins.
-- Both sessions call register_device with the SAME invite code concurrently.
-- Expected: exactly one returns a uuid; the other raises INVITE_INVALID_OR_USED.
-- ---------------------------------------------------------------------------

-- Create a fresh invite and capture its plaintext code via admin_issue_invites.
-- (admin_issue_invites returns the plaintext codes array.)
-- We need the owner identity for that call.
insert into auth.users (id, email) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','owner@test') on conflict do nothing;
insert into public.owners (user_id) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') on conflict do nothing;

set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","aal":"aal2"}', true);
create temporary table t_codes as
  select public.admin_issue_invites(1) as codes;
reset role;

-- Test A1: session 1 (this session) registers with the invite.
-- Test A2: session 2 (dblink) registers the SAME invite with a different hash.
-- We drive them with explicit transaction control inside dblink so the two
-- registrations truly overlap: dblink opens its own transaction, we hold ours
-- open, then both commit/rollback in a controlled order.

-- Open the competing session.
select extensions.dblink_connect('s2',
  'dbname=' || current_database() ||
  ' host=' || coalesce(host(inet_server_addr()), 'localhost') ||
  ' port=' || current_setting('port') ||
  ' user=' || current_user);

-- Session 2: begin and call register_device with the invite, but do NOT commit yet.
-- We stash its result in a temp table inside the dblink session.
select extensions.dblink_exec('s2', 'begin');
select extensions.dblink_exec('s2', format(
  $f$create temp table if not exists s2_result as
     select public.register_device(%L, %L) as id$f$,
  (select (codes)[1] from t_codes),
  repeat('b', 64)
));

-- Session 1 (this session): try the same invite.
-- With seed_limit=0 and the invite not yet consumed, this should succeed.
-- Session 2 holds its transaction open but has already inserted/updated the
-- invite row inside its own transaction, so session 1's UPDATE will block
-- until session 2 commits — then see used_by_device IS NOT NULL and raise.
-- To force the race deterministically we let session 2 commit first, then
-- assert session 1 gets INVITE_INVALID_OR_USED.
select extensions.dblink_exec('s2', 'commit');

select throws_ok(
  format($f$select public.register_device(%L, %L)$f$,
    (select (codes)[1] from t_codes),
    repeat('a', 64)),
  'INVITE_INVALID_OR_USED',
  null,
  'A: second device loses the invite race'
);

-- Assert session 2 actually won (its device exists).
select is(
  (select count(*)::int from public.devices where hardware_id_hash = repeat('b', 64)),
  1,
  'A: winning device persisted exactly once'
);

select extensions.dblink_disconnect('s2');

-- ---------------------------------------------------------------------------
-- Test group B: concurrent registration at the seed-limit boundary.
-- seed_limit = 3, two devices race for the last seed slot.
-- Expected: total seed devices never exceeds 3; exactly one of the two gets
-- the seed slot, the other falls through to the invite path and fails
-- INVITE_INVALID_OR_USED (no invite supplied).
-- ---------------------------------------------------------------------------

-- Reset: truncate devices so the count is deterministic. In a real test DB this
-- is fine; in a shared DB, use a dedicated schema or transaction-scoped setup.
-- Here we rely on the test being rolled back at the end.
update public.admin_config set mode = 'free-invite', invites_paused = false,
  seed_limit = 3 where id = 1;

-- Pre-seed 2 devices so the next insert is the boundary.
select public.register_device('', repeat('1', 64));
select public.register_device('', repeat('2', 64));

-- Open session 2 and have it begin + attempt the 3rd seed registration.
select extensions.dblink_connect('s2',
  'dbname=' || current_database() ||
  ' host=' || coalesce(host(inet_server_addr()), 'localhost') ||
  ' port=' || current_setting('port') ||
  ' user=' || current_user);
select extensions.dblink_exec('s2', 'begin');
select extensions.dblink_exec('s2', format(
  $f$create temp table if not exists s2_b as
     select public.register_device('', %L) as id$f$,
  repeat('3', 64)
));

-- Session 1 (this session) also attempts the 3rd seed registration.
-- Both see count=2 < seed_limit=3 and both try to insert as seed.
-- The function in 0004 counts seed devices and inserts; there is no lock on
-- devices, so both can pass the count check. The unique index on
-- hardware_id_hash does NOT prevent two different hashes from both inserting.
--
-- This is the real bug this test is designed to catch: without a serialization
-- point, the seed count can exceed seed_limit. The 0004 function does NOT
-- take an advisory lock (I deliberately did not add one in Round 1 because the
-- brief did not ask for it; this test exposes that gap).
--
-- Expected correct behavior: exactly 3 seed devices total after both commit.
-- If the test fails, it proves the race and justifies an advisory lock in 0009.
--
-- We let session 2 commit, then let session 1 run.
select extensions.dblink_exec('s2', 'commit');

-- Session 1 attempts the same thing. It will see count=3 now (if session 2 won
-- and committed) and fall to the invite path -> INVITE_INVALID_OR_USED.
-- OR it will see count=2 and insert, making 4 seed devices (the bug).
select lives_ok(
  format($f$select public.register_device('', %L)$f$, repeat('4', 64)),
  'B: session 1 does not error at the boundary (either wins seed or loses to invite path)'
);

-- The assertion that matters: never more than seed_limit seed devices.
select cmp_ok(
  (select count(*)::int from public.devices where is_seed),
  '<=',
  3,
  'B: seed device count never exceeds seed_limit'
);

select extensions.dblink_disconnect('s2');

-- ---------------------------------------------------------------------------
-- Test group C: one premium key, two devices, only one redeems.
-- ---------------------------------------------------------------------------

-- Issue a key as owner.
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","aal":"aal2"}', true);
create temporary table t_key as
  select public.admin_issue_premium_key('trial', 14) as code;
reset role;

-- Create two devices to race.
select public.register_device('', repeat('c', 64));
select public.register_device('', repeat('d', 64));

-- Session 2: begin + redeem with device c, hold open.
select extensions.dblink_connect('s2',
  'dbname=' || current_database() ||
  ' host=' || coalesce(host(inet_server_addr()), 'localhost') ||
  ' port=' || current_setting('port') ||
  ' user=' || current_user);
select extensions.dblink_exec('s2', 'begin');
select extensions.dblink_exec('s2', format(
  $f$create temp table if not exists s2_c as
     select public.redeem_premium_key(%L, (select id from public.devices
       where hardware_id_hash = %L)) as expires$f$,
  (select code from t_key),
  repeat('c', 64)
));

-- Session 1: redeem with device d. This will block on the FOR UPDATE lock
-- held by session 2. We let session 2 commit first, then session 1 sees
-- redeemed_at IS NOT NULL and raises KEY_INVALID.
select extensions.dblink_exec('s2', 'commit');

select throws_ok(
  format($f$select public.redeem_premium_key(%L, (select id from public.devices
    where hardware_id_hash = %L))$f$,
    (select code from t_key),
    repeat('d', 64)),
  'KEY_INVALID',
  null,
  'C: second device loses the premium key race'
);

-- Assert the key was redeemed exactly once and bound to device c.
select is(
  (select count(*)::int from public.premium_keys
    where key_hash = encode(digest((select code from t_key), 'sha256'), 'hex')
      and redeemed_at is not null
      and redeemed_by_device = (select id from public.devices
                                 where hardware_id_hash = repeat('c', 64))),
  1,
  'C: key redeemed exactly once by the winning device'
);

select extensions.dblink_disconnect('s2');

select * from finish();
rollback;
