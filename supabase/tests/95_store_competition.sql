begin;
select plan(21);

-- Fixtures: owner, two publishers, three voters, three apps (literal uuids).
insert into auth.users(id, email) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'owner@test'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'pa@test'),
  ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'pb@test'),
  ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'v1@test'),
  ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', 'v2@test'),
  ('ffffffff-ffff-ffff-ffff-ffffffffffff', 'v3@test');
insert into public.owners(user_id) values ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
insert into public.store_apps(id, name, publisher_id) values
  ('11111111-1111-1111-1111-11111111111a', 'alpha-app', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
  ('11111111-1111-1111-1111-11111111111b', 'beta-app', 'cccccccc-cccc-cccc-cccc-cccccccccccc'),
  ('11111111-1111-1111-1111-11111111111c', 'gamma-app', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');

-- anon: nothing.
set local role anon;
select is((select count(*)::int from public.store_competitions), 0, 'anon cannot read competitions');
select is((select count(*)::int from public.store_votes), 0, 'anon cannot read votes');
select is((select count(*)::int from public.store_dev_messages), 0, 'anon cannot read dev messages');
reset role;

-- Only the owner (moderator) opens competitions.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"dddddddd-dddd-dddd-dddd-dddddddddddd"}', true);
select throws_ok($$select public.store_open_competition('11111111-1111-1111-1111-11111111111a', '11111111-1111-1111-1111-11111111111b', now() + interval '7 days')$$, 'P0001', 'FORBIDDEN', 'non-owner cannot open a competition');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","aal":"aal2"}', true);
select lives_ok($$select public.store_open_competition('11111111-1111-1111-1111-11111111111a', '11111111-1111-1111-1111-11111111111b', now() + interval '7 days')$$, 'owner opens a competition');
select throws_ok($$select public.store_open_competition('11111111-1111-1111-1111-11111111111a', '11111111-1111-1111-1111-11111111111c', now() + interval '7 days')$$, 'P0001', 'CONFLICT: an app already has an open competition', 'a second open competition on the same app is refused');
reset role;

-- Voting.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"ffffffff-ffff-ffff-ffff-ffffffffffff"}', true);
select throws_ok($$select public.store_vote((select id from public.store_competitions limit 1), '11111111-1111-1111-1111-11111111111c')$$, 'P0001', 'BAD_INPUT: choice is not a candidate', 'cannot vote for a non-candidate');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"dddddddd-dddd-dddd-dddd-dddddddddddd"}', true);
select lives_ok($$select public.store_vote((select id from public.store_competitions limit 1), '11111111-1111-1111-1111-11111111111a')$$, 'voter v1 votes for alpha');
select throws_ok($$select public.store_vote((select id from public.store_competitions limit 1), '11111111-1111-1111-1111-11111111111b')$$, '23505', null, 'one vote per account');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"}', true);
select lives_ok($$select public.store_vote((select id from public.store_competitions limit 1), '11111111-1111-1111-1111-11111111111b')$$, 'voter v2 votes for beta: a 1-1 tie');
reset role;

-- Resolution.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"dddddddd-dddd-dddd-dddd-dddddddddddd"}', true);
select throws_ok($$select public.store_resolve_competition((select id from public.store_competitions limit 1), 'tie_break', '11111111-1111-1111-1111-11111111111a', 'x')$$, 'P0001', 'FORBIDDEN', 'non-owner cannot resolve');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","aal":"aal2"}', true);
select throws_ok($$select public.store_resolve_competition((select id from public.store_competitions limit 1), 'majority', '11111111-1111-1111-1111-11111111111a', 'x')$$, 'P0001', 'BAD_INPUT: a majority winner must have more votes', 'majority resolution on a tie is refused');
select throws_ok($$select public.store_resolve_competition((select id from public.store_competitions limit 1), 'tie_break', '11111111-1111-1111-1111-11111111111a')$$, 'P0001', 'BAD_INPUT: tie_break requires the recorded reasoning', 'tie_break without recorded reasoning is refused');
select lives_ok($$select public.store_resolve_competition((select id from public.store_competitions limit 1), 'tie_break', '11111111-1111-1111-1111-11111111111a', 'alpha respects the platform; beta clones it')$$, 'tie_break resolves with reasoning recorded');
reset role;
select is((select status from public.store_apps where id = '11111111-1111-1111-1111-11111111111b'), 'suspended', 'the loser app is suspended');
select throws_ok($$update public.store_competitions set resolution_notes = 'changed'$$, 'P0001', 'FORBIDDEN: a closed competition is immutable', 'a closed competition is immutable');
select throws_ok($$update public.store_votes set choice = '11111111-1111-1111-1111-11111111111b'$$, 'P0001', 'FORBIDDEN: append-only record', 'votes are append-only');

-- Voting on a resolved competition fails.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"ffffffff-ffff-ffff-ffff-ffffffffffff"}', true);
select throws_ok($$select public.store_vote((select id from public.store_competitions limit 1), '11111111-1111-1111-1111-11111111111a')$$, 'P0001', 'CONFLICT: competition is not open', 'no votes on a resolved competition');
reset role;

-- Developer messages: moderation sends, only the addressed publisher reads.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","aal":"aal2"}', true);
select lives_ok($$select public.store_send_dev_message((select id from public.store_competitions limit 1), 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'alpha won; beta had the better onboarding, consider adding it')$$, 'moderation messages a developer');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}', true);
select is((select count(*)::int from public.store_dev_messages), 1, 'the addressed publisher reads the message');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"cccccccc-cccc-cccc-cccc-cccccccccccc"}', true);
select is((select count(*)::int from public.store_dev_messages), 0, 'another publisher does not read it');
reset role;

select * from finish();
rollback;
