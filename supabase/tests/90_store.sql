begin;
select plan(20);

-- Two publishers and two reviewers (uuids are test fixtures only).
\set p1 '''11111111-1111-1111-1111-111111111111'''
\set p2 '''22222222-2222-2222-2222-222222222222'''
\set r1 '''33333333-3333-3333-3333-333333333333'''
\set r2 '''44444444-4444-4444-4444-444444444444'''

insert into auth.users(id, email) values
  (:p1, 'p1@test'), (:p2, 'p2@test'), (:r1, 'r1@test'), (:r2, 'r2@test');
insert into public.store_reviewer_roles(account_id, granted_by) values (:r1, :p1), (:r2, :p1);

-- anon: nothing visible, nothing writable.
set local role anon;
select is((select count(*)::int from public.store_apps), 0, 'anon cannot read store_apps');
select is((select count(*)::int from public.store_submissions), 0, 'anon cannot read store_submissions');
select is((select count(*)::int from public.store_reviews), 0, 'anon cannot read store_reviews');
select throws_ok($$select 1 from public.store_reviewer_roles$$, '42501', null, 'anon cannot read store_reviewer_roles (grant revoked)');
select throws_ok($$insert into public.store_apps(name, publisher_id) values ('x', gen_random_uuid())$$, '42501', null, 'anon cannot insert apps');
reset role;

-- publisher flows.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111"}', true);
select lives_ok($$insert into public.store_apps(name, publisher_id) values ('hello-app', '11111111-1111-1111-1111-111111111111')$$, 'publisher creates own app');
select throws_ok($$insert into public.store_apps(name, publisher_id) values ('evil-app', '22222222-2222-2222-2222-222222222222')$$, '42501', null, 'publisher cannot create an app as someone else');
select lives_ok($$insert into public.store_submissions(app_id, version, sha256, artifact_path, size_bytes)
  select id, '1.0', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'private/hello-app-1.0.deb', 1024 from public.store_apps where name = 'hello-app'$$, 'publisher submits to own app');
reset role;

-- p2: cannot see p1's app, cannot submit to it, cannot review.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222"}', true);
select is((select count(*)::int from public.store_apps), 0, 'publisher p2 cannot see p1 apps');
reset role;

-- Even a reviewer (who can see the queue) has no direct insert path: the function only.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"33333333-3333-3333-3333-333333333333"}', true);
select throws_ok($$insert into public.store_reviews(submission_id, reviewer_id, decision)
  select id, '33333333-3333-3333-3333-333333333333', 'approve' from public.store_submissions limit 1$$, '42501', null, 'no direct review inserts, even for reviewers');
reset role;

-- Direct state update has no policy: silently changes nothing.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111"}', true);
update public.store_submissions set state = 'approved';
reset role;
select is((select state from public.store_submissions limit 1), 'submitted', 'direct state update changed nothing');

-- Non-reviewer cannot use the review function.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111"}', true);
select throws_ok($$select public.store_submit_review((select id from public.store_submissions limit 1), 'approve')$$, 'P0001', 'FORBIDDEN', 'non-reviewer cannot review');
reset role;

-- Reviewer flow: two approvals reach the quorum (2), a duplicate review is refused.
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"33333333-3333-3333-3333-333333333333"}', true);
select lives_ok($$select public.store_submit_review((select id from public.store_submissions limit 1), 'approve')$$, 'reviewer r1 approves');
reset role;
select is((select state from public.store_submissions limit 1), 'in_review', 'one approval moves to in_review');
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"33333333-3333-3333-3333-333333333333"}', true);
select throws_ok($$select public.store_submit_review((select id from public.store_submissions limit 1), 'approve')$$, 'P0001', 'CONFLICT: already reviewed', 'same reviewer cannot review twice');
reset role;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"44444444-4444-4444-4444-444444444444"}', true);
select lives_ok($$select public.store_submit_review((select id from public.store_submissions limit 1), 'approve')$$, 'reviewer r2 approves');
reset role;
select is((select state from public.store_submissions limit 1), 'approved', 'quorum reached: approved');

-- Append-only and legal transitions, checked as superuser (bypasses RLS, triggers still fire).
select throws_ok($$update public.store_reviews set decision = 'reject'$$, 'P0001', 'FORBIDDEN: reviews are append-only', 'review update refused');
select throws_ok($$delete from public.store_reviews$$, 'P0001', 'FORBIDDEN: reviews are append-only', 'review delete refused');
select throws_ok($$update public.store_submissions set state = 'submitted'$$, 'P0001', null, 'illegal transition approved -> submitted refused');

select * from finish();
rollback;
