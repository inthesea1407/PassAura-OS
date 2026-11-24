begin;
select plan(4);

select is(public.rate_limit_hit('t:1', 2, 60)::text, 'true',  'hit 1 allowed');
select is(public.rate_limit_hit('t:1', 2, 60)::text, 'true',  'hit 2 allowed');
select is(public.rate_limit_hit('t:1', 2, 60)::text, 'false', 'hit 3 blocked');

-- Anon cannot call rate_limit_hit.
set local role anon;
select throws_ok($$select public.rate_limit_hit('x',1,60)$$, '42501', null, 'anon cannot call rate_limit_hit');
reset role;

select * from finish();
rollback;
