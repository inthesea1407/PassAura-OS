-- 80_payments.sql — payment records and the (default-off) paid-mode gate.
begin;
select plan(13);

update public.admin_config set mode='paid', paid_enforcement=false, seed_limit=0, invites_paused=false where id=1;

-- Flag off: paid mode behaves like before (needs an invite once the seed window is closed).
select throws_ok($$select public.register_device('', repeat('1',64))$$, 'P0001', 'INVITE_INVALID_OR_USED', 'flag off: paid mode still uses invites');

-- Flag on, no payment.
update public.admin_config set paid_enforcement=true where id=1;
select throws_ok($$select public.register_device('', repeat('1',64))$$, 'P0001', 'PAYMENT_REQUIRED', 'flag on: payment required');
insert into public.invites(code_hash) values (encode(digest('PAYCODE','sha256'),'hex'));
select throws_ok($$select public.register_device('PAYCODE', repeat('1',64))$$, 'P0001', 'PAYMENT_REQUIRED', 'flag on: an invite does not replace payment');

-- Record a payment (idempotent).
select is(public.record_payment(repeat('1',64),'test','ref-1',5000,'EGP') is not null, true, 'payment recorded');
select is(public.record_payment(repeat('1',64),'test','ref-1',5000,'EGP'), (select id from public.payments where provider_ref='ref-1'), 'same ref returns the same row');
select is((select count(*)::int from public.payments where provider_ref='ref-1'), 1, 'no duplicate row');
select throws_ok($$select public.record_payment(repeat('2',64),'test','ref-1',5000,'EGP')$$, 'P0001', 'PAYMENT_REF_CONFLICT', 'same ref for another device is refused');
select throws_ok($$select public.record_payment(repeat('1',64),'test','ref-2',0,'EGP')$$, '23514', null, 'zero amount refused');

-- Paid device joins once; the payment is consumed.
select is(public.register_device('', repeat('1',64)) is not null, true, 'paid device registers');
select is((select device_id is not null from public.payments where provider_ref='ref-1'), true, 'payment consumed');

-- Refunded payment does not count; a used payment cannot be refunded.
select is(public.record_payment(repeat('3',64),'test','ref-3',5000,'EGP') is not null, true, 'second payment recorded');
select is(public.refund_payment('test','ref-3'), true, 'unused payment refunded');
select throws_ok($$select public.register_device('', repeat('3',64))$$, 'P0001', 'PAYMENT_REQUIRED', 'refunded payment does not allow joining');

select * from finish();
rollback;
