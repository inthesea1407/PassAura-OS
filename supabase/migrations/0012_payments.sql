-- 0012_payments.sql — provider-agnostic payment records for "paid" mode.
-- No payment provider is chosen or integrated. Nothing here moves money.
-- A provider webhook (not built) must verify the provider's signature, then call
-- record_payment() with the service_role key. Enforcement stays OFF until the owner sets
-- admin_config.paid_enforcement = true AND mode = 'paid'. Never edit 0001-0011.

begin;

alter table public.admin_config
  add column if not exists paid_enforcement boolean not null default false;

create table if not exists public.payments (
  id uuid primary key default gen_random_uuid(),
  hardware_id_hash text not null check (hardware_id_hash ~ '^[0-9a-f]{64}$'),
  provider text not null check (char_length(provider) between 1 and 40),
  provider_ref text not null check (char_length(provider_ref) between 1 and 200),
  amount_minor int not null check (amount_minor > 0),          -- piasters for EGP
  currency text not null check (currency ~ '^[A-Z]{3}$'),
  status text not null default 'paid' check (status in ('paid','refunded')),
  device_id uuid references public.devices(id),                -- set when the payment is used to join
  created_at timestamptz not null default now(),
  unique (provider, provider_ref)
);
create index if not exists payments_hash_idx on public.payments (hardware_id_hash);

alter table public.payments enable row level security;   -- no policies: clients see nothing
revoke all on table public.payments from public, anon, authenticated;

-- Record a VERIFIED payment. Idempotent on (provider, provider_ref) so webhook retries are safe.
create or replace function public.record_payment(
  p_hardware_id_hash text, p_provider text, p_provider_ref text, p_amount_minor int, p_currency text)
returns uuid language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare v_id uuid; v_existing public.payments;
begin
  select * into v_existing from public.payments where provider = p_provider and provider_ref = p_provider_ref;
  if found then
    if v_existing.hardware_id_hash <> p_hardware_id_hash then raise exception 'PAYMENT_REF_CONFLICT'; end if;
    return v_existing.id;
  end if;
  insert into public.payments (hardware_id_hash, provider, provider_ref, amount_minor, currency)
  values (p_hardware_id_hash, p_provider, p_provider_ref, p_amount_minor, p_currency)
  returning id into v_id;
  return v_id;
exception when unique_violation then
  select id into v_id from public.payments where provider = p_provider and provider_ref = p_provider_ref;
  return v_id;
end $$;

-- Refund an unused payment. A payment already used to join is left alone (returns false).
create or replace function public.refund_payment(p_provider text, p_provider_ref text)
returns boolean language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  update public.payments set status = 'refunded'
   where provider = p_provider and provider_ref = p_provider_ref and device_id is null and status = 'paid';
  return found;
end $$;

revoke all on function public.record_payment(text,text,text,int,text) from public, anon, authenticated;
revoke all on function public.refund_payment(text,text) from public, anon, authenticated;
grant execute on function public.record_payment(text,text,text,int,text) to service_role;
grant execute on function public.refund_payment(text,text) to service_role;

-- register_device: identical to 0009, plus a payment gate that applies only when
-- mode = 'paid' AND paid_enforcement = true. With the flag off the behavior is unchanged.
-- With the gate on, invites and the seed window are not used: a paid, unused payment is required.
create or replace function public.register_device(p_invite_code text, p_hardware_id_hash text)
returns uuid language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare v_cfg public.admin_config; v_inv uuid; v_dev uuid; v_count int; v_pay uuid;
begin
  if p_hardware_id_hash is null or p_hardware_id_hash !~ '^[0-9a-f]{64}$' then raise exception 'BAD_HARDWARE_ID_HASH'; end if;
  perform pg_advisory_xact_lock(7001);
  if exists (select 1 from public.devices where hardware_id_hash = p_hardware_id_hash and revoked) then raise exception 'DEVICE_REVOKED'; end if;
  if exists (select 1 from public.devices where hardware_id_hash = p_hardware_id_hash) then raise exception 'DEVICE_ALREADY_REGISTERED'; end if;
  select * into v_cfg from public.admin_config where id = 1;
  if v_cfg.mode = 'closed' or v_cfg.invites_paused then raise exception 'REGISTRATION_CLOSED'; end if;

  if v_cfg.mode = 'paid' and v_cfg.paid_enforcement then
    select id into v_pay from public.payments
     where hardware_id_hash = p_hardware_id_hash and status = 'paid' and device_id is null
     order by created_at limit 1 for update;
    if v_pay is null then raise exception 'PAYMENT_REQUIRED'; end if;
    insert into public.devices (hardware_id_hash) values (p_hardware_id_hash) returning id into v_dev;
    update public.payments set device_id = v_dev where id = v_pay;
    return v_dev;
  end if;

  select count(*) into v_count from public.devices where is_seed;
  if v_count < v_cfg.seed_limit then
    insert into public.devices (hardware_id_hash, is_seed) values (p_hardware_id_hash, true) returning id into v_dev;
    return v_dev;
  end if;
  select id into v_inv from public.invites
   where code_hash = encode(digest(coalesce(p_invite_code,''),'sha256'),'hex') and used_by_device is null for update;
  if v_inv is null then raise exception 'INVITE_INVALID_OR_USED'; end if;
  insert into public.devices (hardware_id_hash) values (p_hardware_id_hash) returning id into v_dev;
  update public.invites set used_by_device = v_dev where id = v_inv;
  return v_dev;
end $$;
revoke all on function public.register_device(text,text) from public, anon, authenticated;
grant execute on function public.register_device(text,text) to service_role;

commit;
