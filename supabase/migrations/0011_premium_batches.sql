-- 0011_premium_batches.sql — premium key batch generation and expiry reporting.
-- Owner-only, MFA-gated (via public.is_owner() from 0002/0005). Never edit 0001-0009.

begin;

-- ---------------------------------------------------------------------------
-- 1) premium_key_batches — audit trail for batches of generated keys.
-- The plaintext keys are NEVER stored here; only the batch metadata and the
-- hashes in premium_keys. The label is for the owner's own reference.
-- ---------------------------------------------------------------------------
create table if not exists public.premium_key_batches (
  id uuid primary key default gen_random_uuid(),
  label text not null check (char_length(label) between 1 and 80),
  count int not null check (count between 1 and 500),
  valid_days int not null check (valid_days between 1 and 3650),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

alter table public.premium_key_batches enable row level security;

-- Owner-only read. No INSERT/UPDATE/DELETE policies: writes go through
-- generate_premium_keys() only (security definer).
create policy premium_key_batches_owner_select on public.premium_key_batches
  for select to authenticated
  using (public.is_owner());

-- ---------------------------------------------------------------------------
-- 2) generate_premium_keys — creates a batch of keys server-side.
-- Returns the plaintext keys ONCE as a text[]. Never log them; the caller
-- (admin UI) shows them once and discards. Only SHA-256 hashes are stored in
-- premium_keys.
--
-- Keys are 'PA-' || 20 hex chars (10 random bytes). gen_random_bytes is
-- cryptographically strong [citation:2][citation:7].
-- ---------------------------------------------------------------------------
create or replace function public.generate_premium_keys(
  p_batch_label text,
  p_count int,
  p_valid_days int,
  p_project text default 'passaura'
)
returns text[]
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_batch_id uuid;
  v_codes text[] := '{}';
  v_code text;
  i int;
begin
  if not public.is_owner() then
    raise exception 'FORBIDDEN';
  end if;
  if p_batch_label is null or char_length(p_batch_label) < 1 or char_length(p_batch_label) > 80 then
    raise exception 'BAD_LABEL';
  end if;
  if p_count is null or p_count < 1 or p_count > 500 then
    raise exception 'COUNT_1_TO_500';
  end if;
  if p_valid_days is null or p_valid_days < 1 or p_valid_days > 3650 then
    raise exception 'DAYS_1_TO_3650';
  end if;
  if not exists (select 1 from public.projects where slug = p_project) then
    raise exception 'BAD_PROJECT';
  end if;

  insert into public.premium_key_batches (label, count, valid_days, created_by)
  values (p_batch_label, p_count, p_valid_days, (select auth.uid()))
  returning id into v_batch_id;

  for i in 1..p_count loop
    v_code := 'PA-' || upper(encode(gen_random_bytes(10), 'hex'));
    insert into public.premium_keys (project, key_hash, plan, note, expires_at)
    values (
      p_project,
      encode(digest(v_code, 'sha256'), 'hex'),
      'trial',
      'batch:' || v_batch_id::text,
      now() + make_interval(days => p_valid_days)
    );
    v_codes := v_codes || v_code;
  end loop;

  -- The plaintext codes are returned and never written to any table or log.
  return v_codes;
end $$;

revoke all on function public.generate_premium_keys(text,int,int,text)
  from public, anon, authenticated;
grant execute on function public.generate_premium_keys(text,int,int,text)
  to authenticated;

-- ---------------------------------------------------------------------------
-- 3) premium_expiry_report — lists keys and the devices bound to them that
-- expire within p_days_ahead days. Owner+MFA only. Read-only.
-- Returns one row per key, with the device id if redeemed.
-- ---------------------------------------------------------------------------
create or replace function public.premium_expiry_report(p_days_ahead int default 30)
returns table (
  key_id uuid,
  plan text,
  expires_at timestamptz,
  revoked boolean,
  redeemed_at timestamptz,
  device_id uuid,
  device_revoked boolean,
  batch_id uuid
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_owner() then
    raise exception 'FORBIDDEN';
  end if;
  if p_days_ahead is null or p_days_ahead < 0 or p_days_ahead > 3650 then
    raise exception 'BAD_DAYS_AHEAD';
  end if;

  return query
    select
      k.id,
      k.plan,
      k.expires_at,
      k.revoked,
      k.redeemed_at,
      k.redeemed_by_device as device_id,
      coalesce(d.revoked, false) as device_revoked,
      -- Extract batch id from the note if it follows the 'batch:<uuid>' convention.
      case
        when k.note like 'batch:%' then
          nullif(substring(k.note from 7), '')::uuid
        else null
      end as batch_id
    from public.premium_keys k
    left join public.devices d on d.id = k.redeemed_by_device
    where k.expires_at is not null
      and k.expires_at < now() + make_interval(days => p_days_ahead)
      and k.expires_at > now() - interval '7 days'  -- include recently expired for context
    order by k.expires_at asc
    limit 500;
end $$;

revoke all on function public.premium_expiry_report(int)
  from public, anon, authenticated;
grant execute on function public.premium_expiry_report(int)
  to authenticated;

-- ---------------------------------------------------------------------------
-- 4) Batch list RPC for the admin UI: last N batches, owner-only.
-- ---------------------------------------------------------------------------
create or replace function public.admin_list_batches(p_limit int default 50)
returns table (
  id uuid,
  label text,
  count int,
  valid_days int,
  created_by uuid,
  created_at timestamptz
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_owner() then
    raise exception 'FORBIDDEN';
  end if;
  return query
    select b.id, b.label, b.count, b.valid_days, b.created_by, b.created_at
      from public.premium_key_batches b
     order by b.created_at desc
     limit least(greatest(coalesce(p_limit, 50), 1), 500);
end $$;

revoke all on function public.admin_list_batches(int)
  from public, anon, authenticated;
grant execute on function public.admin_list_batches(int)
  to authenticated;

-- ---------------------------------------------------------------------------
-- 5) Index for expiry report and batch lookup.
-- premium_keys already has a unique index on key_hash (0002). The expiry
-- report filters on expires_at and orders by expires_at, so a btree on
-- (expires_at) is justified. Batch note lookup is low-volume; no index on
-- note. premium_key_batches is ordered by created_at; add a btree.
-- ---------------------------------------------------------------------------
create index if not exists premium_keys_expires_at_idx
  on public.premium_keys (expires_at)
  where expires_at is not null;

create index if not exists premium_key_batches_created_at_idx
  on public.premium_key_batches (created_at);

commit;
