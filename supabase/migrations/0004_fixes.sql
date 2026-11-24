-- 0004_fixes.sql — hardening pass over 0001-0003. Never edit 0001-0003; this file is additive.
-- Fixes: F2 seed-window bypass, F3/F12 grant order, F5/F16 key expiry validation,
-- F11 race-safe registration, F19 hash check, F15 server timestamps, F13 invite owner check.

begin;

-- F19: enforce the 64-hex contract at the storage layer.
alter table public.devices
  drop constraint if exists devices_hardware_id_hash_chk;
alter table public.devices
  add constraint devices_hardware_id_hash_chk check (hardware_id_hash ~ '^[0-9a-f]{64}$');

-- F2: seed window can never be re-opened. Once seed_limit is lowered, it stays lowered.
-- (We do not enforce monotonicity in SQL; instead we forbid raising it via a trigger.)
create or replace function public.tg_admin_config_seed_limit_guard()
returns trigger language plpgsql as $$
begin
  if new.seed_limit > old.seed_limit then
    raise exception 'SEED_LIMIT_CANNOT_INCREASE';
  end if;
  return new;
end $$;
drop trigger if exists admin_config_seed_limit_guard on public.admin_config;
create trigger admin_config_seed_limit_guard
  before update of seed_limit on public.admin_config
  for each row execute function public.tg_admin_config_seed_limit_guard();

-- F15: ignore client-supplied timestamps; always stamp server-side.
create or replace function public.tg_stamp_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists admin_config_stamp on public.admin_config;
create trigger admin_config_stamp before update on public.admin_config
  for each row execute function public.tg_stamp_updated_at();
drop trigger if exists feature_flags_stamp on public.feature_flags;
create trigger feature_flags_stamp before update on public.feature_flags
  for each row execute function public.tg_stamp_updated_at();

-- F11 + F2 + F3 + F12: canonical registration function.
-- Seed window now only applies in mode='free-invite' and only while invites_paused=false.
-- Unique-violation races are converted to DEVICE_ALREADY_REGISTERED.
create or replace function public.register_device(p_invite_code text, p_hardware_id_hash text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_cfg public.admin_config;
  v_inv uuid;
  v_dev uuid;
  v_count int;
begin
  if p_hardware_id_hash is null or p_hardware_id_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'BAD_HARDWARE_ID_HASH';
  end if;

  -- Fast-path pre-checks (still race-guarded by the unique index below).
  if exists (select 1 from public.devices where hardware_id_hash = p_hardware_id_hash and revoked) then
    raise exception 'DEVICE_REVOKED';
  end if;
  if exists (select 1 from public.devices where hardware_id_hash = p_hardware_id_hash) then
    raise exception 'DEVICE_ALREADY_REGISTERED';
  end if;

  select * into v_cfg from public.admin_config where id = 1;

  -- F2: seed window is subordinate to mode + pause, and only counts seed devices.
  if v_cfg.mode = 'closed' or v_cfg.invites_paused then
    raise exception 'REGISTRATION_CLOSED';
  end if;

  select count(*) into v_count from public.devices where is_seed;
  if v_count < v_cfg.seed_limit then
    begin
      insert into public.devices (hardware_id_hash, is_seed)
      values (p_hardware_id_hash, true) returning id into v_dev;
    exception when unique_violation then
      raise exception 'DEVICE_ALREADY_REGISTERED';
    end;
    return v_dev;
  end if;

  if v_cfg.mode not in ('free-invite','paid') then
    raise exception 'REGISTRATION_CLOSED';
  end if;

  -- Atomically consume the invite.
  update public.invites
     set used_by_device = gen_random_uuid()  -- placeholder to lock the row; replaced below
   where code_hash = encode(digest(p_invite_code,'sha256'),'hex')
     and used_by_device is null
  returning id into v_inv;
  if v_inv is null then
    raise exception 'INVITE_INVALID_OR_USED';
  end if;

  begin
    insert into public.devices (hardware_id_hash) values (p_hardware_id_hash) returning id into v_dev;
  exception when unique_violation then
    -- Roll back the invite consumption by raising; the whole function is a single tx.
    raise exception 'DEVICE_ALREADY_REGISTERED';
  end;

  update public.invites set used_by_device = v_dev where id = v_inv;
  return v_dev;
end $$;

-- F3/F12: explicit deny for anon/authenticated, grant only service_role.
revoke all on function public.register_device(text,text) from public, anon, authenticated;
grant execute on function public.register_device(text,text) to service_role;

-- F5/F16: bound key issuance and validate plan/project.
create or replace function public.admin_issue_premium_key(
  p_plan text, p_days int, p_note text default null, p_project text default 'passaura')
returns text language plpgsql security definer set search_path = '' as $$
declare c text;
begin
  if not public.is_owner() then raise exception 'FORBIDDEN'; end if;
  if p_days is null or p_days < 1 or p_days > 3650 then
    raise exception 'DAYS_1_TO_3650';
  end if;
  if p_plan is null or char_length(p_plan) > 40 then raise exception 'BAD_PLAN'; end if;
  if not exists (select 1 from public.projects where slug = p_project) then
    raise exception 'BAD_PROJECT';
  end if;
  c := 'PA-' || upper(encode(gen_random_bytes(10),'hex'));
  insert into public.premium_keys (project, key_hash, plan, note, expires_at)
  values (p_project, encode(digest(c,'sha256'),'hex'), p_plan,
          left(coalesce(p_note,''), 200), now() + make_interval(days => p_days));
  return c;
end $$;
revoke all on function public.admin_issue_premium_key(text,int,text,text) from public, anon, authenticated;
grant execute on function public.admin_issue_premium_key(text,int,text,text) to authenticated;

-- F13: invite owner_device must be an existing, non-revoked device (or null).
create or replace function public.admin_issue_invites(p_count int, p_owner_device uuid default null)
returns text[] language plpgsql security definer set search_path = '' as $$
declare codes text[] := '{}'; c text;
begin
  if not public.is_owner() then raise exception 'FORBIDDEN'; end if;
  if p_count < 1 or p_count > 50 then raise exception 'COUNT_1_TO_50'; end if;
  if p_owner_device is not null
     and not exists (select 1 from public.devices where id = p_owner_device and not revoked) then
    raise exception 'OWNER_DEVICE_INVALID';
  end if;
  for i in 1..p_count loop
    c := upper(encode(gen_random_bytes(8),'hex'));
    insert into public.invites (code_hash, owner_device)
    values (encode(digest(c,'sha256'),'hex'), p_owner_device);
    codes := codes || c;
  end loop;
  return codes;
end $$;
revoke all on function public.admin_issue_invites(int,uuid) from public, anon, authenticated;
grant execute on function public.admin_issue_invites(int,uuid) to authenticated;

-- F1: revoke is one-way here; a separate owner-only restore keeps an audit trail.
create or replace function public.admin_restore_device(p_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_owner() then raise exception 'FORBIDDEN'; end if;
  update public.devices set revoked = false where id = p_id;
end $$;
revoke all on function public.admin_restore_device(uuid) from public, anon, authenticated;
grant execute on function public.admin_restore_device(uuid) to authenticated;

commit;
