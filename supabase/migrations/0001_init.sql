-- PassAura OS invite + device registry. DESIGN DRAFT: not yet applied or tested on a live project.
-- Adapted from a DeepSeek draft. Changes: no anon read of invites (the draft let anyone list unused
-- codes), no direct anon insert into devices (it bypassed invite consumption), mode check,
-- seed window (first 1000 devices need no code), 2 invites per member.
create extension if not exists pgcrypto;

create table if not exists admin_config (
  id smallint primary key default 1 check (id = 1),
  mode text not null default 'closed' check (mode in ('free-invite','paid','closed')),
  invites_paused boolean not null default false,
  seed_limit int not null default 1000,
  invites_per_member int not null default 2,
  updated_at timestamptz not null default now()
);
insert into admin_config (id) values (1) on conflict (id) do nothing;

create table if not exists devices (
  id uuid primary key default gen_random_uuid(),
  hardware_id_hash text not null unique,
  is_seed boolean not null default false,
  registered_at timestamptz not null default now(),
  last_seen_at timestamptz,
  revoked boolean not null default false
);

create table if not exists invites (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,          -- store sha256 of the code, never the code
  owner_device uuid references devices(id),
  created_at timestamptz not null default now(),
  used_by_device uuid references devices(id)
);

alter table admin_config enable row level security;
alter table invites enable row level security;
alter table devices enable row level security;
-- No policies for anon/authenticated: deny by default. service_role bypasses RLS.

create or replace function register_device(p_invite_code text, p_hardware_id_hash text)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_cfg admin_config; v_inv uuid; v_dev uuid; v_count int;
begin
  if exists (select 1 from devices where hardware_id_hash = p_hardware_id_hash and revoked) then
    raise exception 'DEVICE_REVOKED';
  end if;
  if exists (select 1 from devices where hardware_id_hash = p_hardware_id_hash) then
    raise exception 'DEVICE_ALREADY_REGISTERED';
  end if;
  lock table devices in share row exclusive mode;  -- serialises the seed-limit count
  select * into v_cfg from admin_config where id = 1;
  select count(*) into v_count from devices;
  if v_count < v_cfg.seed_limit then
    insert into devices (hardware_id_hash, is_seed) values (p_hardware_id_hash, true) returning id into v_dev;
    return v_dev;
  end if;
  if v_cfg.mode = 'closed' or v_cfg.invites_paused then raise exception 'REGISTRATION_CLOSED'; end if;
  select id into v_inv from invites
   where code_hash = encode(digest(p_invite_code,'sha256'),'hex') and used_by_device is null for update;
  if v_inv is null then raise exception 'INVITE_INVALID_OR_USED'; end if;
  insert into devices (hardware_id_hash) values (p_hardware_id_hash) returning id into v_dev;
  update invites set used_by_device = v_dev where id = v_inv;
  return v_dev;
end $$;
revoke all on function register_device(text,text) from public;
grant execute on function register_device(text,text) to anon, service_role;
-- TODO: rate-limit register_device (Edge Function), invite issuing (2 per member), paid scope.
