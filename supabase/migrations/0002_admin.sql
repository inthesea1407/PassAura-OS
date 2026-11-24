-- Owner admin layer. DESIGN DRAFT: not applied, not tested on a live project.
-- Owner = a row in owners, and the session must be MFA (aal2). Bootstrap: owner inserts own
-- auth.users id by hand in the SQL editor after first login + MFA enrolment.
create table if not exists owners (user_id uuid primary key references auth.users(id));
alter table owners enable row level security;

create or replace function is_owner() returns boolean language sql stable security definer
set search_path = public as $$
  select exists (select 1 from owners where user_id = auth.uid())
     and coalesce(auth.jwt()->>'aal','') = 'aal2';
$$;
revoke all on function is_owner() from public; grant execute on function is_owner() to authenticated;

alter table admin_config add column if not exists paid_scope text not null default 'new_only'
  check (paid_scope in ('new_only','everyone'));

create table if not exists projects (
  slug text primary key check (slug ~ '^[a-z0-9-]{2,40}$'), name text not null,
  created_at timestamptz not null default now());
insert into projects (slug,name) values ('passaura','PassAura'),('pos','PassAura OS') on conflict do nothing;
alter table projects enable row level security;
create policy owner_proj_all on projects for all to authenticated using (is_owner()) with check (is_owner());

create table if not exists premium_keys (
  project text not null default 'passaura' references projects(slug),
  id uuid primary key default gen_random_uuid(),
  key_hash text not null unique, plan text not null default 'trial',
  note text, expires_at timestamptz, revoked boolean not null default false,
  redeemed_at timestamptz, created_at timestamptz not null default now());
create table if not exists feature_flags (
  project text not null default 'passaura' references projects(slug), key text, value jsonb not null default 'null', is_public boolean not null default true,
  updated_at timestamptz not null default now(), primary key (project, key));
create table if not exists announcements (
  id uuid primary key default gen_random_uuid(), project text not null default 'passaura' references projects(slug), title text not null, body text not null default '',
  published boolean not null default false, created_at timestamptz not null default now());
alter table premium_keys enable row level security;
alter table feature_flags enable row level security;
alter table announcements enable row level security;

-- owner-only access
create policy owner_cfg_sel on admin_config for select to authenticated using (is_owner());
create policy owner_cfg_upd on admin_config for update to authenticated using (is_owner()) with check (is_owner());
create policy owner_dev_sel on devices for select to authenticated using (is_owner());
create policy owner_inv_sel on invites for select to authenticated using (is_owner());
create policy owner_key_sel on premium_keys for select to authenticated using (is_owner());
create policy owner_flag_all on feature_flags for all to authenticated using (is_owner()) with check (is_owner());
create policy owner_ann_all on announcements for all to authenticated using (is_owner()) with check (is_owner());
-- the PassAura site reads only public flags and published announcements
create policy public_flags on feature_flags for select to anon using (is_public);
create policy public_ann on announcements for select to anon using (published);

-- writes that must be atomic or return a secret go through functions
create or replace function admin_issue_invites(p_count int, p_owner_device uuid default null)
returns text[] language plpgsql security definer set search_path = public as $$
declare codes text[] := '{}'; c text;
begin
  if not is_owner() then raise exception 'FORBIDDEN'; end if;
  if p_count < 1 or p_count > 50 then raise exception 'COUNT_1_TO_50'; end if;
  for i in 1..p_count loop
    c := upper(encode(gen_random_bytes(8),'hex'));
    insert into invites (code_hash, owner_device) values (encode(digest(c,'sha256'),'hex'), p_owner_device);
    codes := codes || c;
  end loop;
  return codes;   -- shown once; only hashes are stored
end $$;

create or replace function admin_revoke_invite(p_id uuid) returns void language plpgsql
security definer set search_path = public as $$
begin
  if not is_owner() then raise exception 'FORBIDDEN'; end if;
  delete from invites where id = p_id and used_by_device is null;
end $$;

create or replace function admin_set_device_revoked(p_id uuid, p_revoked boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_owner() then raise exception 'FORBIDDEN'; end if;
  update devices set revoked = p_revoked where id = p_id;   -- only the owner can revoke
end $$;

create or replace function admin_issue_premium_key(p_plan text, p_days int, p_note text default null, p_project text default 'passaura')
returns text language plpgsql security definer set search_path = public as $$
declare c text;
begin
  if not is_owner() then raise exception 'FORBIDDEN'; end if;
  c := 'PA-' || upper(encode(gen_random_bytes(10),'hex'));
  insert into premium_keys (project, key_hash, plan, note, expires_at)
  values (p_project, encode(digest(c,'sha256'),'hex'), p_plan, p_note, now() + make_interval(days => p_days));
  return c;
end $$;

create or replace function admin_revoke_premium_key(p_id uuid) returns void language plpgsql
security definer set search_path = public as $$
begin
  if not is_owner() then raise exception 'FORBIDDEN'; end if;
  update premium_keys set revoked = true where id = p_id;
end $$;

revoke all on function admin_issue_invites(int,uuid), admin_revoke_invite(uuid),
  admin_set_device_revoked(uuid,boolean), admin_issue_premium_key(text,int,text,text),
  admin_revoke_premium_key(uuid) from public;
grant execute on function admin_issue_invites(int,uuid), admin_revoke_invite(uuid),
  admin_set_device_revoked(uuid,boolean), admin_issue_premium_key(text,int,text,text),
  admin_revoke_premium_key(uuid) to authenticated;
-- Note: register_device() in 0001 should also reject revoked hardware; add before real use.
-- Project registry: add a new site/project = insert a row in projects. Flags, announcements and keys are per project.
-- POS membership tables (invites/devices/admin_config) are the POS project's own; a future site that needs
-- members should get its own tables or a project column, decided when it exists.
