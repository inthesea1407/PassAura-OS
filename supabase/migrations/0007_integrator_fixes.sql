-- 0007: integrator fixes found while merging 0004-0006.
-- (1) 0004 register_device set invites.used_by_device to a random uuid to "lock" the row, but that column has a
--     foreign key to devices(id), so every invite registration would fail. Lock with FOR UPDATE instead.
-- (2) search_path = '' hides pgcrypto's digest()/gen_random_bytes() (Supabase keeps pgcrypto in "extensions").
--     Use pg_catalog, public, extensions and keep tables schema-qualified.
-- (3) Serialise the seed-window count with a transaction advisory lock.
begin;
create or replace function public.register_device(p_invite_code text, p_hardware_id_hash text)
returns uuid language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare v_cfg public.admin_config; v_inv uuid; v_dev uuid; v_count int;
begin
  if p_hardware_id_hash is null or p_hardware_id_hash !~ '^[0-9a-f]{64}$' then raise exception 'BAD_HARDWARE_ID_HASH'; end if;
  perform pg_advisory_xact_lock(7001);
  if exists (select 1 from public.devices where hardware_id_hash = p_hardware_id_hash and revoked) then raise exception 'DEVICE_REVOKED'; end if;
  if exists (select 1 from public.devices where hardware_id_hash = p_hardware_id_hash) then raise exception 'DEVICE_ALREADY_REGISTERED'; end if;
  select * into v_cfg from public.admin_config where id = 1;
  if v_cfg.mode = 'closed' or v_cfg.invites_paused then raise exception 'REGISTRATION_CLOSED'; end if;
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

alter function public.admin_issue_premium_key(text,int,text,text) set search_path = pg_catalog, public, extensions;
alter function public.admin_issue_invites(int,uuid) set search_path = pg_catalog, public, extensions;
alter function public.redeem_premium_key(text,uuid) set search_path = pg_catalog, public, extensions;  -- 0003 used 'public' only, so digest() was not found
commit;
