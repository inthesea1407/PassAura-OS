-- 0005_admin_deny_and_helpers.sql — F6 explicit deny on owners; F14 document security definer;
-- helper for tests to assert "no policies on a table" and hardened search_path on all admin_*.
begin;

-- F6: owners is RLS-enabled with no policy. Make the intent explicit and revoke table grants.
revoke all on table public.owners from anon, authenticated;
-- Owners are managed out-of-band (SQL editor) by the project owner only.

-- Harden search_path on the remaining SECURITY DEFINER functions (0002).
create or replace function public.is_owner() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.owners where user_id = (select auth.uid()))
     and coalesce((select auth.jwt()->>'aal'), '') = 'aal2';
$$;
revoke all on function public.is_owner() from public, anon;
grant execute on function public.is_owner() to authenticated;

create or replace function public.admin_revoke_invite(p_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_owner() then raise exception 'FORBIDDEN'; end if;
  delete from public.invites where id = p_id and used_by_device is null;
end $$;

create or replace function public.admin_set_device_revoked(p_id uuid, p_revoked boolean) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_owner() then raise exception 'FORBIDDEN'; end if;
  -- F1: only allow setting to true here; restoring is a separate function.
  if p_revoked is not true then raise exception 'USE_ADMIN_RESTORE_DEVICE'; end if;
  update public.devices set revoked = true where id = p_id;
end $$;

create or replace function public.admin_revoke_premium_key(p_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_owner() then raise exception 'FORBIDDEN'; end if;
  update public.premium_keys set revoked = true where id = p_id;
end $$;

revoke all on function public.admin_revoke_invite(uuid),
                   public.admin_set_device_revoked(uuid,boolean),
                   public.admin_revoke_premium_key(uuid)
  from public, anon;
grant execute on function public.admin_revoke_invite(uuid),
                   public.admin_set_device_revoked(uuid,boolean),
                   public.admin_revoke_premium_key(uuid)
  to authenticated;

commit;
