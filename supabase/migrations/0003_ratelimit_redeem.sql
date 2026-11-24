-- DESIGN DRAFT: not applied/tested. Rate limiting + premium key redemption.
create table if not exists rate_limits (
  bucket text not null, window_start timestamptz not null, hits int not null default 0,
  primary key (bucket, window_start));
alter table rate_limits enable row level security;   -- no policies: service_role only

create or replace function rate_limit_hit(p_bucket text, p_max int, p_window_seconds int)
returns boolean language plpgsql security definer set search_path = public as $$
declare w timestamptz := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds); h int;
begin
  insert into rate_limits (bucket, window_start, hits) values (p_bucket, w, 1)
  on conflict (bucket, window_start) do update set hits = rate_limits.hits + 1 returning hits into h;
  delete from rate_limits where window_start < now() - interval '1 day';
  return h <= p_max;
end $$;

-- Registration and redemption are reachable only through the Edge Functions (service_role).
revoke execute on function register_device(text,text) from anon;
revoke all on function rate_limit_hit(text,int,int) from public, anon, authenticated;
grant execute on function rate_limit_hit(text,int,int) to service_role;

create or replace function redeem_premium_key(p_code text, p_device uuid)
returns timestamptz language plpgsql security definer set search_path = public as $$
declare k premium_keys;
begin
  select * into k from premium_keys where key_hash = encode(digest(p_code,'sha256'),'hex') for update;
  if k.id is null or k.revoked or k.redeemed_at is not null or (k.expires_at is not null and k.expires_at < now()) then
    raise exception 'KEY_INVALID';
  end if;
  if not exists (select 1 from devices where id = p_device and not revoked) then raise exception 'DEVICE_INVALID'; end if;
  update premium_keys set redeemed_at = now() where id = k.id;
  return k.expires_at;
end $$;
revoke all on function redeem_premium_key(text,uuid) from public, anon, authenticated;
grant execute on function redeem_premium_key(text,uuid) to service_role;
-- Open: a redeemed key is not yet bound to a device (add premium_device column) and entitlement checks
-- by the PassAura site are not built.

-- Bind redeemed key to the device and expose an entitlement check (service_role only).
alter table premium_keys add column if not exists redeemed_by_device uuid references devices(id);
create or replace function redeem_premium_key(p_code text, p_device uuid)
returns timestamptz language plpgsql security definer set search_path = public as $$
declare k premium_keys;
begin
  select * into k from premium_keys where key_hash = encode(digest(p_code,'sha256'),'hex') for update;
  if k.id is null or k.revoked or k.redeemed_at is not null or (k.expires_at is not null and k.expires_at < now()) then
    raise exception 'KEY_INVALID';
  end if;
  if not exists (select 1 from devices where id = p_device and not revoked) then raise exception 'DEVICE_INVALID'; end if;
  update premium_keys set redeemed_at = now(), redeemed_by_device = p_device where id = k.id;
  return k.expires_at;
end $$;
create or replace function premium_active(p_device uuid) returns boolean language sql stable
security definer set search_path = public as $$
  select exists (select 1 from premium_keys k join devices d on d.id = k.redeemed_by_device
   where k.redeemed_by_device = p_device and not k.revoked and not d.revoked
     and (k.expires_at is null or k.expires_at > now()));
$$;
revoke all on function premium_active(uuid) from public, anon, authenticated;
grant execute on function premium_active(uuid) to service_role;
