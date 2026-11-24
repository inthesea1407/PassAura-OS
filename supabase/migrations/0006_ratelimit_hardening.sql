-- 0006_ratelimit_hardening.sql — F4: bound the prune, validate inputs, harden search_path.
begin;

create or replace function public.rate_limit_hit(p_bucket text, p_max int, p_window_seconds int)
returns boolean language plpgsql security definer set search_path = '' as $$
declare
  w timestamptz;
  h int;
begin
  if p_bucket is null or char_length(p_bucket) > 200 then raise exception 'BAD_BUCKET'; end if;
  if p_max is null or p_max < 1 or p_max > 100000 then raise exception 'BAD_MAX'; end if;
  if p_window_seconds is null or p_window_seconds < 1 or p_window_seconds > 86400 then
    raise exception 'BAD_WINDOW';
  end if;
  w := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
  insert into public.rate_limits (bucket, window_start, hits)
  values (p_bucket, w, 1)
  on conflict (bucket, window_start) do update set hits = public.rate_limits.hits + 1
  returning hits into h;
  -- F4: bounded prune (max 500 rows) instead of unbounded delete on every call.
  delete from public.rate_limits
   where ctid in (
     select ctid from public.rate_limits
      where window_start < now() - interval '1 day'
      limit 500
   );
  return h <= p_max;
end $$;
revoke all on function public.rate_limit_hit(text,int,int) from public, anon, authenticated;
grant execute on function public.rate_limit_hit(text,int,int) to service_role;

commit;
