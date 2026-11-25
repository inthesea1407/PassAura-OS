-- 0008_ratelimit_cleanup.sql — bounded, scheduled cleanup of rate_limits.
-- Never edit 0001-0006. This migration is additive.
--
-- Background: 0006 bounded the per-call prune to 500 rows, which prevents a
-- single rate_limit_hit call from doing an unbounded delete. But 0006 does not
-- guarantee the table stops growing: if traffic outpaces the 500-row prune,
-- or if the bounded delete always hits the same 500 rows under a hot bucket,
-- the table grows. This migration adds a pg_cron job (available on the
-- Supabase free tier) that deletes expired rows in bounded batches on a
-- schedule, independent of request traffic.

begin;

-- pg_cron is available on all Supabase plans including free.
-- Create it in the extensions schema per Supabase convention.

-- Cleanup function: deletes up to p_limit expired rows per call.
-- Bounded so it never takes a long lock or bloats WAL in one shot.
create or replace function public.cleanup_rate_limits(p_retention_seconds int default 86400,
                                                      p_limit int default 5000)
returns int language plpgsql security definer set search_path = '' as $$
declare v_deleted int;
begin
  if p_retention_seconds is null or p_retention_seconds < 60 then
    raise exception 'RETENTION_TOO_SHORT';
  end if;
  if p_limit is null or p_limit < 1 or p_limit > 50000 then
    raise exception 'BAD_LIMIT';
  end if;

  delete from public.rate_limits
   where ctid in (
     select ctid from public.rate_limits
      where window_start < now() - make_interval(secs => p_retention_seconds)
      limit p_limit
   );
  get diagnostics v_deleted = row_count;
  return v_deleted;
end $$;

revoke all on function public.cleanup_rate_limits(int,int) from public, anon, authenticated;
grant execute on function public.cleanup_rate_limits(int,int) to service_role;
-- pg_cron runs as the database owner (postgres), which is superuser-equivalent
-- in Supabase's managed Postgres; the grant above is belt-and-braces.

-- Schedule: every 15 minutes, delete rows older than 24 hours, max 5000/run.
-- 5000 * 96 runs/day = 480k rows/day cleanup capacity, far above the
-- steady-state arrival rate for a free-tier project. Uses UTC.
-- cron.schedule is idempotent on jobname: re-running this migration replaces
-- the schedule rather than duplicating it.
do $do$
begin
  create extension if not exists pg_cron with schema extensions;
  perform cron.schedule('passaura-rate-limit-cleanup', '*/15 * * * *', 'select public.cleanup_rate_limits(86400, 5000)');
exception when others then
  raise notice 'pg_cron not available (%): schedule the cleanup manually', sqlerrm;
end $do$;

commit;
