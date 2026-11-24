-- 0007_indexes.sql — indexes justified by the actual access patterns of register_device,
-- redeem_premium_key, and rate_limit_hit. Every index here is explained; anything not
-- justified was deliberately omitted. Never edit 0001-0006.

begin;

-- ---------------------------------------------------------------------------
-- 1) invites: register_device looks up an UNUSED invite by code_hash.
--
-- Query shape (0004_fixes.sql):
--   update public.invites set used_by_device = ...
--    where code_hash = encode(digest($1,'sha256'),'hex')
--      and used_by_device is null
--   returning id;
--
-- The unique index invites_code_hash_key (from 0001) already covers the
-- code_hash equality. The extra predicate used_by_device IS NULL is NOT
-- indexable by that btree (IS NULL is not an indexable operator in a plain
-- btree), so Postgres would fetch the row and filter. A partial index on
-- (code_hash) WHERE used_by_device IS NULL makes the entire lookup index-only
-- for the common case and keeps the index tiny (it only contains open invites,
-- which is a small fraction of the table).
--
-- Justification: hot path on every non-seed registration; the table grows
-- monotonically with issued invites, so the win grows over time.
-- ---------------------------------------------------------------------------
create index if not exists invites_open_code_hash_idx
  on public.invites (code_hash)
  where used_by_device is null;

-- ---------------------------------------------------------------------------
-- 2) invites: admin panel and admin_revoke_invite.
--
-- admin_revoke_invite (0005): delete from invites where id = $1 and
-- used_by_device is null. The primary key already covers id; the
-- used_by_device IS NULL predicate is again non-indexable on a plain btree.
-- A partial index on (id) WHERE used_by_device IS NULL lets the DELETE find
-- the row without a heap fetch. This is low-volume (owner action, not user
-- traffic), so the benefit is modest — but it is free to add and the index is
-- minuscule (only open invites).
--
-- Actually: the PK on id is already a unique btree; the planner will use it
-- and then filter used_by_device. Adding a second index on id is redundant.
-- OMITTED. The admin path is not hot enough to justify a redundant index.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 3) devices: register_device seed-limit count.
--
-- Query shape (0004_fixes.sql):
--   select count(*) into v_count from public.devices where is_seed;
--
-- This is a full scan of devices every time the seed window is still open.
-- At 1000 seed devices the table is small, and after the window closes this
-- query is not reached (the function returns early on invite path). A partial
-- index on (1) WHERE is_seed would make the count index-only, but the table
-- is capped at seed_limit (max 1000) and the function does not run this count
-- once the window closes. NOT JUSTIFIED — the cost is bounded and one-time.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 4) devices: redeem_premium_key device validity check.
--
-- Query shape (0003):
--   if not exists (select 1 from devices where id = p_device and not revoked)
--      then raise 'DEVICE_INVALID';
--
-- The PK on devices(id) is a unique btree and already serves the equality on
-- id. The extra predicate `not revoked` is a single boolean filter on a row
-- already fetched by PK. No additional index justified.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 5) premium_keys: redeem_premium_key lookup.
--
-- Query shape (0003):
--   select * into k from premium_keys
--    where key_hash = encode(digest($1,'sha256'),'hex') for update;
--
-- The unique index premium_keys_key_hash_key (from 0002) already covers the
-- equality. FOR UPDATE requires a row lock, which uses the PK/unique index to
-- locate the row. No additional index justified.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 6) rate_limits: rate_limit_hit hot path and cleanup.
--
-- The primary key is (bucket, window_start). rate_limit_hit does:
--   insert ... on conflict (bucket, window_start) do update ...
-- which uses the PK unique index. The cleanup in 0006 and 0008 does:
--   delete from rate_limits where window_start < now() - interval 'X'
-- The PK leads with `bucket`, so a predicate on window_start alone cannot use
-- it for a range scan — it forces a seq scan. A btree on (window_start) lets
-- both the bounded ctid-subquery prune in 0006 and the cron cleanup in 0008
-- find expired rows without scanning the whole table.
--
-- Justification: the table is append-heavy and its only range predicate is on
-- window_start. This is the single most important index for keeping the
-- cleanup cheap.
-- ---------------------------------------------------------------------------
create index if not exists rate_limits_window_start_idx
  on public.rate_limits (window_start);

commit;
