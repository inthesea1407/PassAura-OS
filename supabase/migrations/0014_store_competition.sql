-- 0014_store_competition.sql — store duplicate-idea competition path. DESIGN DRAFT: not yet
-- applied or tested on a live project. Implements docs/STORE_REVIEW_MODEL.md section 5a (owner
-- decision 2026-11-27): no two apps with the same idea; overlaps are rated by users, the loser
-- is removed. Voting is phase-3: it needs real users, so nothing here runs yet.
--
-- Deviations from the section-7 sketch: vote counts are computed from store_votes at resolve
-- time (no denormalized votes_a/votes_b to drift), and "removal" here only RECORDS the outcome
-- (competition resolved, loser app suspended). The device-side removal is unchanged: the owner
-- releases a new allowlist without the entry (section 8), exactly like any other revocation.
-- Moderation is the owner (is_owner()); a separate moderator role can come later.

create table if not exists public.store_competitions (
  id uuid primary key default gen_random_uuid(),
  app_a uuid not null references public.store_apps(id),
  app_b uuid not null references public.store_apps(id),
  opened_by uuid not null,
  opened_at timestamptz not null default now(),
  closes_at timestamptz not null,
  state text not null default 'open' check (state in ('open','resolved','canceled')),
  winner_app_id uuid references public.store_apps(id),
  resolution text check (resolution in ('majority','no_agreement','tie_break')),
  resolution_notes text not null default '',
  resolved_at timestamptz,
  check (app_a <> app_b)
);

-- One vote per account per competition. Append-only, like reviews.
create table if not exists public.store_votes (
  id uuid primary key default gen_random_uuid(),
  competition_id uuid not null references public.store_competitions(id),
  account_id uuid not null,
  choice uuid not null references public.store_apps(id),
  created_at timestamptz not null default now(),
  unique (competition_id, account_id)
);

-- The feature-gap message moderation sends to both developers (section 5a). Append-only.
create table if not exists public.store_dev_messages (
  id uuid primary key default gen_random_uuid(),
  competition_id uuid references public.store_competitions(id),
  to_publisher_id uuid not null,
  body text not null check (length(body) between 1 and 4000),
  created_at timestamptz not null default now()
);

alter table public.store_competitions enable row level security;
alter table public.store_votes enable row level security;
alter table public.store_dev_messages enable row level security;

create index if not exists store_competitions_state_idx on public.store_competitions(state);
create index if not exists store_votes_competition_idx on public.store_votes(competition_id);
create index if not exists store_dev_messages_publisher_idx on public.store_dev_messages(to_publisher_id);

-- Members read competitions and tallies; publishers read their own messages. All writes go
-- through the functions below.
create policy competitions_sel on public.store_competitions for select to authenticated
  using (true);
create policy votes_sel on public.store_votes for select to authenticated
  using (true);
create policy dev_messages_sel on public.store_dev_messages for select to authenticated
  using (to_publisher_id = (select auth.uid()) or (select public.is_owner()));

create or replace function public.store_append_only() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'FORBIDDEN: append-only record' using errcode = 'P0001';
end $$;
revoke all on function public.store_append_only() from public, anon, authenticated;

create trigger store_votes_no_update before update or delete on public.store_votes
  for each row execute function public.store_append_only();
create trigger store_dev_messages_no_update before update or delete on public.store_dev_messages
  for each row execute function public.store_append_only();

-- A competition's identity fields are immutable; once closed it is entirely immutable.
create or replace function public.store_competitions_guard() returns trigger
language plpgsql set search_path = '' as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'FORBIDDEN: competitions are never deleted' using errcode = 'P0001';
  end if;
  if old.state <> 'open' then
    raise exception 'FORBIDDEN: a closed competition is immutable' using errcode = 'P0001';
  end if;
  if new.app_a <> old.app_a or new.app_b <> old.app_b
     or new.opened_by <> old.opened_by or new.closes_at <> old.closes_at
     or new.opened_at <> old.opened_at then
    raise exception 'FORBIDDEN: competition fields are immutable' using errcode = 'P0001';
  end if;
  return new;
end $$;
revoke all on function public.store_competitions_guard() from public, anon, authenticated;

create trigger store_competitions_guard_trigger before update or delete on public.store_competitions
  for each row execute function public.store_competitions_guard();

create or replace function public.store_open_competition(p_app_a uuid, p_app_b uuid, p_closes_at timestamptz)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_id uuid;
begin
  if not (select public.is_owner()) then
    raise exception 'FORBIDDEN' using errcode = 'P0001';
  end if;
  if p_app_a = p_app_b then
    raise exception 'BAD_INPUT: same app' using errcode = 'P0001';
  end if;
  if p_closes_at is null or p_closes_at <= now() then
    raise exception 'BAD_INPUT: closes_at must be in the future' using errcode = 'P0001';
  end if;
  if not exists (select 1 from public.store_apps where id = p_app_a)
     or not exists (select 1 from public.store_apps where id = p_app_b) then
    raise exception 'NOT_FOUND' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.store_competitions
             where state = 'open'
               and (app_a in (p_app_a, p_app_b) or app_b in (p_app_a, p_app_b))) then
    raise exception 'CONFLICT: an app already has an open competition' using errcode = 'P0001';
  end if;
  insert into public.store_competitions (app_a, app_b, opened_by, closes_at)
    values (p_app_a, p_app_b, (select auth.uid()), p_closes_at)
    returning id into v_id;
  return v_id;
end $$;
revoke all on function public.store_open_competition(uuid, uuid, timestamptz) from public, anon;

create or replace function public.store_vote(p_competition uuid, p_choice uuid)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_comp record;
  v_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'FORBIDDEN' using errcode = 'P0001';
  end if;
  select * into v_comp from public.store_competitions where id = p_competition;
  if not found then
    raise exception 'NOT_FOUND' using errcode = 'P0001';
  end if;
  if v_comp.state <> 'open' then
    raise exception 'CONFLICT: competition is not open' using errcode = 'P0001';
  end if;
  if now() >= v_comp.closes_at then
    raise exception 'CONFLICT: voting has closed' using errcode = 'P0001';
  end if;
  if p_choice not in (v_comp.app_a, v_comp.app_b) then
    raise exception 'BAD_INPUT: choice is not a candidate' using errcode = 'P0001';
  end if;
  insert into public.store_votes (competition_id, account_id, choice)
    values (p_competition, (select auth.uid()), p_choice)
    returning id into v_id;
  return v_id;
end $$;
revoke all on function public.store_vote(uuid, uuid) from public, anon;

-- Resolves per the owner's rules (section 5a): majority = winner has more votes; no_agreement =
-- the developers did not agree and the LOWER-rated app is removed; tie_break = tied votes, the
-- owner-delegated judgment, and the reasoning is recorded (required, non-empty).
create or replace function public.store_resolve_competition(p_id uuid, p_resolution text, p_winner uuid, p_notes text default '')
returns void language plpgsql security definer set search_path = '' as $$
declare
  v_comp record;
  v_a int;
  v_b int;
  v_loser uuid;
begin
  if not (select public.is_owner()) then
    raise exception 'FORBIDDEN' using errcode = 'P0001';
  end if;
  if p_resolution not in ('majority','no_agreement','tie_break') then
    raise exception 'BAD_INPUT: unknown resolution' using errcode = 'P0001';
  end if;
  select * into v_comp from public.store_competitions where id = p_id for update;
  if not found then
    raise exception 'NOT_FOUND' using errcode = 'P0001';
  end if;
  if v_comp.state <> 'open' then
    raise exception 'CONFLICT: competition is not open' using errcode = 'P0001';
  end if;
  if p_winner not in (v_comp.app_a, v_comp.app_b) then
    raise exception 'BAD_INPUT: winner is not a candidate' using errcode = 'P0001';
  end if;
  select count(*) into v_a from public.store_votes where competition_id = p_id and choice = v_comp.app_a;
  select count(*) into v_b from public.store_votes where competition_id = p_id and choice = v_comp.app_b;
  if p_resolution = 'majority' then
    if (p_winner = v_comp.app_a and v_a <= v_b) or (p_winner = v_comp.app_b and v_b <= v_a) then
      raise exception 'BAD_INPUT: a majority winner must have more votes' using errcode = 'P0001';
    end if;
  elsif p_resolution = 'no_agreement' then
    if v_a = v_b then
      raise exception 'BAD_INPUT: tied votes use tie_break, not no_agreement' using errcode = 'P0001';
    end if;
    if (p_winner = v_comp.app_a and v_a < v_b) or (p_winner = v_comp.app_b and v_b < v_a) then
      raise exception 'BAD_INPUT: no_agreement removes the lower-rated app' using errcode = 'P0001';
    end if;
  else
    if v_a <> v_b then
      raise exception 'BAD_INPUT: tie_break requires tied votes' using errcode = 'P0001';
    end if;
    if length(p_notes) = 0 then
      raise exception 'BAD_INPUT: tie_break requires the recorded reasoning' using errcode = 'P0001';
    end if;
  end if;
  v_loser := case when p_winner = v_comp.app_a then v_comp.app_b else v_comp.app_a end;
  update public.store_competitions
     set state = 'resolved', winner_app_id = p_winner, resolution = p_resolution,
         resolution_notes = p_notes, resolved_at = now()
   where id = p_id;
  update public.store_apps set status = 'suspended' where id = v_loser;
end $$;
revoke all on function public.store_resolve_competition(uuid, text, uuid, text) from public, anon;

create or replace function public.store_send_dev_message(p_competition uuid, p_to_publisher uuid, p_body text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_id uuid;
begin
  if not (select public.is_owner()) then
    raise exception 'FORBIDDEN' using errcode = 'P0001';
  end if;
  if p_competition is not null
     and not exists (select 1 from public.store_competitions where id = p_competition) then
    raise exception 'NOT_FOUND' using errcode = 'P0001';
  end if;
  if not exists (select 1 from public.store_apps where publisher_id = p_to_publisher) then
    raise exception 'NOT_FOUND: publisher' using errcode = 'P0001';
  end if;
  insert into public.store_dev_messages (competition_id, to_publisher_id, body)
    values (p_competition, p_to_publisher, p_body)
    returning id into v_id;
  return v_id;
end $$;
revoke all on function public.store_send_dev_message(uuid, uuid, text) from public, anon;
