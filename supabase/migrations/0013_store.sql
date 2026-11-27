-- 0013_store.sql — PassAura OS store review model. DESIGN DRAFT: not yet applied or tested on
-- a live project. Implements docs/STORE_REVIEW_MODEL.md section 7: reviews are append-only,
-- submission state changes go through security-definer functions only, and devices never see
-- any of this (devices only ever receive signed allowlists). The quorum default (2) and the
-- one-reject-vetoes policy are placeholders pending the owner's decision (design doc, item 4).

alter table public.admin_config
  add column if not exists store_review_quorum int not null default 2
    check (store_review_quorum between 1 and 5);

create table if not exists public.store_apps (
  id uuid primary key default gen_random_uuid(),
  -- debian package name shape; the gate's safe-name rules are the device-side authority
  name text not null check (name ~ '^[a-z0-9][a-z0-9+.-]{1,63}$'),
  publisher_id uuid not null, -- auth.users id
  created_at timestamptz not null default now(),
  status text not null default 'active' check (status in ('active','suspended')),
  unique (publisher_id, name)
);

create table if not exists public.store_submissions (
  id uuid primary key default gen_random_uuid(),
  app_id uuid not null references public.store_apps(id),
  version text not null check (length(version) between 1 and 64),
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  artifact_path text not null, -- private storage bucket path; never public
  size_bytes bigint not null check (size_bytes > 0 and size_bytes <= 536870912), -- 512 MiB cap
  state text not null default 'submitted'
    check (state in ('submitted','in_review','approved','rejected','published','revoked')),
  submitted_at timestamptz not null default now(),
  unique (app_id, version, sha256)
);

create table if not exists public.store_reviews (
  id uuid primary key default gen_random_uuid(),
  submission_id uuid not null references public.store_submissions(id),
  reviewer_id uuid not null,
  decision text not null check (decision in ('approve','reject')),
  notes text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.store_reviewer_roles (
  account_id uuid primary key,
  granted_by uuid not null,
  granted_at timestamptz not null default now(),
  revoked_at timestamptz
);

alter table public.store_apps enable row level security;
alter table public.store_submissions enable row level security;
alter table public.store_reviews enable row level security;
alter table public.store_reviewer_roles enable row level security;
-- Roles table has no policies at all; make the deny explicit (F6 pattern).
revoke all on table public.store_reviewer_roles from anon, authenticated;

create index if not exists store_apps_publisher_idx on public.store_apps(publisher_id);
create index if not exists store_submissions_state_idx on public.store_submissions(state);
create index if not exists store_reviews_submission_idx on public.store_reviews(submission_id);

create or replace function public.is_store_reviewer() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.store_reviewer_roles
                 where account_id = (select auth.uid()) and revoked_at is null)
$$;
revoke all on function public.is_store_reviewer() from public, anon;

-- Publishers manage their own apps and submissions; reviewers read the queue.
create policy publisher_apps_ins on public.store_apps for insert to authenticated
  with check (publisher_id = (select auth.uid()));
create policy publisher_apps_sel on public.store_apps for select to authenticated
  using (publisher_id = (select auth.uid()) or (select public.is_store_reviewer()));

create policy publisher_subs_ins on public.store_submissions for insert to authenticated
  with check (state = 'submitted' and exists (
    select 1 from public.store_apps a
    where a.id = app_id and a.publisher_id = (select auth.uid()) and a.status = 'active'));
create policy publisher_subs_sel on public.store_submissions for select to authenticated
  using ((select public.is_store_reviewer()) or exists (
    select 1 from public.store_apps a where a.id = app_id and a.publisher_id = (select auth.uid())));
-- No update/delete policies on submissions: state changes only through the functions below.

create policy reviews_sel on public.store_reviews for select to authenticated
  using ((select public.is_store_reviewer()) or exists (
    select 1 from public.store_submissions s join public.store_apps a on a.id = s.app_id
    where s.id = submission_id and a.publisher_id = (select auth.uid())));
-- No insert/update/delete policies on reviews: only store_submit_review writes them.

-- Reviews are append-only even for roles that bypass RLS (design doc: a changed mind is a new
-- review on a new submission, never an edit).
create or replace function public.store_reviews_append_only() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'FORBIDDEN: reviews are append-only' using errcode = 'P0001';
end $$;
revoke all on function public.store_reviews_append_only() from public, anon, authenticated;

create trigger store_reviews_no_update before update or delete on public.store_reviews
  for each row execute function public.store_reviews_append_only();

-- Legal state transitions (design doc section 3). Fires for every role, service_role included.
create or replace function public.store_submissions_legal_transition() returns trigger
language plpgsql set search_path = '' as $$
begin
  if new.state = old.state then return new; end if;
  if (old.state = 'submitted' and new.state in ('in_review','rejected'))
     or (old.state = 'in_review' and new.state in ('approved','rejected'))
     or (old.state = 'approved' and new.state = 'published')
     or (old.state = 'published' and new.state = 'revoked') then
    return new;
  end if;
  raise exception 'FORBIDDEN: illegal submission state transition % -> %', old.state, new.state
    using errcode = 'P0001';
end $$;
revoke all on function public.store_submissions_legal_transition() from public, anon, authenticated;

create trigger store_submissions_transition before update of state on public.store_submissions
  for each row execute function public.store_submissions_legal_transition();

-- A reviewer records a decision. First review moves submitted -> in_review; quorum approvals
-- -> approved; any reject vetoes the round (publisher re-submits a fixed artifact).
create or replace function public.store_submit_review(p_submission uuid, p_decision text, p_notes text default '')
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_state text;
  v_approvals int;
  v_quorum int;
  v_id uuid;
begin
  if not (select public.is_store_reviewer()) then
    raise exception 'FORBIDDEN' using errcode = 'P0001';
  end if;
  if p_decision not in ('approve','reject') then
    raise exception 'BAD_INPUT: decision must be approve or reject' using errcode = 'P0001';
  end if;
  select state into v_state from public.store_submissions where id = p_submission for update;
  if not found then
    raise exception 'NOT_FOUND' using errcode = 'P0001';
  end if;
  if v_state not in ('submitted','in_review') then
    raise exception 'CONFLICT: submission is %', v_state using errcode = 'P0001';
  end if;
  if exists (select 1 from public.store_reviews
             where submission_id = p_submission and reviewer_id = (select auth.uid())) then
    raise exception 'CONFLICT: already reviewed' using errcode = 'P0001';
  end if;
  insert into public.store_reviews (submission_id, reviewer_id, decision, notes)
    values (p_submission, (select auth.uid()), p_decision, p_notes)
    returning id into v_id;
  if p_decision = 'reject' then
    update public.store_submissions set state = 'rejected' where id = p_submission;
  else
    select store_review_quorum into v_quorum from public.admin_config where id = 1;
    select count(*) into v_approvals from public.store_reviews
      where submission_id = p_submission and decision = 'approve';
    if v_approvals >= v_quorum then
      update public.store_submissions set state = 'approved' where id = p_submission;
    else
      update public.store_submissions set state = 'in_review' where id = p_submission;
    end if;
  end if;
  return v_id;
end $$;
revoke all on function public.store_submit_review(uuid, text, text) from public, anon;

-- Release tooling (service_role only) moves approved -> published once the re-hash and the
-- signed allowlist are done, and published -> revoked on a takedown. Never callable by users.
create or replace function public.store_mark_published(p_submission uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.store_submissions set state = 'published' where id = p_submission and state = 'approved';
  if not found then
    raise exception 'CONFLICT: submission is not approved' using errcode = 'P0001';
  end if;
end $$;
revoke all on function public.store_mark_published(uuid) from public, anon, authenticated;

create or replace function public.store_mark_revoked(p_submission uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.store_submissions set state = 'revoked' where id = p_submission and state = 'published';
  if not found then
    raise exception 'CONFLICT: submission is not published' using errcode = 'P0001';
  end if;
end $$;
revoke all on function public.store_mark_revoked(uuid) from public, anon, authenticated;
