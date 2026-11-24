# PassAura OS — Backup, Restore, and Migration Runbook

**Scope:** Free-tier Supabase only. No paid features, no secrets in files, MIT-licensed.
**Audience:** The project owner (single-operator deployment).

> **Free-tier reality check.** Supabase's free plan does **not** include automated
> database backups [citation:13]. Every backup described here is a logical dump you
> run yourself. Treat this runbook as the only thing standing between your data and
> a deleted project.

---

## English

### 1. Logical backup with `pg_dump`

The scripts live in `scripts/backup/` and read the database URL **only** from the
`DATABASE_URL` environment variable. They never read a file, never accept a URL as an
argument, and never write the URL to disk.

**What gets backed up:** schema and data from the `public` schema, plus the `auth`
schema's *non-secret* tables (`auth.users` without password hashes is not possible via
plain `pg_dump` — see below). **What does not:** the `auth` schema's internal secrets
(`auth.users.encrypted_password`, refresh tokens), Vault secrets, and any
`service_role` material. Those live outside Postgres or are re-created on restore.

**Command:**

```sh
export DATABASE_URL='postgresql://postgres:[password]@db.[ref].supabase.co:5432/postgres'
./scripts/backup/backup.sh

<!-- Runbook fragments below were split by the chat rendering; review order before commit. -->

```
export DATABASE_URL='postgresql://postgres:[password]@db.[new-ref].supabase.co:5432/postgres'
./scripts/backup/restore.sh scripts/backup/out/schema-<ts>.sql scripts/backup/out/data-<ts>.sql
```

```
psql "$DATABASE_URL" -c "select count(*) from public.devices;"
psql "$DATABASE_URL" -c "select count(*) from public.premium_keys;"
psql "$DATABASE_URL" -c "select count(*) from auth.users;"  # users restored, sessions not
```

```
# Link to the project (one time)
supabase link --project-ref <project-ref>

# Apply all migrations in supabase/migrations/ in filename order
supabase db push
```

```
supabase test db
```

```
for f in supabase/migrations/*.sql; do
  echo "Applying $f"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f" || exit 1
done
```

```
export DATABASE_URL='postgresql://postgres:[password]@db.[ref].supabase.co:5432/postgres'
./scripts/backup/backup.sh
```

```
supabase link --project-ref <project-ref>
supabase db push
```
