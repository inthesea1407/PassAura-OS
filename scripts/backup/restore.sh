#!/usr/bin/env bash
# restore.sh — restore a logical backup into a Supabase project.
# Reads DATABASE_URL from the environment ONLY. Never from files or arguments.
# Refuses to run against a non-empty database unless --force is passed.
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "ERROR: DATABASE_URL is not set. Export it before running this script." >&2
  exit 1
fi

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <schema.sql> <data.sql> [--force]" >&2
  exit 1
fi

SCHEMA_FILE="$1"
DATA_FILE="$2"
FORCE=false
if [[ "${3:-}" == "--force" ]]; then
  FORCE=true
fi

if [[ ! -f "$SCHEMA_FILE" ]]; then echo "ERROR: schema file not found: $SCHEMA_FILE" >&2; exit 1; fi
if [[ ! -f "$DATA_FILE" ]]; then echo "ERROR: data file not found: $DATA_FILE" >&2; exit 1; fi

CHECKSUM_FILE="$(dirname "$SCHEMA_FILE")/checksums-$(basename "$SCHEMA_FILE" | sed 's/^schema-//; s/\.sql$//').sha256"
if [[ -f "$CHECKSUM_FILE" ]]; then
  echo "==> Verifying checksums from ${CHECKSUM_FILE}"
  ( cd "$(dirname "$SCHEMA_FILE")" && sha256sum -c "$(basename "$CHECKSUM_FILE")" )
else
  echo "WARNING: no checksum file found at ${CHECKSUM_FILE}; skipping verification." >&2
fi

echo "==> Checking target database is empty"
# Query row counts in the core tables. If any is non-zero and --force not passed, refuse.
ROW_COUNT="$(psql "$DATABASE_URL" -tAc "
  select coalesce(sum(c), 0) from (
    select count(*) as c from public.devices
    union all select count(*) from public.invites
    union all select count(*) from public.premium_keys
    union all select count(*) from public.admin_config
  ) t;
" 2>/dev/null || echo "0")"

if [[ "$ROW_COUNT" != "0" ]] && [[ "$FORCE" != "true" ]]; then
  echo "ERROR: target database is not empty (${ROW_COUNT} rows in core tables)." >&2
  echo "  Refusing to overwrite. Pass --force to proceed anyway." >&2
  exit 1
fi

echo "==> Restoring schema from ${SCHEMA_FILE}"
psql "$DATABASE_URL" \
  --single-transaction \
  --variable ON_ERROR_STOP=1 \
  --file "$SCHEMA_FILE"

echo "==> Restoring data from ${DATA_FILE} (triggers disabled)"
# SET session_replication_role = replica disables triggers during import.
# This prevents double-encryption and unintended audit_log writes on restore.
psql "$DATABASE_URL" \
  --single-transaction \
  --variable ON_ERROR_STOP=1 \
  --command "SET session_replication_role = replica;" \
  --file "$DATA_FILE"

echo "==> Restore complete."
echo "    Verify with:"
echo "      psql \"\$DATABASE_URL\" -c 'select count(*) from public.devices;'"
echo "      psql \"\$DATABASE_URL\" -c 'select count(*) from public.premium_keys;'"
