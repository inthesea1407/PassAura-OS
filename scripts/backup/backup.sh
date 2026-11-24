#!/usr/bin/env bash
# backup.sh — logical backup of a Supabase free-tier project.
# Reads DATABASE_URL from the environment ONLY. Never from files or arguments.
# Produces schema.sql, data.sql, and a SHA-256 checksum file under scripts/backup/out/.
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "ERROR: DATABASE_URL is not set. Export it before running this script." >&2
  echo "  export DATABASE_URL='postgresql://postgres:[password]@db.[ref].supabase.co:5432/postgres'" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
mkdir -p "$OUT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SCHEMA_FILE="${OUT_DIR}/schema-${TS}.sql"
DATA_FILE="${OUT_DIR}/data-${TS}.sql"
CHECKSUM_FILE="${OUT_DIR}/checksums-${TS}.sha256"

echo "==> Backing up schema (public + auth) to ${SCHEMA_FILE}"
# --schema-only: DDL only. Includes public tables, policies, functions, triggers.
# --schema=auth: include auth.users structure (no data here; data is dumped separately
#                but we exclude password hashes by only dumping public data below).
pg_dump "$DATABASE_URL" \
  --schema-only \
  --schema=public \
  --schema=auth \
  --no-owner \
  --no-privileges \
  --file="$SCHEMA_FILE"

echo "==> Backing up data (public only, excluding auth secrets) to ${DATA_FILE}"
# --data-only --use-copy: fast COPY format.
# --schema=public only: auth.users data is deliberately NOT dumped here.
#   Rationale: encrypted_password and refresh tokens are secrets. Users must
#   re-authenticate on restore anyway because JWT secrets change.
# --exclude-table: defensively skip any auth table that might leak credentials.
pg_dump "$DATABASE_URL" \
  --data-only \
  --use-copy \
  --schema=public \
  --exclude-table='auth.*' \
  --no-owner \
  --no-privileges \
  --file="$DATA_FILE"

echo "==> Writing checksums to ${CHECKSUM_FILE}"
(
  cd "$OUT_DIR"
  sha256sum "$(basename "$SCHEMA_FILE")" "$(basename "$DATA_FILE")" > "$(basename "$CHECKSUM_FILE")"
)

echo "==> Backup complete."
echo "    Schema:   ${SCHEMA_FILE}"
echo "    Data:     ${DATA_FILE}"
echo "    Checksums: ${CHECKSUM_FILE}"
echo ""
echo "To restore, run:"
echo "  ./scripts/backup/restore.sh '${SCHEMA_FILE}' '${DATA_FILE}'"
