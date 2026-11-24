#!/usr/bin/env bash
# verify.sh — restore a backup into a throwaway Docker Postgres and run supabase/tests/*.sql.
# Requires: Docker, pg_dump client (same major version as source), psql client.
# Reads DATABASE_URL from the environment ONLY to take a fresh backup before verifying.
# The throwaway container uses a random password and is destroyed on exit.
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "ERROR: DATABASE_URL is not set. Export the source database URL." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TESTS_DIR="${REPO_ROOT}/supabase/tests"
PG_IMAGE="${PG_IMAGE:-postgres:15}"  # adjust to match your project's major version
CONTAINER_NAME="passaura-verify-$$"
TMP_DIR="$(mktemp -d)"

cleanup() {
  echo "==> Cleaning up"
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> Taking a fresh backup from the source database"
"${SCRIPT_DIR}/backup.sh"

LATEST_SCHEMA="$(ls -1t "${SCRIPT_DIR}/out"/schema-*.sql | head -1)"
LATEST_DATA="$(ls -1t "${SCRIPT_DIR}/out"/data-*.sql | head -1)"
if [[ -z "$LATEST_SCHEMA" ]] || [[ -z "$LATEST_DATA" ]]; then
  echo "ERROR: no backup files found in ${SCRIPT_DIR}/out/" >&2
  exit 1
fi

echo "==> Starting throwaway Postgres ${PG_IMAGE} as ${CONTAINER_NAME}"
RESTORE_PASSWORD="$(openssl rand -hex 32)"
docker run -d --name "$CONTAINER_NAME" \
  -e POSTGRES_PASSWORD="$RESTORE_PASSWORD" \
  -e POSTGRES_DB=verify \
  -p 0:5432 \
  "$PG_IMAGE" >/dev/null

echo "==> Waiting for Postgres to be ready"
for i in $(seq 1 30); do
  if docker exec "$CONTAINER_NAME" pg_isready -U postgres -d verify >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 30 ]]; then echo "ERROR: Postgres did not start" >&2; exit 1; fi
  sleep 1
done

RESTORE_PORT="$(docker port "$CONTAINER_NAME" 5432/tcp | cut -d: -f2)"
RESTORE_URL="postgresql://postgres:${RESTORE_PASSWORD}@127.0.0.1:${RESTORE_PORT}/verify"

echo "==> Restoring schema into throwaway Postgres"
psql "$RESTORE_URL" --single-transaction --variable ON_ERROR_STOP=1 --file "$LATEST_SCHEMA"

echo "==> Restoring data into throwaway Postgres (triggers disabled)"
psql "$RESTORE_URL" --single-transaction --variable ON_ERROR_STOP=1 \
  --command "SET session_replication_role = replica;" \
  --file "$LATEST_DATA"

echo "==> Running supabase/tests/*.sql against the restored database"
shopt -s nullglob
TEST_FILES=("${TESTS_DIR}"/*.sql)
if [[ ${#TEST_FILES[@]} -eq 0 ]]; then
  echo "WARNING: no .sql test files found in ${TESTS_DIR}" >&2
else
  for f in "${TEST_FILES[@]}"; do
    echo "  --> $(basename "$f")"
    psql "$RESTORE_URL" --variable ON_ERROR_STOP=1 --file "$f"
  done
fi

echo "==> Verification complete. All tests ran against the restored database."
