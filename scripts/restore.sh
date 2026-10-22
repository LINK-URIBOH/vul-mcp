#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
backup_dir="${1:?Specify backup directory}"
if [ "${2:-}" != '--confirm-replace' ]; then echo 'Restore replaces database contents. Pass --confirm-replace.'; exit 1; fi
test -r "$backup_dir/vul.dump" && test -r "$backup_dir/keycloak.dump" && test -r "$backup_dir/reports.tar.gz"
docker compose stop web worker keycloak
docker compose exec -T db pg_restore -U postgres --clean --if-exists --exit-on-error -d vul < "$backup_dir/vul.dump"
docker compose exec -T db pg_restore -U postgres --clean --if-exists --exit-on-error -d keycloak < "$backup_dir/keycloak.dump"
docker compose run --rm --no-deps -T web python -m scripts.archive_reports restore < "$backup_dir/reports.tar.gz"
docker compose start keycloak web worker
echo 'Restore complete. Validate OAuth and report downloads before enabling delivery.'
