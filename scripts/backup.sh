#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
backup_dir="${1:?Specify a new backup directory}"
if [ -e "$backup_dir" ]; then echo 'Backup directory already exists'; exit 1; fi
mkdir -m 700 -p -- "$backup_dir"
docker compose stop web worker keycloak
trap 'docker compose start keycloak web worker' EXIT
docker compose exec -T db pg_dump -U postgres -Fc vul > "$backup_dir/vul.dump"
docker compose exec -T db pg_dump -U postgres -Fc keycloak > "$backup_dir/keycloak.dump"
docker compose run --rm --no-deps -T web python -m scripts.archive_reports backup > "$backup_dir/reports.tar.gz"
chmod 600 "$backup_dir"/*
echo 'Backup complete. Back up .env and realm secrets separately using encrypted storage.'
