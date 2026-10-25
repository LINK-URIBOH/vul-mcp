#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Stop the previous screen repair first. Its owner lock is never overridden.
docker compose stop worker
docker compose run --rm --no-deps -T web python -u -m vulintel.cli reset-recent \
  --days 7 --clear-vulnerabilities --clear-reports "$@"
docker compose up -d --no-deps worker
docker compose exec -T web python -m vulintel.cli status
