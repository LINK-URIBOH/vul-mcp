#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose stop worker publisher
trap 'docker compose up -d --no-deps worker publisher' EXIT
docker compose run --rm --no-deps -T web python -u -m vulintel.cli repair-publication-dates --rebuild-unpublished
docker compose exec -T web python -m vulintel.cli status
