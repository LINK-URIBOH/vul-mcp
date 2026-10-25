#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Run after deploying the 1.2.0 image to web. Keycloak and the database stay up.
# Restoring worker on failure is safe: its durable maintenance fence leaves it
# idle until this command is resumed successfully.
docker compose stop worker publisher
trap 'docker compose up -d --no-deps worker publisher' EXIT
docker compose run --rm --no-deps -T web python -u -m vulintel.cli repair-history --clear-reports
docker compose exec -T web python -m vulintel.cli status
