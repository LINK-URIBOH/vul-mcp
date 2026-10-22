#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  --set=vul_pass="$VUL_DB_PASSWORD" --set=kc_pass="$KEYCLOAK_DB_PASSWORD" <<'SQL'
CREATE USER vul WITH PASSWORD :'vul_pass';
CREATE DATABASE vul OWNER vul;
CREATE USER keycloak WITH PASSWORD :'kc_pass';
CREATE DATABASE keycloak OWNER keycloak;
REVOKE ALL ON DATABASE vul FROM PUBLIC;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
SQL
