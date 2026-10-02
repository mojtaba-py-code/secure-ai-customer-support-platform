#!/bin/sh
# Creates the application roles on the first start of the PostgreSQL container.
#
#   postgres     (POSTGRES_USER)  bootstrap superuser: used by this script and by a DBA only,
#                                 never by the application or the migrations
#   aegis_owner                   owns the database and its schema; used only by `aegis migrate`
#                                 (no superuser, cannot create roles or databases)
#   aegis_app                     runtime role: DML on application tables, INSERT/SELECT on the
#                                 audit trail, no DDL, owns nothing (see migration 0002)
#
# The official entrypoint *sources* non-executable scripts, so this file must not change the
# entrypoint's shell options beyond `set -e` (which the entrypoint uses itself); `set -u`
# would leak into it. Missing passwords still fail fast through the `:?` expansions below.
set -e

: "${AEGIS_DB_OWNER_PASSWORD:?AEGIS_DB_OWNER_PASSWORD must be set}"
: "${AEGIS_DB_APP_PASSWORD:?AEGIS_DB_APP_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v db="$POSTGRES_DB" \
     -v owner_password="$AEGIS_DB_OWNER_PASSWORD" \
     -v app_password="$AEGIS_DB_APP_PASSWORD" <<'SQL'
CREATE ROLE aegis_owner LOGIN PASSWORD :'owner_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE aegis_app LOGIN PASSWORD :'app_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;

-- The owner role owns the database, so (PostgreSQL 15+) it also owns the public schema through
-- pg_database_owner. Nobody else may connect or create objects.
ALTER DATABASE :"db" OWNER TO aegis_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO aegis_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO aegis_app;

-- Tables the owner creates later (migrations) are usable by the runtime role; migration 0002
-- then narrows the audit trail to INSERT/SELECT.
ALTER DEFAULT PRIVILEGES FOR ROLE aegis_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegis_app;
ALTER DEFAULT PRIVILEGES FOR ROLE aegis_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO aegis_app;

ALTER ROLE aegis_app SET statement_timeout = '15s';
ALTER ROLE aegis_app SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE aegis_owner SET lock_timeout = '10s';
SQL
