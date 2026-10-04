#!/usr/bin/env bash
# Drops the SecLab database. The API re-creates and re-seeds it on next start (EnsureCreated + Seed).
# Needed whenever a step changes the schema, because the starter has no migrations.
docker exec seclab-sql /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P 'Passw0rd!Passw0rd' \
  -Q "IF DB_ID('SecLab') IS NOT NULL BEGIN ALTER DATABASE SecLab SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE SecLab; END"
echo "SecLab database dropped."
