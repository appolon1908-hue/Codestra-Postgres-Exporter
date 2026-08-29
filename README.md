# Codestra PostgreSQL Exporter

Principal source authority for Codestra PostgreSQL Exporter configuration, upstream provenance, least-privilege database monitoring policy, release validation and runbooks.

## Status

`SOURCE_PREPARED_NOT_DEPLOYED`

Deployment is disabled. This repository contains no production credential, database password, private key, certificate or secret-bearing connection string.

## Authority boundary

This repository owns PostgreSQL Exporter packaging and configuration. It does not own PostgreSQL application schema, database administration, Prometheus scrape policy, Grafana dashboards, Alertmanager routing, infrastructure orchestration or secrets.

Official upstream source is imported from [prometheus-community/postgres_exporter](https://github.com/prometheus-community/postgres_exporter) into `upstream/` by a controlled synchronization workflow and recorded in `CODESTRA_UPSTREAM_LOCK.json`.

## Network and exposure

- Internal service identity: `postgres-exporter:9187`
- Metrics path: `/metrics`
- Native port `9187` is private and must never be published to the Internet.
- The exporter joins only approved observability and database networks.
- Prometheus is the only routine scrape consumer.
- No public Codestra hostname is assigned or required. DNS must not be invented to bypass private-network controls.

## Database access

Use a dedicated non-login/application-independent monitoring role with the minimum supported PostgreSQL monitoring privileges. It must not be a superuser, database owner, replication administrator or application writer.

Connection components are injected from runtime secret files:

- `/run/secrets/postgres_exporter_uri`
- `/run/secrets/postgres_exporter_user`
- `/run/secrets/postgres_exporter_password`

Production values belong in OpenBao or the approved runtime secret mechanism, never Git.

## Promotion

After bootstrap, use:

`feature/* -> development -> test -> staging -> production -> main`

Merge does not authorize deployment. Target activation requires a private-network scrape test, `pg_up == 1`, least-privilege review, cardinality review, immutable image digest, and rollback evidence.
