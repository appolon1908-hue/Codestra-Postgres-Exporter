# Codestra PostgreSQL Exporter

Principal source authority for Codestra PostgreSQL Exporter configuration, upstream provenance, least-privilege database monitoring policy, release validation and runbooks.

## Status

`SOURCE_PREPARED_NOT_DEPLOYED`

Deployment is disabled. This repository contains no production credential, database password, private key, certificate or secret-bearing connection string.

## Authority boundary

This repository owns PostgreSQL Exporter packaging and configuration. It does not own PostgreSQL application schema, database administration, Prometheus scrape policy, Grafana dashboards, Alertmanager routing, infrastructure orchestration or secrets.

Official upstream source is imported from `prometheus-community/postgres_exporter` into `upstream/` by a controlled synchronization workflow and recorded in `CODESTRA_UPSTREAM_LOCK.json`.

## Network and exposure

- Canonical hostname: `pgex.codestra.media`
- DNS A target: `37.27.128.39`
- Internal service identity: `postgres-exporter:9187`
- Metrics path: `/metrics`
- Native port `9187` is private and must never be published to the Internet.
- The exporter joins only approved observability and database networks.
- Prometheus is the only routine scrape consumer.
- DNS assignment does not authorize public access; `pgex.codestra.media` remains an internal/private monitoring identity.

## Database access

Use a dedicated application-independent monitoring role with the minimum supported PostgreSQL monitoring privileges. It must not be a superuser, database owner, replication administrator, bypass-RLS role, or application writer.

Connection components are injected from runtime secret files:

- `/run/secrets/postgres_exporter_uri`
- `/run/secrets/postgres_exporter_user`
- `/run/secrets/postgres_exporter_password`

Production values belong in OpenBao or the approved runtime secret mechanism, never Git.

## Monitoring target

The Codestra expansion target covers connection saturation, transactions, locks/deadlocks, blocked queries, replication/lag, WAL/checkpoints, cache hit ratio, long-running transactions, database/table/index growth, vacuum/autovacuum health, dead tuples, reviewed bloat indicators, and sequence exhaustion risk. Custom SQL collectors require explicit safety, cost, sensitive-column, and cardinality review.

## Validation and promotion

Repository CI validates the hardened compose candidate, external secret references, immutable-image requirement, private network-only exposure, disabled database auto-discovery, bounded collection timeout, least-privilege role template, and activation gates.

Promotion is `feature/* -> development -> test -> staging -> production -> main`. Merge does not authorize deployment. Target activation requires a private-network scrape test, `pg_up == 1`, least-privilege review, cardinality review, immutable image digest, and rollback evidence. `DEPLOYMENT_ENABLED=NO` remains binding during the repository-first release train.
