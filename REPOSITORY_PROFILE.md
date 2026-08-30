# Repository Profile — `Codestra-Postgres-Exporter`

## Identity

- **Repository:** `appolon1908-hue/Codestra-Postgres-Exporter`
- **Category:** Observability exporter — PostgreSQL
- **Visibility:** `public`
- **Default branch:** `main`
- **Canonical hostname:** `pgex.codestra.media`
- **Exposure:** Internal/private only; no public native metrics endpoint
- **Authority:** Primary safe PostgreSQL availability, connection, lock, transaction, replication, WAL, checkpoint, vacuum, and capacity metrics authority

## Purpose

Exports bounded database-health metrics to Prometheus using a dedicated least-privilege monitoring identity without selecting business-table rows or granting database mutation authority.

## Owns

- PostgreSQL Exporter runtime and approved query/collector scope
- Rerunnable least-privilege monitoring-role template based on `pg_monitor`
- Private observability/database networks, external secret-file references, immutable packaging, and validation source

## Does not own

- Business-table data, customer records, query result payloads, or database ownership
- Superuser, replication, write, bypass-RLS, or schema-mutation privileges
- Public exposure of the native exporter listener

## Key integrations

- Approved PostgreSQL instances
- Prometheus
- Grafana and Alertmanager
- OpenBao/runtime secret delivery where adopted

## Current priorities

1. Maintain the exact least-privilege role and approved-query boundary
2. Validate locks, deadlocks, long transactions, replication, WAL, checkpoints, vacuum, bloat indicators, sequence, and capacity metrics
3. Prove credential rotation, connection failure, permission denial, scrape behavior, and private networking
4. Add immutable packaging, upgrade, rollback, and database-version compatibility evidence

## Governance and safety

- Promotion model: `feature/docs/fix/security/upgrade -> development -> test -> staging -> production -> main`.
- Native port `9187` must remain private; `pgex.codestra.media` must not expose metrics publicly.
- Never commit DSNs, passwords, certificates, business queries, customer data, or database dumps.
- Monitoring identities must remain read-only, non-owner, non-superuser, and narrowly scoped.
- Merge does not create database roles, install credentials, start the exporter, activate scraping, or expose ports.

## Account-wide catalog

See `appolon1908-hue/documentaions/REPOSITORY_CATALOG.md`.
