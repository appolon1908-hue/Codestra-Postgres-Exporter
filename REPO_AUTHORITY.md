# Repository Authority

This repository is the principal source authority for Codestra PostgreSQL Exporter deployment/configuration.

## Service identity

- Private service DNS: `postgres-exporter`
- Native metrics port: `9187`
- Metrics path: `/metrics`
- Public hostname: unassigned and not required

Do not invent or expose a public hostname. The exporter endpoint is reachable only from Prometheus and explicitly approved private monitoring networks.

## Ownership

Own PostgreSQL Exporter upstream provenance, packaging, least-privilege monitoring connection policy, metric exposure validation and upgrade runbooks.

Do not own PostgreSQL application schemas, database administration, Prometheus scrape policy, Grafana dashboards, Alertmanager routing, shared infrastructure orchestration, edge routing or secrets.

## Integration

Approved PostgreSQL instances -> monitoring-only role -> PostgreSQL Exporter -> Prometheus -> Grafana and Alertmanager.

Credentials are supplied from OpenBao or approved runtime secret files. Secret material is forbidden in Git.

## Branch and promotion policy

Persistent branches: `main`, `development`, `test`, `staging`, `production`.

Temporary branches: `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, optional `release/*` and `rollback/*`.

Promotion: work -> development -> test -> staging -> production -> main. Never perform an upstream upgrade directly on staging, production or main. Source merge does not authorize deployment.
