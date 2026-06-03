# Deployment

Temren can be deployed three ways, in increasing order of operational complexity.

## 1. Docker Compose (single host, recommended for dev / small teams)

```bash
cp .env.example .env
# edit JWT_SECRET, ANTHROPIC_API_KEY (optional), etc.
docker compose up -d
```

Compose brings up:

- `api` (Fiber + WebSocket, port 8080)
- `worker` (Asynq consumer)
- `frontend` (Next.js, port 3000)
- `postgres` 15
- `redis` 7

Healthchecks:

```bash
curl localhost:8080/healthz
docker compose logs -f worker
```

## 2. Kubernetes / Helm

```bash
helm install temren ./helm/temren \
  --set image.tag=v1.0.0 \
  --set postgres.password=$(openssl rand -hex 16) \
  --set jwt.secret=$(openssl rand -hex 32)
```

Tunables of note:

| Key | Default | Notes |
|-----|---------|-------|
| `replicaCount.api` | 2 | API is stateless; scale horizontally |
| `replicaCount.worker` | 3 | Each pod processes `WORKER_CONCURRENCY` jobs |
| `autoscaling.enabled` | false | HPA on `cpu>70%` |
| `ingress.enabled` | false | Set host + TLS for prod |
| `persistence.size` | 20Gi | Postgres PVC |

## 3. Bare-metal binary

Download a release from GitHub releases or build locally with `make release`.

```bash
sudo useradd -r -s /usr/sbin/nologin temren
sudo install -m 0755 dist/temren-linux-amd64 /usr/local/bin/temren
sudo cp deploy/systemd/temren-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now temren-api
```

## Hardening checklist

- Set `JWT_SECRET` to a random 32-byte value (rotated every 90 days).
- Run behind a TLS-terminating reverse proxy (Caddy, Nginx, traefik).
- Restrict outbound egress from worker pods if running against the public internet — Temren probes can reach 169.254.169.254 by design.
- Enable WAL archiving on Postgres; Temren writes to `findings` and `audit_log` continuously.
- Forward `audit_log` to a SIEM (Splunk, Datadog, Loki).
- Configure `notify` with PagerDuty / OpsGenie for CRITICAL findings.

## Backups

```bash
docker exec temren-postgres pg_dump -U temren temren | gzip > backup-$(date +%F).sql.gz
```

Restore:

```bash
gunzip -c backup-2026-05-15.sql.gz | docker exec -i temren-postgres psql -U temren temren
```
