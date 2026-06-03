# Contributing to TemrenSec

Thanks for your interest! Temren welcomes contributions of every size — new scanners,
bug fixes, documentation, and UX polish.

## Quick start

```bash
git clone https://github.com/nickzsche/TemrenSec
cd temren
make all                       # lint + test + build
./bin/temren scan --target https://example.com
```

You will need:
- Go 1.21+
- Node 18+ (for the dashboard)
- Docker & Docker Compose (for end-to-end tests against vulnerable demo apps)

## Project layout

```
cmd/temren        CLI entry points (cobra subcommands)
cmd/api          REST + WebSocket API server
cmd/worker       Background scan worker
pkg/scanner      Active vulnerability scanners
pkg/cloudscan    Static analysis for Dockerfile / K8s / Terraform
pkg/notify       Notification channels (Slack, ntfy, PagerDuty, …)
pkg/exporter     Output formats (SARIF, CycloneDX, JUnit, JIRA, …)
pkg/compliance   PCI-DSS / HIPAA / GDPR / ISO 27001 / SOC2 mappings
pkg/threatintel  NVD / EPSS / CISA-KEV enrichment
pkg/ai           LLM-backed triage and exploit-chain analysis
frontend         Next.js 15 dashboard
```

## Adding a new scanner

1. Create `pkg/scanner/myscanner.go` implementing the `scanner.Scanner` interface:

   ```go
   type Scanner interface {
       Name() string
       Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error)
   }
   ```

2. Return `Finding` values with at least `Title`, `Severity`, `Confidence`, `Scanner`, and `OWASPCategory`.
3. Tag the OWASP category from the [2021 list](https://owasp.org/Top10/) so compliance mapping works.
4. Add tests at `pkg/scanner/myscanner_test.go` using `httptest` to stub the target.
5. Register the scanner in `pkg/scanner/engine.go`.

## Style

- `gofmt -s` everything; `goimports` keeps imports tidy
- Package names: lowercase, no underscores
- Public types/funcs need doc comments
- Tests live alongside production code, named `*_test.go`
- Prefer table-driven tests for new payload sets

## Commits

We follow Conventional Commits (loose form). Examples:

- `feat(scanner): add NoSQL operator injection probes`
- `fix(notify): respect HTTP timeout on Telegram errors`
- `docs: expand contributing guide`

## Pull requests

- Open against `main`
- All CI checks must pass (build, test, lint, gosec, govuln)
- Cover new code with tests; aim ≥80% on touched files
- Update CHANGELOG.md under `## [Unreleased]`

## Security disclosures

If you discover a vulnerability **in Temren itself**, please email
`security@zerosixlab.com` — do not file a public issue. See [SECURITY.md](SECURITY.md).
