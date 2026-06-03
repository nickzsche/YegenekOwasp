# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **13 new active scanners**
  - HTTP Request Smuggling (CL.TE / TE.CL / TE.TE-obf)
  - Web Cache Poisoning (unkeyed header reflection)
  - Race Condition (TOCTOU smell via concurrent identical requests)
  - Mass Assignment / BOLA probes
  - LDAP Injection
  - XPath Injection
  - Insecure Deserialization (Java / PHP / Python / Ruby / .NET magic bytes)
  - OAuth / OIDC Discovery misconfiguration (alg=none, missing PKCE, implicit flow)
  - CORS Preflight (wildcard+credentials, null origin, reflected origin)
  - GraphQL Batching & Alias overloading
  - SSRF — Cloud Metadata (AWS / GCP / Azure / Alibaba / OpenStack)
  - Host Header Injection (password-reset poisoning)
  - Security Headers audit (HSTS, CSP, XFO, RP, PP, COOP, CORP, cookie flags)
  - SSTI engine fingerprinting (Jinja2 / Twig / FreeMarker / ERB / Spring EL)
  - Web Cache Deception
  - Exposed Sensitive Endpoints (.git, .env, actuator, pprof, etc.)

- **`pkg/cloudscan`** — offline Dockerfile / Kubernetes / Terraform / .env audit
- **`pkg/compliance`** — PCI-DSS 4.0 / HIPAA / GDPR / ISO 27001:2022 / SOC 2 / NIST CSF 2.0 / CIS Controls v8 / OWASP ASVS 5.0 mapping with executive summaries
- **`pkg/threatintel`** — NVD CVE lookup, EPSS exploit probability, CISA KEV flagging, blended prioritization score
- **`pkg/notify`** — unified dispatcher with ntfy / Pushover / Telegram / PagerDuty / OpsGenie / Mattermost / RocketChat / Twilio SMS / signed generic webhook
- **`pkg/exporter`** — SARIF v2.1, CycloneDX 1.5, JUnit, CSV, JSONL, Markdown, JIRA wiki markup
- **`pkg/ai`** — pluggable LLM provider for finding triage, exploit-chain reasoning, natural-language → scan-query translation, executive summary
- **CLI subcommands** — `temren cloud`, `temren export`, `temren compliance`, `temren intel`, `temren baseline`, `temren notify`, `temren tui`, `temren completion`
- **Frontend pages** — Compliance, Threat Intel, AI Advisor, Asset Inventory, Risk Heatmap, Attack Paths, Notifications, Team, Audit Log, Settings (API keys, integrations, profile)
- **CI / DevEx** — Makefile, `.golangci.yml`, security workflow (gosec / govulncheck / Trivy / Semgrep), release workflow (goreleaser + GHCR multi-arch), CONTRIBUTING / SECURITY / CODE_OF_CONDUCT

### Tests

- ≥60 new tests covering cloudscan, compliance, threatintel, notify, ai, exporter packages.

## [1.0.0] - 2026-05-13

Initial public release.
