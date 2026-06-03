# TemrenSec — Detaylı Teknik Dokümantasyon

> Bu doküman projenin **ne yaptığını, nasıl çalıştığını ve hangi dosyanın hangi sorumluluğu taşıdığını** uçtan uca açıklar. Amaç: başka bir Claude oturumuna ya da yeni bir geliştiriciye verildiğinde, projeyi açıp tek tek dosyaları okumak zorunda kalmadan tam zihinsel modeli oluşturabilmesi.
>
> Repo: `github.com/nickzsche/TemrenSec` · Modül: `github.com/temren` · Dil: Go 1.26 + Next.js 15 (TypeScript)

---

## 1. Ne Bu Proje?

**TemrenSec**, OWASP Top 10 odaklı, **80+ aktif tarayıcı**, **35+ destek paketi**, **3 binary** (API, worker, CLI) ve **bir Next.js dashboard**'dan oluşan **self-hosted DAST + ASPM** (Dynamic Application Security Testing + Application Security Posture Management) platformudur.

Tek satırla: **bir URL ver, sana yüzlerce zafiyet kontrolü, uyum eşleştirmesi, AI özet ve CI/CD'ye entegre edilebilir rapor üretsin.**

### Temel kabiliyet aileleri
1. **Aktif tarama** — HTTP istekleriyle SQLi/XSS/SSRF/SSTI/RCE/IDOR vs. tespit
2. **Pasif analiz** — TLS sertifikası, security headers, SPF/DMARC, SRI eksikliği
3. **Tedarik zinciri** — lockfile + OSV.dev + CycloneDX SBOM
4. **Tehdit istihbaratı** — NVD CVE + EPSS + CISA KEV zenginleştirme
5. **AI destekli** — Anthropic / OpenAI / Ollama ile özetleme, triage, prompt-injection tarama
6. **Uyum (Compliance)** — PCI-DSS, HIPAA, GDPR, ISO 27001, SOC2, NIST CSF, CIS, ASVS eşleştirmesi
7. **Çıktı/ihracat** — SARIF, CycloneDX, JUnit, CSV, Markdown, JIRA, JSONL
8. **CI/CD** — GitHub Action, GitLab MR, Jenkins, Azure DevOps; threshold + exit code
9. **Bildirim** — 13 kanal (Slack, Discord, Teams, Email, ntfy, Pushover, Telegram, PagerDuty, Opsgenie, Mattermost, Rocket.Chat, Twilio, Webhook)
10. **Operasyon** — workspace, policy DSL, scan template, audit log (hash-chain), triage kuralları, scan diff

---

## 2. Mimari Üst Görünüm

```
┌─────────────────────────────────────────────────────────────────────┐
│                        İSTEMCİ KATMANI                              │
│  CLI (`temren`)   │   Web Dashboard (Next.js)   │   VSCode Extension │
└─────────────────────────────────────────────────────────────────────┘
                  │                  │                       │
                  └────────── HTTP/WebSocket ─────────────────┘
                                  │
┌─────────────────────────────────────────────────────────────────────┐
│  API (cmd/api)  — Fiber HTTP, JWT, rate-limit, WebSocket push      │
│   ├── internal/handler/routes.go       (auth + projects + scans)   │
│   └── internal/handler/v2_routes.go    (compliance, AI, intel...)  │
└─────────────────────────────────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
┌────────────────┐    ┌────────────────────┐    ┌──────────────────┐
│  Postgres      │    │  Redis + asynq     │    │  Worker          │
│  (pgx/v5)      │    │  (job kuyruğu)     │    │  (cmd/worker)    │
│  migrations/   │    │                    │    │  Tarama yapar    │
└────────────────┘    └────────────────────┘    └──────────────────┘
                                                          │
                                  ┌───────────────────────┼──────────────────┐
                                  ▼                                          ▼
                       ┌─────────────────────┐                  ┌─────────────────────┐
                       │  pkg/scanner/*      │                  │  pkg/* destek       │
                       │  80+ scanner        │   ◀──── kayıt ──▶│  compliance, AI,    │
                       │  registry.go        │                  │  exporter, notify…  │
                       └─────────────────────┘                  └─────────────────────┘
```

---

## 3. Dizin Haritası (Klasör Klasör)

### `/cmd` — Çalıştırılabilir binaryler

| Yol | Ne Yapar |
|---|---|
| `cmd/api/main.go` | Fiber HTTP API. `handler.RegisterV2()` çağrısıyla v2 endpoint'leri bağlar; `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `OLLAMA_MODEL` env'ine göre AI provider'ı otomatik seçer. |
| `cmd/worker/main.go` | asynq (Redis-backed) job worker. Kuyruktan tarama görevlerini alır, `pkg/scanner` motorunu çalıştırır, sonuçları DB'ye yazar. |
| `cmd/temren/main.go` | Cobra tabanlı CLI giriş noktası. |
| `cmd/temren/cmd/*.go` | 32 alt komut. (Tam liste §6'da) |

### `/internal` — Yalnızca bu modüle özel kod

| Yol | Ne Yapar |
|---|---|
| `internal/config/` | Env / config yükleme. |
| `internal/database/` | pgx connection pool, migration runner, repository pattern (scan, target, project, vulnerability, user). |
| `internal/handler/routes.go` | Auth (register/login/2FA), project CRUD, target CRUD, scan başlatma, webhook, JIRA/GitHub entegrasyonları. |
| `internal/handler/v2_routes.go` | **12 yeni endpoint**: `compliance/summary`, `intel/lookup`, `ai/chat`, `profiles`, `sbom`, `workspaces`, `policies/evaluate`, `triage`, `risk`, `scans/diff`, `honeypot`, `export/:format`, `notify/test`. Ayrıca `ConfigureAI(provider)` çağrısı bu paketten. |
| `internal/handler/auth_handler.go` | JWT issue/verify, refresh token, TOTP 2FA. |
| `internal/handler/scan_handler.go` | Tarama yaratma → asynq queue'ya at, ilerleme/sonuç döndür. |
| `internal/handler/cli_handler.go` | CLI'dan gelen tarama sonuçlarını alıp DB'ye persist eder (`/api/cli/scan-results`). |
| `internal/queue/` | asynq client + handler tipleri. |
| `internal/scheduler/` | gocron tabanlı zamanlanmış tarama yöneticisi. |
| `internal/middleware/` | JWT auth, rate limit (per IP / per user), CORS, audit-log middleware. |
| `internal/websocket/` | Fiber WebSocket Hub — canlı tarama ilerleme yayını, finding stream. |
| `internal/webhook/` | HMAC-SHA256 imzalı outbound webhook dispatcher. |
| `internal/email/` | SMTP (STARTTLS + implicit TLS) gönderim. |
| `internal/pdf/` | go-pdf/fpdf ile bulgu PDF raporu. |
| `internal/payloads/` | Tarayıcılar için gömülü payload listeleri. |
| `internal/metrics/` | Prometheus collector kayıt ve `/metrics` handler. |
| `internal/service/` | Domain servis katmanı (scan orkestrasyonu, notification routing, vb.). |

### `/pkg` — Yeniden kullanılabilir paketler (dış projelerin de import edebileceği seviye)

Aşağıdaki tablo **her paketin tek cümlelik özetini** verir. Detaylar §5'te.

| Paket | Sorumluluk |
|---|---|
| `pkg/scanner` | **Çekirdek.** 80+ scanner, ortak `Finding` tipi, `ScanEngine`, **`registry.go` (tek doğruluk kaynağı)**, CVSS 4.0 hesaplayıcı. |
| `pkg/scanners` | Eski/legacy scanner ad alanı (geçiş için tutuluyor). |
| `pkg/httpengine` | Rate-limited HTTP client, redirect kontrolü, custom user-agent, TLS skip seçeneği. |
| `pkg/spider` | URL crawler (BFS, same-domain, max-depth, max-pages). |
| `pkg/ai` | **Provider abstraction.** `Anthropic` (claude-sonnet-4-6), `OpenAI` (gpt-4o-mini), `Ollama` (local). Bulgu özeti, triage önerisi, chat. |
| `pkg/compliance` | Bulguları **PCI-DSS / HIPAA / GDPR / ISO 27001 / SOC2 / NIST CSF / CIS / OWASP ASVS** kontrollerine eşler; summary üretir. |
| `pkg/threatintel` | NVD CVE → CVSS, EPSS exploitability score, CISA KEV flag. Cache: `cve_cache` tablosu. |
| `pkg/exporter` | SARIF 2.1.0, CycloneDX 1.5, JUnit XML, CSV, Markdown, JIRA-ready JSON, JSONL. |
| `pkg/sbom` | Lockfile (npm/Go/PyPI/RubyGems/Cargo/Composer) → CycloneDX 1.5 SBOM. |
| `pkg/depscan` | Lockfile parse + OSV.dev cross-ref → vulnerable dependency listesi. |
| `pkg/policy` | **YAML policy DSL.** Expression evaluator (`severity == "critical" && cvss >= 9.0`); rule decision = `fail`/`warn`/`pass`. |
| `pkg/triage` | Dedup, suppress (regex / scanner / URL), re-rank, false-positive rule engine. |
| `pkg/risk` | Blended risk score = CVSS × EPSS × KEV × asset criticality × business context. |
| `pkg/scandiff` | İki tarama JSON'u arasında semantic diff: `added`/`fixed`/`regressed`/`improved`. |
| `pkg/profiles` | Curated tarama profilleri (`api-quick`, `full-owasp`, `pre-prod`, vs.). |
| `pkg/scantemplate` | YAML tarama şablonu validate + pretty-print. |
| `pkg/workspace` | Çoklu workspace (multi-tenant benzeri) ayrımı, asset tag'leme. |
| `pkg/cookieaudit` | Cookie güvenlik attribute audit (Secure, HttpOnly, SameSite, Domain scope). |
| `pkg/honeypot` | Hedef honeypot olasılığını skorlar (0-100); fake server pattern, fingerprint heuristic. |
| `pkg/tlsaudit` | TLS handshake, sertifika zinciri, expiry, weak cipher, protocol downgrade. |
| `pkg/emailauth` | DNS üzerinden SPF, DMARC, DKIM record audit. |
| `pkg/secretsmgr` | Secret bilgilerini env / file / vault üzerinden alır (vault shim). |
| `pkg/sandbox` | Subprocess sandbox: CPU/RAM/cüzdan zaman limiti, env scrub, cap-writer. |
| `pkg/llmscan` | Bir LLM endpoint'i için: prompt injection, system-prompt leak, jailbreak, çıktı XSS testleri. |
| `pkg/mcp` | MCP (Model Context Protocol) HTTP sunucusunu unauth tool/resource için audit. |
| `pkg/dnsenum` | Subdomain enumeration: DNS bruteforce + certificate-transparency log. |
| `pkg/observability` | Structured logging (JSON), trace id, scan correlation id. |
| `pkg/replay` | Proxy ile kaydedilmiş JSONL trace'i lokal HTTP sunucusunda tekrar oynat. |
| `pkg/proxy` | Recording HTTP/HTTPS forward proxy (her transaction → JSONL stdout). |
| `pkg/wordlists` | Gömülü directory / parameter / subdomain wordlist'leri. |
| `pkg/openapi` | OpenAPI/Swagger spec parse → scan edilebilir operation listesi. |
| `pkg/auditlog` | **Hash-chain (SHA-256) audit log.** Her event önceki event'in hash'ini içerir → tamper-evident. |
| `pkg/orchestrator` | Topolojik sıralı scan orchestration (`depends_on` graph). |
| `pkg/cloudscan` | Dockerfile, Kubernetes YAML, Terraform misconfig auditi. |
| `pkg/server` | (Embedded) Laptop modu HTTP sunucusu — Postgres/Redis olmadan çalışan dashboard. |
| `pkg/notify` | **13 bildirim kanalı.** Hepsi `Notifier` interface'ini implement eder. |
| `pkg/integration/github` | GitHub Issue create/update; PR comment; severity → label. |
| `pkg/integration/gitlab` | GitLab Issue + MR note; aynı pattern. |
| `pkg/integration/defectdojo` | DefectDojo finding push (engagement + product). |
| `pkg/integration/notify` | (Eski) Slack/Discord/Teams shim — yeni kod `pkg/notify` kullanır. |
| `pkg/auth` | JWT helpers, password hashing (bcrypt), TOTP. |
| `pkg/discovery` | Service discovery / asset inventory. |
| `pkg/wafbypass` | WAF tespiti + bypass payload mutasyonları (encoding, case, comment injection). |
| `pkg/analyzer` | Bulgu post-process: kategorize, severity normalize. |
| `pkg/report` | Bulguları struct'a topla, format-agnostic Report nesnesi. SARIF üretici da burada. |
| `pkg/remediation` | Bulgu → CWE-spesifik düzeltme önerisi metni. |
| `pkg/collaboration` | (Embed) Yorum, atama, thread basit collaboration. |
| `pkg/plugin` | Dış scanner plugin loader (Lua + gopher-lua). |
| `pkg/scheduler` | (pkg-seviye) gocron wrapper. |

### `/migrations` — Postgres şeması

| Dosya | İçerik |
|---|---|
| `001_init.sql` | `users`, `projects`, `targets`, `scans`, `vulnerabilities`, `webhooks`, `integrations`. |
| `002_schedules_webhooks.sql` | Zamanlanmış taramalar + webhook config. |
| `003_workspaces_policies_audit.sql` | **Yeni.** `workspaces`, `workspace_targets`, `policies`, `scan_templates`, `audit_events` (hash-chain), `notifications`, `asset_tags`, `triage_suppressions`, `cve_cache`, `plugins`. |

### `/frontend` — Next.js 15 dashboard (TypeScript + App Router)

`/frontend/src/app/dashboard/` altında her sayfa bir feature:

| Sayfa | Ne Gösterir |
|---|---|
| `advisor/` | AI destekli, doğal dil ile bulgu sorgu/önerisi. |
| `ai-chat/` | Direkt LLM provider chat (Anthropic/OpenAI/Ollama). |
| `assets/` | Asset inventory + tag yönetimi. |
| `attack-paths/` | Bulgular arasında graph (toxic combination) ekranı. |
| `audit-log/` | Hash-chain audit event timeline. |
| `compliance/` | PCI/HIPAA/ISO/SOC2 vs. heatmap. |
| `diff/` | İki tarama arası semantic diff UI. |
| `kanban/` | Bulgu kanban board (open / triaged / fixed). |
| `live/` | WebSocket'le canlı tarama ilerleme. |
| `notifications/` | Bildirim merkezi. |
| `plugins/` | Lua plugin yükle/etkinleştir. |
| `policies/` | Policy DSL editör + dry-run. |
| `risk-heatmap/` | Asset × severity matris. |
| `sbom/` | CycloneDX SBOM view + export. |
| `scans/` | Tarama listesi + detay. |
| `schedules/` | Zamanlanmış tarama yönetimi. |
| `settings/` | API key, provider, theme. |
| `targets/` | Target CRUD. |
| `team/` | Üyelik / rol. |
| `threat-intel/` | CVE arama + EPSS/KEV bilgisi. |
| `vulnerabilities/` | Tüm bulgular global view. |

`/frontend/src/lib/api.ts` → API client (fetch wrapper, JWT inject).
`/frontend/src/components/ui/` → minimal design system (button, card, badge, modal, skeleton, pagination, empty-state).

### Diğer dizinler

| Yol | İçerik |
|---|---|
| `action/` | GitHub Action wrapper (CI'da `temren ci` çalıştırır). |
| `vscode-extension/` | VS Code eklentisi (TypeScript). |
| `helm/temren/` | Helm chart. |
| `k8s/base/` | Ham Kubernetes manifestler. |
| `docker-compose.yml` / `.dev.yml` | Compose stack (api + worker + postgres + redis + frontend). |
| `examples/` | Örnek scan template, policy, ntfy config. |
| `tools/` | Geliştirme yardımcıları. |
| `docs/` | Dış dokümantasyon (mimari kararlar, runbook). |
| `specs/` | OpenAPI spec + protokol şemaları. |

---

## 4. Veri Akışı — Tipik Tarama Yolculuğu

```
1. Kullanıcı  →  POST /api/v1/targets/:id/scans  (handler/scan_handler.go)
                                │
2. handler  →  asynq.Enqueue("scan:run", {scan_id, profile})
                                │
3. cmd/worker  →  asynq handler  →  pkg/scanner.NewScanEngine(...)
                                │
4. scan engine  →  spider.Crawl(target)  →  URL listesi
                                │
5. scanner.EnabledScanners(filter)  →  her URL × her scanner   (registry.go)
                                │
6. Her scanner  →  httpengine.Client.Do(...)   payload mutasyonları
                                │                                  │
                                ▼                                  ▼
                       Finding{} listesi              pkg/wafbypass mutator
                                │
7. pkg/analyzer  →  dedupe, severity normalize
8. pkg/scanner.InferCVSS4Vector → CalculateCVSS4 → SeverityFromCVSS
9. pkg/triage  →  suppression / FP filtre
10. pkg/risk   →  blended risk score (CVSS × EPSS × KEV × asset)
                                │
11. Persist  →  database.SaveScan + SaveVulnerabilities
12. Stream   →  websocket.Hub.Broadcast(scan_id, findings)
13. Bildirim →  pkg/notify (kullanıcı kanalına göre)
14. Audit    →  pkg/auditlog (hash-chain SHA-256)
                                │
15. Kullanıcı  →  GET /api/v1/scans/:id  veya  /api/v2/export/:format
```

---

## 5. Kritik Paketlerin Detayı

### 5.1 `pkg/scanner/registry.go` — Tek Doğruluk Kaynağı

Tüm scanner'lar burada **tek bir slice'ta** kayıtlı. Yeni scanner eklemek:

1. `pkg/scanner/yeni_scanner.go` yaz, `Scanner` interface'ini implement et.
2. `registry.go`'ya `New<İsim>()` constructor'ı ekle.

`AllScanners()` ve `EnabledScanners(filter []string)` — CLI ve API her ikisi de bunu kullanır. **CLI'da artık hardcoded liste YOK.**

### 5.2 `pkg/scanner/scanner.go` — Ortak Tipler

- `Severity` enum: `Critical | High | Medium | Low | Info`
- `Confidence`: `Certain | Firm | Tentative`
- `Finding` struct: `Scanner, Title, Severity, URL, Description, Evidence, Payload, OWASPCategory, CWE, CVSSScore, Timestamp, Tags, ...`
- `Scanner` interface: `Name() string` + `Scan(ctx, url, client) ([]Finding, error)`
- `ScanEngine` — concurrency-limited fan-out, URL × scanner cross-product.

### 5.3 `pkg/scanner/cvss.go` — CVSS 4.0

- `InferCVSS4Vector(finding) Vector` — bulgu tipinden vektör tahmin.
- `CalculateCVSS4(vector) float64` — 0.0–10.0 skor.
- `SeverityFromCVSS(score) Severity` — eşik mapping.

### 5.4 `pkg/ai/` — Provider Soyutlaması

```go
type Provider interface {
    Chat(ctx context.Context, msgs []Message, opts ChatOptions) (string, error)
    Name() string
}
```

- `anthropic.go` — Anthropic Messages API, `claude-sonnet-4-6`.
- `openai.go` — OpenAI Chat Completions, `gpt-4o-mini`.
- `ollama.go` — Local `/api/chat` endpoint.

`cmd/api/main.go` env'den otomatik seçer:
- `ANTHROPIC_API_KEY` → Anthropic
- `OPENAI_API_KEY` → OpenAI
- `OLLAMA_MODEL` → Ollama
- Yoksa → AI özelliği disabled (endpoint 503 döner).

### 5.5 `pkg/notify/` — 13 Kanal

Her dosya bir kanal, hepsi şu interface:

```go
type Notifier interface {
    Send(ctx context.Context, msg Message) error
    Name() string
}
```

`notify.go` — registry + factory; YAML config'den kanal yükler.

Kanallar: **Slack, Discord, Teams, Email (SMTP+STARTTLS), ntfy, Pushover, Telegram, PagerDuty, Opsgenie, Mattermost, Rocket.Chat, Twilio (SMS), Webhook (HMAC-SHA256 imzalı).**

### 5.6 `pkg/policy/` — YAML DSL

```yaml
rules:
  - name: block-critical-prod
    when: "severity == 'critical' && env == 'prod'"
    decision: fail
  - name: warn-medium
    when: "severity == 'medium'"
    decision: warn
```

`Evaluator.Evaluate(findings, ctx)` → `Decision{Pass, Warn, Fail}` + matched rule listesi. `temren policy` komutu CI'da exit code üretir.

### 5.7 `pkg/auditlog/` — Hash-Chain

Her event:
```
event_n.hash = SHA256(event_n.payload || event_{n-1}.hash)
```

`temren audit-verify` komutu zinciri uçtan uca doğrular. Tamper olursa hash uyuşmaz, satır numarası verir.

### 5.8 `pkg/integration/github/` ve `pkg/integration/gitlab/`

- Bulgu → Issue title `[Temren] [SEVERITY] Title`
- Mevcut issue varsa update, yoksa create
- Severity → label (`security-critical`, `security-high`, …)
- PR/MR yorumu: severity-count tablosu + Critical/High listesi
- Status code toleransı: 2xx range (sadece 201 değil)

### 5.9 `pkg/sandbox/` — Subprocess Hapishanesi

- CPU time, RSS memory, wall-clock limit
- Env scrub: `Limits.Env` boşsa sadece minimal `PATH` enjekte
- Exit 141 (SIGPIPE) tolere
- Cap-writer: stdout/stderr boyutunu sınırla

---

## 6. CLI Komutları (`temren`)

| Komut | Ne Yapar |
|---|---|
| `temren scan --target URL` | Tüm enabled scanner'ları çalıştır. |
| `temren ci --target URL --threshold high` | CI optimized; threshold üstünde bulgu varsa exit 1. SARIF/JSON/text. |
| `temren serve` | Embedded laptop dashboard (Postgres/Redis gerektirmez). |
| `temren tui` | Terminal UI scan-profile picker. |
| `temren profile [name]` | Curated profil listesi/detay. |
| `temren template` | Scan template YAML validate. |
| `temren schedule {create,list,run,enable,disable,delete}` | Zamanlanmış taramalar. |
| `temren baseline` | Bulguları baseline'a karşı diff'le; regression → exit !=0. |
| `temren scan-diff` | İki scan JSON'u arasında semantic diff. |
| `temren triage` | Triage rules ile dedup/suppress/rerank. |
| `temren policy` | YAML policy değerlendir. |
| `temren compliance` | PCI/HIPAA/GDPR/ISO/SOC2/NIST/CIS eşleştirme raporu. |
| `temren risk` | Blended risk skoru hesapla. |
| `temren intel CVE-2024-XXXX` | NVD + EPSS + KEV zenginleştirme. |
| `temren dep` | Lockfile dep scan (OSV.dev). |
| `temren sbom` | CycloneDX SBOM üret. |
| `temren swagger` | OpenAPI spec parse → scannable operation listesi. |
| `temren cloud` | Dockerfile / K8s YAML / Terraform misconfig. |
| `temren dns` | Subdomain enumeration. |
| `temren llm` | LLM endpoint güvenlik testi. |
| `temren mcp` | MCP server audit. |
| `temren honeypot` | Honeypot olasılık skoru. |
| `temren proxy` | Recording forward proxy. |
| `temren replay` | Recorded JSONL trace replay. |
| `temren notify` | Notification channel smoke test. |
| `temren export` | Findings JSON → SARIF/CycloneDX/JUnit/CSV/MD/JIRA/JSONL. |
| `temren audit-verify` | Hash-chain audit log doğrula. |
| `temren self-test` | Built-in vulnerable target + tüm subsystem entegrasyon testi. |
| `temren completion [shell]` | Shell completion script. |

---

## 7. HTTP API Yüzeyi

### v1 (auth + asset + scan; `internal/handler/routes.go`)

```
POST   /api/v1/auth/register
POST   /api/v1/auth/login           [rate-limited per IP]
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout          [auth required]
GET    /api/v1/auth/me
POST   /api/v1/auth/2fa/enable
POST   /api/v1/auth/2fa/verify

GET    /api/v1/dashboard

POST   /api/v1/projects
GET    /api/v1/projects
GET    /api/v1/projects/:id
PUT    /api/v1/projects/:id
DELETE /api/v1/projects/:id

POST   /api/v1/targets
GET    /api/v1/projects/:projectId/targets
GET    /api/v1/targets/:id
PUT    /api/v1/targets/:id
DELETE /api/v1/targets/:id

POST   /api/v1/targets/:targetId/schedule
GET    /api/v1/targets/:targetId/schedule
DELETE /api/v1/targets/:targetId/schedule

POST   /api/v1/targets/:targetId/scans
GET    /api/v1/targets/:targetId/scans
GET    /api/v1/scans/:scanId
GET    /api/v1/scans/:scanId/progress
GET    /api/v1/scans/:scanId/vulnerabilities

GET    /api/v1/targets/:targetId/vulnerabilities
PATCH  /api/v1/vulnerabilities/:vulnId
GET    /api/v1/vulnerabilities/:vulnId

GET    /api/v1/webhooks
POST   /api/v1/webhooks
DELETE /api/v1/webhooks/:id
POST   /api/v1/webhooks/:id/test

POST   /api/v1/integrations/jira/configure
POST   /api/v1/integrations/jira/test
POST   /api/v1/integrations/github/configure
POST   /api/v1/integrations/github/test

POST   /api/v1/cli/scan-results       (CLI → API persist)

GET    /health
GET    /ws                            (WebSocket; canlı stream)
```

### v2 (`internal/handler/v2_routes.go`)

```
POST   /api/v2/compliance/summary     (bulgu listesi → framework eşleştirmesi)
POST   /api/v2/intel/lookup           (CVE listesi → NVD+EPSS+KEV)
POST   /api/v2/ai/chat                (AI provider chat passthrough)
GET    /api/v2/profiles               (curated scan profil listesi)
GET    /api/v2/sbom                   (CycloneDX SBOM)
GET    /api/v2/workspaces             (workspace listesi)
POST   /api/v2/workspaces             (workspace create)
POST   /api/v2/policies/evaluate      (findings + YAML → decision)
POST   /api/v2/triage                 (dedup/suppress/rerank)
POST   /api/v2/risk                   (blended risk score)
POST   /api/v2/scans/diff             (iki scan JSON → semantic diff)
GET    /api/v2/honeypot               (honeypot skoru)
POST   /api/v2/export/:format         (sarif|cyclonedx|junit|csv|md|jira|jsonl)
POST   /api/v2/notify/test            (notification smoke test)
```

---

## 8. Konfigürasyon & Env

`.env.example` referansı. Önemli değişkenler:

| Env | Amaç |
|---|---|
| `DATABASE_URL` | Postgres DSN |
| `REDIS_URL` | Redis (asynq) |
| `JWT_SECRET` | Token imzalama |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `OLLAMA_MODEL` | AI provider seçimi |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Email bildirim |
| `WEBHOOK_HMAC_SECRET` | Outbound webhook imzası |
| `LISTEN_ADDR` | API port (varsayılan `:8080`) |

---

## 9. Test Stratejisi

- **Unit:** her paket içinde `*_test.go`. Sıfır failing test.
- **Scanner test pattern:** lokal `httptest.NewServer` + zafiyetli handler + scanner çalıştır + finding assert.
- **Integration:** `pkg/integration/github`, `pkg/integration/gitlab` → mock GitHub/GitLab API (2xx tolerance, `r.URL.EscapedPath()` ile path encoding farkı).
- **Sandbox:** `TestCapWriterCaps` SIGPIPE exit 141 tolere, `TestEnvScrubbed` PATH-only enjekte.
- **Timeout:** `TestScanner_Timeout` 5 saniyelik `context.WithTimeout` budget.
- **TLS audit:** `AuditWithConfig()` ile `InsecureSkipVerify` test'lerde geçer.

```bash
GOCACHE=/tmp/temren-gocache GOMODCACHE=/tmp/temren-gomodcache go test ./...
```

---

## 10. Deployment

### Docker Compose

```bash
docker compose up -d        # api + worker + postgres + redis + frontend
docker compose -f docker-compose.dev.yml up
```

### Kubernetes

```bash
kubectl apply -k k8s/base/
# veya
helm install temren helm/temren/
```

### Tek-binary laptop modu

```bash
temren serve --port 8080     # gömülü dashboard, DB yok, in-memory
```

### CI'da kullanım

```yaml
# .github/workflows/security.yml
- uses: nickzsche/TemrenSec@v1
  with:
    target: https://app.example.com
    threshold: high
    format: sarif
    output: temren.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: temren.sarif }
```

---

## 11. Güvenlik & Operasyon Notları

- **Outbound webhook:** HMAC-SHA256 imzalı (`X-Temren-Signature`). Replay korumalı timestamp header.
- **JWT:** access token kısa ömürlü (15 dk varsayılan), refresh ayrı endpoint.
- **2FA:** TOTP, QR kod base64.
- **Rate limit:** IP başına `/auth/login` ve `/auth/register` — bruteforce koruması.
- **Audit log:** her destructive action zincire eklenir; `temren audit-verify` ile doğrulanır.
- **Secret yönetimi:** `pkg/secretsmgr` shim — env / file / external vault.
- **Sandbox:** plugin execution sandbox altında (CPU/RAM/walltime limit + env scrub).
- **TLS:** Tarayıcı kendi TLS audit'i yapar; test ortamında `AuditWithConfig` ile insecure skip.

---

## 12. Genişletme Rehberi

### Yeni scanner ekle
1. `pkg/scanner/foo_scanner.go` — `Scanner` interface implement et.
2. `pkg/scanner/registry.go` `AllScanners()` slice'ına `NewFooScanner()` ekle.
3. (İsteğe bağlı) `cmd/temren/cmd/ci.go` filter listesine adını ekle.
4. CLI, API ve dashboard otomatik görür.

### Yeni notification kanalı
1. `pkg/notify/foo.go` — `Notifier` interface.
2. `pkg/notify/notify.go` factory'ye ekle.
3. Config YAML şemasını güncelle.

### Yeni export format
1. `pkg/exporter/exporter.go` `Export(format, findings)` switch'ine case ekle.
2. v2 route `/api/v2/export/:format` tanır.
3. `temren export -f <format>` tanır.

### Yeni compliance framework
1. `pkg/compliance/<framework>.go` — kontrol → CWE / OWASP ID mapping tablosu.
2. `pkg/compliance/summary.go` framework registry'sine ekle.

### Yeni AI provider
1. `pkg/ai/<provider>.go` — `Provider` interface.
2. `cmd/api/main.go` env-based auto-wire bloğuna ekle.

---

## 13. Bilinen Sınırlamalar / Trade-off'lar

- **Active scan etik:** Sadece sahibi olduğun ya da explicit izinli sistemler için kullan. SSRF/RCE payloadları gerçek bulgu üretmek için tasarlanmıştır.
- **AI provider opsiyonel:** Yoksa endpoint 503 döner; CLI'da `--no-ai` flag.
- **Postgres + Redis zorunlu** — `cmd/api` ve `cmd/worker` için. `temren serve` (embedded) için değil.
- **Spider scope:** `same-domain` varsayılan; subdomain'lere geçilmez. `--scope` ile genişletilebilir.
- **WAF bypass:** Yalnızca tespit + mutation; rate-limit / IP rotation içermez.

---

## 14. Versiyon, Sürüm, Yayın

- `CHANGELOG.md` — sürüm notları.
- `.goreleaser.yaml` — multi-platform binary (darwin/linux/windows × amd64/arm64).
- `Dockerfile` — multi-stage, statik linked Go binary, `scratch` base.
- `Makefile` — `make build / test / lint / docker / release`.

---

## 15. Bağlı Standartlar & Kaynaklar

| Standart | Nerede |
|---|---|
| OWASP Top 10 (Web 2021) | `pkg/scanner` her bulguda `OWASPCategory` field |
| OWASP API Security Top 10 | `pkg/scanner/api_security.go` |
| CVSS 4.0 | `pkg/scanner/cvss.go` |
| CWE | Finding `CWE` field |
| SARIF 2.1.0 | `pkg/exporter` + `pkg/report` |
| CycloneDX 1.5 | `pkg/sbom`, `pkg/exporter` |
| NIST CSF / CIS / ISO 27001 / SOC2 / PCI-DSS / HIPAA / GDPR / OWASP ASVS | `pkg/compliance` |
| MITRE ATT&CK | `pkg/attackpath` (pkg/scanner içinde) |

---

## 16. Bu Dokümantasyonu Inceleyen Claude İçin Notlar

Eğer bu dosyayı inceleyip projeyi sorgulayacaksan, bilmen gereken **kritik nokta**lar:

1. **`pkg/scanner/registry.go` tek doğruluk kaynağıdır.** CLI ve API her ikisi de buradan okur — yeni scanner eklerken iki yere ayrı kayıt YOK.
2. **`internal/handler/v2_routes.go`** v2 endpoint'lerin hepsini içerir; `cmd/api/main.go` içinden `handler.RegisterV2(app)` ile bağlanır.
3. **AI provider'lar opsiyoneldir;** env yoksa modül disable edilir, hata vermez.
4. **Tüm test'ler yeşildir** — `go test ./...` repo bazında 0 failure.
5. **Hash-chain audit log** tamper-evident; her destructive action zincire eklenir.
6. **Tarama etik kısıtı:** Aktif payload'lar üretir; sadece izinli sistemlerde kullanılmalı.
7. **3 binary** — `temren` (CLI), `temren-api` (HTTP), `temren-worker` (asynq job runner). Aynı modül, farklı `main`.

Sorulabilecek soruların büyük çoğunluğunun cevabı:
- "Bu özellik nerede?" → §3 dizin haritası
- "Bu nasıl çalışıyor?" → §4 veri akışı + §5 paket detayları
- "Nasıl genişletirim?" → §12 genişletme rehberi
- "Hangi endpoint var?" → §7 HTTP API
- "Hangi CLI komutu?" → §6

İyi okumalar. ✦
