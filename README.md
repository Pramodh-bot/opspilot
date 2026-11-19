# OpsPilot — Autonomous Incident & Infrastructure Triage Agent

OpsPilot ingests incidents (manually or from Prometheus Alertmanager), triages them with a LangGraph agent
(RAG over runbooks + an LLM, with an offline fallback), and proposes remediation actions that a human must
approve before anything runs.

**Stack:** Python / FastAPI · React + TypeScript (Vite) · PostgreSQL · LangGraph + OpenAI API · Docker ·
Prometheus, Alertmanager & Grafana · GitHub Actions

```
Alertmanager ──webhook──▶ FastAPI ──▶ PostgreSQL
React UI ───REST/JWT────▶   │
                            ├─▶ LangGraph:  retrieve (BM25 runbooks) → analyze (OpenAI ▸ circuit breaker ▸ rules fallback)
                            │               → plan (allowlisted actions) → policy gate
                            ├─▶ approvals: low-risk auto-runs, medium = responder, high = admin
                            └─▶ /metrics ──▶ Prometheus ──▶ Grafana  (+ alerts back to the webhook)
```

## Quick start

### Run the whole stack (Docker)
```bash
cp .env.example .env        # then replace every CHANGE-ME (openssl rand -hex 32)
make up                     # or: docker compose up --build -d
make seed-demo              # optional: demo users + sample incidents (local use only)
```
| URL | What |
|---|---|
| http://localhost:8080 | OpsPilot UI (sign in with `BOOTSTRAP_ADMIN_*`, or demo users: `admin@/responder@/viewer@opspilot.local`, password `OpsPilot-Demo-2026`) |
| http://localhost:3000 | Grafana → *OpsPilot Overview* dashboard |
| http://localhost:9090 / :9093 | Prometheus / Alertmanager (bound to localhost only) |

Set `OPENAI_API_KEY` to enable the LLM; without it the agent runs on the deterministic offline rules engine.

### Develop locally
```bash
make setup                                        # venv + npm ci
cd backend && DATABASE_URL=sqlite:///dev.db ../.venv/bin/uvicorn app.main:app --reload   # API on :8000 (docs at /docs)
cd frontend && npm run dev                        # UI on :5173, proxies /api to :8000
# first admin: set BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD (>=10 chars, letters+digits) before first start
```

### Tests
```bash
make test            # backend: 72 tests, coverage gate 90% (currently ~99%)
make frontend-test   # typecheck + vitest + axe accessibility checks
make eval            # agent accuracy on the labelled datasets
TEST_DATABASE_URL=postgresql+psycopg://user:pw@localhost:5432/testdb make test   # run the suite on PostgreSQL
```

## How the agent works
1. **Retrieve** – BM25 search over the runbook table (title/tags weighted higher). Admins can add runbooks; they are used immediately.
2. **Analyze** – OpenAI (JSON mode, temperature 0, 20 s timeout) returns category, severity, hypothesis, confidence and suggested actions, validated by a strict Pydantic schema. A **circuit breaker** (3 failures → open for 30 s → half-open probe) wraps the call; any error, timeout, invalid JSON or open circuit degrades to the deterministic rules engine, so triage never hard-fails. Fallback use is stored on each triage and exported as a metric.
3. **Plan** – suggestions are filtered through an **allowlist** (`app/agent/actions.py`). Unknown/hallucinated actions are dropped, risk is taken from the catalog (never from model output), `collect_diagnostics` always goes first, max 4 actions.
4. **Policy gate / human-in-the-loop** – only low-risk read-only actions auto-run. Medium-risk needs a responder, high-risk (rollback, DB failover, credential rotation, traffic blocking) needs an admin. Approval takes a row lock so two people cannot execute the same action; a re-triage supersedes stale pending actions.
5. Execution is **simulated** (`EXECUTOR_MODE=simulate`). Real integrations (Kubernetes, cloud APIs) plug into `execute_action()`; it must keep the allowlist check.

Incident text is treated as untrusted: it is delimited in the prompt, the model can only pick from the allowlist, and nothing executes without policy/approval.

## Security
- **AuthN/Z:** bcrypt passwords, short-lived JWTs (HS256, `exp` required, `alg=none` rejected), 3-tier **RBAC** enforced on every endpoint, inactive users rejected on each request, login lockout (5 failures/15 min per email+IP), uniform error + dummy hash to avoid user enumeration.
- **Least privilege:** the API connects to PostgreSQL as `opspilot_app`, which has data-only rights (no DDL — verified: `CREATE/DROP/ALTER` are denied). A one-shot `migrate` job runs as the owner role. Containers run non-root, read-only filesystem, all capabilities dropped. Metrics and the webhook are not exposed through the public frontend proxy; admin ports bind to localhost.
- **Input validation:** Pydantic length/enum/regex constraints (service names, text sizes, list sizes), control characters stripped, parameterised SQL only, LIKE wildcards escaped, pagination caps.
- **Webhook:** shared-secret (`Authorization: Bearer` or `X-Webhook-Token`), constant-time compare, duplicate suppression.
- **Production guards:** app refuses to start with the dev JWT secret; API docs disabled; security headers + CSP; CORS allowlist.
- *Known trade-off:* lockout is keyed by email+IP, so behind a proxy an attacker can lock a user out; swap in a shared store (Redis) and per-client IPs for multi-replica deployments. The login throttle is in-memory (per process).

## Observability
Structured JSON logs with a per-request `X-Request-ID`; Prometheus metrics (HTTP, incidents by status/severity, triage by provider/category/fallback, action outcomes, LLM circuit state, login failures); Grafana dashboard `infra/grafana/dashboards/opspilot.json`; alert rules in `infra/prometheus/alerts.yml` (backend down, 5xx rate, latency, LLM circuit open, approval backlog, login spike) which Alertmanager forwards to OpsPilot itself.

## Accessibility
Skip link, landmarks, labelled controls, `role="alert"`/`status` live regions, focus moved to the page on navigation, text-bearing badges (colour never the only signal), visible focus ring, reduced-motion support, text contrast ≥ 4.5:1 (computed for every colour pair). Automated **axe-core** checks run in the test suite for each screen. Automated checks cover only part of WCAG — do a manual keyboard and screen-reader pass before claiming conformance.

## Measured results (and what you can honestly claim)
These numbers come from running the code in this repo, not from the project description:

| Item | Measured here |
|---|---|
| Backend tests | 72 passing on SQLite **and** on PostgreSQL 16; line coverage ≈ 99% |
| Frontend | 14 tests passing, incl. axe; production build OK |
| Triage accuracy, offline rules engine | **100% category / ~71% severity** on `eval/dataset.json` (48 cases, *in-sample: the rules and cases were written together*) and **75% category / 75% severity** on `eval/holdout.json` (16 cases with fresh wording) |
| Triage accuracy, OpenAI + RAG | **Not measured** (no API key was available while building). Run `OPENAI_API_KEY=... python -m app.agent.eval --provider openai` |
| 35% faster triage, 40% faster detection | **Not measurable from code.** The dashboard tracks `opspilot_incident_time_to_triage_seconds` and `opspilot_incident_detection_seconds`; collect a before/after baseline from real usage |

Before quoting figures such as "94% triage accuracy" or "35% / 40% improvements" on a resume, produce them with the eval harness
on a larger labelled set (and the real LLM) and with a measured baseline — interviewers will ask how they were computed.

## Layout
```
backend/app      FastAPI app (routers/, agent/{graph,llm,rag,actions,service,eval}.py, models, security, metrics)
backend/eval     labelled datasets for the agent
backend/tests    pytest suite
frontend/src     React UI (pages/, components/, test/)
infra/           postgres role script, prometheus, alertmanager, grafana provisioning + dashboard
```

## Limitations
- Remediation actions are simulated, by design. No real infrastructure is touched.
- Docker images were not built in the authoring environment (no Docker daemon); the compose file is validated with `docker compose config`, the same flow was exercised by hand on PostgreSQL 16, and CI builds the images.
- Schema is created with `create_all` (no Alembic migration history); add Alembic before evolving the schema in production.
