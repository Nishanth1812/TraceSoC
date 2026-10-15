# TraceSOC

TraceSOC is an evidence-first, AI-assisted security investigation platform.
The MVP turns a reproducible synthetic account-compromise sequence into an
inspectable incident, a constrained investigation, and a verified simulated
response.

## Current status

The deterministic evidence slice is implemented: JSON/JSONL ingestion produces
validated canonical events, idempotent fingerprints, evidence-linked findings,
and candidate incidents through versioned API routes. The analyst workspace is
available under `apps/web`; the frontend's investigation report and response
controls are intentionally self-contained mock/simulation states until the
corresponding backend routes are exposed.

## Repository layout

```text
apps/api/       FastAPI backend
apps/web/       Next.js analyst workspace (demo fixture or API-backed)
data/scenarios/ Versioned synthetic security fixtures
docs/           Product, contract, threat-model, and demo notes
scripts/        Repeatable validation and developer commands
```

## Local prerequisites

- Python 3.11+
- `uv` 0.13+
- Node.js 22+ and npm 10+ when the web application is added
- Docker Desktop with Compose for PostgreSQL-backed local development

The current development container has Python and Node installed, but does not
have Docker or PostgreSQL. The backend supports PostgreSQL through the normal
SQLAlchemy/Alembic configuration and supports SQLite through the same
repository and schema for local tests and development.

## Analyst workspace

The frontend is self-contained and can be run without the backend. See
[`apps/web/README.md`](apps/web/README.md) for exact install, demo-fixture, API
configuration, and verification steps. With no API base URL, it opens the
frozen `primary-v1` incident as an explicitly labeled offline/demo workspace.

## First checks

```bash
uv sync
uv run ruff check .
uv run pytest
uv run python scripts/validate_scenario.py
```

To run the evidence slice without PostgreSQL, use a SQLite URL. The tables are
created automatically for SQLite when the API starts; PostgreSQL remains
migration-managed:

```bash
DATABASE_URL=sqlite:///./tracesoc.db uv run uvicorn apps.api.app.main:app --port 8000
DATABASE_URL=sqlite:///./tracesoc.db uv run alembic upgrade head
```

The equivalent PowerShell setting is
`$env:DATABASE_URL="sqlite:///./tracesoc.db"`. For PostgreSQL, set
`DATABASE_URL=postgresql+psycopg://...` and run `uv run alembic upgrade head`.

To run the API locally after dependencies are installed:

```bash
uv run uvicorn apps.api.app.main:app --reload --port 8000
curl http://localhost:8000/api/v1/health
```

The health endpoint is expected to report a degraded database status until a
configured database instance is available. Its response contract is unchanged.

## Deterministic evidence API

Ingestion requires an `Idempotency-Key` header and uses the fixed contract
tenant `demo`:

- `POST /api/v1/events/ingest` with `{ "events": [...] }` or a JSON array;
- `POST /api/v1/events/upload` with newline-delimited JSON;
- `GET /api/v1/ingestion-runs/{run_id}` for accepted, rejected, duplicate,
  failed, and record-level error counts;
- `GET /api/v1/events` for bounded ordered event inspection;
- `GET /api/v1/incidents` and `GET /api/v1/incidents/{incident_id}` for
  candidate incidents, findings, raw events, and canonical entities;
- `GET /api/v1/incidents/{incident_id}/timeline` and `/findings` for bounded
  evidence views.

The fingerprint is the documented `sha256-v1` compact sorted-key JSON digest.
The deterministic rules are versioned in the implementation and emit signals
with event evidence; a fired rule is not represented as proof of compromise.

## Build plan

The implementation roadmap is in
[`tracesoc_phasewise_project_plan.md`](tracesoc_phasewise_project_plan.md).
The first implemented backend slice is the deterministic ingestion, detection,
correlation, and evidence inspection path.
