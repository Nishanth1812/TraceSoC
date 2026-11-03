# TraceSOC

TraceSOC is an evidence-first, AI-assisted security investigation platform.
The MVP turns a reproducible synthetic account-compromise sequence into an
inspectable incident, a constrained investigation, and a verified simulated
response.

## Current status

The deterministic evidence slice, constrained mock investigation, and
simulation-only response workflow are implemented. The analyst workspace is
available under `apps/web`; it runs against the backend or the checked-in
offline fixture.

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
- Node.js 22+ and npm 10+ for the web application
- Docker Desktop with Compose for PostgreSQL-backed local development

The backend supports PostgreSQL through SQLAlchemy/Alembic and SQLite through
the same repository and schema for local tests and development.

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

With Docker available, the complete local stack is:

```bash
docker compose up --build
```

Then open <http://localhost:3000>. The API is available at
<http://localhost:8000>. Compose applies database migrations before starting
the API. Seed the primary scenario from the repository root:

```bash
curl -X POST http://localhost:8000/api/v1/events/upload \
  -H "Idempotency-Key: primary-v1" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary '@data/scenarios/primary-v1/events.jsonl'
```

In PowerShell, use `curl.exe` in place of `curl` and put the command on one
line. Refresh the workspace to see the incident. Repeating the request is
safe; its idempotency key returns the original ingestion run.

To reset the demo, `docker compose down -v` removes the Compose database volume
and **all data in it**. Start the stack and seed it again afterwards. For a
SQLite demo, stop the API and remove only the demo database file you created,
then restart the API and repeat the seed request.

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
- `GET /api/v1/incidents/{incident_id}/graph` for evidence-backed relationships;
- `POST /api/v1/incidents/{incident_id}/investigations` and
  `GET /api/v1/investigations/{run_id}` for constrained investigation runs;
- `POST /api/v1/incidents/{incident_id}/response-plans` for simulation proposals;
- `POST /api/v1/response-actions/{action_id}/approve`, `/reject`, and
  `/execute` for backend-enforced response decisions;
- `GET /api/v1/response-actions/{action_id}/verification` and
  `GET /api/v1/incidents/{incident_id}/audit` for independent verification and
  audit history.

The fingerprint is the documented `sha256-v1` compact sorted-key JSON digest.
The deterministic rules are versioned in the implementation and emit signals
with event evidence; a fired rule is not represented as proof of compromise.

## Build plan

The implementation roadmap is in
[`tracesoc_phasewise_project_plan.md`](tracesoc_phasewise_project_plan.md).
The implemented backend path is:

```text
Ingest -> Normalize -> Correlate -> Investigate -> Approve -> Simulate -> Verify
```

All response actions are local simulations, and the mock investigator remains
available without an AI provider key.

For the walkthrough, comparison scenarios, recovery steps, and security
limitations, see [`docs/demo-scenario.md`](docs/demo-scenario.md).
