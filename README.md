# TraceSOC

TraceSOC is an evidence-first, AI-assisted security investigation platform.
The MVP turns a reproducible synthetic account-compromise sequence into an
inspectable incident, a constrained investigation, and a verified simulated
response.

## Current status

The repository is in the bootstrap stage. The frozen scenario contracts and
the initial FastAPI health service are being built before ingestion and
detection are added.

## Repository layout

```text
apps/api/       FastAPI backend
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
have Docker or PostgreSQL. The backend tests therefore use the deterministic
health contract and report the database-backed check as an environment gap
until Docker is available.

## First checks

```bash
uv sync
uv run ruff check .
uv run pytest
uv run python scripts/validate_scenario.py
```

To run the API locally after dependencies are installed:

```bash
uv run uvicorn apps.api.app.main:app --reload --port 8000
curl http://localhost:8000/api/v1/health
```

The health endpoint is expected to report a degraded database status until a
PostgreSQL instance is available.

## Build plan

The implementation roadmap is in
[`tracesoc_phasewise_project_plan.md`](tracesoc_phasewise_project_plan.md).
The first feature slice freezes the demo scenario and locks the contracts;
event ingestion is the next implementation phase.
