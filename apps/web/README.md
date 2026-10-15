# TraceSOC analyst workspace

This is the analyst-facing single-page experience for TraceSOC. It is a
self-contained Next.js application: a clean checkout can open the frozen
`primary-v1` scenario without a running API, while an API base URL can be
provided for real incident and evidence data.

## Prerequisites

- Node.js 22+
- npm 10+

## Install and run

From this directory:

```bash
npm install
npm run dev
```

Open <http://localhost:3000>. With no environment variable set, the header is
clearly labeled **OFFLINE / DEMO FIXTURE** and the app uses the checked-in
primary scenario in `lib/fixture.ts`.

## Connect the API

Copy `.env.example` to `.env.local` and set the FastAPI origin (without a
trailing slash):

```bash
NEXT_PUBLIC_TRACESOC_API_BASE_URL=http://localhost:8000
```

Restart the Next.js process after changing the environment. The live path uses:

- `GET /api/v1/incidents?limit=100`
- `GET /api/v1/incidents/{incident_id}`
- `GET /api/v1/incidents/{incident_id}/graph`
- `POST /api/v1/incidents/{incident_id}/investigations`
- `POST /api/v1/incidents/{incident_id}/response-plans`
- `POST /api/v1/response-actions/{action_id}/approve`
- `POST /api/v1/response-actions/{action_id}/execute`
- `GET /api/v1/response-actions/{action_id}/verification`

The incident detail and graph contracts supply the timeline, findings,
entities, and evidence-backed relationships. The investigation and response
controls call the backend routes when connected. The offline fixture keeps a
clearly labeled local state machine for demos without a backend.

## Checks

```bash
npm run typecheck
npm run build
```

The single reproducibility check is:

```bash
npm test
```

The pinned Node runtime is in `.nvmrc`. A production container can be built
and run with:

```bash
docker build -t tracesoc-web .
docker run --rm -p 3000:3000 tracesoc-web
```

## UI states to exercise

- Loading: initial page load shows skeleton panels.
- Demo/offline: default when no API base is configured.
- Error: set an unreachable API base URL, then use **Open demo fixture**.
- Empty: an API returning `{"items": []}` shows the incident empty state.
- Evidence: select a timeline event, switch between normalized and raw JSON.
- Graph: select a node to inspect its linked source event IDs.
- Investigation: run the deterministic mock report to reveal cited facts and
  competing hypotheses.
- Response: step through request approval, approval, execution, and independent
  verification for `revoke_session(session-S104)`.
