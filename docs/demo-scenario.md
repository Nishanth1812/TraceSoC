# Demo scenario: suspicious account session

## Narrative

The `alice` account receives a burst of failed logins from
`203.0.113.50`. A successful login follows from that address, then a
privileged session appears on `ws-07`. A sensitive process and an unusual
outbound connection provide corroborating host and network context.

TraceSOC creates one candidate incident, links the findings to source event
IDs, and proposes revoking the simulated session `session-S104`. The response
is not considered successful until the verifier observes that the session is
inactive.

## Primary fixture

- Fixture ID: `primary-v1`
- Tenant: `demo`
- Account: `alice`
- Host: `ws-07`
- Source IP: `203.0.113.50`
- Destination IP: `198.51.100.24`
- Session: `session-S104`
- Raw event count: 7
- Expected accepted count: 7
- Expected duplicate count on replay: 7
- Expected rejected count: 0
- Expected candidate incident: `INC-PRIMARY-001`
- Expected response action: `revoke_session(session-S104)`

## Demo order

1. Ingest `data/scenarios/primary-v1/events.jsonl`.
2. Show accepted records and the normalized event stream.
3. Open `INC-PRIMARY-001`.
4. Inspect the timeline and the source event behind a finding.
5. Inspect the user, host, session, process, and network relationships.
6. Run the mock investigation and review competing hypotheses.
7. Review the response rationale, risk, rollback, and postcondition.
8. Approve and execute the simulation.
9. Verify the session state independently.
10. Show the benign or failed-verification comparison below.

## Comparisons and evaluation

The versioned `benign-v1` fixture contains one successful login. On a clean
database, upload `data/scenarios/benign-v1/events.jsonl` to
`POST /api/v1/events/upload` with a unique `Idempotency-Key`. It should accept
one event and create no candidate incidents, as recorded in its `expected.json`.
The primary fixture and benign fixture should be run separately when comparing
incident counts; the primary incident remains in a database after ingestion.

The failed-verification comparison is automated rather than a UI control. The
test executes an approved simulated revocation, changes the local simulated
session back to active, and checks that independent verification returns
`verification_failed` and the incident remains `investigating`. It changes no
external system. Run both comparisons and the primary scenario with:

```bash
uv run pytest apps/api/tests/test_evidence_slice.py apps/api/tests/test_investigation_response.py
```

The suite also checks duplicate ingestion, ordering, malformed records,
evidence references, provider failure, and response approval and replay.
Each test uses its own in-memory SQLite database. These synthetic cases show
whether the specified examples behave as expected; they do not establish
real-world detection accuracy, security assurance, or production readiness.

## Recovery and limits

- If the API workspace shows no incidents, check the API connection and seed
  the primary fixture using the root README instructions, then refresh.
- If the stack cannot start, the offline fixture remains available in the web
  workspace. It demonstrates local UI states without persisting API actions.
- Resetting the Compose database removes all data in that database volume;
  follow the root README reset instructions only for a disposable demo.
- The investigator is a deterministic mock. Response actions modify only local
  simulated state, and signals should not be presented as proof of compromise.
- The fixed `analyst-demo` actor is not authentication or access control. The
  application is a local demonstration and is not safe to expose as a
  production security product.
