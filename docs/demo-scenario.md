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
10. Repeat with the benign or failed-verification variant.
