# TraceSOC contracts

This file contains the contracts that must be stable before feature work is
parallelized. Contract changes require updates to the scenario expectations
and contract tests.

## Runtime and identity

- Tenant: `demo`
- Analyst actor: `analyst-demo`
- Runtime: Python 3.11+; the current development environment uses Python
  3.11.2.
- AI provider: `mock` by default; a real provider is optional.
- Response mode: simulation only.

The production persistence target remains PostgreSQL 16 through SQLAlchemy and
Alembic. The deterministic backend also supports an explicit SQLite URL
(`sqlite:///...` or `sqlite:///:memory:`) for local tests and development using
the same repository and table model; this is a deployment configuration choice
and does not change the event, fingerprint, or API contracts.

## Canonical event

Every source adapter produces a canonical event before detection runs.

| Field | Required | Meaning |
| --- | --- | --- |
| `event_id` | Yes | Internal event identifier |
| `tenant_id` | Yes | Data boundary; `demo` for the MVP |
| `source_event_id` | No | Identifier from the source system |
| `event_fingerprint` | Yes | Versioned deduplication fingerprint |
| `source_type` | Yes | `authentication`, `system`, `endpoint`, or `network` |
| `event_type` | Yes | Normalized classification |
| `event_time` | Yes | Timezone-aware UTC event timestamp |
| `ingested_at` | Yes | Server-side ingestion timestamp |
| `username` | No | Associated user |
| `host_id` | No | Associated host |
| `source_ip` | No | Origin IP address |
| `destination_ip` | No | Destination IP address |
| `session_id` | No | Session correlation key |
| `process_name` | No | Process name |
| `outcome` | No | `success`, `failure`, `blocked`, or `unknown` |
| `severity` | No | Source or normalized severity |
| `raw_event` | Yes | Original source payload, unchanged |
| `normalized_fields` | Yes | Validated source-independent attributes |

Missing values are unknown, not evidence of absence. Event timestamps are
stored in UTC. Ordering is `event_time`, then `ingested_at`, then `event_id`.

## Fingerprinting and idempotency

The current contract is `sha256-v1`. The canonical input is the compact JSON
encoding, with sorted keys and no insignificant whitespace, of:

```json
{
  "source_type": "authentication",
  "event_type": "login_failure",
  "event_time": "2026-10-15T09:00:00Z",
  "username": "alice",
  "host_id": null,
  "source_ip": "203.0.113.50",
  "destination_ip": null,
  "session_id": null,
  "process_name": null,
  "outcome": "failure"
}
```

The stored value is `sha256-v1:<lowercase-hex-digest>`. Within a tenant,
submitting the same fingerprint again is a duplicate and must not create a
second event. Source IDs are retained for traceability but are not assumed to
be globally unique when a fingerprint is available.

## Findings and evidence

Finding status is one of:

- `observed`: directly represented by stored event data;
- `inferred`: derived from multiple observed records;
- `unconfirmed`: plausible but missing supporting evidence; or
- `disproven`: contradicted by available evidence.

Every material finding references one or more stored event IDs, or explicitly
states that evidence is missing. A detection rule firing is a signal, not
proof of compromise.

## Incident states

```text
new -> investigating -> awaiting_approval -> responding -> contained -> resolved
                 \-> false_positive
```

Allowed additional paths:

- `awaiting_approval -> investigating` when a proposal is rejected or revised;
- `responding -> investigating` when verification fails or activity persists;
- `contained -> investigating` when new evidence indicates continued activity.

The backend validates transitions. The frontend cannot set arbitrary status
strings.

## Response states

Response actions are independent from incident status:

```text
proposed -> awaiting_approval -> approved -> executing -> succeeded
                         \-> rejected       \-> failed
succeeded -> verified | verification_failed | inconclusive
```

The only MVP action is `revoke_session`. It targets an existing simulated
session and has the postcondition `active == false`. Action version, target,
approval, execution, verification, actor, timestamp, and reason are audited.

## API errors

All API errors use this shape:

```json
{
  "code": "stable_machine_code",
  "message": "Human-readable explanation",
  "details": {},
  "request_id": "request identifier"
}
```
