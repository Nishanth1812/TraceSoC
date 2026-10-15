# Threat model

The MVP is a local, synthetic demonstration, but it must demonstrate the
boundaries expected of a security product.

## Assets

- Raw and normalized security events.
- Evidence links, findings, incident state, and audit history.
- Simulated session state and response-action approvals.
- Provider configuration and any model credentials.

## Threats and controls

| Threat | Control |
| --- | --- |
| Prompt injection in a log field | Treat all log content as data; delimit it from instructions; allow only registered tools |
| Unauthorized response execution | Separate response routes; backend approval and actor checks at execution |
| Cross-tenant data access | Carry the tenant boundary through repositories, routes, and tools |
| Duplicate or replayed events | Versioned fingerprints, uniqueness constraint, and idempotent ingestion |
| Out-of-order events | Store event and ingestion times; use documented deterministic ordering |
| Missing or malformed telemetry | Persist record-level errors and label uncertainty rather than inferring absence |
| Model hallucinated evidence | Validate output and require stored event IDs for material claims |
| Model timeout or provider outage | Offline mock provider; deterministic findings remain available |
| Destructive external action | Simulation-only adapter; no external credentials or integrations in MVP |
| Sensitive data in logs | Avoid secrets, bound payloads, and redact investigation step summaries |
| Arbitrary model code execution | Never execute model-generated shell, SQL, URLs, or code |

## Trust boundaries

1. Uploaded events are untrusted input.
2. The deterministic application core is trusted to validate and constrain
   input, but its outputs remain evidence-based signals.
3. The AI provider is untrusted for factual accuracy and capability control.
4. The response simulator is trusted only to change local simulated state;
   verification must read that state independently.

## Security acceptance criteria

- A prompt-injection fixture cannot add a tool or change permissions.
- Direct execution without an approved exact action version is rejected.
- A failed verification cannot transition the incident to `contained`.
- Query and tool boundaries prevent access outside the requested incident and
  tenant.
- No provider credential is present in source control or test fixtures.
