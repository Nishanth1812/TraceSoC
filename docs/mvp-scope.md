# MVP scope

## In scope

- A single-tenant local demonstration with the fixed tenant `demo`.
- A fixed local analyst actor, `analyst-demo`.
- One versioned JSONL event source shape.
- A synthetic account-compromise sequence with benign and failure variants.
- UTC normalization, deterministic fingerprints, idempotent ingestion, and
  record-level parse errors.
- Transparent deterministic detection and bounded correlation.
- Candidate incidents, evidence-linked findings, a timeline, and a small
  entity graph.
- An offline/mock constrained investigator with read-only tools.
- One simulated response action: `revoke_session`.
- Backend-enforced approval, idempotent simulated execution, and independent
  verification.
- Repeatable tests and resettable demo data.

## Out of scope

- Real-world response actions or external-system integrations.
- Production endpoint agents, live attacks, and offensive activity.
- Full SIEM/SOAR capabilities or every vendor log format.
- User registration, SSO, RBAC administration, and multi-tenant management.
- Custom model training, unrestricted agent tools, and multi-agent workflows.
- Enterprise retention, compliance, high availability, and calibrated
  detection probabilities.

## Release rule

If a feature does not improve investigation quality, evidence traceability,
response safety, or demo reliability, defer it until the core vertical slice
works.
