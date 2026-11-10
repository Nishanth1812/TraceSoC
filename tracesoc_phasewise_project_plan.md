# TraceSOC MVP: Phase-Wise Implementation Plan

> **Product promise:** Don't just detect the alert. Reconstruct the attack,
> show the evidence, and verify the response.

| Item | Decision |
| --- | --- |
| Project | TraceSOC |
| Purpose | Evidence-first, AI-assisted security investigation for a reproducible local demo |
| Current repository state | Bootstrap implementation underway on the `dev` branch |
| Target release | Hackathon-ready MVP, not a production SIEM or SOAR |
| Plan status | Implementation-ready baseline |
| Primary user | Security analyst investigating a suspected account compromise |
| Delivery principle | Build and test one complete vertical slice before broadening scope |

## 1. How to use this plan

This document is the working implementation roadmap. The phases are ordered by
dependency, and each phase has an explicit exit gate. Do not move to the next
phase because the code exists; move when the behavior at the exit gate is
demonstrated by a repeatable check.

The plan intentionally makes several MVP decisions that the previous draft
left open:

- The demo is single-tenant and uses a fixed local analyst actor. Full identity
  management and multi-tenant administration are deferred.
- The primary dataset is one synthetic account-compromise sequence. A benign
  comparison and a failed-verification variant are also required.
- The deterministic pipeline is authoritative. AI investigation is optional,
  bounded, and never required for ingestion or detection.
- Response actions are simulation-only. No route, tool, or adapter may modify
  a real external system.
- The first implementation is a modular monolith with synchronous requests.
  Queues, streaming, and microservices are deferred until a measured need
  exists.

### Phase overview

| Phase | Name | Outcome | Depends on |
| --- | --- | --- | --- |
| 0 | Scope and scenario freeze | One testable product contract and fixture set | None |
| 1 | Repository bootstrap and contracts | A runnable skeleton with locked interfaces | 0 |
| 2 | Deterministic evidence slice | Ingest → normalize → detect → create incident → inspect evidence | 1 |
| 3 | Analyst investigation experience | Timeline, findings, entities, graph, and evidence navigation | 2 |
| 4 | Constrained AI investigation | Optional tool-backed, evidence-cited investigation report | 2; 3 for graph tools |
| 5 | Simulated response and verification | Approve → execute → verify with safe state transitions | 2; 4 may provide recommendations |
| 6 | Evaluation and security hardening | Repeatable tests for core and abuse cases | 2–5 |
| 7 | Demo release and handoff | Resettable, documented, rehearsed presentation build | 6 |

### Working rule

Every phase must leave the repository in a runnable state. Each feature should
be implemented in this order:

1. Define or update the contract.
2. Add a failing test or fixture that expresses the behavior.
3. Implement the smallest complete path.
4. Add the relevant UI or API behavior.
5. Run the phase exit checks and record the result.

## 2. Product outcome and scope

### 2.1 The MVP user journey

An analyst should be able to:

1. Load a known batch of security events.
2. See accepted, rejected, and duplicate ingestion counts.
3. Open the candidate incident produced by deterministic rules.
4. Follow the incident timeline and inspect raw source evidence.
5. See how the affected user, host, session, IP, and process are related.
6. Run an optional constrained investigation that compares hypotheses.
7. Review a simulated containment action with rationale, risk, and rollback.
8. Approve or reject it through a backend-enforced workflow.
9. See the simulated action execute and be independently verified.
10. Export or inspect an evidence-backed final incident summary.

### 2.2 In scope for the MVP

- JSONL upload and a JSON batch ingestion endpoint.
- One canonical event schema and one source adapter for the demo fixture.
- UTC timestamp normalization, fingerprinting, idempotency, and parse errors.
- Two or three transparent detection rules and bounded event correlation.
- Candidate incident creation with evidence references.
- An incident detail view with timeline, findings, raw events, and entities.
- A small evidence-backed entity graph and bounded blast-radius summary.
- Three read-only investigation tools and a mock/offline investigator.
- One optional real LLM provider adapter behind a configuration flag.
- One simulated response action, approval gate, execution state, and verifier.
- Audit records for investigation, approval, execution, and verification.
- Automated unit, integration, security, and scenario tests.
- Seed/reset commands and a short demo script.

### 2.3 Explicitly out of scope

- Production endpoint agents or real containment integrations.
- Live attacks, offensive security activity, or external-system modification.
- A full SIEM, SOAR, data lake, or distributed event-streaming platform.
- Every vendor-specific log format.
- Full user registration, SSO, RBAC administration, and multi-tenancy.
- Custom model training, autonomous multi-agent orchestration, or unrestricted
  agent tools.
- Calibrated probability claims from hand-written confidence scores.
- Enterprise retention, compliance, tamper-evidence, and high-availability
  controls.
- Broad real-time dashboards before the core investigation path works.

## 3. Frozen demo scenario

The scenario is fixed before application scaffolding. It is the source of
truth for fixtures, expected detections, graph edges, screenshots, and
acceptance tests.

### 3.1 Primary suspicious sequence

Use synthetic identifiers and clearly label all data as simulated.

| Order | Event | Key entities | Expected interpretation |
| ---: | --- | --- | --- |
| 1 | Several failed logins | `alice`, `203.0.113.50` | Suspicious authentication burst |
| 2 | Successful login from the same source | `alice`, `203.0.113.50`, `ws-07` | Possible account compromise |
| 3 | New privileged session | `alice`, `session-S104`, `ws-07` | Elevated-risk follow-on activity |
| 4 | Sensitive process starts | `ws-07`, `powershell.exe` | Corroborating host activity |
| 5 | Unusual outbound connection | `ws-07`, `198.51.100.24` | Possible command or data path |
| 6 | Candidate incident created | all related entities | Evidence-backed detection |
| 7 | Session revocation proposed | `session-S104` | Simulated containment action |
| 8 | Session becomes inactive | `session-S104` | Independently verifiable postcondition |

The exact event count, timestamps, source fields, expected rule IDs, and
expected evidence IDs must be committed as versioned fixtures in Phase 0. The
identifiers above are illustrative defaults and may be replaced before the
fixture is frozen.

### 3.2 Required comparison scenarios

| Scenario | Purpose | Expected result |
| --- | --- | --- |
| Benign unusual login | Prevent every anomaly from becoming a compromise | Signal or low-confidence finding, not confirmed compromise |
| Failed-login burst without success | Test incomplete evidence | Candidate signal with missing corroboration |
| Duplicate submission | Test idempotency | No additional event or incident evidence |
| Out-of-order events | Test timeline reconstruction | Stable event order using documented tie-breakers |
| Malformed record | Test partial batch failure | Record-level error; valid records still persist |
| Prompt injection in a log field | Test AI boundary | No new tool, permission, or instruction is accepted |
| Failed verification | Test closed-loop response | Action is not marked contained or verified |

### 3.3 MVP success definition

The MVP is successful when a new viewer can follow the suspicious sequence from
ingestion to independently verified simulated containment, inspect the source
evidence for every material claim, and see that benign, ambiguous, rejected,
and failed paths are not reported as successful compromise or containment.

## 4. Architecture and implementation decisions

### 4.1 System shape

```text
JSONL / JSON batch
        |
        v
Ingestion -> Normalize -> Fingerprint -> Persist
                                      |
                                      v
                            Detect -> Correlate -> Incident
                                      |
             +------------------------+------------------------+
             |                        |                        |
             v                        v                        v
        Timeline                 Entity graph             AI tools
             |                        |                        |
             +------------------------+------------------------+
                                      v
                           Findings and response plan
                                      |
                                      v
                         Approve -> Simulate -> Verify
```

The backend is a modular monolith. Modules have clear interfaces but share one
deployable service and one PostgreSQL database:

```text
apps/api/app/
├── api/             # FastAPI routes, dependencies, error handling
├── schemas/         # Pydantic request, response, and domain contracts
├── ingestion/       # Adapters, normalization, fingerprints, parse errors
├── detection/       # Versioned deterministic rules and severity factors
├── correlation/     # Time windows, entity links, incident grouping
├── cases/           # Incident lifecycle, findings, notes, evidence links
├── graph/           # Entity extraction, relationships, bounded traversal
├── investigation/   # Tool registry, provider adapter, run orchestration
├── response/        # Allowlisted actions, approval, simulation, verification
├── audit/           # Append-only application audit records
└── main.py
apps/web/            # Next.js analyst UI
data/scenarios/      # Versioned synthetic fixtures and expected outputs
docs/                # Scope, contracts, threat model, demo notes
scripts/             # Seed, reset, check, and local developer commands
```

### 4.2 Default stack

| Layer | Choice | Constraint |
| --- | --- | --- |
| Backend | Python 3.11+, FastAPI, Pydantic 2, SQLAlchemy 2 | Current environment uses Python 3.11.2; all input and output contracts are validated |
| Database | PostgreSQL 16 with Alembic migrations | No production database is required for the demo |
| Frontend | Next.js, TypeScript, Tailwind CSS | Build only the screens needed by the demo path |
| Graph | NetworkX in the backend; React Flow in the UI | Scope traversal to one incident and a bounded time window |
| AI | Provider adapter plus deterministic mock provider | Mock path must work without an API key |
| Tests | pytest, API integration tests, frontend tests, scenario tests | Tests run from a clean checkout |
| Local runtime | Docker Compose for PostgreSQL and app services | No queue or Kubernetes in the MVP |

Pin runtime major versions, dependencies, and lockfiles in Phase 1. If the
repository already adopts a different tool, record that decision rather than
silently introducing a second toolchain.

### 4.3 Safety boundaries

1. Log text is untrusted data, never instructions.
2. Deterministic parsing, detection, authorization, and response execution are
   ordinary application code; the model cannot replace them.
3. Investigation tools are read-only and allowlisted.
4. Response actions are separate from investigation tools and simulation-only.
5. Backend authorization is checked again at approval and execution time.
6. No model-generated shell commands, SQL, URLs, or arbitrary code are run.
7. Secrets are read from environment configuration and never committed.
8. The demo is single-tenant, but every data access function still accepts a
   tenant boundary so the boundary is not accidentally omitted.

## 5. Contracts to lock before feature work

These decisions belong in `docs/contracts.md`. Once Phase 1 exits, changes
require an explicit decision note and updates to contract tests.

### 5.1 Canonical event contract

Every source adapter produces the same validated event shape before detection.

| Field | Required | Rule |
| --- | --- | --- |
| `event_id` | Yes | Internal stable ID generated by the application |
| `tenant_id` | Yes | `demo` for the MVP; retained for safe query boundaries |
| `source_event_id` | No | Original source identifier when available |
| `event_fingerprint` | Yes | Versioned deterministic deduplication key |
| `source_type` | Yes | `authentication`, `system`, `endpoint`, or `network` |
| `event_type` | Yes | Normalized event classification |
| `event_time` | Yes | Timezone-aware UTC timestamp |
| `ingested_at` | Yes | Server-side ingestion timestamp |
| `username` | No | Canonical user identifier |
| `host_id` | No | Canonical host identifier |
| `source_ip` | No | Validated IP address when present |
| `destination_ip` | No | Validated IP address when present |
| `session_id` | No | Correlation key when present |
| `process_name` | No | Process name when present |
| `outcome` | No | `success`, `failure`, `blocked`, or `unknown` |
| `severity` | No | Source or normalized severity; never the sole conclusion |
| `raw_event` | Yes | Original payload retained unchanged |
| `normalized_fields` | Yes | Validated source-independent attributes |

Contract rules:

- Missing values mean unknown; they are not evidence of absence.
- The fingerprint algorithm and version are documented and tested.
- Duplicate ingestion is idempotent within a tenant.
- Event ordering is `event_time`, then `ingested_at`, then `event_id`.
- Parse failures are returned and persisted; malformed records never disappear.
- Query filters are parameterized and bounded.

### 5.2 Minimal persistence model

Start with the smallest model that supports the frozen scenario:

- `security_events`: raw and normalized events, source metadata, timestamps,
  fingerprint, and tenant boundary.
- `ingestion_runs`: counts, status, source, and record-level errors.
- `incidents`: title, status, severity, confidence, and observed time range.
- `incident_events`: unique incident-to-event links with relationship type.
- `entities`: canonical user, host, IP, session, process, or service records.
- `entity_relationships`: observed or inferred links plus evidence references.
- `findings`: observed, inferred, unconfirmed, or disproven claims.
- `investigation_runs` and `investigation_steps`: bounded, auditable tool use.
- `response_actions`: action version, target, approval, execution, and result.
- `audit_logs`: actor, action, target, timestamp, and non-secret metadata.
- `simulated_state`: the state read by response verification.

Use normalized evidence-link tables where relationships need querying. JSONB is
appropriate for raw payloads and provider-specific metadata, not as a shortcut
for every relationship.

### 5.3 Status models

Incident status and response-action status are independent. Backend code owns
all transitions; the frontend cannot submit arbitrary status strings.

#### Incident statuses

| From | Allowed next state | Condition |
| --- | --- | --- |
| `new` | `investigating`, `false_positive` | Candidate incident is triaged |
| `investigating` | `awaiting_approval`, `false_positive`, `resolved` | Evidence review is complete, dismissed, or no action is needed |
| `awaiting_approval` | `investigating`, `responding` | Plan rejected/revised, or an action is approved |
| `responding` | `investigating`, `contained` | Verification fails/continues, or postcondition is verified |
| `contained` | `investigating`, `resolved` | New activity appears, or closure criteria are met |
| `resolved` | None in MVP | Terminal presentation state |
| `false_positive` | None in MVP | Terminal presentation state |

#### Response-action statuses

`proposed → awaiting_approval → approved → executing → succeeded` or
`failed`. A succeeded action then becomes `verified`, `verification_failed`, or
`inconclusive` after an independent check. Rejected and stale actions are
terminal for that action version. A new proposal must receive a new version
and approval.

Every transition records the actor, timestamp, previous state, new state, and
reason in the audit log.

### 5.4 API conventions

- Prefix routes with `/api/v1`.
- Return JSON with a stable error shape: `code`, `message`, `details`, and
  `request_id`.
- Use cursor pagination only if the first implementation needs it; otherwise
  use bounded `limit` plus `offset` and document the maximum.
- Use UUIDs or another single documented ID type consistently.
- Require an idempotency key on ingestion runs and response execution.
- Never return raw secrets, provider credentials, or unbounded log payloads.
- Include `observed`, `inferred`, and `unknown` labels wherever a conclusion
  could be mistaken for a fact.

### 5.5 Initial API surface

Implement routes only when their phase needs them.

| Method | Endpoint | First phase | Purpose |
| --- | --- | ---: | --- |
| `GET` | `/api/v1/health` | 1 | Service and database health |
| `POST` | `/api/v1/events/ingest` | 2 | Ingest a validated JSON batch |
| `POST` | `/api/v1/events/upload` | 2 | Upload the supported JSONL fixture |
| `GET` | `/api/v1/ingestion-runs/{run_id}` | 2 | Counts and record-level errors |
| `GET` | `/api/v1/events` | 2 | Bounded event search and pagination |
| `GET` | `/api/v1/incidents` | 2 | List candidate incidents |
| `GET` | `/api/v1/incidents/{incident_id}` | 2 | Incident summary and status |
| `GET` | `/api/v1/incidents/{incident_id}/timeline` | 3 | Ordered evidence timeline |
| `GET` | `/api/v1/incidents/{incident_id}/graph` | 3 | Evidence-backed graph data |
| `GET` | `/api/v1/incidents/{incident_id}/findings` | 3 | Findings and evidence links |
| `POST` | `/api/v1/incidents/{incident_id}/investigations` | 4 | Start mock or provider investigation |
| `GET` | `/api/v1/investigations/{run_id}` | 4 | Investigation status and result |
| `POST` | `/api/v1/incidents/{incident_id}/response-plans` | 5 | Create an allowlisted proposal |
| `POST` | `/api/v1/response-actions/{action_id}/approve` | 5 | Approve exact action version |
| `POST` | `/api/v1/response-actions/{action_id}/reject` | 5 | Reject exact action version |
| `POST` | `/api/v1/response-actions/{action_id}/execute` | 5 | Execute approved simulation |
| `GET` | `/api/v1/response-actions/{action_id}/verification` | 5 | Inspect independent verification |
| `GET` | `/api/v1/incidents/{incident_id}/audit` | 5 | Review case audit trail |

## 6. Phase 0 — Scope and scenario freeze

### Objective

Turn the product idea into a finite, testable contract before application
scaffolding begins.

### Work items

1. Write the one-paragraph problem statement and primary persona.
2. Freeze the suspicious, benign, malformed, duplicate, out-of-order,
   prompt-injection, rejected-action, and failed-verification fixtures.
3. Record exact event counts, timestamps, identifiers, expected fingerprints,
   rule IDs, evidence IDs, graph nodes, and postconditions.
4. Decide the single-tenant local-demo posture and fixed analyst actor.
5. Choose the one response action: simulated session revocation.
6. Define the incident and response state transitions in `docs/contracts.md`.
7. Write the threat model for untrusted logs, unauthorized actions, missing
   telemetry, cross-tenant access, and duplicate/out-of-order input.
8. Sketch only the screens required for the end-to-end journey.
9. Create an acceptance-test checklist from the success definition.

### Deliverables

- `docs/problem-statement.md`
- `docs/mvp-scope.md`
- `docs/threat-model.md`
- `docs/demo-scenario.md`
- `data/scenarios/primary-v1/` with expected-output metadata
- Initial wireframe or low-fidelity screen notes

### Exit gate

- The scenario can be explained in under one minute.
- The fixture has a documented expected result, not just raw input.
- The team can name every feature that is in or out of the MVP.
- No response path can affect a real external system.
- The state machine has no undefined transition required by later phases.

## 7. Phase 1 — Repository bootstrap and contract lock

### Objective

Make the empty repository runnable and lock the contracts that enable parallel
implementation without disconnected assumptions.

### Work items

1. Create the backend and frontend skeleton using the selected stack.
2. Add dependency lockfiles, formatting, linting, type checking, and test
   configuration.
3. Add Docker Compose for PostgreSQL and local app services.
4. Add `.env.example`, startup validation, and safe development defaults.
5. Add Alembic migrations and create the minimal persistence model.
6. Define Pydantic domain models and API request/response/error schemas.
7. Define ID generation, timestamp handling, pagination, fingerprints,
   idempotency, and deterministic event ordering.
8. Add `GET /api/v1/health` and one database-backed contract test.
9. Add a small CI workflow for backend tests, frontend checks, and Markdown
   or configuration validation.
10. Add documented seed/reset command shapes, even if the implementation is
    completed in Phase 2.

### Required local commands

Document exact commands and their working directories. The concrete package
manager can be selected during this phase, but the final README must expose
equivalents for Linux/macOS and PowerShell where practical.

```text
docker compose up --build
<migration command>
<backend test command>
<frontend lint and test command>
<health check command>
```

The commands must run from a clean checkout without a real AI provider key.

### Deliverables

- Runnable repository layout
- Database service and initial migration
- Locked contract document and contract tests
- Health endpoint
- CI checks and developer setup documentation

### Exit gate

- A new developer can start the stack from documented commands.
- Migrations succeed on an empty database.
- The health endpoint reports the expected service and database state.
- Contract tests pass without an external model provider.
- No secrets or local database files are committed.

## 8. Phase 2 — Deterministic evidence slice

### Objective

Implement the first complete backend path: ingestion → normalization →
deduplication → detection → candidate incident → evidence-linked timeline
data.

### Work items

#### Ingestion and normalization

1. Support the frozen JSONL source shape and JSON batch requests.
2. Validate each record without aborting the entire batch.
3. Preserve raw input exactly and store normalized fields separately.
4. Normalize timestamps to UTC and validate IP, host, user, and outcome
   fields.
5. Compute the versioned event fingerprint and enforce idempotency.
6. Persist `accepted`, `rejected`, `duplicate`, and `failed` counts.
7. Persist record-level parser errors without exposing secrets.
8. Enforce request, record, and payload-size limits.

#### Detection and correlation

1. Add a versioned rule registry.
2. Implement only the rules needed by the frozen scenario:
   - repeated failed authentication within a time window;
   - failed logins followed by a successful login for the same account;
   - privileged session or sensitive process activity on the related host.
3. Correlate by canonical entities and bounded time windows.
4. Support the documented out-of-order tolerance.
5. Group related detections into one candidate incident.
6. Store rule ID, rule version, triggering event IDs, and transparent severity
   factors.
7. Describe a fired rule as a signal or finding, never as proof of compromise.

#### Case foundation

1. Create the candidate incident and attach its supporting events.
2. Add the initial status transition to `investigating`.
3. Add findings with `observed`, `inferred`, or `unconfirmed` status.
4. Add bounded event and incident queries for the later UI and tools.

### Deliverables

- Ingestion API and JSONL adapter
- Canonical event models and persistence
- Fingerprinting, deduplication, and parse-error behavior
- Versioned detection and correlation rules
- Candidate incident and finding records
- Primary, benign, malformed, duplicate, and out-of-order tests

### Exit gate

- The primary fixture returns exact accepted/rejected/duplicate counts.
- Re-ingesting the same fixture creates zero additional events.
- Raw and normalized events are both retrievable.
- The expected rule version creates one candidate incident with the expected
  evidence event IDs.
- A malformed record does not prevent valid records from being stored.
- Timeline ordering is stable for out-of-order and equal-time events.
- The benign fixture is not labeled a confirmed compromise.

## 9. Phase 3 — Analyst investigation experience

### Objective

Give an analyst an inspectable case rather than a raw alert list. The UI is
part of the evidence contract: it must show what is known, what is inferred,
and what is still missing.

### Work items

#### Incident and evidence views

1. Add the incident list with bounded search and filters.
2. Add the incident detail page with summary, status, severity, confidence,
   and time range.
3. Render the timeline using `event_time`, `ingested_at`, and the documented
   tie-breaker when ingestion order differs.
4. Make every material finding link to one or more event records.
5. Show raw and normalized event views side by side or through a clear toggle.
6. Display parse failures and missing telemetry instead of hiding them.
7. Add loading, empty, partial-data, and error states.
8. Add analyst notes only if they can be stored and audited safely.

#### Entities and graph

1. Create canonical keys for users, hosts, IPs, sessions, and processes.
2. Extract only the entities needed by the primary fixture.
3. Create relationships from observed events and attach evidence links.
4. Mark weak or derived relationships as inferred rather than observed.
5. Build a bounded NetworkX graph for one incident and its time window.
6. Return graph data through the incident API.
7. Render the graph with React Flow and connect node selection to related
   events.
8. Show a small blast-radius summary based on bounded traversal; do not imply
   that reachability proves compromise.

### Deliverables

- Incident list and incident detail screens
- Timeline and evidence panel
- Entity and relationship service
- Evidence-backed graph endpoint and component
- Findings, raw event, empty, loading, and error states
- Graph and timeline tests

### Exit gate

- A new viewer can open the primary incident and follow the complete sequence.
- Every material finding has a working evidence link or explicitly says that
  evidence is missing.
- The graph contains the expected nodes and relationships for the fixture.
- Selecting a graph node reveals related events.
- Observed and inferred relationships are visually distinct.
- The UI never presents a possible path as a confirmed attack.

## 10. Phase 4 — Constrained AI investigation

### Objective

Add an optional investigator that gathers evidence through trusted application
tools and produces a validated report. The AI explains and compares evidence;
it does not create the source of truth.

### Work items

#### Provider and run control

1. Define a provider interface with a deterministic mock implementation.
2. Keep the mock path fully functional without an API key or network call.
3. Add one real provider adapter only after the mock path is complete.
4. Version prompts, tool schemas, and final output schemas.
5. Enforce a timeout, maximum tool-call count, maximum output size, and safe
   failure state.
6. Make runs restartable or clearly mark them failed; do not leave indefinite
   `running` records.

#### Read-only tool registry

Start with three tools and add others only when a tested user flow needs them:

- `get_incident_events(incident_id, time_range, filters)`
- `get_event_details(event_id)`
- `get_related_events(entity_id, time_window)`

Every tool must validate arguments, enforce the tenant and incident boundary,
apply result limits, return structured data, and record a redacted step.

#### Investigation result

The validated final result must contain:

- executive summary;
- incident assessment;
- competing hypotheses;
- observed facts;
- inferences;
- contradicting evidence;
- missing evidence;
- affected entities;
- severity and confidence explanations;
- recommended simulated actions;
- referenced event IDs; and
- limitations.

Each hypothesis is `supported`, `partially_supported`, `unsupported`, or
`inconclusive`. Model-generated confidence is not called a calibrated
probability.

#### Guardrails and tests

1. Delimit event content from system instructions.
2. Treat prompt-injection text as a field value, not a command.
3. Allow only registered read-only tools and validated arguments.
4. Never permit arbitrary SQL, shell commands, URLs, or tool registration.
5. Reject invalid model output without replacing deterministic findings.
6. Let an analyst accept, correct, or reject a model finding.

### Deliverables

- Provider interface and deterministic mock provider
- Three-tool registry and authorization checks
- Investigation orchestrator and run history
- Hypothesis and final-report schemas
- Timeout, failure, and invalid-output handling
- Prompt-injection and evidence-citation tests

### Exit gate

- The mock investigation works offline and cites stored event IDs.
- The real provider is optional and cannot block deterministic behavior.
- A factual claim without evidence is rejected or labeled as a hypothesis.
- Prompt-injection content cannot change tool permissions.
- Model failure leaves ingestion, detection, incident data, and evidence
  available.
- Investigation steps are auditable without logging unnecessary sensitive data.

## 11. Phase 5 — Simulated response and verification

### Objective

Implement the closed-loop safety flow: propose an action, require backend
approval, execute only a simulation, and independently verify the result.

### Work items

#### Response proposal

1. Create an allowlist containing only `revoke_session` for the MVP.
2. Require a target, evidence references, rationale, risk, expected outcome,
   operational impact, preconditions, rollback plan, and verification method.
3. Bind the proposal to an action version and exact target.
4. Keep response permissions separate from investigation permissions.

#### Approval and execution

1. Revalidate actor, action version, target, status, and preconditions on
   approval submission.
2. Reject stale, unauthorized, rejected, or already-used approvals.
3. Require an idempotency key at execution and prevent duplicate execution.
4. Record actor and timestamp for proposal, approval, rejection, execution,
   and result.
5. Execute against `simulated_state` only.
6. Keep successful execution separate from successful verification.

#### Verification

1. Store the expected postcondition before execution.
2. Read the simulated state after execution through a separate verifier.
3. Mark the result `verified`, `verification_failed`, or `inconclusive`.
4. Update the incident based on the verification evidence.
5. Reopen investigation or recommend escalation when suspicious activity
   persists or verification fails.
6. Preserve before-and-after state for the demo.

### Deliverables

- Response-plan and action schemas
- Approval and rejection routes
- Simulated session state and execution adapter
- Independent verifier and verification result model
- Case UI for proposal, approval, execution, and verification
- Authorization, idempotency, stale-action, and failure-path tests

### Exit gate

- An unapproved or rejected action cannot execute.
- A stale action version cannot be approved or executed.
- Replaying an execution request does not duplicate the action.
- Backend checks enforce the approval regardless of frontend behavior.
- A successful execution can be followed by a deliberately failed
  verification, and the case does not become verified or contained.
- A successful verification reads simulated state rather than trusting the
  executor response.
- The MVP cannot affect external production infrastructure.

## 12. Phase 6 — Evaluation and security hardening

### Objective

Prove that the main behavior is repeatable and that common failure or abuse
cases do not bypass evidence, authorization, or safety boundaries.

### Test layers

#### Unit tests

- Event parsing, normalization, timestamp conversion, and fingerprinting.
- Deduplication and ingestion counters.
- Detection windows, rule versions, severity factors, and grouping.
- Entity resolution and bounded graph traversal.
- Timeline ordering and state transitions.
- Evidence citation validation and output-schema validation.
- Response authorization, idempotency, and verification logic.

#### Integration tests

- Ingestion through PostgreSQL persistence.
- Ingestion through detection and incident creation.
- Incident data through timeline and graph endpoints.
- Tool calls against persisted data and tenant boundaries.
- Investigation failure without loss of deterministic findings.
- Approval through simulated execution and independent verification.
- Audit records for all important case and response transitions.

#### Scenario tests

Run the full scenario suite from a clean database:

1. Primary account-compromise sequence.
2. Benign unusual login.
3. Failed-login burst without subsequent success.
4. Duplicate submission.
5. Out-of-order events.
6. Malformed and missing fields.
7. Suspicious events with insufficient evidence.
8. Prompt-injection text in a log field.
9. Approved response.
10. Rejected response.
11. Stale or unauthorized response.
12. Failed response verification.
13. Repeated response request.
14. Model timeout, invalid output, and unavailable provider.

### Security checklist

- Validate every API input and bound every query result.
- Enforce the tenant boundary in repositories, routes, and investigation tools.
- Use parameterized SQL and avoid arbitrary query construction.
- Restrict upload size and accepted formats.
- Avoid secrets and unnecessary personal data in logs and prompts.
- Apply timeouts and rate limits to expensive model and graph operations.
- Never execute model-generated shell commands or SQL.
- Keep response actions allowlisted and server-authorized.
- Audit approvals, attempts, state transitions, and verification results.
- Run dependency, lint, type, and static checks available in the chosen stack.

### Metrics to report

Report measurements against the versioned synthetic fixtures, with their
limitations:

- accepted, rejected, and duplicate ingestion counts;
- duplicate suppression correctness;
- detection precision and recall on labeled scenarios;
- percentage of material findings with evidence links;
- timeline reconstruction correctness;
- graph edge evidence coverage;
- response verification classification correctness;
- investigation latency, timeout, and invalid-output rate; and
- false-positive behavior on benign scenarios.

Do not describe a small synthetic dataset as enterprise-grade performance or a
hand-written confidence category as a calibrated probability.

### Deliverables

- Automated unit, integration, and scenario suite
- Labeled fixtures and expected-output files
- Security test report and known-limitations document
- Evaluation command with a reproducible summary

### Exit gate

- The main scenario passes end to end from a clean reset.
- Benign and ambiguous scenarios are not confirmed compromises.
- Unauthorized, rejected, stale, and repeated response attempts fail safely.
- Prompt injection cannot bypass tool restrictions.
- Verification failures produce the documented follow-up state.
- Results can be reproduced with documented commands.

## 13. Phase 7 — Demo release and handoff

### Objective

Package the implementation as a reliable, repeatable demonstration with a
clear technical narrative and honest limitations.

### Work items

1. Provide one documented startup path and one reset/seed path.
2. Seed a clean database with the primary and comparison scenarios.
3. Make the deterministic path work without an AI provider key.
4. Show a clearly labeled mock/fallback investigation if the provider is
   unavailable.
5. Verify that the demo depends on no live attack or unstable third-party
   service.
6. Add setup, architecture, contracts, API, test, and limitation notes to
   the repository README or linked `docs/` files.
7. Rehearse a three-to-five-minute walkthrough and record recovery steps.
8. Capture a backup recording or screenshots after the live flow is stable.
9. Prepare concise answers about evidence, uncertainty, safety, false
   positives, and how TraceSOC differs from a chatbot.

### Recommended demo narrative

1. Start from a clean state and ingest the synthetic event batch.
2. Show normalization, duplicate handling, and the generated incident.
3. Open the timeline and inspect the raw event behind a finding.
4. Follow the entity graph and bounded blast-radius explanation.
5. Run the mock or provider-backed investigation and compare hypotheses.
6. Review the proposed session revocation and its risk/rollback details.
7. Approve the exact simulated action.
8. Show execution followed by independent verification.
9. Repeat with a failed verification or benign scenario to demonstrate
   uncertainty and safe failure behavior.
10. End on the evidence-backed case summary and audit trail.

### Deliverables

- Resettable demo environment
- Seed and reset scripts
- Updated README and linked project docs
- Architecture diagram and API notes
- Evaluation summary and known limitations
- Presentation outline and backup recording/screenshots

### Exit gate

- The full demo runs repeatedly from a clean state.
- The audience sees evidence, not only AI prose.
- Successful, unsuccessful, and inconclusive outcomes are distinct.
- Setup, reset, test, and limitation commands are documented.
- No real-world system can be modified by any demo workflow.

## 14. Definition of Done

TraceSOC MVP is ready to present only when all boxes are true:

- [ ] A clean checkout starts from documented commands.
- [ ] The database migration succeeds on an empty database.
- [ ] The primary dataset can be ingested repeatedly without duplicate events.
- [ ] Exact ingestion counts and record-level errors are visible.
- [ ] The expected deterministic rule creates the candidate incident.
- [ ] The timeline is correctly ordered and linked to raw evidence.
- [ ] Findings distinguish observed facts, inferences, and unknowns.
- [ ] The graph has evidence-backed relationships and distinguishable inferred
      edges.
- [ ] The offline investigation produces a validated, evidence-cited result.
- [ ] Model failure does not remove deterministic findings.
- [ ] Backend authorization blocks unapproved, stale, rejected, and repeated
      actions.
- [ ] The simulated action can succeed or fail in a controlled way.
- [ ] Verification reads actual simulated state and is separate from execution.
- [ ] Audit records cover investigation and response decisions.
- [ ] Benign, ambiguous, malformed, duplicate, out-of-order, and
      prompt-injection scenarios are tested.
- [ ] The demo can be reset and rerun.
- [ ] Known limitations are documented honestly.
- [ ] No real-world system can be affected by the MVP.

## 15. Team execution and parallel work

Phases 0 and 1 are sequential: the scenario, contracts, IDs, statuses, and
error shapes must be locked first. After Phase 1, work can be parallelized by
interface, not by isolated components.

| Workstream | Scope | Required integration point |
| --- | --- | --- |
| Backend and data | Schemas, migrations, ingestion, cases, audit | API contracts and scenario fixtures |
| Detection and graph | Rules, correlation, entity links, graph data | Expected rule/evidence/graph outputs |
| AI investigation | Provider adapter, tools, schemas, guardrails | Read-only API and evidence IDs |
| Frontend | Timeline, evidence, graph, investigation, response states | API response fixtures and error states |
| Test and demo | Scenario runner, reset flow, evaluation, rehearsal | Clean-database end-to-end command |

Integration rules:

- Every workstream uses the same versioned fixture and contract tests.
- Frontend work is not complete until it handles empty, partial, and failed
  API responses.
- AI work is not complete until the deterministic mock path passes.
- Response work is not complete until direct backend calls without approval
  are rejected.
- Merge a working vertical slice frequently; do not wait for all screens or
  all tools to be polished.

## 16. Priority and defer list

### Must have

1. One reproducible synthetic scenario.
2. Validated, idempotent event ingestion.
3. Deterministic detection and incident grouping.
4. Evidence-linked timeline and raw event inspection.
5. Basic entity graph.
6. Offline constrained investigation with evidence citations.
7. Simulated response with backend approval.
8. Independent post-action verification.
9. Scenario tests and a repeatable demo reset.

### Should have

- One real provider adapter.
- Competing hypotheses and contradictory evidence.
- Benign comparison in the live UI.
- Audit timeline and evaluation summary.
- Bounded blast-radius explanation.

### Defer until the core works

- Multiple vendor adapters and live product integrations.
- Real production containment or endpoint agents.
- Distributed queues, streaming, SSE, and microservices.
- Full multi-tenant administration and SSO.
- Custom ML models and behavioral baselines.
- Eleven-tool or multi-agent orchestration.
- Advanced graph analytics and broad event exploration.
- Enterprise retention, compliance, high availability, and tamper-evidence.
- Decorative UI polish that does not improve evidence comprehension or demo
  reliability.

**Scope rule:** If a feature does not improve investigation quality, evidence
traceability, response safety, or demo reliability, defer it.

## 17. Final implementation sequence

The intended build loop is:

```text
Freeze scenario
  -> Lock contracts
  -> Build deterministic evidence slice
  -> Make evidence inspectable
  -> Add optional constrained investigation
  -> Add simulated response and independent verification
  -> Test abuse and failure paths
  -> Package and rehearse the demo
```

The differentiator must remain visible throughout implementation: TraceSOC
does not ask an analyst to trust an AI-generated incident story. It provides a
traceable investigation that the analyst can inspect, challenge, approve, and
verify.
