export type DataMode = "demo" | "api";
export type EvidenceStatus =
  | "observed"
  | "inferred"
  | "unconfirmed"
  | "disproven";
export type InvestigationStatus = "idle" | "running" | "completed" | "failed";
export type ResponseState =
  | "proposed"
  | "awaiting_approval"
  | "approved"
  | "executing"
  | "succeeded"
  | "verified"
  | "verification_failed"
  | "inconclusive";

export type EventRecord = {
  event_id: string;
  source_event_id: string;
  source_type: string;
  event_type: string;
  event_time: string;
  ingested_at: string;
  outcome: string;
  severity: string;
  username?: string;
  host_id?: string;
  source_ip?: string;
  destination_ip?: string;
  session_id?: string;
  process_name?: string;
  summary: string;
  raw_event: Record<string, unknown>;
  normalized_fields: Record<string, unknown>;
};

export type Finding = {
  finding_id: string;
  status: EvidenceStatus;
  title: string;
  description: string;
  rule_id: string;
  rule_version: string;
  evidence: string[];
  evidence_event_ids: string[];
  severity_factors: string[];
};

export type Entity = {
  entity_id: string;
  entity_type: "user" | "host" | "ip" | "session" | "process";
  display_value: string;
  canonical_key: string;
};

export type Relationship = {
  from: string;
  to: string;
  label: string;
  status: EvidenceStatus;
  evidence: string[];
};

export type Incident = {
  incident_id: string;
  tenant_id: string;
  title: string;
  status: string;
  severity: string;
  confidence: string;
  correlation_key: string;
  observed_start: string;
  observed_end: string;
  created_at: string;
  updated_at: string;
};

export type Report = {
  executive_summary: string;
  incident_assessment: string;
  observed_facts: Array<{ claim: string; evidence: string[] }>;
  inferences: Array<{ claim: string; evidence: string[] }>;
  competing_hypotheses: Array<{
    name: string;
    assessment: string;
    explanation: string;
  }>;
  missing_evidence: string[];
  limitations: string[];
};

export type InvestigationRun = {
  run_id: string;
  incident_id: string;
  status: "running" | "completed" | "failed";
  result?: {
    executive_summary: string;
    incident_assessment: string;
    observed_facts: Array<{ claim: string; evidence_event_ids: string[] }>;
    inferences: Array<{ claim: string; evidence_event_ids: string[] }>;
    competing_hypotheses: Array<{
      name: string;
      assessment: string;
      explanation: string;
      evidence_event_ids: string[];
    }>;
    missing_evidence: string[];
    limitations: string[];
  };
  error?: { code?: string; message?: string } | null;
};

export type ResponseAction = {
  action_id: string;
  incident_id: string;
  action_version: number;
  target: string;
  status: string;
  expected_postcondition: { active: boolean };
  approval?: { actor_id: string; approved_at: string } | null;
  execution?: {
    executed_at: string;
    before_state: Record<string, unknown>;
    after_state: Record<string, unknown>;
  } | null;
  verification?: {
    status: "verified" | "verification_failed" | "inconclusive";
    observed_state: Record<string, unknown> | null;
  } | null;
};

export type Verification = {
  action_id: string;
  incident_id: string;
  status: "verified" | "verification_failed" | "inconclusive";
  observed_state: Record<string, unknown> | null;
};

export type IncidentData = {
  incident: Incident;
  events: EventRecord[];
  findings: Finding[];
  entities: Entity[];
  relationships: Relationship[];
  report: Report;
  response: {
    action_type: "revoke_session";
    target: string;
    expected_postcondition: { active: boolean };
  };
};
