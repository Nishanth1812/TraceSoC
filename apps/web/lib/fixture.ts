import type { IncidentData, Relationship } from "@/lib/types";

const eventTime = (minutes: number) => `2026-10-15T09:0${minutes}:00Z`;

const relationships: Relationship[] = [
  { from: "user:alice", to: "ip:203.0.113.50", label: "authenticated from", status: "observed", evidence: ["AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004"] },
  { from: "user:alice", to: "host:ws-07", label: "logged into", status: "observed", evidence: ["AUTH-004", "SESSION-001"] },
  { from: "user:alice", to: "session:session-S104", label: "owns session", status: "observed", evidence: ["SESSION-001"] },
  { from: "session:session-S104", to: "host:ws-07", label: "runs on", status: "observed", evidence: ["SESSION-001", "PROC-001", "NET-001"] },
  { from: "session:session-S104", to: "process:powershell.exe", label: "started", status: "observed", evidence: ["PROC-001"] },
  { from: "session:session-S104", to: "ip:198.51.100.24", label: "connected to", status: "inferred", evidence: ["NET-001"] },
];

export const DEMO_INCIDENT: IncidentData = {
  incident: {
    incident_id: "INC-PRIMARY-001",
    tenant_id: "demo",
    title: "Suspicious account session",
    status: "investigating",
    severity: "high",
    confidence: "high",
    correlation_key: "user:alice / host:ws-07 / source:203.0.113.50",
    observed_start: "2026-10-15T09:00:00Z",
    observed_end: "2026-10-15T09:04:00Z",
    created_at: "2026-10-15T09:04:12Z",
    updated_at: "2026-10-15T09:04:12Z",
  },
  events: [
    {
      event_id: "evt-auth-001", source_event_id: "AUTH-001", source_type: "authentication", event_type: "login_failure", event_time: eventTime(0), ingested_at: "2026-10-15T09:05:01Z", outcome: "failure", severity: "medium", username: "alice", source_ip: "203.0.113.50", summary: "Failed login for alice from the same source address.", raw_event: { source_event_id: "AUTH-001", event_type: "login_failure", username: "alice", source_ip: "203.0.113.50", outcome: "failure" }, normalized_fields: { principal: "alice", source: "203.0.113.50", result: "failure" },
    },
    {
      event_id: "evt-auth-002", source_event_id: "AUTH-002", source_type: "authentication", event_type: "login_failure", event_time: eventTime(0).replace(":00Z", ":10Z"), ingested_at: "2026-10-15T09:05:01Z", outcome: "failure", severity: "medium", username: "alice", source_ip: "203.0.113.50", summary: "Second failed login arrives ten seconds later.", raw_event: { source_event_id: "AUTH-002", event_type: "login_failure", username: "alice", source_ip: "203.0.113.50", outcome: "failure" }, normalized_fields: { principal: "alice", source: "203.0.113.50", result: "failure" },
    },
    {
      event_id: "evt-auth-003", source_event_id: "AUTH-003", source_type: "authentication", event_type: "login_failure", event_time: eventTime(0).replace(":00Z", ":20Z"), ingested_at: "2026-10-15T09:05:01Z", outcome: "failure", severity: "medium", username: "alice", source_ip: "203.0.113.50", summary: "Third failed login completes the authentication burst.", raw_event: { source_event_id: "AUTH-003", event_type: "login_failure", username: "alice", source_ip: "203.0.113.50", outcome: "failure" }, normalized_fields: { principal: "alice", source: "203.0.113.50", result: "failure" },
    },
    {
      event_id: "evt-auth-004", source_event_id: "AUTH-004", source_type: "authentication", event_type: "login_success", event_time: eventTime(1), ingested_at: "2026-10-15T09:05:01Z", outcome: "success", severity: "high", username: "alice", host_id: "ws-07", source_ip: "203.0.113.50", summary: "Successful login follows the burst on workstation ws-07.", raw_event: { source_event_id: "AUTH-004", event_type: "login_success", username: "alice", host_id: "ws-07", source_ip: "203.0.113.50", outcome: "success" }, normalized_fields: { principal: "alice", source: "203.0.113.50", host: "ws-07", result: "success" },
    },
    {
      event_id: "evt-session-001", source_event_id: "SESSION-001", source_type: "endpoint", event_type: "privileged_session_started", event_time: eventTime(2), ingested_at: "2026-10-15T09:05:01Z", outcome: "success", severity: "high", username: "alice", host_id: "ws-07", session_id: "session-S104", summary: "Privileged session S104 starts on ws-07.", raw_event: { source_event_id: "SESSION-001", event_type: "privileged_session_started", username: "alice", host_id: "ws-07", session_id: "session-S104", outcome: "success" }, normalized_fields: { principal: "alice", host: "ws-07", session: "session-S104", privilege: "elevated" },
    },
    {
      event_id: "evt-proc-001", source_event_id: "PROC-001", source_type: "endpoint", event_type: "sensitive_process_started", event_time: eventTime(3), ingested_at: "2026-10-15T09:05:01Z", outcome: "success", severity: "high", username: "alice", host_id: "ws-07", session_id: "session-S104", process_name: "powershell.exe", summary: "PowerShell starts inside the privileged session.", raw_event: { source_event_id: "PROC-001", event_type: "sensitive_process_started", username: "alice", host_id: "ws-07", session_id: "session-S104", process_name: "powershell.exe", outcome: "success" }, normalized_fields: { host: "ws-07", session: "session-S104", process: "powershell.exe", sensitivity: "high" },
    },
    {
      event_id: "evt-net-001", source_event_id: "NET-001", source_type: "network", event_type: "unusual_outbound_connection", event_time: eventTime(4), ingested_at: "2026-10-15T09:05:01Z", outcome: "success", severity: "high", username: "alice", host_id: "ws-07", session_id: "session-S104", destination_ip: "198.51.100.24", summary: "Unusual outbound connection leaves ws-07.", raw_event: { source_event_id: "NET-001", event_type: "unusual_outbound_connection", username: "alice", host_id: "ws-07", session_id: "session-S104", destination_ip: "198.51.100.24", outcome: "success" }, normalized_fields: { host: "ws-07", session: "session-S104", destination: "198.51.100.24", network: "unusual" },
    },
  ],
  findings: [
    { finding_id: "finding-auth-burst", status: "inferred", title: "Authentication burst", description: "Three failed logins from one source preceded the successful session.", rule_id: "AUTH-BURST-001", rule_version: "1.0", evidence: ["AUTH-001", "AUTH-002", "AUTH-003"], evidence_event_ids: ["evt-auth-001", "evt-auth-002", "evt-auth-003"], severity_factors: ["3 failures in 20 seconds", "same principal and source"] },
    { finding_id: "finding-success", status: "observed", title: "Success after burst", description: "A successful login for alice followed the failed authentication sequence.", rule_id: "AUTH-SUCCESS-AFTER-BURST-001", rule_version: "1.0", evidence: ["AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004"], evidence_event_ids: ["evt-auth-001", "evt-auth-002", "evt-auth-003", "evt-auth-004"], severity_factors: ["same source address", "one-minute sequence"] },
    { finding_id: "finding-follow-on", status: "inferred", title: "Privileged follow-on activity", description: "A privileged session, sensitive process, and unusual outbound connection share the same host and session.", rule_id: "PRIVILEGED-FOLLOW-ON-001", rule_version: "1.0", evidence: ["AUTH-004", "SESSION-001", "PROC-001", "NET-001"], evidence_event_ids: ["evt-auth-004", "evt-session-001", "evt-proc-001", "evt-net-001"], severity_factors: ["privileged session", "sensitive process", "unusual egress"] },
  ],
  entities: [
    { entity_id: "user:alice", entity_type: "user", display_value: "alice", canonical_key: "user:alice" },
    { entity_id: "ip:203.0.113.50", entity_type: "ip", display_value: "203.0.113.50", canonical_key: "ip:203.0.113.50" },
    { entity_id: "host:ws-07", entity_type: "host", display_value: "ws-07", canonical_key: "host:ws-07" },
    { entity_id: "session:session-S104", entity_type: "session", display_value: "session-S104", canonical_key: "session:session-S104" },
    { entity_id: "process:powershell.exe", entity_type: "process", display_value: "powershell.exe", canonical_key: "process:powershell.exe" },
    { entity_id: "ip:198.51.100.24", entity_type: "ip", display_value: "198.51.100.24", canonical_key: "ip:198.51.100.24" },
  ],
  relationships,
  report: {
    executive_summary: "Stored evidence supports suspicious account activity; the deterministic findings remain the source of truth.",
    incident_assessment: "The sequence warrants containment review, not an assertion of confirmed compromise.",
    observed_facts: [
      { claim: "Three failed logins for alice came from 203.0.113.50 before a successful login.", evidence: ["AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004"] },
      { claim: "A privileged session and PowerShell process were observed on ws-07.", evidence: ["SESSION-001", "PROC-001"] },
      { claim: "The session made an unusual outbound connection to 198.51.100.24.", evidence: ["NET-001"] },
    ],
    inferences: [{ claim: "The activity warrants containment review, but telemetry does not establish user intent.", evidence: ["AUTH-004", "SESSION-001", "PROC-001", "NET-001"] }],
    competing_hypotheses: [
      { name: "Account compromise", assessment: "supported", explanation: "The ordered evidence contains a failed-login burst and subsequent privileged activity." },
      { name: "Benign user error", assessment: "inconclusive", explanation: "The available telemetry does not establish whether the activity was authorized." },
    ],
    missing_evidence: ["No independent identity confirmation or endpoint memory evidence is available in this fixture."],
    limitations: ["The provider is an offline deterministic mock and cannot establish intent.", "Only read-only allowlisted tools were available."],
  },
  response: { action_type: "revoke_session", target: "session-S104", expected_postcondition: { active: false } },
};

export const DEMO_INCIDENT_LIST = [DEMO_INCIDENT.incident];
