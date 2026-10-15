import { DEMO_INCIDENT, DEMO_INCIDENT_LIST } from "@/lib/fixture";
import type {
  DataMode,
  Incident,
  IncidentData,
  InvestigationRun,
  ResponseAction,
  Verification,
} from "@/lib/types";

export const configuredApiBase =
  process.env.NEXT_PUBLIC_TRACESOC_API_BASE_URL?.trim().replace(/\/$/, "") ??
  "";

export function getDataMode(): DataMode {
  return configuredApiBase ? "api" : "demo";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${configuredApiBase}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...init?.headers,
    },
    cache: "no-store",
  });
  if (!response.ok) {
    let message = `Request failed with ${response.status}`;
    try {
      const payload = (await response.json()) as { message?: string };
      message = payload.message ?? message;
    } catch {
      // Keep the HTTP status when the API did not return the documented error shape.
    }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

function apiOnly() {
  if (!configuredApiBase)
    throw new Error("The live API is not configured; demo mode is active.");
}

type ApiIncidentDetail = {
  incident: Incident;
  events: IncidentData["events"];
  findings: IncidentData["findings"];
  entities: IncidentData["entities"];
  graph?: {
    edges: Array<{
      from: string;
      to: string;
      relationship_type: string;
      status: "observed" | "inferred" | "unconfirmed" | "disproven";
      evidence_event_ids: string[];
    }>;
  };
};

export async function fetchIncidentData(
  incidentId: string,
): Promise<IncidentData> {
  if (!configuredApiBase) return DEMO_INCIDENT;
  const [detail, graph] = await Promise.all([
    request<ApiIncidentDetail>(
      `/api/v1/incidents/${encodeURIComponent(incidentId)}`,
    ),
    request<ApiIncidentDetail["graph"]>(
      `/api/v1/incidents/${encodeURIComponent(incidentId)}/graph`,
    ),
  ]);
  detail.graph = graph ?? undefined;
  const session =
    detail.entities.find((entity) => entity.entity_type === "session")
      ?.display_value ??
    detail.events.find((event) => event.session_id)?.session_id ??
    "session not identified";
  return {
    ...DEMO_INCIDENT,
    incident: detail.incident,
    events: detail.events.map((event) => ({
      ...event,
      summary: event.summary ?? humanizeEvent(event.event_type),
      raw_event: event.raw_event ?? {},
      normalized_fields: event.normalized_fields ?? {},
    })),
    findings: detail.findings,
    entities: detail.entities,
    relationships:
      detail.graph?.edges?.map((edge) => ({
        from: edge.from,
        to: edge.to,
        label: edge.relationship_type.replaceAll("_", " "),
        status: edge.status,
        evidence: edge.evidence_event_ids,
      })) ?? deriveRelationships(detail),
    report: buildApiReport(detail),
    response: {
      action_type: "revoke_session",
      target: session,
      expected_postcondition: { active: false },
    },
  };
}

export async function fetchIncidentList(): Promise<Incident[]> {
  if (!configuredApiBase) return DEMO_INCIDENT_LIST;
  const response = await request<{ items: Incident[] }>(
    "/api/v1/incidents?limit=100",
  );
  return response.items;
}

export async function startInvestigation(
  incidentId: string,
): Promise<InvestigationRun> {
  apiOnly();
  return request<InvestigationRun>(
    `/api/v1/incidents/${encodeURIComponent(incidentId)}/investigations`,
    {
      method: "POST",
      body: JSON.stringify({ provider: "mock" }),
    },
  );
}

export async function createResponsePlan(
  data: IncidentData,
): Promise<ResponseAction> {
  apiOnly();
  const evidence = data.findings
    .flatMap((finding) => finding.evidence_event_ids)
    .slice(0, 20);
  return request<ResponseAction>(
    `/api/v1/incidents/${encodeURIComponent(data.incident.incident_id)}/response-plans`,
    {
      method: "POST",
      body: JSON.stringify({
        action_type: "revoke_session",
        target_session_id: data.response.target,
        evidence_event_ids: evidence,
        rationale:
          "Revoke the simulated session while preserving the evidence trail.",
        risk: "Low: one simulated session is affected.",
        expected_outcome: "The session is no longer active.",
        operational_impact:
          "End one session for the affected user in the simulation.",
        preconditions: ["The target session is active."],
        rollback_plan: "Reset the local scenario state.",
        verification_method: "Read simulated state after execution.",
      }),
    },
  );
}

export async function approveResponseAction(
  action: ResponseAction,
): Promise<ResponseAction> {
  apiOnly();
  return request<ResponseAction>(
    `/api/v1/response-actions/${encodeURIComponent(action.action_id)}/approve`,
    {
      method: "POST",
      body: JSON.stringify({ action_version: action.action_version }),
    },
  );
}

export async function executeResponseAction(
  action: ResponseAction,
): Promise<ResponseAction> {
  apiOnly();
  return request<ResponseAction>(
    `/api/v1/response-actions/${encodeURIComponent(action.action_id)}/execute`,
    {
      method: "POST",
      headers: {
        "Idempotency-Key": `web-${action.action_id}-${action.action_version}`,
      },
      body: JSON.stringify({ action_version: action.action_version }),
    },
  );
}

export async function verifyResponseAction(
  action: ResponseAction,
): Promise<Verification> {
  apiOnly();
  return request<Verification>(
    `/api/v1/response-actions/${encodeURIComponent(action.action_id)}/verification`,
  );
}

function humanizeEvent(eventType: string) {
  return eventType
    .replaceAll("_", " ")
    .replace(/^./, (letter) => letter.toUpperCase());
}

function buildApiReport(detail: ApiIncidentDetail): IncidentData["report"] {
  return {
    executive_summary: `The live API returned ${detail.events.length} stored evidence records for this incident. Deterministic findings remain the source of truth.`,
    incident_assessment: `${detail.incident.title} warrants analyst review; the available telemetry does not by itself establish intent.`,
    observed_facts: detail.findings.slice(0, 3).map((finding) => ({
      claim: `${finding.title}: ${finding.description}`,
      evidence: finding.evidence ?? finding.evidence_event_ids,
    })),
    inferences: [
      {
        claim:
          "The incident should be assessed within its bounded evidence and entity relationships.",
        evidence: detail.events.map((event) => event.source_event_id),
      },
    ],
    competing_hypotheses: [
      {
        name: "Malicious activity",
        assessment: "inconclusive",
        explanation:
          "The API evidence is available for review, but intent requires analyst judgment.",
      },
      {
        name: "Benign activity",
        assessment: "inconclusive",
        explanation:
          "The current incident contract does not independently confirm authorization.",
      },
    ],
    missing_evidence: [
      "The live incident contract does not include independent identity confirmation or endpoint memory evidence.",
    ],
    limitations: [
      "This report is a frontend evidence summary until an investigation run endpoint is connected.",
      "No response action is sent by this UI yet; controls are simulation states.",
    ],
  };
}

export function reportFromInvestigation(
  run: InvestigationRun,
): IncidentData["report"] {
  if (!run.result) {
    throw new Error(
      run.error?.message ?? "The investigation did not return a report.",
    );
  }
  return {
    executive_summary: run.result.executive_summary,
    incident_assessment: run.result.incident_assessment,
    observed_facts: run.result.observed_facts.map((item) => ({
      claim: item.claim,
      evidence: item.evidence_event_ids,
    })),
    inferences: run.result.inferences.map((item) => ({
      claim: item.claim,
      evidence: item.evidence_event_ids,
    })),
    competing_hypotheses: run.result.competing_hypotheses.map((item) => ({
      name: item.name,
      assessment: item.assessment,
      explanation: item.explanation,
    })),
    missing_evidence: run.result.missing_evidence,
    limitations: run.result.limitations,
  };
}

function deriveRelationships(detail: ApiIncidentDetail) {
  const byType = (type: string) =>
    detail.entities.find((entity) => entity.entity_type === type)?.entity_id;
  const user = byType("user");
  const host = byType("host");
  const session = byType("session");
  const process = byType("process");
  const ips = detail.entities.filter((entity) => entity.entity_type === "ip");
  const sourceIp = ips.find((entity) =>
    detail.events.some((event) => event.source_ip === entity.display_value),
  )?.entity_id;
  const destinationIp = ips.find((entity) =>
    detail.events.some(
      (event) => event.destination_ip === entity.display_value,
    ),
  )?.entity_id;
  return [
    user &&
      sourceIp && {
        from: user,
        to: sourceIp,
        label: "authenticated from",
        status: "observed" as const,
        evidence: detail.events
          .filter((event) => event.source_ip)
          .map((event) => event.source_event_id),
      },
    user &&
      host && {
        from: user,
        to: host,
        label: "logged into",
        status: "observed" as const,
        evidence: detail.events
          .filter((event) => event.host_id)
          .map((event) => event.source_event_id),
      },
    user &&
      session && {
        from: user,
        to: session,
        label: "owns session",
        status: "observed" as const,
        evidence: detail.events
          .filter((event) => event.session_id)
          .map((event) => event.source_event_id),
      },
    session &&
      host && {
        from: session,
        to: host,
        label: "runs on",
        status: "observed" as const,
        evidence: detail.events
          .filter((event) => event.session_id && event.host_id)
          .map((event) => event.source_event_id),
      },
    session &&
      process && {
        from: session,
        to: process,
        label: "started",
        status: "observed" as const,
        evidence: detail.events
          .filter((event) => event.process_name)
          .map((event) => event.source_event_id),
      },
    session &&
      destinationIp && {
        from: session,
        to: destinationIp,
        label: "connected to",
        status: "inferred" as const,
        evidence: detail.events
          .filter((event) => event.destination_ip)
          .map((event) => event.source_event_id),
      },
  ].filter(Boolean) as IncidentData["relationships"];
}
