"use client";

import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  Globe2,
  Loader2,
  LockKeyhole,
  Monitor,
  Moon,
  Play,
  Radar,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Terminal,
  UserRound,
  WifiOff,
  XCircle,
} from "lucide-react";
import {
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type ReactNode,
} from "react";

import {
  approveResponseAction,
  configuredApiBase,
  createResponsePlan,
  executeResponseAction,
  fetchIncidentData,
  fetchIncidentList,
  getDataMode,
  reportFromInvestigation,
  startInvestigation,
  verifyResponseAction,
} from "@/lib/api";
import { DEMO_INCIDENT, DEMO_INCIDENT_LIST } from "@/lib/fixture";
import type {
  DataMode,
  Entity,
  EventRecord,
  Incident,
  IncidentData,
  InvestigationStatus,
  ResponseAction,
  ResponseState,
} from "@/lib/types";

type LoadState = "loading" | "ready" | "empty" | "error";
type EvidenceView = "normalized" | "raw";
type PanelTab = "evidence" | "entities" | "report" | "response";
type Tone = "neutral" | "amber" | "blue" | "green" | "red";

const INCIDENT_ID = "INC-PRIMARY-001";

const iconForEntity: Record<Entity["entity_type"], typeof UserRound> = {
  user: UserRound,
  host: Monitor,
  ip: Globe2,
  session: ShieldCheck,
  process: Terminal,
};

const formatter = (options: Intl.DateTimeFormatOptions) =>
  new Intl.DateTimeFormat("en-GB", { ...options, timeZone: "UTC" });
const timeFormat = formatter({
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const dateFormat = formatter({ day: "2-digit", month: "short", year: "numeric" });

const formatTime = (value: string) => timeFormat.format(new Date(value));
const formatDate = (value: string) => dateFormat.format(new Date(value));

function humanize(value: string) {
  const text = value.replaceAll("_", " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function matchesSource(event: EventRecord, sourceId: string) {
  return event.source_event_id === sourceId || event.event_id === sourceId;
}

function seconds(from: string, to: string) {
  return Math.max(0, Math.round((Date.parse(to) - Date.parse(from)) / 1000));
}

function duration(total: number) {
  return total >= 60
    ? `${Math.floor(total / 60)} min${total % 60 ? ` ${total % 60} s` : ""}`
    : `${total} s`;
}

function ThemeToggle() {
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);
  useEffect(() => {
    const read = () =>
      setTheme(document.documentElement.dataset.theme === "dark" ? "dark" : "light");
    read();
    // Follow the OS only while the analyst has not picked a theme themselves.
    const media = matchMedia("(prefers-color-scheme: dark)");
    const onSystem = () => {
      if (!localStorage.getItem("tracesoc-theme")) {
        document.documentElement.dataset.theme = media.matches ? "dark" : "light";
        read();
      }
    };
    media.addEventListener("change", onSystem);
    return () => media.removeEventListener("change", onSystem);
  }, []);
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      className="icon-button"
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      onClick={() => {
        document.documentElement.dataset.theme = next;
        localStorage.setItem("tracesoc-theme", next);
        setTheme(next);
      }}
    >
      {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}

function Tag({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`tag tag--${tone}`}>{children}</span>;
}

/* ------------------------------------------------------------------ shell */

function AppShell({
  children,
  mode,
  switcher,
  onModeChange,
}: {
  children: ReactNode;
  mode: DataMode;
  switcher?: ReactNode;
  onModeChange: () => void;
}) {
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Radar size={20} strokeWidth={2.4} aria-hidden="true" />
          <strong>TraceSOC</strong>
        </div>
        {switcher}
        <div className="topbar__end">
          <span className="topbar__zone">Times in UTC</span>
          <button
            className="source-chip"
            onClick={onModeChange}
            title={
              mode === "demo"
                ? "Offline fixture. Set an API base URL to connect real data."
                : `Live API at ${configuredApiBase}. Switch to the offline fixture.`
            }
          >
            <span className={`dot dot--${mode === "demo" ? "amber" : "green"}`} />
            {mode === "demo" ? "Offline fixture" : "Live API"}
          </button>
          <ThemeToggle />
          <button
            className="icon-button"
            aria-label="Reload workspace"
            onClick={() => window.location.reload()}
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </header>
      {children}
    </div>
  );
}

function CaseSwitcher({
  incidents,
  selectedId,
  onSelect,
}: {
  incidents: Incident[];
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  const [search, setSearch] = useState("");
  const ref = useRef<HTMLDetailsElement>(null);
  const current = incidents.find((incident) => incident.incident_id === selectedId);
  const filtered = incidents.filter((incident) =>
    `${incident.incident_id} ${incident.title} ${incident.status}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  return (
    <details className="switcher" ref={ref}>
      <summary>
        <span className="switcher__id">{current?.incident_id ?? "Cases"}</span>
        <span className="switcher__title">{current?.title ?? "Choose a case"}</span>
        <span className="switcher__count">
          {incidents.length} {incidents.length === 1 ? "case" : "cases"}
        </span>
        <ChevronDown size={15} aria-hidden="true" />
      </summary>
      <div className="switcher__menu">
        <label className="search">
          <Search size={15} aria-hidden="true" />
          <input
            aria-label="Search cases"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search by ID, title or status"
          />
        </label>
        <ul>
          {filtered.map((incident) => (
            <li key={incident.incident_id}>
              <button
                aria-current={incident.incident_id === selectedId}
                onClick={() => {
                  onSelect(incident.incident_id);
                  ref.current?.removeAttribute("open");
                }}
              >
                <span className="switcher__id">{incident.incident_id}</span>
                <span>{incident.title}</span>
                <small>
                  {humanize(incident.status)} · {humanize(incident.severity)} severity ·
                  updated {formatTime(incident.updated_at)}
                </small>
              </button>
            </li>
          ))}
        </ul>
        {!filtered.length && <p className="menu-empty">No case matches that search.</p>}
      </div>
    </details>
  );
}

function ErrorBanner({ error, onDemo }: { error: string; onDemo: () => void }) {
  return (
    <div className="banner" role="alert">
      <XCircle size={17} aria-hidden="true" />
      <div>
        <strong>Live incident data is unavailable</strong>
        <span>{error}</span>
      </div>
      <button className="button button--quiet" onClick={onDemo}>
        Open offline fixture
      </button>
    </div>
  );
}

function LoadingScreen() {
  return (
    <main className="page" aria-busy="true">
      <div className="skeleton skeleton--title" />
      <div className="skeleton skeleton--line" />
      <div className="skeleton skeleton--block" />
    </main>
  );
}

function Notice({
  icon,
  title,
  children,
  actions,
}: {
  icon: ReactNode;
  title: string;
  children: ReactNode;
  actions: ReactNode;
}) {
  return (
    <main className="page">
      <div className="notice">
        <div className="notice__icon">{icon}</div>
        <h1>{title}</h1>
        <p>{children}</p>
        <div className="notice__actions">{actions}</div>
      </div>
    </main>
  );
}

/* -------------------------------------------------------------- case head */

function CaseHead({
  data,
  onReview,
}: {
  data: IncidentData;
  onReview: () => void;
}) {
  const { incident } = data;
  const span = seconds(incident.observed_start, incident.observed_end);
  return (
    <section className="case-head">
      <div className="case-head__main">
        <span className="mono case-head__id">{incident.incident_id}</span>
        <h1>{incident.title}</h1>
        <p>
          {data.events.length} events between {formatTime(incident.observed_start)} and{" "}
          {formatTime(incident.observed_end)} UTC ({duration(span)}) triggered{" "}
          {data.findings.length} detection {data.findings.length === 1 ? "signal" : "signals"}{" "}
          across {data.entities.length} entities.
        </p>
        <div className="case-head__tags">
          <Tag tone="amber">{humanize(incident.status)}</Tag>
          <Tag tone="red">{humanize(incident.severity)} severity</Tag>
          <Tag>{humanize(incident.confidence)} confidence</Tag>
          <Tag>{incident.tenant_id} tenant</Tag>
        </div>
      </div>
      <button className="button button--primary" onClick={onReview}>
        <ShieldAlert size={16} aria-hidden="true" /> Review response
      </button>
    </section>
  );
}

/* ---------------------------------------------------------------- signals */

function Signals({
  data,
  focusId,
  onFocus,
  onEvidence,
}: {
  data: IncidentData;
  focusId: string | null;
  onFocus: (id: string | null) => void;
  onEvidence: (sourceId: string) => void;
}) {
  return (
    <section className="block" aria-labelledby="signals-title">
      <div className="block__head">
        <h2 id="signals-title">Why this case is open</h2>
        <p>
          Detection rules raised these signals. Choose one to highlight the events
          behind it; the evidence stays the source of truth.
        </p>
      </div>
      <ul className="signals">
        {data.findings.map((finding) => {
          const active = focusId === finding.finding_id;
          return (
            <li
              key={finding.finding_id}
              className={`signal ${active ? "is-active" : ""}`}
            >
              <button
                className="signal__head"
                aria-pressed={active}
                onClick={() => onFocus(active ? null : finding.finding_id)}
              >
                <span className="signal__title">{finding.title}</span>
                <Tag tone={finding.status === "observed" ? "green" : "amber"}>
                  {humanize(finding.status)}
                </Tag>
              </button>
              <p>{finding.description}</p>
              <div className="signal__foot">
                <span className="mono signal__rule">{finding.rule_id}</span>
                <span className="chips">
                  {finding.evidence.map((id) => (
                    <button className="chip" key={id} onClick={() => onEvidence(id)}>
                      {id}
                    </button>
                  ))}
                </span>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/* --------------------------------------------------------------- timeline */

function Timeline({
  data,
  selectedId,
  citedIds,
  onSelect,
}: {
  data: IncidentData;
  selectedId: string;
  citedIds: Set<string> | null;
  onSelect: (id: string) => void;
}) {
  const start = data.events[0]?.event_time;
  return (
    <section className="block" aria-labelledby="timeline-title">
      <div className="block__head">
        <h2 id="timeline-title">What happened</h2>
        <p>
          Events in the order they occurred; spacing grows with the time between them.
        </p>
      </div>
      <ol className="timeline">
        {data.events.map((event, index) => {
          const previous = data.events[index - 1];
          const gap = previous
            ? Math.min(40, Math.sqrt(seconds(previous.event_time, event.event_time)) * 3)
            : 0;
          const cited = citedIds
            ? [...citedIds].some((id) => matchesSource(event, id))
            : null;
          const failed = event.outcome === "failure";
          return (
            <li
              key={event.event_id}
              style={{ "--gap": `${gap}px` } as CSSProperties}
              className={cited === null ? "" : cited ? "is-cited" : "is-dim"}
            >
              <button
                className={`beat ${selectedId === event.event_id ? "is-selected" : ""}`}
                aria-current={selectedId === event.event_id}
                onClick={() => onSelect(event.event_id)}
              >
                <span className="beat__time">
                  <span className="mono">{formatTime(event.event_time)}</span>
                  <small>+{seconds(start, event.event_time)} s</small>
                </span>
                <span
                  className={`beat__node ${failed ? "beat__node--failure" : ""}`}
                  aria-hidden="true"
                />
                <span className="beat__body">
                  <strong>{event.summary}</strong>
                  <span className="beat__meta">
                    {humanize(event.event_type) === event.summary
                      ? humanize(event.source_type)
                      : `${humanize(event.event_type)} · ${event.source_type}`}
                    {failed && <Tag tone="red">Failed</Tag>}
                  </span>
                  <span className="beat__refs">
                    {event.username && (
                      <span>
                        <UserRound size={13} aria-hidden="true" /> {event.username}
                      </span>
                    )}
                    {event.host_id && (
                      <span>
                        <Monitor size={13} aria-hidden="true" /> {event.host_id}
                      </span>
                    )}
                    {event.session_id && (
                      <span>
                        <LockKeyhole size={13} aria-hidden="true" /> {event.session_id}
                      </span>
                    )}
                  </span>
                </span>
                <span className="mono beat__id">{event.source_event_id}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

/* ------------------------------------------------------------ side panels */

function EvidencePanel({ event }: { event?: EventRecord }) {
  const [view, setView] = useState<EvidenceView>("normalized");
  useEffect(() => setView("normalized"), [event?.event_id]);
  if (!event)
    return <p className="empty">Select an event in the timeline to read its source record.</p>;
  const payload = view === "normalized" ? event.normalized_fields : event.raw_event;
  return (
    <div className="stack">
      <div>
        <div className="row row--between">
          <h3 className="mono">{event.source_event_id}</h3>
          <Tag tone={event.outcome === "failure" ? "red" : "green"}>
            {humanize(event.outcome)}
          </Tag>
        </div>
        <p className="muted">{event.summary}</p>
      </div>
      <dl className="facts">
        <div>
          <dt>Event time</dt>
          <dd className="mono">
            {formatDate(event.event_time)} {formatTime(event.event_time)}
          </dd>
        </div>
        <div>
          <dt>Ingested</dt>
          <dd className="mono">{formatTime(event.ingested_at)}</dd>
        </div>
        <div className="facts__wide">
          <dt>Record ID</dt>
          <dd className="mono">{event.event_id}</dd>
        </div>
      </dl>
      <div className="segmented" role="group" aria-label="Record view">
        <button aria-pressed={view === "normalized"} onClick={() => setView("normalized")}>
          Normalized
        </button>
        <button aria-pressed={view === "raw"} onClick={() => setView("raw")}>
          Raw source
        </button>
      </div>
      <pre className="code" tabIndex={0} aria-label="Event payload">
        {JSON.stringify(payload, null, 2)}
      </pre>
    </div>
  );
}

const NODE_POSITIONS: Record<string, { x: number; y: number }> = {
  "user:alice": { x: 16, y: 28 },
  "ip:203.0.113.50": { x: 16, y: 78 },
  "host:ws-07": { x: 50, y: 14 },
  "session:session-S104": { x: 50, y: 62 },
  "process:powershell.exe": { x: 84, y: 34 },
  "ip:198.51.100.24": { x: 84, y: 82 },
};
const GRAPH_W = 400;
const GRAPH_H = 300;

function EntitiesPanel({
  data,
  selectedEntityId,
  onSelect,
  onEvidence,
}: {
  data: IncidentData;
  selectedEntityId: string;
  onSelect: (id: string) => void;
  onEvidence: (sourceId: string) => void;
}) {
  const selected =
    data.entities.find((entity) => entity.entity_id === selectedEntityId) ??
    data.entities[0];
  const nodes = data.entities.map((entity, index) => {
    const spot = NODE_POSITIONS[entity.canonical_key] ?? {
      x: 16 + (index % 3) * 34,
      y: 22 + Math.floor(index / 3) * 50,
    };
    const width = 40 + entity.display_value.length * 7.6;
    return {
      entity,
      width,
      x: Math.min(GRAPH_W - width / 2 - 4, Math.max(width / 2 + 4, (spot.x / 100) * GRAPH_W)),
      y: (spot.y / 100) * GRAPH_H,
    };
  });
  const byId = new Map(nodes.map((node) => [node.entity.entity_id, node]));
  const related = data.relationships.filter(
    (link) => link.from === selected?.entity_id || link.to === selected?.entity_id,
  );
  const onKey = (id: string) => (event: KeyboardEvent) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(id);
    }
  };
  return (
    <div className="stack">
      <p className="muted">
        Solid lines are observed links, dashed lines are inferred. A shared appearance
        in the logs is not proof that one entity caused another.
      </p>
      <svg
        className="graph"
        viewBox={`0 0 ${GRAPH_W} ${GRAPH_H}`}
        role="group"
        aria-label="Entity relationships"
      >
        {data.relationships.map((link) => {
          const from = byId.get(link.from);
          const to = byId.get(link.to);
          if (!from || !to) return null;
          const active = link.from === selected?.entity_id || link.to === selected?.entity_id;
          return (
            <line
              key={`${link.from}-${link.to}`}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              className={`${active ? "is-active" : ""} ${link.status === "observed" ? "" : "is-inferred"}`}
            />
          );
        })}
        {nodes.map(({ entity, x, y, width }) => {
          const Icon = iconForEntity[entity.entity_type];
          const isSelected = entity.entity_id === selected?.entity_id;
          return (
            <g
              key={entity.entity_id}
              className={`node ${isSelected ? "is-selected" : ""}`}
              transform={`translate(${x - width / 2} ${y - 15})`}
              role="button"
              tabIndex={0}
              aria-pressed={isSelected}
              aria-label={`${entity.entity_type} ${entity.display_value}`}
              onClick={() => onSelect(entity.entity_id)}
              onKeyDown={onKey(entity.entity_id)}
            >
              <rect width={width} height={30} rx={6} />
              <Icon x={10} y={8} width={14} height={14} />
              <text x={32} y={20}>
                {entity.display_value}
              </text>
            </g>
          );
        })}
      </svg>
      {selected && (
        <div className="stack stack--tight">
          <div className="row row--between">
            <h3>{selected.display_value}</h3>
            <Tag>{humanize(selected.entity_type)}</Tag>
          </div>
          <p className="mono muted">{selected.canonical_key}</p>
          <ul className="links">
            {related.map((link) => {
              const otherId = link.from === selected.entity_id ? link.to : link.from;
              const other = data.entities.find((entity) => entity.entity_id === otherId);
              return (
                <li key={`${link.from}-${link.to}`}>
                  <div className="row row--between">
                    <span>
                      {link.from === selected.entity_id ? "to" : "from"}{" "}
                      <strong>{other?.display_value}</strong>
                    </span>
                    <Tag tone={link.status === "observed" ? "green" : "amber"}>
                      {humanize(link.status)}
                    </Tag>
                  </div>
                  <span className="chips">
                    {link.evidence.map((id) => (
                      <button className="chip" key={id} onClick={() => onEvidence(id)}>
                        {id}
                      </button>
                    ))}
                  </span>
                </li>
              );
            })}
          </ul>
          {!related.length && (
            <p className="muted">No linked evidence inside this incident boundary.</p>
          )}
        </div>
      )}
    </div>
  );
}

function ReportPanel({
  data,
  status,
  onRun,
  onEvidence,
}: {
  data: IncidentData;
  status: InvestigationStatus;
  onRun: () => void;
  onEvidence: (sourceId: string) => void;
}) {
  if (status === "idle" || status === "failed")
    return (
      <div className="stack">
        <div className="callout">
          <h3>{status === "failed" ? "The investigation failed" : "No report yet"}</h3>
          <p>
            {status === "failed"
              ? "The deterministic evidence is still available. Run the investigation again."
              : "The investigator reads stored events through read-only tools, weighs two hypotheses and cites the events behind every claim. It cannot create evidence or take action."}
          </p>
          <button className="button button--primary" onClick={onRun}>
            <Play size={15} aria-hidden="true" />
            {status === "failed" ? "Retry investigation" : "Run mock investigation"}
          </button>
        </div>
      </div>
    );
  if (status === "running")
    return (
      <div className="callout" role="status">
        <h3>
          <Loader2 size={16} className="spin" aria-hidden="true" /> Reading the evidence
        </h3>
        <p>Inspecting the timeline, event details and session relationships.</p>
      </div>
    );
  const { report } = data;
  return (
    <div className="stack stack--loose">
      <div className="stack stack--tight">
        <p className="lede">{report.executive_summary}</p>
        <p className="muted">Offline mock investigator · read-only tools</p>
      </div>
      <section>
        <h3>Observed facts</h3>
        <ul className="claims">
          {report.observed_facts.map((fact) => (
            <li key={fact.claim}>
              <p>{fact.claim}</p>
              <span className="chips">
                {fact.evidence.map((id) => (
                  <button className="chip" key={id} onClick={() => onEvidence(id)}>
                    {data.events.find((event) => matchesSource(event, id))?.source_event_id ?? id.slice(0, 8)}
                  </button>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h3>Competing hypotheses</h3>
        <ul className="claims">
          {report.competing_hypotheses.map((hypothesis) => (
            <li key={hypothesis.name}>
              <div className="row row--between">
                <strong>{hypothesis.name}</strong>
                <Tag tone={hypothesis.assessment === "supported" ? "blue" : "amber"}>
                  {humanize(hypothesis.assessment)}
                </Tag>
              </div>
              <p>{hypothesis.explanation}</p>
            </li>
          ))}
        </ul>
      </section>
      <div className="callout callout--warn">
        <h3>
          <AlertTriangle size={15} aria-hidden="true" /> What is missing
        </h3>
        {report.missing_evidence.map((item) => (
          <p key={item}>{item}</p>
        ))}
        {report.limitations.map((item) => (
          <p className="muted" key={item}>
            {item}
          </p>
        ))}
      </div>
    </div>
  );
}

const responseSteps: Array<{ key: ResponseState; label: string }> = [
  { key: "proposed", label: "Proposed" },
  { key: "awaiting_approval", label: "Awaiting approval" },
  { key: "approved", label: "Approved" },
  { key: "executing", label: "Executed" },
  { key: "verified", label: "Verified" },
];

function ResponsePanel({
  data,
  state,
  error,
  busy,
  onAdvance,
}: {
  data: IncidentData;
  state: ResponseState;
  error: string;
  busy: boolean;
  onAdvance: () => void;
}) {
  const failed = state === "verification_failed" || state === "inconclusive";
  const activeIndex =
    state === "succeeded" || failed
      ? 4
      : responseSteps.findIndex((step) => step.key === state);
  const copy: Record<ResponseState, { title: string; text: string; button: string }> = {
    proposed: {
      title: "Ready for review",
      text: "This action is backed by the evidence in the timeline. Ask for approval to continue.",
      button: "Request approval",
    },
    awaiting_approval: {
      title: "Approval needed",
      text: "The simulation revokes the observed session only after you approve it.",
      button: "Approve simulation",
    },
    approved: {
      title: "Approved",
      text: "The action is allowlisted and limited to the session seen in this incident.",
      button: "Execute simulation",
    },
    executing: {
      title: "Executing",
      text: "Updating the simulated session and writing an audit event.",
      button: "Executing",
    },
    succeeded: {
      title: "Executed",
      text: "The simulated revoke returned. Verify the result independently.",
      button: "Verify session",
    },
    verified: {
      title: "Verified",
      text: `The verifier observed ${data.response.target} with active = false.`,
      button: "Verified",
    },
    verification_failed: {
      title: "Verification failed",
      text: "The verifier did not see the session become inactive.",
      button: "Verification failed",
    },
    inconclusive: {
      title: "Verification inconclusive",
      text: "The verifier could not confirm the expected state.",
      button: "Verification inconclusive",
    },
  };
  const current = copy[state];
  const done = state === "verified";
  return (
    <div className="stack stack--loose">
      <div className="action">
        <div className="row row--between">
          <h3>Revoke session</h3>
          <Tag tone="neutral">Simulation</Tag>
        </div>
        <p className="mono">
          {data.response.target || "no session identified"} → active = false
        </p>
        <dl className="facts facts--stack">
          <div>
            <dt>Why</dt>
            <dd>Ends the simulated session while keeping the evidence trail intact.</dd>
          </div>
          <div>
            <dt>Impact</dt>
            <dd>One session for the affected user.</dd>
          </div>
          <div>
            <dt>Rollback</dt>
            <dd>Reset the simulation state from the fixture.</dd>
          </div>
        </dl>
      </div>
      <ol className="steps" aria-label="Response progress">
        {responseSteps.map((step, index) => (
          <li
            key={step.key}
            className={`${index < activeIndex || done ? "is-done" : ""} ${index === activeIndex && !done ? "is-current" : ""} ${index === activeIndex && failed ? "is-failed" : ""}`}
          >
            <span className="steps__mark">
              {index < activeIndex || done ? <Check size={12} aria-hidden="true" /> : index + 1}
            </span>
            {step.label}
          </li>
        ))}
      </ol>
      <div className={`callout ${failed ? "callout--warn" : ""}`} role="status">
        <h3>{current.title}</h3>
        <p>{current.text}</p>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {!data.response.target && <p className="error">No session was identified for this incident.</p>}
        <button
          className={`button ${done ? "button--success" : "button--primary"}`}
          disabled={busy || !data.response.target || state === "executing" || done || failed}
          onClick={onAdvance}
        >
          {state === "executing" || busy ? (
            <Loader2 size={15} className="spin" aria-hidden="true" />
          ) : done ? (
            <CheckCircle2 size={15} aria-hidden="true" />
          ) : failed ? (
            <AlertTriangle size={15} aria-hidden="true" />
          ) : null}
          {busy ? "Working" : current.button}
        </button>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------- dashboard */

function Dashboard({
  data,
  mode,
  onDemo,
  sourceError,
  setData,
}: {
  data: IncidentData;
  mode: DataMode;
  onDemo: () => void;
  sourceError?: string;
  setData: (data: IncidentData) => void;
}) {
  const [selectedEventId, setSelectedEventId] = useState("evt-auth-004");
  const [selectedEntityId, setSelectedEntityId] = useState("session:session-S104");
  const [focusId, setFocusId] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("evidence");
  const [investigationStatus, setInvestigationStatus] =
    useState<InvestigationStatus>("idle");
  const [responseState, setResponseState] = useState<ResponseState>("proposed");
  const [responseAction, setResponseAction] = useState<ResponseAction | null>(null);
  const [responseError, setResponseError] = useState("");
  const [responseBusy, setResponseBusy] = useState(false);
  const responsePending = useRef(false);
  const selectedEvent =
    data.events.find((event) => event.event_id === selectedEventId) ?? data.events[0];
  const focused = data.findings.find((finding) => finding.finding_id === focusId);
  const citedIds = focused ? new Set(focused.evidence) : null;

  const openEvidence = (sourceId: string) => {
    const event = data.events.find((item) => matchesSource(item, sourceId));
    if (event) {
      setSelectedEventId(event.event_id);
      setTab("evidence");
    }
  };
  const selectEvent = (id: string) => {
    setSelectedEventId(id);
    setTab("evidence");
  };

  const runInvestigation = async () => {
    setInvestigationStatus("running");
    if (mode === "demo") {
      window.setTimeout(() => setInvestigationStatus("completed"), 900);
      return;
    }
    try {
      const run = await startInvestigation(data.incident.incident_id);
      if (run.status !== "completed")
        throw new Error(run.error?.message ?? "Investigation did not complete");
      setData({ ...data, report: reportFromInvestigation(run) });
      setInvestigationStatus("completed");
    } catch {
      setInvestigationStatus("failed");
    }
  };

  const advanceResponse = async () => {
    if (mode === "api") {
      if (responsePending.current) return;
      responsePending.current = true;
      setResponseBusy(true);
      setResponseError("");
      try {
        if (responseState === "proposed") {
          setResponseAction(await createResponsePlan(data));
          setResponseState("awaiting_approval");
        } else if (responseState === "awaiting_approval" && responseAction) {
          setResponseAction(await approveResponseAction(responseAction));
          setResponseState("approved");
        } else if (responseState === "approved" && responseAction) {
          setResponseState("executing");
          setResponseAction(await executeResponseAction(responseAction));
          setResponseState("succeeded");
        } else if (responseState === "succeeded" && responseAction) {
          const verification = await verifyResponseAction(responseAction);
          setResponseState(verification.status);
          setResponseAction((current) =>
            current ? { ...current, status: verification.status, verification } : current,
          );
        }
      } catch (caught) {
        if (responseState === "approved") setResponseState("approved");
        setResponseError(
          caught instanceof Error ? caught.message : "Response request failed.",
        );
      } finally {
        responsePending.current = false;
        setResponseBusy(false);
      }
      return;
    }
    if (responseState === "proposed") setResponseState("awaiting_approval");
    else if (responseState === "awaiting_approval") setResponseState("approved");
    else if (responseState === "approved") {
      setResponseState("executing");
      window.setTimeout(() => setResponseState("succeeded"), 900);
    } else if (responseState === "succeeded") setResponseState("verified");
  };

  const tabs: Array<{ key: PanelTab; label: string; note?: string }> = [
    { key: "evidence", label: "Evidence" },
    { key: "entities", label: "Entities", note: String(data.entities.length) },
    {
      key: "report",
      label: "Report",
      note: investigationStatus === "completed" ? "Ready" : undefined,
    },
    {
      key: "response",
      label: "Response",
      note:
        responseState === "verified"
          ? "Verified"
          : responseState === "proposed"
            ? undefined
            : "In progress",
    },
  ];

  return (
    <main className="page">
      {sourceError && <ErrorBanner error={sourceError} onDemo={onDemo} />}
      <CaseHead
        data={data}
        onReview={() => {
          setTab("response");
          document
            .getElementById("inspector-panel")
            ?.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }}
      />
      <div className="workspace">
        <div className="narrative">
          <Signals
            data={data}
            focusId={focusId}
            onFocus={setFocusId}
            onEvidence={openEvidence}
          />
          <Timeline
            data={data}
            selectedId={selectedEvent?.event_id ?? ""}
            citedIds={citedIds}
            onSelect={selectEvent}
          />
        </div>
        <aside className="inspector" aria-label="Inspector">
          <div className="tabs" role="tablist" aria-label="Inspector sections">
            {tabs.map((item) => (
              <button
                key={item.key}
                role="tab"
                id={`tab-${item.key}`}
                aria-selected={tab === item.key}
                aria-controls="inspector-panel"
                onClick={() => setTab(item.key)}
              >
                {item.label}
                {item.note && <small>{item.note}</small>}
              </button>
            ))}
          </div>
          <div
            className="inspector__body"
            role="tabpanel"
            id="inspector-panel"
            aria-labelledby={`tab-${tab}`}
          >
            {tab === "evidence" && <EvidencePanel event={selectedEvent} />}
            {tab === "entities" && (
              <EntitiesPanel
                data={data}
                selectedEntityId={selectedEntityId}
                onSelect={setSelectedEntityId}
                onEvidence={openEvidence}
              />
            )}
            {tab === "report" && (
              <ReportPanel
                data={data}
                status={investigationStatus}
                onRun={runInvestigation}
                onEvidence={openEvidence}
              />
            )}
            {tab === "response" && (
              <ResponsePanel
                data={data}
                state={responseState}
                error={responseError}
                busy={responseBusy}
                onAdvance={advanceResponse}
              />
            )}
          </div>
        </aside>
      </div>
      <footer className="page-footer">
        <span>Scenario primary-v1</span>
        <span>Updated {formatTime(data.incident.updated_at)} UTC</span>
      </footer>
    </main>
  );
}

/* ------------------------------------------------------------------- root */

export default function HomePage() {
  const [mode, setMode] = useState<DataMode>(getDataMode());
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [data, setData] = useState<IncidentData | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState(INCIDENT_ID);
  const [error, setError] = useState("");

  const loadWorkspace = async () => {
    setLoadState("loading");
    setError("");
    try {
      const list = await fetchIncidentList();
      setIncidents(list);
      if (!list.length) {
        setData(null);
        setLoadState("empty");
        return;
      }
      const firstId = list[0].incident_id;
      const detail = await fetchIncidentData(firstId);
      setSelectedId(firstId);
      setData(detail);
      setLoadState("ready");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unknown API error");
      setLoadState("error");
    }
  };

  useEffect(() => {
    void loadWorkspace();
  }, []);

  const selectIncident = async (incidentId: string) => {
    setSelectedId(incidentId);
    if (mode === "demo") {
      setData(DEMO_INCIDENT);
      return;
    }
    setLoadState("loading");
    try {
      setData(await fetchIncidentData(incidentId));
      setLoadState("ready");
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "Incident detail could not be loaded",
      );
      setLoadState("error");
    }
  };

  const useDemo = () => {
    setMode("demo");
    setIncidents(DEMO_INCIDENT_LIST);
    setSelectedId(INCIDENT_ID);
    setData(DEMO_INCIDENT);
    setError("");
    setLoadState("ready");
  };

  const demoButton = (
    <button className="button button--primary" onClick={useDemo}>
      Open offline fixture
    </button>
  );

  return (
    <AppShell
      mode={mode}
      switcher={
        incidents.length > 0 && (
          <CaseSwitcher
            incidents={incidents}
            selectedId={selectedId}
            onSelect={(id) => void selectIncident(id)}
          />
        )
      }
      onModeChange={
        mode === "demo"
          ? () =>
              window.alert(
                "Set NEXT_PUBLIC_TRACESOC_API_BASE_URL and restart the web app to connect a real API.",
              )
          : useDemo
      }
    >
      {loadState === "loading" ? (
        <LoadingScreen />
      ) : loadState === "error" ? (
        <Notice
          icon={<WifiOff size={22} />}
          title="TraceSOC could not load the case"
          actions={
            <>
              {demoButton}
              <button
                className="button button--quiet"
                onClick={() => window.location.reload()}
              >
                <RefreshCw size={15} aria-hidden="true" /> Retry
              </button>
            </>
          }
        >
          {error}. Check the API address and CORS settings, or continue with the offline
          fixture.
        </Notice>
      ) : loadState === "ready" && data ? (
        <Dashboard
          data={data}
          mode={mode}
          onDemo={useDemo}
          sourceError={mode === "api" ? error : undefined}
          setData={(nextData) => setData(nextData)}
        />
      ) : (
        <Notice icon={<Activity size={22} />} title="No incidents yet" actions={demoButton}>
          The API returned no incidents for this workspace. Ingest events, or open the
          offline fixture to walk through a case.
        </Notice>
      )}
    </AppShell>
  );
}
