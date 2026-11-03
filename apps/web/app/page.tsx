"use client";

import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Clock3,
  Crosshair,
  Database,
  Eye,
  FileText,
  Globe2,
  Layers3,
  Loader2,
  LockKeyhole,
  Monitor,
  Network,
  Play,
  Radar,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  UserRound,
  WifiOff,
  XCircle,
} from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
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
  Relationship,
  ResponseAction,
  ResponseState,
} from "@/lib/types";

type LoadState = "loading" | "ready" | "empty" | "error";
type EvidenceView = "normalized" | "raw";

const INCIDENT_ID = "INC-PRIMARY-001";

const iconForEntity: Record<Entity["entity_type"], typeof UserRound> = {
  user: UserRound,
  host: Monitor,
  ip: Globe2,
  session: ShieldCheck,
  process: Terminal,
};

function formatTime(value: string) {
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(new Date(value));
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  }).format(new Date(value));
}

function humanize(value: string) {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function getSourceEvent(event: EventRecord, sourceId: string) {
  return event.source_event_id === sourceId || event.event_id === sourceId;
}

function AppShell({
  children,
  mode,
  onModeChange,
}: {
  children: ReactNode;
  mode: DataMode;
  onModeChange: () => void;
}) {
  const goTo = (id: string) =>
    document
      .getElementById(id)
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark">
            <Radar size={19} strokeWidth={2.5} />
          </div>
          <div>
            <strong>TraceSOC</strong>
            <span>evidence workspace</span>
          </div>
        </div>
        <div className="tenant-switcher">
          <div className="tenant-icon">
            <Database size={15} />
          </div>
          <div>
            <span>Tenant</span>
            <strong>demo</strong>
          </div>
          <ChevronDown size={14} className="muted-icon" />
        </div>
        <nav className="sidebar-nav" aria-label="Workspace">
          <NavLabel>Workspace</NavLabel>
          <NavItem
            icon={<Layers3 size={16} />}
            label="Case queue"
            active
            onClick={() => goTo("overview")}
            count="01"
          />
          <NavItem
            icon={<Activity size={16} />}
            label="Activity stream"
            onClick={() => goTo("timeline")}
          />
          <NavLabel>Inspect</NavLabel>
          <NavItem
            icon={<Clock3 size={16} />}
            label="Evidence timeline"
            onClick={() => goTo("timeline")}
          />
          <NavItem
            icon={<Network size={16} />}
            label="Entity relationships"
            onClick={() => goTo("relationships")}
          />
          <NavItem
            icon={<FileText size={16} />}
            label="Investigation report"
            onClick={() => goTo("report")}
          />
          <NavLabel>Respond</NavLabel>
          <NavItem
            icon={<ShieldAlert size={16} />}
            label="Response plan"
            onClick={() => goTo("response")}
          />
        </nav>
        <div className="sidebar-footer">
          <button
            className="mode-switch"
            onClick={onModeChange}
            title={
              mode === "demo"
                ? "Configure an API base URL to connect real data"
                : "Use the local demo fixture"
            }
          >
            {mode === "demo" ? <WifiOff size={15} /> : <Activity size={15} />}
            <span>{mode === "demo" ? "Offline fixture" : "Live API"}</span>
            <span className="mode-dot" />
          </button>
          <div className="analyst-chip">
            <div className="avatar">AD</div>
            <div>
              <strong>analyst-demo</strong>
              <span>Local analyst</span>
            </div>
            <ChevronRight size={14} />
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>Incident review</strong>
          </div>
          <div className="topbar-actions">
            <span className="utc-label">
              <CircleDot size={10} /> All times UTC
            </span>
            <button
              className="icon-button"
              aria-label="Refresh view"
              onClick={() => window.location.reload()}
            >
              <RefreshCw size={16} />
            </button>
            <div className="topbar-avatar">AD</div>
          </div>
        </header>
        {children}
      </div>
    </div>
  );
}

function NavLabel({ children }: { children: ReactNode }) {
  return <div className="nav-label">{children}</div>;
}

function NavItem({
  icon,
  label,
  count,
  active,
  onClick,
}: {
  icon: ReactNode;
  label: string;
  count?: string;
  active?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      className={`nav-item ${active ? "is-active" : ""}`}
      onClick={onClick}
    >
      {icon}
      <span>{label}</span>
      {count && <em>{count}</em>}
    </button>
  );
}

function StatusPill({
  children,
  tone = "neutral",
  dot = false,
}: {
  children: ReactNode;
  tone?: "neutral" | "amber" | "cyan" | "green" | "red" | "blue";
  dot?: boolean;
}) {
  return (
    <span className={`status-pill status-pill--${tone}`}>
      {dot && <span className="status-dot" />}
      {children}
    </span>
  );
}

function SourceBanner({
  mode,
  error,
  onDemo,
}: {
  mode: DataMode;
  error?: string;
  onDemo: () => void;
}) {
  if (error) {
    return (
      <div className="state-banner state-banner--error">
        <XCircle size={17} />
        <div>
          <strong>Live incident data unavailable</strong>
          <span>{error}</span>
        </div>
        <button className="button button--quiet" onClick={onDemo}>
          Open demo fixture
        </button>
      </div>
    );
  }
  return (
    <div
      className={`state-banner ${mode === "demo" ? "state-banner--demo" : "state-banner--api"}`}
    >
      <span className="state-banner__icon">
        {mode === "demo" ? <WifiOff size={16} /> : <Activity size={16} />}
      </span>
      <div>
        <strong>
          {mode === "demo"
            ? "OFFLINE / DEMO FIXTURE"
            : "LIVE API / SIMULATED RESPONSE"}
        </strong>
        <span>
          {mode === "demo"
            ? "primary-v1 · frozen account-compromise scenario · no backend required"
            : `${configuredApiBase} · incident and evidence routes`}
        </span>
      </div>
      <span className="state-banner__tail">
        {mode === "demo" ? "LOCAL" : "CONNECTED"}
      </span>
    </div>
  );
}

function LoadingScreen() {
  return (
    <main className="main-content">
      <div className="loading-heading">
        <div className="skeleton skeleton--eyebrow" />
        <div className="skeleton skeleton--title" />
        <div className="skeleton skeleton--copy" />
      </div>
      <div className="loading-grid">
        <div className="skeleton skeleton--panel" />
        <div className="skeleton skeleton--panel" />
        <div className="skeleton skeleton--wide" />
      </div>
    </main>
  );
}

function EmptyState({ onDemo }: { onDemo: () => void }) {
  return (
    <main className="main-content">
      <div className="empty-state">
        <div className="empty-state__icon">
          <Search size={22} />
        </div>
        <span className="eyebrow">Incident queue</span>
        <h1>No incidents in this workspace</h1>
        <p>
          The configured API returned an empty incident set. Load the frozen
          primary fixture to walk the analyst flow locally.
        </p>
        <button className="button button--primary" onClick={onDemo}>
          <Radar size={16} /> Open primary fixture
        </button>
      </div>
    </main>
  );
}

function ErrorState({ error, onDemo }: { error: string; onDemo: () => void }) {
  return (
    <main className="main-content">
      <div className="empty-state empty-state--error">
        <div className="empty-state__icon">
          <WifiOff size={22} />
        </div>
        <span className="eyebrow">Connection issue</span>
        <h1>TraceSOC could not load the case</h1>
        <p>
          {error}. Check the API base URL and CORS settings, or continue with
          the clearly labeled local fixture.
        </p>
        <div className="empty-state__actions">
          <button className="button button--primary" onClick={onDemo}>
            <Radar size={16} /> Open demo fixture
          </button>
          <button
            className="button button--quiet"
            onClick={() => window.location.reload()}
          >
            <RefreshCw size={15} /> Retry API
          </button>
        </div>
      </div>
    </main>
  );
}

function IncidentRail({
  incidents,
  data,
  selectedId,
  onSelect,
  search,
  setSearch,
}: {
  incidents: Incident[];
  data: IncidentData;
  selectedId: string;
  onSelect: (id: string) => void;
  search: string;
  setSearch: (value: string) => void;
}) {
  const filtered = incidents.filter((incident) =>
    `${incident.incident_id} ${incident.title} ${incident.status}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  return (
    <aside className="incident-rail">
      <div className="rail-heading">
        <div>
          <span className="eyebrow">Case queue</span>
          <h2>
            Incidents{" "}
            <span>{incidents.length.toString().padStart(2, "0")}</span>
          </h2>
        </div>
      </div>
      <label className="search-field">
        <Search size={15} />
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search cases"
        />
      </label>
      <div className="incident-list">
        {filtered.length ? (
          filtered.map((incident) => (
            <button
              key={incident.incident_id}
              className={`incident-row ${selectedId === incident.incident_id ? "is-selected" : ""}`}
              onClick={() => onSelect(incident.incident_id)}
            >
              <span className="incident-row__indicator" />
              <div className="incident-row__body">
                <div className="incident-row__top">
                  <strong>{incident.incident_id}</strong>
                  <span>{formatTime(incident.updated_at)}</span>
                </div>
                <h3>{incident.title}</h3>
                <div className="incident-row__meta">
                  <StatusPill tone="amber" dot>
                    {humanize(incident.status)}
                  </StatusPill>
                  <span>{humanize(incident.severity)}</span>
                </div>
              </div>
              <ChevronRight size={14} className="incident-row__chevron" />
            </button>
          ))
        ) : (
          <div className="rail-empty">
            <Search size={18} />
            <span>No matching cases</span>
            <small>Try a different case ID or title.</small>
          </div>
        )}
      </div>
      <div className="rail-footer">
        <div>
          <span className="rail-footer__number">{data.events.length}</span>
          <span>evidence records</span>
        </div>
        <div>
          <span className="rail-footer__number">{data.findings.length}</span>
          <span>findings</span>
        </div>
      </div>
    </aside>
  );
}

function SectionHeading({
  eyebrow,
  title,
  copy,
  action,
}: {
  eyebrow?: string;
  title: string;
  copy?: string;
  action?: ReactNode;
}) {
  return (
    <div className="section-heading">
      <div>
        <div className="section-heading__eyebrow">{eyebrow}</div>
        <h2>{title}</h2>
        {copy && <p>{copy}</p>}
      </div>
      {action}
    </div>
  );
}

function EvidenceChip({
  id,
  onClick,
}: {
  id: string;
  onClick: (id: string) => void;
}) {
  return (
    <button className="evidence-chip" onClick={() => onClick(id)}>
      <span>↗</span>
      {id}
    </button>
  );
}

function FindingsPanel({
  data,
  onEvidence,
}: {
  data: IncidentData;
  onEvidence: (sourceId: string) => void;
}) {
  return (
    <section className="panel findings-panel">
      <SectionHeading
        eyebrow="Deterministic signals"
        title="Why this case is open"
        copy="Rules create investigation signals. Evidence remains the source of truth."
      />
      <div className="finding-list">
        {data.findings.map((finding) => (
          <article className="finding" key={finding.finding_id}>
            <div className="finding__rail">
              <span
                className={`finding__marker finding__marker--${finding.status}`}
              />
              <span className="finding__rule">{finding.rule_id}</span>
            </div>
            <div className="finding__body">
              <div className="finding__title-row">
                <h3>{finding.title}</h3>
                <StatusPill
                  tone={finding.status === "observed" ? "cyan" : "amber"}
                >
                  {finding.status}
                </StatusPill>
              </div>
              <p>{finding.description}</p>
              <div className="finding__evidence">
                {finding.evidence.map((id) => (
                  <EvidenceChip key={id} id={id} onClick={onEvidence} />
                ))}
              </div>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function Timeline({
  data,
  selectedId,
  onSelect,
}: {
  data: IncidentData;
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  return (
    <section className="panel timeline-panel" id="timeline">
      <SectionHeading
        eyebrow="Evidence stream"
        title="Timeline"
        copy="Ordered by event time, then ingestion time, then event ID."
      />
      <div className="timeline-list">
        {data.events.map((event) => (
          <button
            className={`timeline-event ${selectedId === event.event_id ? "is-selected" : ""}`}
            key={event.event_id}
            onClick={() => onSelect(event.event_id)}
          >
            <div className="timeline-event__time">
              <strong>{formatTime(event.event_time)}</strong>
              <span>
                +{Math.max(0, Math.round(
                  (Date.parse(event.event_time) - Date.parse(data.events[0].event_time)) / 1000,
                ))}s
              </span>
            </div>
            <div className="timeline-event__track">
              <span
                className={`timeline-event__node ${event.outcome === "failure" ? "timeline-event__node--failure" : ""}`}
              />
              <span className="timeline-event__line" />
            </div>
            <div className="timeline-event__content">
              <div className="timeline-event__top">
                <StatusPill
                  tone={
                    event.outcome === "failure"
                      ? "red"
                      : event.severity === "high"
                        ? "amber"
                        : "neutral"
                  }
                >
                  {humanize(event.event_type)}
                </StatusPill>
                <span className="timeline-event__source">
                  {event.source_type}
                </span>
                <span className="timeline-event__id">
                  {event.source_event_id}
                </span>
              </div>
              <h3>{event.summary}</h3>
              <p>
                {event.username && (
                  <>
                    <UserRound size={12} /> {event.username}
                  </>
                )}
                {event.host_id && (
                  <>
                    <Monitor size={12} /> {event.host_id}
                  </>
                )}
                {event.session_id && (
                  <>
                    <LockKeyhole size={12} /> {event.session_id}
                  </>
                )}
              </p>
            </div>
            <ChevronRight size={15} className="timeline-event__chevron" />
          </button>
        ))}
      </div>
    </section>
  );
}

function EvidenceDetail({ event }: { event?: EventRecord }) {
  const [view, setView] = useState<EvidenceView>("normalized");
  useEffect(() => setView("normalized"), [event?.event_id]);
  if (!event)
    return (
      <div className="evidence-detail evidence-detail--empty">
        <Eye size={19} />
        <span>Select an event to inspect its source payload.</span>
      </div>
    );
  const payload =
    view === "normalized" ? event.normalized_fields : event.raw_event;
  return (
    <aside className="evidence-detail">
      <div className="evidence-detail__top">
        <div>
          <span className="eyebrow">Selected evidence</span>
          <h3>{event.source_event_id}</h3>
        </div>
        <StatusPill tone={event.outcome === "failure" ? "red" : "cyan"} dot>
          {event.outcome}
        </StatusPill>
      </div>
      <div className="evidence-detail__meta">
        <span>
          <Clock3 size={13} /> {formatDate(event.event_time)} ·{" "}
          {formatTime(event.event_time)}
        </span>
        <span>
          <Database size={13} /> {event.event_id}
        </span>
      </div>
      <div className="segmented-control" role="tablist">
        <button
          className={view === "normalized" ? "is-active" : ""}
          onClick={() => setView("normalized")}
        >
          Normalized
        </button>
        <button
          className={view === "raw" ? "is-active" : ""}
          onClick={() => setView("raw")}
        >
          Raw source
        </button>
      </div>
      <div className="code-block">
        <div className="code-block__header">
          <span>
            {view === "normalized" ? "canonical fields" : "source payload"}
          </span>
          <span>JSON</span>
        </div>
        <pre>{JSON.stringify(payload, null, 2)}</pre>
      </div>
      <div className="evidence-detail__footer">
        <span>ingested {formatTime(event.ingested_at)}</span>
        <span className="verified-label">
          <CheckCircle2 size={13} /> traceable record
        </span>
      </div>
    </aside>
  );
}

function RelationshipMap({
  data,
  selectedEntityId,
  onSelect,
}: {
  data: IncidentData;
  selectedEntityId: string;
  onSelect: (id: string) => void;
}) {
  const positions: Record<string, { x: number; y: number }> = {
    "user:alice": { x: 15, y: 29 },
    "ip:203.0.113.50": { x: 15, y: 76 },
    "host:ws-07": { x: 48, y: 18 },
    "session:session-S104": { x: 48, y: 67 },
    "process:powershell.exe": { x: 82, y: 35 },
    "ip:198.51.100.24": { x: 82, y: 77 },
  };
  const fallbackPosition = (index: number) => ({
    x: 16 + (index % 3) * 33,
    y: 22 + Math.floor(index / 3) * 50,
  });
  const points = data.entities.map((entity, index) => ({
    entity,
    position: positions[entity.canonical_key] ?? fallbackPosition(index),
  }));
  const pointById = new Map(
    points.map((point) => [point.entity.entity_id, point]),
  );
  return (
    <div className="relationship-map">
      <svg
        className="relationship-map__lines"
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        {data.relationships.map((relationship) => {
          const from = pointById.get(relationship.from);
          const to = pointById.get(relationship.to);
          if (!from || !to) return null;
          const active =
            selectedEntityId === relationship.from ||
            selectedEntityId === relationship.to;
          return (
            <g
              key={`${relationship.from}-${relationship.to}`}
              className={`${relationship.status === "inferred" ? "is-inferred" : ""} ${active ? "is-active" : ""}`}
            >
              <line
                x1={from.position.x}
                y1={from.position.y}
                x2={to.position.x}
                y2={to.position.y}
              />
              <text
                x={(from.position.x + to.position.x) / 2}
                y={(from.position.y + to.position.y) / 2 - 2}
              >
                {relationship.label}
              </text>
            </g>
          );
        })}
      </svg>
      {points.map(({ entity, position }) => {
        const Icon = iconForEntity[entity.entity_type];
        return (
          <button
            key={entity.entity_id}
            className={`graph-node graph-node--${entity.entity_type} ${selectedEntityId === entity.entity_id ? "is-selected" : ""}`}
            style={
              {
                "--node-x": `${position.x}%`,
                "--node-y": `${position.y}%`,
              } as CSSProperties
            }
            onClick={() => onSelect(entity.entity_id)}
          >
            <span className="graph-node__icon">
              <Icon size={15} />
            </span>
            <span className="graph-node__copy">
              <strong>{entity.display_value}</strong>
              <small>{entity.entity_type}</small>
            </span>
          </button>
        );
      })}
      <div className="graph-legend">
        <span>
          <i className="legend-line" /> observed
        </span>
        <span>
          <i className="legend-line legend-line--dashed" /> inferred
        </span>
      </div>
    </div>
  );
}

function RelationshipPanel({
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
  const related = data.relationships.filter(
    (relationship) =>
      relationship.from === selected?.entity_id ||
      relationship.to === selected?.entity_id,
  );
  return (
    <section className="panel relationship-panel" id="relationships">
      <SectionHeading
        eyebrow="Bounded entity graph"
        title="Relationships"
        copy="Observed links are solid. Derived links are dashed; reachability is not proof."
        action={
          <StatusPill tone="cyan" dot>
            {data.entities.length} entities
          </StatusPill>
        }
      />
      <div className="relationship-layout">
        <RelationshipMap
          data={data}
          selectedEntityId={selectedEntityId}
          onSelect={onSelect}
        />
        <aside className="relationship-inspector">
          {selected ? (
            <>
              <div className="relationship-inspector__header">
                <span
                  className={`entity-icon entity-icon--${selected.entity_type}`}
                >
                  <EntityIcon type={selected.entity_type} />
                </span>
                <div>
                  <span>{selected.entity_type}</span>
                  <h3>{selected.display_value}</h3>
                </div>
              </div>
              <div className="relationship-inspector__key">
                <span>Canonical key</span>
                <code>{selected.canonical_key}</code>
              </div>
              <div className="relationship-inspector__links">
                <span className="eyebrow">Linked evidence</span>
                {related.length ? (
                  related.map((relationship) => (
                    <div
                      className="relationship-link"
                      key={`${relationship.from}-${relationship.to}`}
                    >
                      <div>
                        <span>
                          {relationship.from === selected.entity_id
                            ? "to"
                            : "from"}
                        </span>
                        <strong>
                          {
                            data.entities.find(
                              (entity) =>
                                entity.entity_id ===
                                (relationship.from === selected.entity_id
                                  ? relationship.to
                                  : relationship.from),
                            )?.display_value
                          }
                        </strong>
                      </div>
                      <StatusPill
                        tone={
                          relationship.status === "inferred" ? "amber" : "cyan"
                        }
                      >
                        {relationship.status}
                      </StatusPill>
                      <div className="relationship-link__evidence">
                        {relationship.evidence.map((id) => (
                          <EvidenceChip id={id} key={id} onClick={onEvidence} />
                        ))}
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="muted-copy">
                    No linked evidence in this incident boundary.
                  </p>
                )}
              </div>
            </>
          ) : (
            <div className="relationship-inspector__empty">
              Select an entity node to inspect its evidence links.
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}

function EntityIcon({ type }: { type: Entity["entity_type"] }) {
  const Icon = iconForEntity[type];
  return <Icon size={16} />;
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
  return (
    <section className="panel report-panel" id="report">
      <div className="report-panel__head">
        <SectionHeading
          eyebrow="Constrained investigation"
          title="Analyst report"
          copy="The investigator can explain evidence, but cannot create new evidence or take action."
        />
        <div className="report-status">
          {status === "completed" ? (
            <StatusPill tone="green" dot>
              Mock run complete
            </StatusPill>
          ) : status === "running" ? (
            <StatusPill tone="cyan" dot>
              Gathering evidence
            </StatusPill>
          ) : (
            <StatusPill tone="neutral">Ready to run</StatusPill>
          )}
        </div>
      </div>
      {(status === "idle" || status === "failed") && (
        <div className="report-callout">
          <div className="report-callout__icon">
            <Play size={17} />
          </div>
          <div>
            <strong>
              {status === "failed"
                ? "Investigation failed"
                : "Run the offline investigator"}
            </strong>
            <p>
              {status === "failed"
                ? "Deterministic evidence remains available. Retry the bounded investigation."
                : "It will inspect the stored events through read-only tools, compare two hypotheses, and cite every material claim."}
            </p>
          </div>
          <button className="button button--primary" onClick={onRun}>
            <Play size={15} />{" "}
            {status === "failed"
              ? "Retry investigation"
              : "Run mock investigation"}
          </button>
        </div>
      )}
      {status === "running" && (
        <div className="report-running">
          <Loader2 size={18} className="spin" />
          <div>
            <strong>Reading the evidence boundary</strong>
            <p>Inspecting timeline, event detail, and session relationships…</p>
          </div>
          <div className="progress-track">
            <span />
          </div>
        </div>
      )}
      {status === "completed" && (
        <div className="report-body">
          <div className="report-summary">
            <span className="report-summary__label">Executive summary</span>
            <p>{data.report.executive_summary}</p>
            <div className="report-meta">
              <span>
                <CheckCircle2 size={13} /> 7 event citations
              </span>
              <span>
                <LockKeyhole size={13} /> 3 read-only tools
              </span>
              <span>
                <Clock3 size={13} /> completed just now
              </span>
            </div>
          </div>
          <div className="report-columns">
            <div>
              <span className="report-subhead">Observed facts</span>
              {data.report.observed_facts.map((fact) => (
                <div className="report-item" key={fact.claim}>
                  <CheckCircle2 size={15} />
                  <div>
                    <p>{fact.claim}</p>
                    <div>
                      {fact.evidence.map((id) => (
                        <EvidenceChip key={id} id={id} onClick={onEvidence} />
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <div>
              <span className="report-subhead">Competing hypotheses</span>
              {data.report.competing_hypotheses.map((hypothesis) => (
                <div className="hypothesis" key={hypothesis.name}>
                  <div className="hypothesis__top">
                    <strong>{hypothesis.name}</strong>
                    <StatusPill
                      tone={
                        hypothesis.assessment === "supported" ? "cyan" : "amber"
                      }
                    >
                      {humanize(hypothesis.assessment)}
                    </StatusPill>
                  </div>
                  <p>{hypothesis.explanation}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="report-footer">
            <span>
              <AlertTriangle size={14} /> Missing telemetry:{" "}
              {data.report.missing_evidence[0]}
            </span>
            <span>{data.report.limitations[0]}</span>
          </div>
        </div>
      )}
    </section>
  );
}

const responseSteps: Array<{
  key: ResponseState;
  label: string;
  note: string;
}> = [
  { key: "proposed", label: "Proposed", note: "allowlisted action" },
  { key: "awaiting_approval", label: "Approval", note: "analyst decision" },
  { key: "approved", label: "Approved", note: "ready to simulate" },
  { key: "executing", label: "Executing", note: "revoke session" },
  { key: "verified", label: "Verification", note: "check postcondition" },
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
  const activeIndex =
    state === "succeeded" ||
    state === "verification_failed" ||
    state === "inconclusive"
      ? 4
      : responseSteps.findIndex((step) => step.key === state);
  const actionCopy: Record<
    ResponseState,
    { title: string; description: string; button: string }
  > = {
    proposed: {
      title: "Review response proposal",
      description: "The evidence-backed action is ready for analyst approval.",
      button: "Request approval",
    },
    awaiting_approval: {
      title: "Approval required",
      description:
        "This simulation will revoke the observed session only after an explicit analyst decision.",
      button: "Approve simulation",
    },
    approved: {
      title: "Approved for simulation",
      description:
        "The action is allowlisted and scoped to the session observed in this incident.",
      button: "Execute simulation",
    },
    executing: {
      title: "Executing simulation",
      description:
        "Updating the simulated session state and writing an audit event…",
      button: "Working",
    },
    succeeded: {
      title: "Simulation completed",
      description:
        "The simulated revoke returned successfully. Verify the postcondition independently.",
      button: "Verify session",
    },
    verified: {
      title: "Response verified",
      description:
        `The independent verifier observed ${data.response.target} with active = false.`,
      button: "Verified",
    },
    verification_failed: {
      title: "Verification failed",
      description:
        "The verifier did not observe the expected inactive session state.",
      button: "Verification failed",
    },
    inconclusive: {
      title: "Verification inconclusive",
      description:
        "The verifier could not establish the expected postcondition.",
      button: "Verification inconclusive",
    },
  };
  const copy = actionCopy[state];
  return (
    <section className="panel response-panel" id="response">
      <div className="response-panel__head">
        <SectionHeading
          eyebrow="Controlled response"
          title="Containment"
          copy="Simulation only · every state change is explicit and auditable."
        />
        <StatusPill
          tone={
            state === "verified"
              ? "green"
              : state === "verification_failed" || state === "inconclusive"
                ? "red"
                : state === "executing"
                  ? "cyan"
                  : "amber"
          }
          dot
        >
          {copy.title}
        </StatusPill>
      </div>
      <div className="response-stepper">
        {responseSteps.map((step, index) => {
          const complete = index < activeIndex;
          const current = index === activeIndex;
          return (
            <div
              className={`response-step ${complete ? "is-complete" : ""} ${current ? "is-current" : ""}`}
              key={step.key}
            >
              <div className="response-step__dot">
                {complete ? <Check size={13} /> : index + 1}
              </div>
              <div>
                <strong>{step.label}</strong>
                <span>{step.note}</span>
              </div>
              {index < responseSteps.length - 1 && (
                <span className="response-step__connector" />
              )}
            </div>
          );
        })}
      </div>
      <div className="response-content">
        <div className="action-summary">
          <div className="action-summary__icon">
            <ShieldAlert size={19} />
          </div>
          <div>
            <span className="eyebrow">Allowlisted action</span>
            <h3>Revoke session</h3>
            <p>
              Target <code>{data.response.target || "not identified"}</code> ·
              expected postcondition <code>active = false</code>
            </p>
          </div>
        </div>
        <div className="action-details">
          <div>
            <span>Rationale</span>
            <p>
              Revoke the simulated session while preserving the evidence trail.
            </p>
          </div>
          <div>
            <span>Operational impact</span>
            <p>End one session for the affected user in the simulation.</p>
          </div>
          <div>
            <span>Rollback</span>
            <p>Simulation state can be reset from the fixture.</p>
          </div>
        </div>
        {error && <p role="alert">{error}</p>}
        {!data.response.target && (
          <p>No session was identified for this incident.</p>
        )}
        <button
          className={`button ${state === "verified" ? "button--success" : "button--primary"}`}
          disabled={
            busy ||
            !data.response.target ||
            state === "executing" ||
            state === "verified" ||
            state === "verification_failed" ||
            state === "inconclusive"
          }
          onClick={onAdvance}
        >
          {state === "executing" ? (
            <Loader2 size={15} className="spin" />
          ) : state === "verified" ? (
            <CheckCircle2 size={15} />
          ) : state === "verification_failed" || state === "inconclusive" ? (
            <AlertTriangle size={15} />
          ) : (
            <ArrowUpRight size={15} />
          )}
          {busy ? "Working…" : copy.button}
        </button>
      </div>
    </section>
  );
}

function Dashboard({
  data,
  incidents,
  mode,
  selectedId,
  onSelect,
  search,
  setSearch,
  onDemo,
  sourceError,
  setData,
}: {
  data: IncidentData;
  incidents: Incident[];
  mode: DataMode;
  selectedId: string;
  onSelect: (id: string) => void;
  search: string;
  setSearch: (value: string) => void;
  onDemo: () => void;
  sourceError?: string;
  setData: (data: IncidentData) => void;
}) {
  const [selectedEventId, setSelectedEventId] = useState("evt-auth-004");
  const [selectedEntityId, setSelectedEntityId] = useState(
    "session:session-S104",
  );
  const [investigationStatus, setInvestigationStatus] =
    useState<InvestigationStatus>("idle");
  const [responseState, setResponseState] = useState<ResponseState>("proposed");
  const [responseAction, setResponseAction] = useState<ResponseAction | null>(
    null,
  );
  const [responseError, setResponseError] = useState("");
  const [responseBusy, setResponseBusy] = useState(false);
  const responsePending = useRef(false);
  const reportRef = useRef<HTMLDivElement>(null);
  const selectedEvent =
    data.events.find((event) => event.event_id === selectedEventId) ??
    data.events[0];
  const openEvidence = (sourceId: string) => {
    const event = data.events.find((item) => getSourceEvent(item, sourceId));
    if (event) {
      setSelectedEventId(event.event_id);
      document
        .getElementById("timeline")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
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
            current
              ? { ...current, status: verification.status, verification }
              : current,
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
    else if (responseState === "awaiting_approval")
      setResponseState("approved");
    else if (responseState === "approved") {
      setResponseState("executing");
      window.setTimeout(() => setResponseState("succeeded"), 900);
    } else if (responseState === "succeeded") setResponseState("verified");
  };
  return (
    <>
      <main className="main-content">
        <SourceBanner mode={mode} error={sourceError} onDemo={onDemo} />
        <div className="case-header" id="overview">
          <div className="case-header__top">
            <div className="case-identity">
              <span className="eyebrow">
                Case file <span className="eyebrow-separator">/</span>{" "}
                {data.incident.incident_id}
              </span>
              <h1>{data.incident.title}</h1>
              <p>
                Review the stored evidence, findings, and simulated response for this incident.
              </p>
            </div>
            <div className="case-header__actions">
              <button
                className="button button--primary button--small"
                onClick={() =>
                  document
                    .getElementById("response")
                    ?.scrollIntoView({ behavior: "smooth" })
                }
              >
                <ShieldAlert size={14} /> Review response
              </button>
            </div>
          </div>
          <div className="case-header__meta">
            <StatusPill tone="amber" dot>
              {humanize(data.incident.status)}
            </StatusPill>
            <StatusPill tone="red">
              {humanize(data.incident.severity)} severity
            </StatusPill>
            <span>
              <Clock3 size={14} /> {formatTime(data.incident.observed_start)} —{" "}
              {formatTime(data.incident.observed_end)} UTC
            </span>
            <span>
              <Database size={14} /> {data.incident.tenant_id} tenant
            </span>
            <span className="case-header__confidence">
              <span className="confidence-ring">
                {data.incident.confidence.slice(0, 2).toUpperCase()}
              </span>{" "}
              confidence category:{" "}
              {data.incident.confidence}
            </span>
          </div>
        </div>
        <div className="summary-strip">
          <div>
            <span className="summary-strip__value">{data.events.length}</span>
            <span className="summary-strip__label">
              linked evidence records
            </span>
          </div>
          <div>
            <span className="summary-strip__value">{data.findings.length}</span>
            <span className="summary-strip__label">deterministic findings</span>
          </div>
          <div>
            <span className="summary-strip__value">{data.entities.length}</span>
            <span className="summary-strip__label">bounded entities</span>
          </div>
          <div>
            <span className="summary-strip__value summary-strip__value--amber">
              {responseAction || (mode === "demo" && responseState !== "proposed") ? 1 : 0}
            </span>
            <span className="summary-strip__label">current response proposal</span>
          </div>
          <div className="summary-strip__end">
            <span className="summary-strip__live">
              <span /> evidence boundary intact
            </span>
          </div>
        </div>
        <div className="overview-grid">
          <FindingsPanel data={data} onEvidence={openEvidence} />
          <div className="triage-note panel">
            <div className="triage-note__head">
              <span className="section-heading__eyebrow">
                Analyst orientation
              </span>
              <Eye size={17} />
            </div>
            <h3>Known, inferred, missing</h3>
            <div className="orientation-row">
              <span className="orientation-dot orientation-dot--cyan" />
              <div>
                <strong>Observed</strong>
                <span>Directly represented by stored event data.</span>
              </div>
            </div>
            <div className="orientation-row">
              <span className="orientation-dot orientation-dot--amber" />
              <div>
                <strong>Inferred</strong>
                <span>Derived from multiple related records.</span>
              </div>
            </div>
            <div className="orientation-row">
              <span className="orientation-dot orientation-dot--muted" />
              <div>
                <strong>Missing</strong>
                <span>No identity confirmation or endpoint memory.</span>
              </div>
            </div>
            <div className="triage-note__footer">
              <Crosshair size={14} /> {data.incident.correlation_key}
            </div>
          </div>
        </div>
        <div className="timeline-layout">
          <Timeline
            data={data}
            selectedId={selectedEvent?.event_id ?? ""}
            onSelect={setSelectedEventId}
          />
          <EvidenceDetail event={selectedEvent} />
        </div>
        <RelationshipPanel
          data={data}
          selectedEntityId={selectedEntityId}
          onSelect={setSelectedEntityId}
          onEvidence={openEvidence}
        />
        <ReportPanel
          data={data}
          status={investigationStatus}
          onRun={runInvestigation}
          onEvidence={openEvidence}
        />
        <ResponsePanel
          data={data}
          state={responseState}
          error={responseError}
          busy={responseBusy}
          onAdvance={advanceResponse}
        />
        <footer className="page-footer">
          <span>
            <Radar size={14} /> TraceSOC analyst workspace
          </span>
          <span>Scenario primary-v1 · source-backed UI</span>
          <span>Updated {formatTime(data.incident.updated_at)} UTC</span>
        </footer>
      </main>
      <IncidentRail
        incidents={incidents}
        data={data}
        selectedId={selectedId}
        onSelect={onSelect}
        search={search}
        setSearch={setSearch}
      />
    </>
  );
}

export default function HomePage() {
  const [mode, setMode] = useState<DataMode>(getDataMode());
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [data, setData] = useState<IncidentData | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState(INCIDENT_ID);
  const [search, setSearch] = useState("");
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
        caught instanceof Error
          ? caught.message
          : "Incident detail could not be loaded",
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

  return (
    <AppShell
      mode={mode}
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
      ) : loadState === "empty" ? (
        <EmptyState onDemo={useDemo} />
      ) : loadState === "error" ? (
        <ErrorState error={error} onDemo={useDemo} />
      ) : data ? (
        <Dashboard
          data={data}
          incidents={incidents}
          mode={mode}
          selectedId={selectedId}
          onSelect={(id) => void selectIncident(id)}
          search={search}
          setSearch={setSearch}
          onDemo={useDemo}
          sourceError={mode === "api" ? error : undefined}
          setData={(nextData) => setData(nextData)}
        />
      ) : (
        <EmptyState onDemo={useDemo} />
      )}
    </AppShell>
  );
}
