import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type TelemetryEvent = {
  id: string;
  timestamp: number | string;
  event_type: string;
  source: string;
  payload: Record<string, unknown>;
};

type Storyline = {
  key: string;
  title: string;
  severity: "critical" | "high" | "medium" | "info";
  summary: string;
  events: TelemetryEvent[];
  lastSeen: number;
};

type DashboardStats = {
  totalEvents: number;
  totalAlerts: number;
  totalIncidents: number;
  totalResponses: number;
};

function getTimestampMs(value: number | string | undefined): number {
  if (typeof value === "number") {
    return value < 10_000_000_000 ? value * 1000 : value;
  }

  if (typeof value === "string") {
    const numeric = Number(value);
    if (!Number.isNaN(numeric) && value.trim() !== "") {
      return numeric < 10_000_000_000 ? numeric * 1000 : numeric;
    }

    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }

  return 0;
}

function formatTimestamp(value: number | string | undefined): string {
  const ms = getTimestampMs(value);
  if (!ms) return String(value ?? "unknown");
  return new Date(ms).toLocaleString();
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function humanizeEventType(eventType: string): string {
  return eventType
    .replace(/^alert_/, "")
    .replace(/^response_/, "")
    .replace(/^agent_/, "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function severityRank(severity: Storyline["severity"]): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    default:
      return 1;
  }
}

function mergeSeverity(
  left: Storyline["severity"],
  right: Storyline["severity"]
): Storyline["severity"] {
  return severityRank(left) >= severityRank(right) ? left : right;
}

function eventSeverity(event: TelemetryEvent): Storyline["severity"] {
  const payload = event.payload ?? {};
  const severity = asString(payload.severity)?.toLowerCase();
  const outcome = asString(payload.outcome)?.toLowerCase();
  const score = asNumber(payload.score);

  if (event.event_type === "alert_behavioral_incident") return "critical";

  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium") return "medium";

  if (event.event_type.startsWith("response_")) {
    if (outcome === "failed") return "high";
    if (outcome === "executed") return "high";
    if (outcome === "blocked") return "medium";
    if (outcome === "suppressed") return "info";
    if (outcome === "simulated") return "medium";
    return "medium";
  }

  if (event.event_type.startsWith("alert_")) {
    if ((score ?? 0) >= 90) return "critical";
    if ((score ?? 0) >= 75) return "high";
    return "medium";
  }

  return "info";
}

function extractPath(event: TelemetryEvent): string | null {
  const payload = event.payload ?? {};
  return (
    asString(payload.path) ??
    asString(payload.old_path) ??
    asString(payload.new_path) ??
    asString(payload.primary_path) ??
    asString(payload.matched_download_path) ??
    null
  );
}

function extractGroupKey(event: TelemetryEvent): string | null {
  const payload = event.payload ?? {};

  return (
    asString(payload.incident_key) ??
    extractPath(event) ??
    asString(payload.action_key) ??
    (() => {
      const pid = asNumber(payload.pid);
      return pid !== null ? `pid:${pid}` : null;
    })() ??
    (event.event_type === "agent_state_snapshot" ? "agent_state" : null)
  );
}

function extractStoryTitle(key: string, events: TelemetryEvent[]): string {
  const incident = events.find((event) => event.event_type === "alert_behavioral_incident");
  if (incident) return "Behavioral Incident";

  const response = events.find((event) => event.event_type.startsWith("response_"));
  if (response) {
    const action = asString(response.payload.action);
    return action ? `Response: ${action.replace(/_/g, " ")}` : "Response Activity";
  }

  if (key === "agent_state") return "Agent State Snapshot";
  if (key.startsWith("pid:")) return `Process ${key.slice(4)}`;

  const tail = key.split("/").pop();
  return tail || key;
}

function eventSummary(event: TelemetryEvent): string {
  const payload = event.payload ?? {};

  if (event.event_type === "alert_behavioral_incident") {
    return [
      asString(payload.reason) ?? "Behavioral incident detected",
      asNumber(payload.score) !== null ? `score=${asNumber(payload.score)}` : null,
    ]
      .filter(Boolean)
      .join(" • ");
  }

  if (event.event_type.startsWith("response_")) {
    return [
      asString(payload.action),
      asString(payload.outcome),
      asString(payload.target_type),
      asNumber(payload.pid) !== null ? `pid=${asNumber(payload.pid)}` : null,
      asString(payload.path) ??
        asString(payload.old_path) ??
        asString(payload.new_path) ??
        null,
      asString(payload.reason),
    ]
      .filter(Boolean)
      .join(" • ");
  }

  if (event.event_type.startsWith("alert_")) {
    return [
      asString(payload.title) ?? asString(payload.reason) ?? humanizeEventType(event.event_type),
      asNumber(payload.score) !== null ? `score=${asNumber(payload.score)}` : null,
      extractPath(event),
    ]
      .filter(Boolean)
      .join(" • ");
  }

  if (event.event_type === "process_started") {
    return [
      asString(payload.command) ?? "process",
      asString(payload.args),
      asString(payload.process_kind),
      asNumber(payload.pid) !== null ? `pid=${asNumber(payload.pid)}` : null,
    ]
      .filter(Boolean)
      .join(" • ");
  }

  if (event.event_type.startsWith("file_")) {
    return [
      humanizeEventType(event.event_type),
      extractPath(event),
    ]
      .filter(Boolean)
      .join(" • ");
  }

  if (event.event_type === "agent_state_snapshot") {
    const normalized = asRecord(payload.normalized_summary);
    return [
      "Periodic state snapshot",
      asNumber(normalized?.active_incidents) !== null
        ? `active_incidents=${asNumber(normalized?.active_incidents)}`
        : null,
      asNumber(normalized?.active_response_cooldowns) !== null
        ? `response_cooldowns=${asNumber(normalized?.active_response_cooldowns)}`
        : null,
    ]
      .filter(Boolean)
      .join(" • ");
  }

  return humanizeEventType(event.event_type);
}

function buildStorySummary(events: TelemetryEvent[]): string {
  const alertCount = events.filter((event) => event.event_type.startsWith("alert_")).length;
  const responseCount = events.filter((event) => event.event_type.startsWith("response_")).length;
  const fileCount = events.filter((event) => event.event_type.startsWith("file_")).length;
  const processCount = events.filter((event) => event.event_type === "process_started").length;
  const strongest = events
    .map(eventSeverity)
    .sort((a, b) => severityRank(b) - severityRank(a))[0];

  return [
    alertCount > 0 ? `${alertCount} alert(s)` : null,
    responseCount > 0 ? `${responseCount} response(s)` : null,
    fileCount > 0 ? `${fileCount} file event(s)` : null,
    processCount > 0 ? `${processCount} process event(s)` : null,
    strongest ? `highest=${strongest}` : null,
  ]
    .filter(Boolean)
    .join(" • ");
}

function App() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState("");

  async function loadEvents() {
    try {
      const lines = await invoke<string[]>("read_agent_events");

      const parsed = lines
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as TelemetryEvent)
        .sort((a, b) => getTimestampMs(a.timestamp) - getTimestampMs(b.timestamp));

      setEvents(parsed);
      setError("");
    } catch (err) {
      console.error(err);
      setError(String(err));
    }
  }

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 2000);
    return () => clearInterval(interval);
  }, []);

  const stats = useMemo<DashboardStats>(() => {
    return {
      totalEvents: events.length,
      totalAlerts: events.filter((event) => event.event_type.startsWith("alert_")).length,
      totalIncidents: events.filter((event) => event.event_type === "alert_behavioral_incident")
        .length,
      totalResponses: events.filter((event) => event.event_type.startsWith("response_")).length,
    };
  }, [events]);

  const storylines = useMemo<Storyline[]>(() => {
    const grouped = new Map<string, TelemetryEvent[]>();

    for (const event of events) {
      const key = extractGroupKey(event);
      if (!key) continue;

      const current = grouped.get(key) ?? [];
      current.push(event);
      grouped.set(key, current);
    }

    return Array.from(grouped.entries())
      .map(([key, groupedEvents]) => {
        const sortedEvents = [...groupedEvents].sort(
          (a, b) => getTimestampMs(a.timestamp) - getTimestampMs(b.timestamp)
        );

        const severity = sortedEvents.reduce<Storyline["severity"]>(
          (acc, event) => mergeSeverity(acc, eventSeverity(event)),
          "info"
        );

        return {
          key,
          title: extractStoryTitle(key, sortedEvents),
          severity,
          summary: buildStorySummary(sortedEvents),
          events: sortedEvents,
          lastSeen: getTimestampMs(sortedEvents[sortedEvents.length - 1]?.timestamp),
        };
      })
      .sort((a, b) => {
        const severityDiff = severityRank(b.severity) - severityRank(a.severity);
        if (severityDiff !== 0) return severityDiff;
        return b.lastSeen - a.lastSeen;
      });
  }, [events]);

  return (
    <main className="container">
      <header className="page-header">
        <div>
          <h1>Agent Security Console</h1>
          <p className="subtitle">
            Local telemetry, detections, incidents, and response history
          </p>
        </div>

        <button className="refresh-button" onClick={loadEvents}>
          Refresh
        </button>
      </header>

      {error ? <div className="error-banner">{error}</div> : null}

      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Events</div>
          <div className="stat-value">{stats.totalEvents}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Alerts</div>
          <div className="stat-value">{stats.totalAlerts}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Behavioral Incidents</div>
          <div className="stat-value">{stats.totalIncidents}</div>
        </div>

        <div className="stat-card">
          <div className="stat-label">Responses</div>
          <div className="stat-value">{stats.totalResponses}</div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Storylines</h2>
        </div>

        {storylines.length === 0 ? (
          <div className="empty-state">No storylines yet.</div>
        ) : (
          <div className="storyline-list">
            {storylines.map((story) => (
              <article className="story-card" key={story.key}>
                <div className="story-card-top">
                  <div>
                    <div className="story-title">{story.title}</div>
                    <div className="story-key">{story.key}</div>
                    <div className="story-summary">{story.summary}</div>
                  </div>

                  <div className={`severity-pill severity-${story.severity}`}>
                    {story.severity.toUpperCase()}
                  </div>
                </div>

                <div className="story-events">
                  {story.events.map((event) => (
                    <div className="story-event-row" key={event.id}>
                      <div className="story-event-time">{formatTimestamp(event.timestamp)}</div>
                      <div className="story-event-type">{event.event_type}</div>
                      <div className="story-event-summary">{eventSummary(event)}</div>
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Raw Events</h2>
        </div>

        {events.length === 0 ? (
          <div className="empty-state">No agent events found yet.</div>
        ) : (
          <div className="raw-event-list">
            {[...events].reverse().map((event) => {
              const severity = eventSeverity(event);
              return (
                <article className="raw-event-card" key={event.id}>
                  <div className="raw-event-top">
                    <div>
                      <div className="raw-event-type">{event.event_type}</div>
                      <div className="raw-event-meta">
                        {formatTimestamp(event.timestamp)} • {event.source}
                      </div>
                    </div>

                    <div className={`severity-pill severity-${severity}`}>
                      {severity.toUpperCase()}
                    </div>
                  </div>

                  <div className="raw-event-summary">{eventSummary(event)}</div>
                  <pre className="payload-block">{JSON.stringify(event.payload, null, 2)}</pre>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </main>
  );
}

export default App;