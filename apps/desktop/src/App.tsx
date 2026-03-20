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
  events: TelemetryEvent[];
  summary: string;
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
    const asNumber = Number(value);
    if (!Number.isNaN(asNumber) && value.trim() !== "") {
      return asNumber < 10_000_000_000 ? asNumber * 1000 : asNumber;
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

function humanizeEventType(eventType: string): string {
  return eventType
    .replace(/^alert_/, "")
    .replace(/^response_/, "")
    .replace(/^agent_/, "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
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

function payloadRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function eventSeverity(event: TelemetryEvent): Storyline["severity"] {
  const payloadSeverity = asString(event.payload?.severity)?.toLowerCase();
  if (payloadSeverity === "critical") return "critical";
  if (payloadSeverity === "high") return "high";
  if (payloadSeverity === "medium") return "medium";

  const score =
    asNumber(event.payload?.score) ??
    asNumber(payloadRecord(event.payload?.details)?.score) ??
    asNumber(payloadRecord(event.payload?.details)?.confidence);

  if (event.event_type === "alert_behavioral_incident") return "critical";
  if (event.event_type.startsWith("response_")) return "high";
  if (event.event_type.startsWith("alert_")) {
    if ((score ?? 0) >= 90) return "critical";
    if ((score ?? 0) >= 75) return "high";
    return "medium";
  }

  return "info";
}

function extractPrimaryPath(event: TelemetryEvent): string | null {
  const details = payloadRecord(event.payload?.details);

  return (
    asString(event.payload?.path) ??
    asString(details?.primary_path) ??
    asString(event.payload?.matched_download) ??
    asString(event.payload?.quarantine_path) ??
    asString(event.payload?.original_path)
  );
}

function extractGroupingKey(event: TelemetryEvent): string | null {
  const details = payloadRecord(event.payload?.details);

  return (
    asString(details?.grouping_key) ??
    extractPrimaryPath(event) ??
    asString(event.payload?.action_key) ??
    (() => {
      const pid = asNumber(event.payload?.pid);
      return pid !== null ? `pid:${pid}` : null;
    })() ??
    (() => {
      const childPid = asNumber(event.payload?.child_pid);
      return childPid !== null ? `pid:${childPid}` : null;
    })() ??
    (() => {
      const chainRootPid = asNumber(details?.chain_root_pid);
      return chainRootPid !== null ? `chain:${chainRootPid}` : null;
    })() ??
    (event.event_type === "agent_state_snapshot" ? "agent_state" : null)
  );
}

function extractStoryTitle(key: string, events: TelemetryEvent[]): string {
  const incident = events.find((event) => event.event_type === "alert_behavioral_incident");
  if (incident) {
    return "Behavioral Incident";
  }

  const response = events.find((event) => event.event_type.startsWith("response_"));
  if (response) {
    return humanizeEventType(response.event_type);
  }

  if (key === "agent_state") {
    return "Agent State Snapshot";
  }

  if (key.startsWith("pid:")) {
    return `Process ${key.replace("pid:", "")}`;
  }

  if (key.startsWith("chain:")) {
    return `Execution Chain ${key.replace("chain:", "")}`;
  }

  const pathSegments = key.split("/");
  const tail = pathSegments[pathSegments.length - 1];
  return tail || key;
}

function eventSummary(event: TelemetryEvent): string {
  const details = payloadRecord(event.payload?.details);

  if (event.event_type === "alert_behavioral_incident") {
    const reason = asString(event.payload?.reason);
    const score = asNumber(event.payload?.score);
    const signalCount = asNumber(details?.signal_count);
    const chainLength = asNumber(details?.attack_chain_length);

    return [
      reason ?? "Behavioral incident detected",
      score !== null ? `score=${score}` : null,
      signalCount !== null ? `signals=${signalCount}` : null,
      chainLength !== null ? `chain_length=${chainLength}` : null,
    ]
      .filter(Boolean)
      .join(" • ");
  }

  if (event.event_type.startsWith("response_")) {
    const reason = asString(event.payload?.reason);
    const actionKey = asString(event.payload?.action_key);
    const path = asString(event.payload?.path);
    const pid = asNumber(event.payload?.pid);

    return [
      reason ?? humanizeEventType(event.event_type),
      actionKey ? `action=${actionKey}` : null,
      path ? `path=${path}` : null,
      pid !== null ? `pid=${pid}` : null,
    ]
      .filter(Boolean)
      .join(" • ");
  }

  if (event.event_type.startsWith("alert_")) {
    const title = asString(event.payload?.title);
    const summary = asString(event.payload?.summary);
    const reason = asString(event.payload?.reason);
    const score = asNumber(event.payload?.score);

    return [
      title ?? summary ?? reason ?? humanizeEventType(event.event_type),
      score !== null ? `score=${score}` : null,
    ]
      .filter(Boolean)
      .join(" • ");
  }

  switch (event.event_type) {
    case "file_created":
    case "file_modified":
    case "file_deleted":
    case "file_became_executable": {
      const path = extractPrimaryPath(event);
      return path ? `${humanizeEventType(event.event_type)} • ${path}` : humanizeEventType(event.event_type);
    }

    case "process_started": {
      const command = asString(event.payload?.command) ?? asString(event.payload?.args);
      const pid = asNumber(event.payload?.pid);
      return [
        command ?? "Process started",
        pid !== null ? `pid=${pid}` : null,
      ]
        .filter(Boolean)
        .join(" • ");
    }

    case "agent_state_snapshot": {
      const normalized = payloadRecord(event.payload?.normalized_summary);
      const activeIncidents = asNumber(normalized?.active_incidents);
      const responseCooldowns = asNumber(normalized?.active_response_cooldowns);

      return [
        "Periodic agent state summary",
        activeIncidents !== null ? `active_incidents=${activeIncidents}` : null,
        responseCooldowns !== null ? `response_cooldowns=${responseCooldowns}` : null,
      ]
        .filter(Boolean)
        .join(" • ");
    }

    default:
      return humanizeEventType(event.event_type);
  }
}

function buildStorySummary(events: TelemetryEvent[]): string {
  const sorted = [...events].sort(
    (a, b) => getTimestampMs(a.timestamp) - getTimestampMs(b.timestamp)
  );

  const incident = sorted.find((event) => event.event_type === "alert_behavioral_incident");
  if (incident) {
    return (
      asString(incident.payload?.reason) ??
      "Multiple high-signal detections were correlated into a behavioral incident."
    );
  }

  const highestSeverity = sorted
    .map(eventSeverity)
    .sort((a, b) => severityRank(b) - severityRank(a))[0];

  const alertCount = sorted.filter((event) => event.event_type.startsWith("alert_")).length;
  const responseCount = sorted.filter((event) => event.event_type.startsWith("response_")).length;
  const fileCount = sorted.filter((event) => event.event_type.startsWith("file_")).length;
  const processCount = sorted.filter((event) => event.event_type === "process_started").length;

  if (responseCount > 0) {
    return `Observed ${alertCount} alert(s), ${responseCount} response action(s), ${fileCount} file event(s), and ${processCount} process event(s). Highest severity: ${highestSeverity}.`;
  }

  if (alertCount > 0) {
    return `Observed ${alertCount} alert(s), ${fileCount} file event(s), and ${processCount} process event(s). Highest severity: ${highestSeverity}.`;
  }

  return `Observed ${fileCount} file event(s) and ${processCount} process event(s).`;
}

function severityRank(severity: Storyline["severity"]): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "info":
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
    const groups = new Map<string, TelemetryEvent[]>();

    for (const event of events) {
      const key = extractGroupingKey(event);
      if (!key) continue;

      const existing = groups.get(key) ?? [];
      existing.push(event);
      groups.set(key, existing);
    }

    return Array.from(groups.entries())
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
          events: sortedEvents,
          summary: buildStorySummary(sortedEvents),
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
      <h1>Agent Security Console</h1>
      <p className="subtitle">Local telemetry, detections, incidents, and automated response</p>

      <div className="toolbar">
        <button onClick={loadEvents}>Refresh</button>
      </div>

      {error ? <div className="error">{error}</div> : null}

      <section className="storylines-section">
        <h2>Overview</h2>
        <div className="storylines">
          <div className="story-card">
            <div className="story-header">
              <div>
                <div className="story-title">Total Events</div>
                <div className="story-summary">{stats.totalEvents}</div>
              </div>
              <div className="severity-pill severity-info">INFO</div>
            </div>
          </div>

          <div className="story-card story-card-alert">
            <div className="story-header">
              <div>
                <div className="story-title">Alerts</div>
                <div className="story-summary">{stats.totalAlerts}</div>
              </div>
              <div className="severity-pill severity-high">HIGH</div>
            </div>
          </div>

          <div className="story-card story-card-alert">
            <div className="story-header">
              <div>
                <div className="story-title">Behavioral Incidents</div>
                <div className="story-summary">{stats.totalIncidents}</div>
              </div>
              <div className="severity-pill severity-critical">CRITICAL</div>
            </div>
          </div>

          <div className="story-card">
            <div className="story-header">
              <div>
                <div className="story-title">Response Actions</div>
                <div className="story-summary">{stats.totalResponses}</div>
              </div>
              <div className="severity-pill severity-medium">MEDIUM</div>
            </div>
          </div>
        </div>
      </section>

      <section className="storylines-section">
        <h2>Storylines</h2>

        {storylines.length === 0 ? (
          <div className="empty">No storylines yet.</div>
        ) : (
          <div className="storylines">
            {storylines.map((story) => (
              <div
                key={story.key}
                className={`story-card ${
                  severityRank(story.severity) >= severityRank("high") ? "story-card-alert" : ""
                }`}
              >
                <div className="story-header">
                  <div>
                    <div className="story-title">{story.title}</div>
                    <div className="story-path">{story.key}</div>
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
                      <div className="story-event-summary">
                        {event.event_type.startsWith("alert_") ||
                        event.event_type.startsWith("response_") ? (
                          <strong>{eventSummary(event)}</strong>
                        ) : (
                          eventSummary(event)
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="raw-events-section">
        <h2>Raw Events</h2>

        <div className="events">
          {events.length === 0 ? (
            <div className="empty">No agent events found yet.</div>
          ) : (
            [...events].reverse().map((event) => {
              const severity = eventSeverity(event);
              const isElevated = severityRank(severity) >= severityRank("high");

              return (
                <div
                  className={`event-card ${isElevated ? "alert-card" : ""}`}
                  key={event.id}
                >
                  <div>
                    <strong>ID:</strong> {event.id}
                  </div>
                  <div>
                    <strong>Timestamp:</strong> {formatTimestamp(event.timestamp)}
                  </div>
                  <div>
                    <strong>Type:</strong> {event.event_type}
                  </div>
                  <div>
                    <strong>Source:</strong> {event.source}
                  </div>
                  <div>
                    <strong>Summary:</strong> {eventSummary(event)}
                  </div>
                  <pre>{JSON.stringify(event.payload, null, 2)}</pre>
                </div>
              );
            })
          )}
        </div>
      </section>
    </main>
  );
}

export default App;