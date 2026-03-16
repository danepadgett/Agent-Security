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
  severity: "high" | "info";
  events: TelemetryEvent[];
  summary: string;
};

function extractStoryKey(event: TelemetryEvent): string | null {
  const payload = event.payload ?? {};

  if (event.event_type === "alert") {
    const ruleId = payload.rule_id;
    if (ruleId === "burst_file_activity") {
      return "burst_file_activity";
    }

    const matchedDownload = payload.matched_download;
    if (typeof matchedDownload === "string" && matchedDownload.length > 0) {
      return matchedDownload;
    }
  }

  if (event.event_type === "file_create" || event.event_type === "file_modify") {
    const path = payload.path;
    if (typeof path === "string" && path.length > 0) {
      return path;
    }
  }

  if (event.event_type === "process_start") {
    const args = payload.args;
    if (typeof args === "string") {
      const match = args.match(/\/Users\/[^\s]+/);
      if (match) return match[0];
    }
  }

  return null;
}

function extractStoryTitle(key: string): string {
  if (key === "burst_file_activity") {
    return "Burst File Activity";
  }

  const parts = key.split("/");
  return parts[parts.length - 1] || key;
}

function eventSummary(event: TelemetryEvent): string {
  switch (event.event_type) {
    case "file_create":
      return "File created in monitored directory";
    case "file_modify":
      return "File modified in monitored directory";
    case "process_start":
      return "Process executed with matching file path in args";
    case "alert":
      return `${String(event.payload.title ?? "Alert")} — ${String(
        event.payload.summary ?? ""
      )}`;
    default:
      return "Telemetry event recorded";
  }
}

function buildStorySummary(key: string, groupedEvents: TelemetryEvent[]): string {
  const alertEvent = groupedEvents.find((e) => e.event_type === "alert");

  if (key === "burst_file_activity" && alertEvent) {
    const count = alertEvent.payload.count;
    return `${String(count ?? "Multiple")} files were created or modified rapidly, triggering a ransomware-style alert.`;
  }

  if (alertEvent) {
    return String(alertEvent.payload.summary ?? "Suspicious activity detected.");
  }

  const fileCreates = groupedEvents.filter((e) => e.event_type === "file_create").length;
  const fileModifies = groupedEvents.filter((e) => e.event_type === "file_modify").length;
  const processStarts = groupedEvents.filter((e) => e.event_type === "process_start").length;

  return `Observed ${fileCreates} file creations, ${fileModifies} file modifications, and ${processStarts} process executions.`;
}

function App() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [error, setError] = useState<string>("");

  async function loadEvents() {
    try {
      const lines = await invoke<string[]>("read_agent_events");
      const parsed = lines
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as TelemetryEvent)
        .sort((a, b) => Number(a.timestamp ?? 0) - Number(b.timestamp ?? 0));

      setEvents(parsed);
      setError("");
    } catch (err) {
      console.error(err);
      setError(String(err));
    }
  }

  useEffect(() => {
    loadEvents();

    const interval = setInterval(() => {
      loadEvents();
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const storylines = useMemo<Storyline[]>(() => {
    const groups = new Map<string, TelemetryEvent[]>();

    for (const event of events) {
      const key = extractStoryKey(event);
      if (!key) continue;

      const current = groups.get(key) ?? [];
      current.push(event);
      groups.set(key, current);
    }

    return Array.from(groups.entries())
      .map(([key, groupedEvents]): Storyline => {
        const hasAlert = groupedEvents.some((e) => e.event_type === "alert");
        const severity: Storyline["severity"] = hasAlert ? "high" : "info";

        const sortedEvents = groupedEvents.sort(
          (a, b) => Number(a.timestamp ?? 0) - Number(b.timestamp ?? 0)
        );

        return {
          key,
          title: extractStoryTitle(key),
          severity,
          events: sortedEvents,
          summary: buildStorySummary(key, sortedEvents),
        };
      })
      .sort((a, b) => {
        if (a.severity === "high" && b.severity !== "high") return -1;
        if (a.severity !== "high" && b.severity === "high") return 1;

        return (
          Number(b.events[b.events.length - 1]?.timestamp ?? 0) -
          Number(a.events[a.events.length - 1]?.timestamp ?? 0)
        );
      });
  }, [events]);

  return (
    <main className="container">
      <h1>Personal Cyber Platform</h1>
      <p className="subtitle">Local agent telemetry and storylines</p>

      <div className="toolbar">
        <button onClick={loadEvents}>Refresh</button>
      </div>

      {error ? <div className="error">{error}</div> : null}

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
                  story.severity === "high" ? "story-card-alert" : ""
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
                      <div className="story-event-time">
                        {String(event.timestamp)}
                      </div>
                      <div className="story-event-type">{event.event_type}</div>
                      <div className="story-event-summary">
                        {event.event_type === "alert" ? (
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
              const isAlert = event.event_type === "alert";

              return (
                <div
                  className={`event-card ${isAlert ? "alert-card" : ""}`}
                  key={event.id}
                >
                  <div>
                    <strong>ID:</strong> {event.id}
                  </div>
                  <div>
                    <strong>Timestamp:</strong> {String(event.timestamp)}
                  </div>
                  <div>
                    <strong>Type:</strong> {event.event_type}
                  </div>
                  <div>
                    <strong>Source:</strong> {event.source}
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