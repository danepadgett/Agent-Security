import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

import type { AgentStatus, AppView, BehavioralIncident, Severity, TelemetryEvent } from "./types";
import { getTimestampMs, parseBehavioralIncident, severityRank } from "./utils";

import { Sidebar } from "./components/Sidebar";
import { ProtectionHero } from "./components/ProtectionHero";
import { IncidentFeed } from "./components/IncidentFeed";
import { IncidentDetail } from "./components/IncidentDetail";
import { HealthDashboard } from "./components/HealthDashboard";
import { SettingsView } from "./components/SettingsView";
import { ToastStack, type ToastItem } from "./components/Toast";

let _toastSeq = 0;

export default function App() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [acknowledgedIds, setAcknowledgedIds] = useState<Set<string>>(new Set());
  const [viewedIds, setViewedIds] = useState<Set<string>>(new Set());
  const [newArrivalIds, setNewArrivalIds] = useState<Set<string>>(new Set());
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [activeView, setActiveView] = useState<AppView>("incidents");
  const [selectedIncident, setSelectedIncident] = useState<BehavioralIncident | null>(null);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [uptimeSeconds, setUptimeSeconds] = useState(0);
  const [aiConfigured, setAiConfigured] = useState(false);
  const prevIncidentIds = useRef<Set<string>>(new Set());

  // Parse and sort incidents from raw events
  const incidents = useMemo<BehavioralIncident[]>(() => {
    return events
      .filter((e) => e.event_type === "alert_behavioral_incident")
      .map(parseBehavioralIncident)
      .sort((a, b) => getTimestampMs(b.timestamp) - getTimestampMs(a.timestamp));
  }, [events]);

  // Track new arrivals for animation + toasts
  useEffect(() => {
    const prev = prevIncidentIds.current;
    const arrivals = incidents.filter((i) => !prev.has(i.id));

    if (arrivals.length > 0 && prev.size > 0) {
      const newIds = new Set(arrivals.map((i) => i.id));
      setNewArrivalIds((s) => new Set([...s, ...newIds]));

      // Show toast for up to 2 new incidents
      const toastItems: ToastItem[] = arrivals.slice(0, 2).map((inc) => ({
        id: `toast-${++_toastSeq}`,
        severity: inc.severity,
        title: inc.attack_chain_label,
      }));
      setToasts((t) => [...t, ...toastItems]);

      // Clear new-arrival animation flag after 1.5s
      setTimeout(() => {
        setNewArrivalIds((s) => {
          const next = new Set(s);
          newIds.forEach((id) => next.delete(id));
          return next;
        });
      }, 1500);
    }

    prevIncidentIds.current = new Set(incidents.map((i) => i.id));
  }, [incidents]);

  // Derived state
  const threatLevel = useMemo<Severity>(() => {
    const active = incidents.filter((i) => !acknowledgedIds.has(i.id));
    if (active.length === 0) return "info";
    return active.reduce<Severity>(
      (worst, i) => (severityRank(i.severity) > severityRank(worst) ? i.severity : worst),
      "info"
    );
  }, [incidents, acknowledgedIds]);

  const unackedCount = useMemo(
    () => incidents.filter((i) => !acknowledgedIds.has(i.id)).length,
    [incidents, acknowledgedIds]
  );

  const activeIncidents = useMemo(
    () => incidents.filter((i) => !acknowledgedIds.has(i.id)).length,
    [incidents, acknowledgedIds]
  );

  // Data loaders
  const loadEvents = useCallback(async () => {
    try {
      const lines = await invoke<string[]>("read_agent_events");
      const parsed = lines
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l) as TelemetryEvent)
        .sort((a, b) => getTimestampMs(a.timestamp) - getTimestampMs(b.timestamp));
      setEvents(parsed);
      setError("");
    } catch (err) {
      setError(String(err));
    }
  }, []);

  const loadAgentStatus = useCallback(async () => {
    try {
      const status = await invoke<AgentStatus>("get_agent_status");
      setAgentStatus(status);
    } catch {
      // Non-fatal
    }
  }, []);

  const loadAcknowledged = useCallback(async () => {
    try {
      const ids = await invoke<string[]>("get_acknowledged_incidents");
      setAcknowledgedIds(new Set(ids));
    } catch {
      // Non-fatal
    }
  }, []);

  const loadAiConfigured = useCallback(async () => {
    try {
      const configured = await invoke<boolean>("get_ai_configured");
      setAiConfigured(configured);
    } catch {
      // Non-fatal
    }
  }, []);

  // Initial load
  useEffect(() => {
    Promise.all([loadEvents(), loadAgentStatus(), loadAcknowledged(), loadAiConfigured()]).finally(
      () => setLoading(false)
    );
  }, [loadEvents, loadAgentStatus, loadAcknowledged, loadAiConfigured]);

  // Real-time updates
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    listen("agent-events-updated", () => loadEvents()).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, [loadEvents]);

  // Agent status polling
  useEffect(() => {
    const id = setInterval(loadAgentStatus, 10_000);
    return () => clearInterval(id);
  }, [loadAgentStatus]);

  // Uptime counter
  useEffect(() => {
    const id = setInterval(() => setUptimeSeconds((s) => s + 1), 1000);
    return () => clearInterval(id);
  }, []);

  // Handlers
  async function handleAcknowledge(incidentId: string) {
    try {
      await invoke("acknowledge_incident", { incidentId });
      setAcknowledgedIds((prev) => new Set([...prev, incidentId]));
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleToggleSimMode(enabled: boolean) {
    try {
      await invoke("set_simulation_mode", { enabled });
      await loadAgentStatus();
    } catch (err) {
      setError(String(err));
    }
  }

  function handleSelectIncident(incident: BehavioralIncident) {
    setSelectedIncident(incident);
    setViewedIds((s) => new Set([...s, incident.id]));
  }

  function handleCloseDetail() {
    setSelectedIncident(null);
  }

  function handleNavigate(view: AppView) {
    setActiveView(view);
    if (view !== "incidents") setSelectedIncident(null);
  }

  function dismissToast(id: string) {
    setToasts((t) => t.filter((x) => x.id !== id));
  }

  const detailOpen = activeView === "incidents" && selectedIncident !== null;

  return (
    <div className="app-shell">
      <Sidebar
        activeView={activeView}
        onNavigate={handleNavigate}
        incidentCount={unackedCount}
      />

      <div className="app-main">
        {/* Error banner */}
        {error && (
          <div className="error-banner" onClick={() => setError("")}>
            {error} <span className="error-dismiss">✕</span>
          </div>
        )}

        {/* Loading skeleton */}
        {loading && (
          <div className="loading-skeleton">
            <div className="skeleton-hero" />
            <div className="skeleton-cards">
              {[1, 2, 3].map((i) => (
                <div key={i} className="skeleton-card" style={{ opacity: 1 - i * 0.2 }} />
              ))}
            </div>
          </div>
        )}

        {!loading && activeView === "incidents" && (
          <>
            <ProtectionHero
              threatLevel={threatLevel}
              agentStatus={agentStatus}
              totalIncidents={incidents.length}
              activeIncidents={activeIncidents}
              totalEvents={events.length}
              uptimeSeconds={uptimeSeconds}
            />

            <div className="incidents-row">
              <div className="feed-col">
                <IncidentFeed
                  incidents={incidents}
                  acknowledgedIds={acknowledgedIds}
                  viewedIds={viewedIds}
                  newArrivalIds={newArrivalIds}
                  selectedId={selectedIncident?.id ?? null}
                  onSelect={handleSelectIncident}
                />
              </div>
              <div className={`detail-col ${detailOpen ? "detail-col--open" : ""}`}>
                <IncidentDetail
                  incident={selectedIncident}
                  acknowledged={selectedIncident ? acknowledgedIds.has(selectedIncident.id) : false}
                  onClose={handleCloseDetail}
                  onAcknowledge={handleAcknowledge}
                />
              </div>
            </div>
          </>
        )}

        {!loading && activeView === "health" && (
          <div className="view-scroll">
            <HealthDashboard
              events={events}
              incidents={incidents}
              agentStatus={agentStatus}
              onToggleSimMode={handleToggleSimMode}
            />
          </div>
        )}

        {!loading && activeView === "settings" && (
          <div className="view-scroll">
            <SettingsView
              aiConfigured={aiConfigured}
              onAiConfigured={() => setAiConfigured(true)}
            />
          </div>
        )}
      </div>

      <ToastStack toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
