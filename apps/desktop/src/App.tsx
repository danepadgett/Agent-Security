import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

import type {
  AcknowledgedRecord,
  AgentStatus,
  AppView,
  BehavioralIncident,
  Severity,
  StoryLine,
  TelemetryEvent,
} from "./types";
import { getTimestampMs, parseBehavioralIncident, severityRank } from "./utils";

import { Sidebar } from "./components/Sidebar";
import { ProtectionHero } from "./components/ProtectionHero";
import { IncidentFeed } from "./components/IncidentFeed";
import { StoryLinePanel } from "./components/StoryLine";
import { HistoryView } from "./components/HistoryView";
import { HealthDashboard } from "./components/HealthDashboard";
import { SettingsView } from "./components/SettingsView";
import { ToastStack, type ToastItem } from "./components/Toast";
import { Onboarding } from "./components/Onboarding";
import { AuthScreen } from "./components/AuthScreen";
import { DarkWebMonitor } from "./components/DarkWebMonitor";

let _toastSeq = 0;
const NOTIFICATION_COOLDOWN_MS = 30_000;
const BURST_WINDOW_MS = 10_000;
const BURST_THRESHOLD = 5;
const BURST_QUIET_MS = 15_000;

export default function App() {
  // ── Onboarding / auth flow ──────────────────────────────────────────────
  // null = loading (haven't checked yet), true/false = known state
  const [flowLoading, setFlowLoading] = useState(true);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [showAuth, setShowAuth] = useState(false);

  useEffect(() => {
    Promise.all([
      invoke<boolean>("is_first_run"),
      invoke<string | null>("get_auth_token"),
    ])
      .then(([isFirst, authToken]) => {
        setShowOnboarding(isFirst);
        setShowAuth(!isFirst && authToken === null);
      })
      .catch(() => {
        // On any error (e.g. no config), skip the flow and go straight to main app
      })
      .finally(() => setFlowLoading(false));
  }, []);

  async function handleOnboardingComplete() {
    setShowOnboarding(false);
    const authToken = await invoke<string | null>("get_auth_token").catch(() => null);
    setShowAuth(authToken === null);
  }

  function handleAuthComplete() {
    setShowAuth(false);
  }

  // ── Main app state ──────────────────────────────────────────────────────
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [persistedEvents, setPersistedEvents] = useState<TelemetryEvent[]>([]);
  const [acknowledgedRecords, setAcknowledgedRecords] = useState<Map<string, AcknowledgedRecord>>(new Map());
  const [storylines, setStorylines] = useState<Map<string, StoryLine>>(new Map());
  const [viewedIds, setViewedIds] = useState<Set<string>>(new Set());
  const [newArrivalIds, setNewArrivalIds] = useState<Set<string>>(new Set());
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [activeView, setActiveView] = useState<AppView>("incidents");
  const [selectedIncident, setSelectedIncident] = useState<BehavioralIncident | null>(null);
  const [selectedStoryLine, setSelectedStoryLine] = useState<StoryLine | null>(null);
  const [storyLineLoading, setStoryLineLoading] = useState(false);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [logPath, setLogPath] = useState("");
  const [uptimeSeconds, setUptimeSeconds] = useState(0);
  const [aiConfigured, setAiConfigured] = useState(false);
  const [totalBreachCount, setTotalBreachCount] = useState(0);
  const [burstMode, setBurstMode] = useState(false);
  const [burstSignalCount, setBurstSignalCount] = useState(0);

  const prevIncidentIds = useRef<Set<string>>(new Set());
  const lastNotificationTime = useRef<number>(0);
  const recentEventTimestamps = useRef<number[]>([]);
  const burstTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const didInitialSync = useRef(false);

  // ── Derived state ──────────────────────────────────────────────────────────

  const incidents = useMemo<BehavioralIncident[]>(() => {
    // Merge log-file events with events loaded from the persistence file.
    // The persistence file ensures incidents survive the 1MB log-tail window across restarts.
    const allEventIds = new Set(events.map((e) => e.id));
    const mergedEvents = [
      ...events,
      ...persistedEvents.filter((e) => !allEventIds.has(e.id)),
    ];

    // Parse all behavioral incident events, oldest-first so the first occurrence
    // becomes the canonical incident for each incident_key (stable across restarts).
    const allParsed = mergedEvents
      .filter((e) => e.event_type === "alert_behavioral_incident")
      .map(parseBehavioralIncident)
      .sort((a, b) => getTimestampMs(a.timestamp) - getTimestampMs(b.timestamp));

    // Deduplicate by incident_key: keep first occurrence as canonical.
    // Subsequent firings of the same key (after cooldown) accumulate signals but
    // do NOT create a second card — suppression/cooldown is invisible to the UI.
    const byKey = new Map<string, BehavioralIncident>();
    for (const inc of allParsed) {
      if (!byKey.has(inc.incident_key)) {
        byKey.set(inc.incident_key, inc);
      } else {
        const existing = byKey.get(inc.incident_key)!;
        const merged = Array.from(
          new Set([...existing.supporting_events, ...inc.supporting_events])
        );
        byKey.set(inc.incident_key, {
          ...existing,
          score: Math.max(existing.score, inc.score),
          supporting_events: merged,
        });
      }
    }

    return Array.from(byKey.values()).sort(
      (a, b) => getTimestampMs(b.timestamp) - getTimestampMs(a.timestamp)
    );
  }, [events, persistedEvents]);

  const atomicAlerts = useMemo(() => {
    return events.filter(
      (e) =>
        (e.event_type.startsWith("alert_") && e.event_type !== "alert_behavioral_incident") ||
        e.event_type === "response_blocked_by_whitelist"
    );
  }, [events]);

  // acknowledgedIds derived from records (backward compat)
  const acknowledgedIds = useMemo(
    () => new Set(acknowledgedRecords.keys()),
    [acknowledgedRecords]
  );

  const threatLevel = useMemo<Severity>(() => {
    const active = incidents.filter((i) => !acknowledgedIds.has(i.id));
    if (active.length === 0) return "info";
    return active.reduce<Severity>(
      (worst, i) => (severityRank(i.severity) > severityRank(worst) ? i.severity : worst),
      "info"
    );
  }, [incidents, acknowledgedIds]);

  // Badge = unacknowledged INCIDENTS only (not raw atomic alerts)
  const unackedIncidentCount = useMemo(
    () => incidents.filter((i) => !acknowledgedIds.has(i.id)).length,
    [incidents, acknowledgedIds]
  );

  const activeIncidents = unackedIncidentCount;

  // ── New arrival tracking + notification throttling ─────────────────────────

  useEffect(() => {
    const prev = prevIncidentIds.current;
    const arrivals = incidents.filter((i) => !prev.has(i.id));

    if (arrivals.length > 0 && prev.size > 0) {
      const newIds = new Set(arrivals.map((i) => i.id));
      setNewArrivalIds((s) => new Set([...s, ...newIds]));

      const now = Date.now();
      const sinceLastNotification = now - lastNotificationTime.current;

      if (sinceLastNotification >= NOTIFICATION_COOLDOWN_MS) {
        // Show one toast: summary if many, individual if single
        let toastItem: ToastItem;
        if (arrivals.length >= 3) {
          toastItem = {
            id: `toast-${++_toastSeq}`,
            severity: "critical",
            title: `Multiple threats detected — ${arrivals.length} incidents need review`,
          };
        } else {
          toastItem = {
            id: `toast-${++_toastSeq}`,
            severity: arrivals[0].severity,
            title: arrivals[0].attack_chain_label,
          };
        }
        setToasts((t) => [...t, toastItem]);
        lastNotificationTime.current = now;
      }

      setTimeout(() => {
        setNewArrivalIds((s) => {
          const next = new Set(s);
          newIds.forEach((id) => next.delete(id));
          return next;
        });
      }, 1500);

      // Persist each genuinely new (not yet acknowledged) incident so it
      // survives app restarts even after the log file tail window moves on.
      for (const arrival of arrivals) {
        // Find the raw TelemetryEvent that produced this (deduplicated) incident.
        // The canonical incident id is the first-occurrence event id.
        const rawEvent =
          events.find((e) => e.id === arrival.id) ??
          persistedEvents.find((e) => e.id === arrival.id);
        if (rawEvent) {
          invoke("save_unacknowledged_incident", {
            eventJson: JSON.stringify(rawEvent),
          }).catch(() => {});
        }
      }
    }

    prevIncidentIds.current = new Set(incidents.map((i) => i.id));
  }, [incidents]); // eslint-disable-line react-hooks/exhaustive-deps

  // After the initial load completes, sync any unacknowledged incidents that are
  // already in the log file into the persistence file.  This catches incidents
  // that existed before the persistence layer was introduced, and ensures that
  // even the very first session saves correctly without waiting for the next event.
  useEffect(() => {
    if (loading || didInitialSync.current) return;
    didInitialSync.current = true;

    const unackedEvents = events.filter(
      (e) => e.event_type === "alert_behavioral_incident" && !acknowledgedIds.has(e.id)
    );
    if (unackedEvents.length > 0) {
      invoke("sync_unacknowledged_incidents", {
        eventJsons: unackedEvents.map((e) => JSON.stringify(e)),
      }).catch(() => {});
    }
  }, [loading]); // intentionally runs only when loading transitions to false

  // ── Burst mode detection ───────────────────────────────────────────────────

  useEffect(() => {
    if (events.length === 0) return;
    const now = Date.now();
    // Track recent event arrivals
    recentEventTimestamps.current = [
      ...recentEventTimestamps.current.filter((t) => now - t < BURST_WINDOW_MS),
      now,
    ];
    const recentCount = recentEventTimestamps.current.length;
    if (recentCount >= BURST_THRESHOLD) {
      setBurstMode(true);
      setBurstSignalCount(recentCount);
    }
    // Reset quiet timer
    if (burstTimerRef.current) clearTimeout(burstTimerRef.current);
    burstTimerRef.current = setTimeout(() => setBurstMode(false), BURST_QUIET_MS);
  }, [events]);

  // ── Data loaders ───────────────────────────────────────────────────────────

  const loadEvents = useCallback(async () => {
    try {
      const lines = await invoke<string[]>("read_agent_events");
      const parsed = lines
        .filter((l) => l.trim().length > 0)
        .flatMap((l) => {
          try { return [JSON.parse(l) as TelemetryEvent]; } catch { return []; }
        })
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
    } catch { /* non-fatal */ }
  }, []);

  const loadAcknowledgedRecords = useCallback(async () => {
    try {
      // Load v2 records first (with resolved_reason)
      const records = await invoke<AcknowledgedRecord[]>("get_acknowledged_records");
      const map = new Map(records.map((r) => [r.id, r]));
      // Also load old-format IDs for acks that predate v2
      const oldIds = await invoke<string[]>("get_acknowledged_incidents");
      for (const id of oldIds) {
        if (!map.has(id)) {
          map.set(id, { id, resolved_reason: "user_acknowledged", resolved_at: "" });
        }
      }
      setAcknowledgedRecords(map);
    } catch { /* non-fatal */ }
  }, []);

  const loadStorylines = useCallback(async () => {
    try {
      const sls = await invoke<StoryLine[]>("get_storylines");
      const map = new Map(sls.map((sl) => [sl.incident_id, sl]));
      setStorylines(map);
    } catch { /* non-fatal */ }
  }, []);

  const loadAiConfigured = useCallback(async () => {
    try {
      const configured = await invoke<boolean>("get_ai_configured");
      setAiConfigured(configured);
    } catch { /* non-fatal */ }
  }, []);

  const loadPersistedIncidents = useCallback(async () => {
    try {
      const raw = await invoke<unknown[]>("get_unacknowledged_incidents");
      setPersistedEvents(raw as TelemetryEvent[]);
    } catch { /* non-fatal */ }
  }, []);

  // ── Initial load ───────────────────────────────────────────────────────────

  useEffect(() => {
    Promise.all([
      loadEvents(),
      loadAgentStatus(),
      loadAcknowledgedRecords(),
      loadStorylines(),
      loadAiConfigured(),
      loadPersistedIncidents(),
      invoke<string>("get_log_path").then(setLogPath).catch(() => {}),
    ]).finally(() => setLoading(false));
  }, [loadEvents, loadAgentStatus, loadAcknowledgedRecords, loadStorylines, loadAiConfigured, loadPersistedIncidents]);

  // Real-time event updates
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    listen("agent-events-updated", () => loadEvents()).then((fn) => { unlisten = fn; });
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

  // Agent heartbeat — fires every 5 minutes once the main app is active
  useEffect(() => {
    if (flowLoading || showOnboarding || showAuth) return;
    const appStartMs = Date.now();

    const sendHeartbeat = async () => {
      const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string | undefined;
      if (!supabaseUrl || supabaseUrl.includes("placeholder")) return;

      const uptimeSecs = Math.floor((Date.now() - appStartMs) / 1000);
      const now = Date.now();
      const incidents24h = incidents.filter(
        (i) => now - getTimestampMs(i.timestamp) < 86_400_000
      ).length;

      const [agentId, macosVersion, authToken] = await Promise.all([
        invoke<string>("get_agent_id").catch(() => "unknown"),
        invoke<string>("get_macos_version").catch(() => "unknown"),
        invoke<string | null>("get_auth_token").catch(() => null),
      ]);

      try {
        await fetch(`${supabaseUrl}/functions/v1/heartbeat`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
          },
          body: JSON.stringify({
            agent_id: agentId,
            agent_version: "0.1.0",
            macos_version: macosVersion,
            incidents_24h: incidents24h,
            simulation_mode: agentStatus?.simulation_mode ?? true,
            uptime_seconds: uptimeSecs,
          }),
        });
      } catch { /* non-fatal */ }
    };

    const id = setInterval(sendHeartbeat, 5 * 60 * 1000);
    sendHeartbeat();
    return () => clearInterval(id);
  }, [flowLoading, showOnboarding, showAuth]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Handlers ───────────────────────────────────────────────────────────────

  async function handleSelectIncident(incident: BehavioralIncident) {
    setSelectedIncident(incident);
    setViewedIds((s) => new Set([...s, incident.id]));

    // Check if we already have a saved StoryLine for this incident
    const existing = storylines.get(incident.id);
    if (existing) {
      setSelectedStoryLine(existing);
      return;
    }

    // Generate StoryLine on the fly (deterministic, fast, no save yet)
    setSelectedStoryLine(null);
    setStoryLineLoading(true);
    try {
      const sl = await invoke<StoryLine>("generate_storyline", {
        incidentJson: JSON.stringify(incident),
      });
      setSelectedStoryLine(sl);
      // Cache locally for this session
      setStorylines((m) => new Map([...m, [incident.id, sl]]));
    } catch {
      setSelectedStoryLine(null);
    } finally {
      setStoryLineLoading(false);
    }
  }

  async function handleAcknowledge(incidentId: string, resolvedReason: string) {
    const incident = incidents.find((i) => i.id === incidentId);
    if (!incident) return;
    try {
      // acknowledge_with_storyline: acknowledges + generates + saves StoryLine atomically
      const savedSl = await invoke<StoryLine>("acknowledge_with_storyline", {
        incidentJson: JSON.stringify(incident),
        resolvedReason,
      });
      setAcknowledgedRecords((m) =>
        new Map([...m, [incidentId, {
          id: incidentId,
          resolved_reason: resolvedReason,
          resolved_at: new Date().toISOString(),
        }]])
      );
      setStorylines((m) => new Map([...m, [incidentId, savedSl]]));
      setSelectedStoryLine(savedSl);
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

  function handleCloseDetail() {
    setSelectedIncident(null);
    setSelectedStoryLine(null);
  }

  function handleNavigate(view: AppView) {
    setActiveView(view);
    if (view !== "incidents") {
      setSelectedIncident(null);
      setSelectedStoryLine(null);
    }
  }

  function handleSelectHistoryStoryLine(sl: StoryLine) {
    // Find the matching incident if it exists and navigate to it
    const inc = incidents.find((i) => i.id === sl.incident_id);
    if (inc) {
      setSelectedIncident(inc);
      setSelectedStoryLine(sl);
      setActiveView("incidents");
    }
  }

  function dismissToast(id: string) {
    setToasts((t) => t.filter((x) => x.id !== id));
  }

  const detailOpen = activeView === "incidents" && selectedIncident !== null;

  // All storylines as array for HistoryView (newest first — already reversed from backend)
  const storylinesArray = useMemo(
    () => Array.from(storylines.values()).sort((a, b) =>
      b.timestamp.localeCompare(a.timestamp)
    ),
    [storylines]
  );

  // ── Pre-main-app flow ───────────────────────────────────────────────────

  if (flowLoading) {
    return <div className="onboarding-overlay" />;
  }

  if (showOnboarding) {
    return <Onboarding onComplete={handleOnboardingComplete} />;
  }

  if (showAuth) {
    return <AuthScreen onComplete={handleAuthComplete} />;
  }

  // ── Main app ────────────────────────────────────────────────────────────

  return (
    <div className="app-shell">
      <Sidebar
        activeView={activeView}
        onNavigate={handleNavigate}
        incidentCount={unackedIncidentCount}
        breachCount={totalBreachCount}
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

        {/* ── Incidents view ── */}
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
                  atomicAlerts={atomicAlerts}
                  acknowledgedIds={acknowledgedIds}
                  acknowledgedRecords={acknowledgedRecords}
                  storylines={storylines}
                  viewedIds={viewedIds}
                  newArrivalIds={newArrivalIds}
                  selectedId={selectedIncident?.id ?? null}
                  totalEvents={events.length}
                  burstMode={burstMode}
                  burstSignalCount={burstSignalCount}
                  onSelect={handleSelectIncident}
                />
              </div>
              <div className={`detail-col ${detailOpen ? "detail-col--open" : ""}`}>
                <StoryLinePanel
                  incident={selectedIncident}
                  storyline={selectedStoryLine}
                  storylineLoading={storyLineLoading}
                  acknowledged={selectedIncident ? acknowledgedIds.has(selectedIncident.id) : false}
                  resolvedReason={
                    selectedIncident
                      ? acknowledgedRecords.get(selectedIncident.id)?.resolved_reason
                      : undefined
                  }
                  aiConfigured={aiConfigured}
                  onClose={handleCloseDetail}
                  onAcknowledge={handleAcknowledge}
                />
              </div>
            </div>
          </>
        )}

        {/* ── Health view ── */}
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

        {/* ── Settings view ── */}
        {!loading && activeView === "settings" && (
          <div className="view-scroll">
            <SettingsView
              aiConfigured={aiConfigured}
              onAiConfigured={() => setAiConfigured(true)}
              logPath={logPath}
            />
          </div>
        )}

        {/* ── History view ── */}
        {!loading && activeView === "history" && (
          <div className="view-scroll">
            <HistoryView
              storylines={storylinesArray}
              onSelect={handleSelectHistoryStoryLine}
            />
          </div>
        )}

        {/* ── Dark Web Monitor view ── */}
        {!loading && activeView === "dark-web" && (
          <div className="view-scroll">
            <DarkWebMonitor onBreachCountChange={setTotalBreachCount} />
          </div>
        )}
      </div>

      <ToastStack toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
