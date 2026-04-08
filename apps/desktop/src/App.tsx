import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "./lib/supabase";
import "./App.css";

import type {
  AcknowledgedRecord,
  AgentStatus,
  AppView,
  BehavioralIncident,
  HoundTrace,
  TelemetryEvent,
} from "./types";
import { getTimestampMs, parseBehavioralIncident } from "./utils";

import { Sidebar } from "./components/Sidebar";
import { Dashboard } from "./components/Dashboard";
import { IncidentFeed } from "./components/IncidentFeed";
import { HoundTracePanel } from "./components/HoundTrace";
import { HistoryView } from "./components/HistoryView";
import { SettingsView } from "./components/SettingsView";
import { AccountView } from "./components/AccountView";
import { ToastStack, type ToastItem } from "./components/Toast";
import { Onboarding } from "./components/Onboarding";
import { AuthScreen } from "./components/AuthScreen";
import { DarkWebMonitor } from "./components/DarkWebMonitor";

let _toastSeq = 0;
const NOTIFICATION_COOLDOWN_MS = 30_000;
const BURST_WINDOW_MS = 10_000;
const BURST_THRESHOLD = 5;
const BURST_QUIET_MS = 15_000;

// Scope violation chains that always warrant notification regardless of score.
const ALWAYS_NOTIFY_CHAINS = new Set([
  "credential_theft",
  "curl_pipe_bash",
  "download_and_execute",
  "ransomware_attack",
  "lateral_movement_chain",
  "staging_and_exfil",
  "persistence_installation",
  "privilege_escalation_chain",
  "supply_chain_compromise",
]);

// Core philosophy: silence unless something actually matters.
// Low-confidence behavioral_chain noise is suppressed; only genuine scope
// violations (credential access, exfiltration, persistence, privilege escalation,
// download-and-execute) produce notifications.
function shouldNotify(incident: BehavioralIncident): boolean {
  const score = incident.score ?? 0;
  // Always notify on high-confidence violations in scope violation chains
  if (ALWAYS_NOTIFY_CHAINS.has(incident.attack_chain_label)) return true;
  // Suppress generic behavioral_chain below threshold — these fire on normal dev activity
  if (incident.attack_chain_label === "behavioral_chain" && score < 50) return false;
  // Notify on anything else that crosses the high-confidence bar
  return score >= 50;
}

function getNotificationText(incidents: BehavioralIncident[]): string {
  if (incidents.length >= 3) {
    return `${incidents.length} scope violations detected — review Incidents`;
  }
  const inc = incidents[0];
  const label = inc.attack_chain_label.replace(/_/g, " ");
  const process = inc.process_name ?? inc.primary_path ?? null;
  return process ? `${label} — ${process}` : label;
}

export default function App() {
  // ── Flow state ──────────────────────────────────────────────────────────
  const [flowLoading, setFlowLoading] = useState(true);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [showAuth, setShowAuth] = useState(false);
  const [session, setSession] = useState<Session | null>(null);

  useEffect(() => {
    // Load Supabase session
    supabase.auth.getSession().then(({ data: { session: s } }) => {
      setSession(s);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, s) => {
      setSession(s);
    });

    return () => subscription.unsubscribe();
  }, []);

  useEffect(() => {
    Promise.all([
      invoke<boolean>("is_first_run"),
      invoke<string | null>("get_auth_token"),
    ])
      .then(([isFirst, authToken]) => {
        setShowOnboarding(isFirst);
        setShowAuth(!isFirst && authToken === null);
      })
      .catch(() => {})
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

  async function handleSignOut() {
    await supabase.auth.signOut().catch(() => {});
    await invoke("sign_out").catch(() => {});
    setSession(null);
    setShowAuth(true);
  }

  // ── Main app state ───────────────────────────────────────────────────────
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [persistedEvents, setPersistedEvents] = useState<TelemetryEvent[]>([]);
  const [acknowledgedRecords, setAcknowledgedRecords] = useState<Map<string, AcknowledgedRecord>>(new Map());
  const [houndTraces, setHoundTraces] = useState<Map<string, HoundTrace>>(new Map());
  const [viewedIds, setViewedIds] = useState<Set<string>>(new Set());
  const [newArrivalIds, setNewArrivalIds] = useState<Set<string>>(new Set());
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [activeView, setActiveView] = useState<AppView>("dashboard");
  const [showSettings, setShowSettings] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<BehavioralIncident | null>(null);
  const [selectedHoundTrace, setSelectedHoundTrace] = useState<HoundTrace | null>(null);
  const [houndTraceLoading, setHoundTraceLoading] = useState(false);
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

  // ── Derived state ────────────────────────────────────────────────────────

  const incidents = useMemo<BehavioralIncident[]>(() => {
    const allEventIds = new Set(events.map((e) => e.id));
    const mergedEvents = [
      ...events,
      ...persistedEvents.filter((e) => !allEventIds.has(e.id)),
    ];

    const allParsed = mergedEvents
      .filter((e) => e.event_type === "alert_behavioral_incident")
      .map(parseBehavioralIncident)
      .sort((a, b) => getTimestampMs(a.timestamp) - getTimestampMs(b.timestamp));

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

  const acknowledgedIds = useMemo(
    () => new Set(acknowledgedRecords.keys()),
    [acknowledgedRecords]
  );

  const unackedIncidentCount = useMemo(
    () => incidents.filter((i) => !acknowledgedIds.has(i.id)).length,
    [incidents, acknowledgedIds]
  );

  // High-confidence only (score >= 50) — used for Dashboard stat to avoid inflating with low-confidence chains
  const activeRealIncidentCount = useMemo(
    () => incidents.filter((i) => !acknowledgedIds.has(i.id) && (i.score ?? 0) >= 50).length,
    [incidents, acknowledgedIds]
  );

  // ── New arrival tracking ─────────────────────────────────────────────────

  useEffect(() => {
    const prev = prevIncidentIds.current;
    const arrivals = incidents.filter((i) => !prev.has(i.id));

    if (arrivals.length > 0 && prev.size > 0) {
      const newIds = new Set(arrivals.map((i) => i.id));
      setNewArrivalIds((s) => new Set([...s, ...newIds]));

      const now = Date.now();
      const notifyArrivals = arrivals.filter(shouldNotify);
      if (notifyArrivals.length > 0 && now - lastNotificationTime.current >= NOTIFICATION_COOLDOWN_MS) {
        const toastItem: ToastItem = {
          id: `toast-${++_toastSeq}`,
          severity: notifyArrivals[0].severity,
          title: getNotificationText(notifyArrivals),
        };
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

      for (const arrival of arrivals) {
        const rawEvent =
          events.find((e) => e.id === arrival.id) ??
          persistedEvents.find((e) => e.id === arrival.id);
        if (rawEvent) {
          invoke("save_unacknowledged_incident", { eventJson: JSON.stringify(rawEvent) }).catch(() => {});
        }
      }
    }

    prevIncidentIds.current = new Set(incidents.map((i) => i.id));
  }, [incidents]); // eslint-disable-line react-hooks/exhaustive-deps

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
  }, [loading]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Burst mode ───────────────────────────────────────────────────────────

  useEffect(() => {
    if (events.length === 0) return;
    const now = Date.now();
    recentEventTimestamps.current = [
      ...recentEventTimestamps.current.filter((t) => now - t < BURST_WINDOW_MS),
      now,
    ];
    const recentCount = recentEventTimestamps.current.length;
    if (recentCount >= BURST_THRESHOLD) {
      setBurstMode(true);
      setBurstSignalCount(recentCount);
    }
    if (burstTimerRef.current) clearTimeout(burstTimerRef.current);
    burstTimerRef.current = setTimeout(() => setBurstMode(false), BURST_QUIET_MS);
  }, [events]);

  // ── Data loaders ─────────────────────────────────────────────────────────

  const loadEvents = useCallback(async () => {
    try {
      const lines = await invoke<string[]>("read_agent_events");
      const parsed = lines
        .filter((l) => l.trim().length > 0)
        .flatMap((l) => { try { return [JSON.parse(l) as TelemetryEvent]; } catch { return []; } })
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
      const records = await invoke<AcknowledgedRecord[]>("get_acknowledged_records");
      const map = new Map(records.map((r) => [r.id, r]));
      const oldIds = await invoke<string[]>("get_acknowledged_incidents");
      for (const id of oldIds) {
        if (!map.has(id)) {
          map.set(id, { id, resolved_reason: "user_acknowledged", resolved_at: "" });
        }
      }
      setAcknowledgedRecords(map);
    } catch { /* non-fatal */ }
  }, []);

  const loadHoundTraces = useCallback(async () => {
    try {
      const traces = await invoke<HoundTrace[]>("get_hound_traces");
      const map = new Map(traces.map((t) => [t.incident_id, t]));
      setHoundTraces(map);
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

  // ── Initial load ─────────────────────────────────────────────────────────

  useEffect(() => {
    Promise.all([
      loadEvents(),
      loadAgentStatus(),
      loadAcknowledgedRecords(),
      loadHoundTraces(),
      loadAiConfigured(),
      loadPersistedIncidents(),
      invoke<string>("get_log_path").then(setLogPath).catch(() => {}),
    ]).finally(() => setLoading(false));
  }, [loadEvents, loadAgentStatus, loadAcknowledgedRecords, loadHoundTraces, loadAiConfigured, loadPersistedIncidents]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    listen("agent-events-updated", () => loadEvents()).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, [loadEvents]);

  useEffect(() => {
    const id = setInterval(loadAgentStatus, 10_000);
    return () => clearInterval(id);
  }, [loadAgentStatus]);

  useEffect(() => {
    const id = setInterval(() => setUptimeSeconds((s) => s + 1), 1000);
    return () => clearInterval(id);
  }, []);

  // Agent heartbeat
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

  // ── Handlers ─────────────────────────────────────────────────────────────

  async function handleSelectIncident(incident: BehavioralIncident) {
    setSelectedIncident(incident);
    setViewedIds((s) => new Set([...s, incident.id]));

    const existing = houndTraces.get(incident.id);
    if (existing) {
      setSelectedHoundTrace(existing);
      return;
    }

    setSelectedHoundTrace(null);
    setHoundTraceLoading(true);
    try {
      const trace = await invoke<HoundTrace>("generate_hound_trace", {
        incidentJson: JSON.stringify(incident),
      });
      setSelectedHoundTrace(trace);
      setHoundTraces((m) => new Map([...m, [incident.id, trace]]));
    } catch {
      setSelectedHoundTrace(null);
    } finally {
      setHoundTraceLoading(false);
    }
  }

  async function handleAcknowledge(incidentId: string, resolvedReason: string) {
    const incident = incidents.find((i) => i.id === incidentId);
    if (!incident) return;
    try {
      const savedTrace = await invoke<HoundTrace>("acknowledge_with_hound_trace", {
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
      setHoundTraces((m) => new Map([...m, [incidentId, savedTrace]]));
      setSelectedHoundTrace(savedTrace);
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
    setSelectedHoundTrace(null);
  }

  function handleNavigate(view: AppView) {
    setActiveView(view);
    if (view !== "incidents") handleCloseDetail();
  }

  function handleSelectHistoryHoundTrace(trace: HoundTrace) {
    const inc = incidents.find((i) => i.id === trace.incident_id);
    if (inc) {
      setSelectedIncident(inc);
      setSelectedHoundTrace(trace);
      setActiveView("incidents");
    }
  }

  function dismissToast(id: string) {
    setToasts((t) => t.filter((x) => x.id !== id));
  }

  const detailOpen = activeView === "incidents" && selectedIncident !== null;

  const houndTracesArray = useMemo(
    () => Array.from(houndTraces.values()).sort((a, b) =>
      b.timestamp.localeCompare(a.timestamp)
    ),
    [houndTraces]
  );

  // ── Pre-main flow ────────────────────────────────────────────────────────

  if (flowLoading) return <div className="onboarding-overlay" />;
  if (showOnboarding) return <Onboarding onComplete={handleOnboardingComplete} />;
  if (showAuth) return <AuthScreen onComplete={handleAuthComplete} />;

  // ── Main app ─────────────────────────────────────────────────────────────

  return (
    <div className={`app-shell ${detailOpen ? "app-shell--panel-open" : ""}`}>
      {/* Col 1: Nav */}
      <Sidebar
        activeView={activeView}
        onNavigate={handleNavigate}
        onOpenSettings={() => setShowSettings(true)}
        incidentCount={unackedIncidentCount}
        breachCount={totalBreachCount}
      />

      {/* Col 2: Content */}
      <div className="app-content">
        {error && (
          <div className="error-banner" onClick={() => setError("")}>
            {error}
          </div>
        )}

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

        {!loading && activeView === "dashboard" && (
          <Dashboard
            agentStatus={agentStatus}
            totalIncidents={incidents.length}
            activeIncidents={activeRealIncidentCount}
            totalEvents={events.length}
            uptimeSeconds={uptimeSeconds}
            recentIncidents={incidents.slice(0, 5)}
            recentHoundTraces={houndTracesArray.slice(0, 5)}
            onViewIncidents={() => handleNavigate("incidents")}
            onViewHistory={() => handleNavigate("history")}
          />
        )}

        {!loading && activeView === "incidents" && (
          <IncidentFeed
            incidents={incidents}
            atomicAlerts={atomicAlerts}
            acknowledgedIds={acknowledgedIds}
            acknowledgedRecords={acknowledgedRecords}
            houndTraces={houndTraces}
            viewedIds={viewedIds}
            newArrivalIds={newArrivalIds}
            selectedId={selectedIncident?.id ?? null}
            totalEvents={events.length}
            burstMode={burstMode}
            burstSignalCount={burstSignalCount}
            onSelect={handleSelectIncident}
          />
        )}

        {!loading && activeView === "history" && (
          <div className="view-scroll">
            <HistoryView
              houndTraces={houndTracesArray}
              onSelect={handleSelectHistoryHoundTrace}
            />
          </div>
        )}

        {!loading && activeView === "dark-web" && (
          <DarkWebMonitor onBreachCountChange={setTotalBreachCount} />
        )}

        {!loading && activeView === "account" && (
          <div className="view-scroll">
            <AccountView session={session} onSignOut={handleSignOut} />
          </div>
        )}
      </div>

      {/* Col 3: Detail panel */}
      <div className="app-detail">
        <HoundTracePanel
          incident={selectedIncident}
          houndTrace={selectedHoundTrace}
          houndTraceLoading={houndTraceLoading}
          acknowledged={selectedIncident ? acknowledgedIds.has(selectedIncident.id) : false}
          resolvedReason={selectedIncident ? acknowledgedRecords.get(selectedIncident.id)?.resolved_reason : undefined}
          aiConfigured={aiConfigured}
          onClose={handleCloseDetail}
          onAcknowledge={handleAcknowledge}
        />
      </div>

      {/* Settings modal */}
      {showSettings && (
        <SettingsView
          aiConfigured={aiConfigured}
          onAiConfigured={() => setAiConfigured(true)}
          logPath={logPath}
          agentSimMode={agentStatus?.simulation_mode ?? true}
          onToggleSimMode={handleToggleSimMode}
          onClose={() => setShowSettings(false)}
        />
      )}

      <ToastStack toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
