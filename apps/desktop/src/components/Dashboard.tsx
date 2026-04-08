import type { AgentStatus, BehavioralIncident, HoundTrace } from "../types";
import { ShieldIcon } from "./icons";
import { formatRelativeTime, formatUptime } from "../utils";

type Props = {
  agentStatus: AgentStatus | null;
  totalIncidents: number;
  activeIncidents: number;
  totalEvents: number;
  uptimeSeconds: number;
  recentHoundTraces: HoundTrace[];
  recentIncidents: BehavioralIncident[];
  onViewIncidents: () => void;
  onViewHistory: () => void;
};

const VERDICT_COLOR: Record<string, string> = {
  Blocked: "#ef4444",
  "Simulated block": "#f97316",
  Monitoring: "#3b82f6",
};

export function Dashboard({
  agentStatus,
  totalIncidents,
  activeIncidents,
  totalEvents,
  uptimeSeconds,
  recentHoundTraces,
  recentIncidents,
  onViewIncidents,
  onViewHistory,
}: Props) {
  const isOffline = agentStatus !== null && !agentStatus.running;
  const isSimMode = agentStatus?.simulation_mode ?? true;
  const hasViolations = activeIncidents > 0;

  // State A: all clear. State B: violations present.
  const allClear = !isOffline && !hasViolations;

  const recentTraces = recentHoundTraces.slice(0, 5);

  return (
    <div className="dashboard">
      {/* Status hero */}
      <div className={`dashboard-status-bar ${hasViolations ? "dashboard-status-bar--alert" : ""}`}>
        <div
          className={`dashboard-shield ${
            isOffline
              ? "dashboard-shield--offline"
              : hasViolations
              ? "dashboard-shield--threat"
              : "dashboard-shield--protected"
          }`}
        >
          <ShieldIcon size={20} />
        </div>

        <div className="dashboard-status-text">
          {isOffline ? (
            <>
              <div className="dashboard-status-label">Agent offline</div>
              <div className="dashboard-status-sub">The monitoring agent is not running.</div>
            </>
          ) : allClear ? (
            <>
              <div className="dashboard-status-label">All clear</div>
              <div className="dashboard-status-sub">
                {totalEvents.toLocaleString()} events analyzed — no scope violations.
              </div>
            </>
          ) : (
            <>
              <div className="dashboard-status-label">
                {activeIncidents} scope violation{activeIncidents !== 1 ? "s" : ""}
              </div>
              <div className="dashboard-status-sub">Review the Incidents tab for details.</div>
            </>
          )}
        </div>

        {!isOffline && isSimMode && (
          <span className="sim-badge">Simulation</span>
        )}
        {isOffline && (
          <span className="offline-badge">Offline</span>
        )}
      </div>

      {/* Stat row */}
      <div className="dashboard-stats">
        <div className="dashboard-stat">
          <div className="dashboard-stat-value">{totalEvents.toLocaleString()}</div>
          <div className="dashboard-stat-label">Events analyzed</div>
        </div>
        <div className="dashboard-stat">
          <div className="dashboard-stat-value">{totalIncidents}</div>
          <div className="dashboard-stat-label">Total incidents</div>
        </div>
        <div className="dashboard-stat">
          <div className="dashboard-stat-value">{formatUptime(uptimeSeconds)}</div>
          <div className="dashboard-stat-label">Uptime</div>
        </div>
      </div>

      {/* Trace feed */}
      <div className="dashboard-activity">
        <div className="dashboard-activity-header">
          <span className="dashboard-activity-title">Recent traces</span>
          <div className="dashboard-activity-actions">
            {activeIncidents > 0 && (
              <button className="dashboard-view-all" onClick={onViewIncidents}>
                Incidents
              </button>
            )}
            {totalIncidents > 0 && (
              <button className="dashboard-view-all" onClick={onViewHistory}>
                History
              </button>
            )}
          </div>
        </div>

        {recentTraces.length === 0 && recentIncidents.length === 0 ? (
          <div className="dashboard-empty">
            <div className="dashboard-empty-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
                <path
                  d="M12 2L3.5 6v5.5C3.5 16.9 7.2 21.4 12 23c4.8-1.6 8.5-6.1 8.5-11.5V6L12 2z"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <polyline
                  points="9 12 11 14 15 10"
                  stroke="var(--border-strong)"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </div>
            No traces yet. Hound Traces are generated when incidents are resolved.
          </div>
        ) : recentTraces.length > 0 ? (
          <div className="trace-feed">
            {recentTraces.map((trace) => (
              <div
                key={trace.incident_id}
                className="trace-row"
                onClick={onViewHistory}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && onViewHistory()}
              >
                <div
                  className="trace-row-bar"
                  style={{ background: riskColor(trace.risk_level) }}
                />
                <div className="trace-row-body">
                  <div className="trace-row-headline">{trace.headline}</div>
                  <div className="trace-row-sub">
                    {trace.what_happened.slice(0, 80)}
                    {trace.what_happened.length > 80 ? "…" : ""}
                  </div>
                </div>
                <div className="trace-row-meta">
                  <span
                    className="trace-verdict"
                    style={{ color: VERDICT_COLOR[trace.verdict] ?? "var(--text-tertiary)" }}
                  >
                    {trace.verdict}
                  </span>
                  <span className="trace-row-time">{formatRelativeTime(trace.timestamp)}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          // Fallback: show raw incidents when no traces exist yet
          <div className="incident-list">
            {recentIncidents.slice(0, 5).map((inc) => (
              <div
                key={inc.id}
                className="incident-row"
                onClick={onViewIncidents}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && onViewIncidents()}
              >
                <div
                  className="incident-row-sev"
                  style={{ background: sevColor(inc.severity) }}
                />
                <div className="incident-row-body">
                  <div className="incident-row-label">{inc.attack_chain_label}</div>
                  <div className="incident-row-meta">
                    {inc.process_name ?? inc.primary_path ?? inc.reason}
                  </div>
                </div>
                <div className="incident-row-time">{formatRelativeTime(inc.timestamp)}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function riskColor(risk: string): string {
  switch (risk.toLowerCase()) {
    case "critical": return "#ef4444";
    case "high":     return "#f97316";
    case "medium":   return "#eab308";
    default:         return "#606060";
  }
}

function sevColor(sev: string): string {
  switch (sev) {
    case "critical": return "#ef4444";
    case "high":     return "#f97316";
    case "medium":   return "#eab308";
    default:         return "#606060";
  }
}
