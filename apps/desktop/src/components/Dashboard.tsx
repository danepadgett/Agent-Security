import type { AgentStatus, BehavioralIncident, HoundTrace } from "../types";
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


function verdictClass(verdict: string): string {
  const v = verdict.toLowerCase();
  if (v === "blocked" || v === "critical") return "verdict-badge critical";
  if (v === "simulated block" || v === "notable") return "verdict-badge notable";
  return "verdict-badge clean";
}

function verdictLabel(verdict: string): string {
  const v = verdict.toLowerCase();
  if (v === "blocked") return "Blocked";
  if (v === "simulated block") return "Simulated";
  if (v === "monitoring") return "Monitoring";
  return verdict;
}

function sevColor(sev: string): string {
  switch (sev) {
    case "critical": return "#ef4444";
    case "high":     return "#f97316";
    case "medium":   return "#eab308";
    default:         return "#606060";
  }
}

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
  const hasTraces = recentHoundTraces.length > 0;

  // State A: all clear — calm, no drama
  if (!isOffline && !hasViolations && !hasTraces) {
    return (
      <div className="dashboard-clean">
        <div className="protection-status">
          <div className="status-dot active" />
          <span className="status-text">Watching quietly</span>
          {isSimMode && <span className="sim-badge-inline">Simulation</span>}
          <span className="status-uptime">{formatUptime(uptimeSeconds)}</span>
        </div>

        <div className="clean-message">
          <h2>Everything looks normal.</h2>
          <p>
            Hound has analyzed {totalEvents.toLocaleString()} events.
            Nothing has stepped outside its expected scope.
          </p>
        </div>

        <div className="stat-row">
          <div className="stat">
            <span className="stat-value">0</span>
            <span className="stat-label">Scope violations</span>
          </div>
          <div className="stat">
            <span className="stat-value">{totalEvents.toLocaleString()}</span>
            <span className="stat-label">Events analyzed</span>
          </div>
          <div className="stat">
            <span className="stat-value">{formatUptime(uptimeSeconds)}</span>
            <span className="stat-label">Uptime</span>
          </div>
        </div>
      </div>
    );
  }

  // State B: recent traces or active violations
  return (
    <div className="dashboard">
      {/* Status bar */}
      <div className={`dashboard-status-bar ${hasViolations ? "dashboard-status-bar--alert" : ""}`}>
        <div className="protection-status">
          <div className={`status-dot ${isOffline ? "offline" : hasViolations ? "alert" : "active"}`} />
          <span className="status-text">
            {isOffline
              ? "Agent offline"
              : hasViolations
              ? `${activeIncidents} scope violation${activeIncidents !== 1 ? "s" : ""}`
              : "Watching quietly"}
          </span>
          {!isOffline && isSimMode && <span className="sim-badge-inline">Simulation</span>}
        </div>

        <div className="dashboard-stat-row">
          <div className="dashboard-stat-sm">
            <span className="stat-value-sm">{totalEvents.toLocaleString()}</span>
            <span className="stat-label-sm">events</span>
          </div>
          <div className="dashboard-stat-sm">
            <span className="stat-value-sm">{totalIncidents}</span>
            <span className="stat-label-sm">traces</span>
          </div>
          <div className="dashboard-stat-sm">
            <span className="stat-value-sm">{formatUptime(uptimeSeconds)}</span>
            <span className="stat-label-sm">uptime</span>
          </div>
        </div>
      </div>

      {/* Trace feed */}
      <div className="trace-feed-section">
        <div className="trace-feed-header">
          <span className="trace-feed-title">
            {hasTraces ? "Recent traces" : "Scope violations"}
          </span>
          <div className="trace-feed-actions">
            {activeIncidents > 0 && (
              <button className="trace-link-btn" onClick={onViewIncidents}>
                Traces →
              </button>
            )}
            {totalIncidents > 0 && (
              <button className="trace-link-btn" onClick={onViewHistory}>
                History →
              </button>
            )}
          </div>
        </div>

        <div className="trace-feed">
          {hasTraces ? (
            recentHoundTraces.map((trace) => (
              <div
                key={trace.incident_id}
                className="trace-row"
                onClick={onViewHistory}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && onViewHistory()}
              >
                <div className="trace-source">
                  <span className="source-name">
                    {/* source isn't on legacy HoundTrace — use risk_level color as fallback indicator */}
                    Hound Trace
                  </span>
                </div>
                <div className="trace-summary">
                  {trace.what_happened.slice(0, 80)}
                  {trace.what_happened.length > 80 ? "…" : ""}
                </div>
                <div className="trace-meta">
                  <span className="trace-time">{formatRelativeTime(trace.timestamp)}</span>
                  <span className={verdictClass(trace.verdict)}>
                    {verdictLabel(trace.verdict)}
                  </span>
                </div>
              </div>
            ))
          ) : (
            // Fallback: raw incidents when no traces exist
            recentIncidents.slice(0, 5).map((inc) => (
              <div
                key={inc.id}
                className="trace-row"
                onClick={onViewIncidents}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && onViewIncidents()}
              >
                <div className="trace-source">
                  <span className="source-name">{inc.process_name ?? "Unknown"}</span>
                </div>
                <div className="trace-summary">{inc.attack_chain_label.replace(/_/g, " ")}</div>
                <div className="trace-meta">
                  <span className="trace-time">{formatRelativeTime(inc.timestamp)}</span>
                  <span
                    className="verdict-badge notable"
                    style={{ background: sevColor(inc.severity) + "1a", color: sevColor(inc.severity) }}
                  >
                    {inc.severity}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
