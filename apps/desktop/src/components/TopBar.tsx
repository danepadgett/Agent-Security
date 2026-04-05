import type { AgentStatus, Severity } from "../types";
import { severityColor } from "../utils";

type Props = {
  agentStatus: AgentStatus | null;
  threatLevel: Severity;
};

function threatLabel(level: Severity, running: boolean): string {
  if (!running) return "Agent not running";
  switch (level) {
    case "critical": return "Critical threat detected";
    case "high": return "High severity incident active";
    case "medium": return "Warnings present";
    case "low": return "Low severity activity";
    default: return "Protected";
  }
}

export function TopBar({ agentStatus, threatLevel }: Props) {
  const running = agentStatus?.running ?? false;
  const simMode = agentStatus?.simulation_mode ?? true;

  const statusColor = !running
    ? "#6b7280"
    : threatLevel === "info" || threatLevel === "low"
    ? "#22c55e"
    : severityColor(threatLevel);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <div className="topbar-logo">
          <svg className="topbar-shield-svg" width="18" height="18" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
              fill="rgba(16,185,129,0.2)"
              stroke="#10b981"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
            <path
              d="M9 12l2 2 4-4"
              stroke="#10b981"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span className="topbar-title">Hound</span>
        </div>
      </div>

      <div className="topbar-center">
        {simMode && (
          <div className="sim-mode-badge">
            SIMULATION MODE — threats detected, no automatic actions taken
          </div>
        )}
      </div>

      <div className="topbar-right">
        <div className="status-indicator">
          <span
            className="status-dot"
            style={{ background: statusColor }}
          />
          <span className="status-label">
            {threatLabel(threatLevel, running)}
          </span>
        </div>
      </div>
    </header>
  );
}
