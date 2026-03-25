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
          <span className="topbar-shield">⬡</span>
          <span className="topbar-title">Agent Security</span>
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
