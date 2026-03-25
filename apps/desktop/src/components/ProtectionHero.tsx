import type { AgentStatus, Severity } from "../types";
import { ShieldIcon } from "./icons";
import { formatUptime } from "../utils";

type Props = {
  threatLevel: Severity;
  agentStatus: AgentStatus | null;
  totalIncidents: number;
  activeIncidents: number;
  totalEvents: number;
  uptimeSeconds: number;
};

export function ProtectionHero({
  threatLevel,
  agentStatus,
  totalIncidents,
  activeIncidents,
  totalEvents,
  uptimeSeconds,
}: Props) {
  const isClean = activeIncidents === 0 && agentStatus?.running !== false;
  const isOffline = agentStatus?.running === false;

  const statusLabel = isOffline
    ? "Agent Offline"
    : activeIncidents > 0
    ? `${activeIncidents} Active Threat${activeIncidents !== 1 ? "s" : ""}`
    : "Monitoring Active";

  const sevAttr = isOffline ? "info" : threatLevel;

  return (
    <div className="hero" data-sev={sevAttr}>
      <div className="hero-shield-wrap">
        <div className={`hero-shield-ring ${isClean && !isOffline ? "hero-shield-ring--pulse-clean" : !isClean && !isOffline ? "hero-shield-ring--pulse-threat" : ""}`}>
          <ShieldIcon size={36} className="hero-shield-icon" />
        </div>
      </div>

      <div className="hero-center">
        <div className="hero-status-label" data-sev={sevAttr}>
          {statusLabel}
        </div>
        <div className="hero-app-name">Agent Security</div>
      </div>

      <div className="hero-stats">
        <HeroStat label="Active" value={activeIncidents} accent={activeIncidents > 0} />
        <div className="hero-stat-divider" />
        <HeroStat label="Total" value={totalIncidents} />
        <div className="hero-stat-divider" />
        <HeroStat label="Events" value={totalEvents} />
        <div className="hero-stat-divider" />
        <HeroStatStr label="Uptime" value={formatUptime(uptimeSeconds)} />
      </div>
    </div>
  );
}

function HeroStat({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="hero-stat">
      <div className={`hero-stat-value ${accent ? "hero-stat-value--accent" : ""}`}>
        {value.toLocaleString()}
      </div>
      <div className="hero-stat-label">{label}</div>
    </div>
  );
}

function HeroStatStr({ label, value }: { label: string; value: string }) {
  return (
    <div className="hero-stat">
      <div className="hero-stat-value">{value}</div>
      <div className="hero-stat-label">{label}</div>
    </div>
  );
}
