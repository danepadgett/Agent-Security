import { useMemo, useState } from "react";
import type { AgentStatus, BehavioralIncident, Severity, TelemetryEvent } from "../types";
import { getTimestampMs, severityColor } from "../utils";

type Props = {
  events: TelemetryEvent[];
  incidents: BehavioralIncident[];
  agentStatus: AgentStatus | null;
  onToggleSimMode: (enabled: boolean) => void;
};

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function HealthDashboard({ events, incidents, agentStatus, onToggleSimMode }: Props) {
  const [simToggling, setSimToggling] = useState(false);

  const stats = useMemo(() => {
    const now = Date.now();
    const DAY = 86_400_000;
    const WEEK = 7 * DAY;

    const today = incidents.filter((i) => now - getTimestampMs(i.timestamp) < DAY).length;
    const thisWeek = incidents.filter((i) => now - getTimestampMs(i.timestamp) < WEEK).length;

    const bySev: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const i of incidents) bySev[i.severity]++;

    const techCounts: Record<string, number> = {};
    for (const i of incidents) {
      for (const t of i.mitre_techniques) {
        techCounts[t] = (techCounts[t] ?? 0) + 1;
      }
    }
    const topTech = Object.entries(techCounts).sort(([, a], [, b]) => b - a).slice(0, 8);

    // 24-hour bar chart: group incidents into hourly buckets
    const hourBuckets = Array<number>(24).fill(0);
    for (const i of incidents) {
      const ageMs = now - getTimestampMs(i.timestamp);
      if (ageMs < DAY) {
        const hIdx = Math.min(23, Math.floor(ageMs / (DAY / 24)));
        hourBuckets[23 - hIdx]++;
      }
    }

    const totalAlerts = events.filter((e) => e.event_type.startsWith("alert_")).length;
    const totalResponses = events.filter((e) => e.event_type.startsWith("response_")).length;

    return { today, thisWeek, allTime: incidents.length, bySev, topTech, hourBuckets, totalAlerts, totalResponses };
  }, [events, incidents]);

  const maxHour = Math.max(...stats.hourBuckets, 1);
  const maxTech = Math.max(...stats.topTech.map(([, c]) => c), 1);

  async function handleSimToggle() {
    if (simToggling) return;
    setSimToggling(true);
    try {
      await onToggleSimMode(!(agentStatus?.simulation_mode ?? true));
    } finally {
      setSimToggling(false);
    }
  }

  return (
    <div className="health">
      {/* Agent status */}
      <div className={`agent-status-bar ${agentStatus?.running ? "agent-status-bar--up" : "agent-status-bar--down"}`}>
        <span className="agent-status-dot" />
        <span className="agent-status-text">
          {agentStatus?.running
            ? "Core agent running — monitoring active"
            : "Core agent not running — start core-agent to begin monitoring"}
        </span>
      </div>

      {/* Stats row */}
      <div className="health-stats">
        <StatCard label="Today" value={stats.today} />
        <StatCard label="This week" value={stats.thisWeek} />
        <StatCard label="All time" value={stats.allTime} />
        <StatCard label="Total alerts" value={stats.totalAlerts} />
        <StatCard label="Responses" value={stats.totalResponses} />
        <StatCard label="Events" value={events.length} />
      </div>

      {/* 24-hour bar chart */}
      <div className="health-section">
        <div className="health-section-label">Traces — last 24 hours</div>
        <div className="bar-chart">
          {stats.hourBuckets.map((count, i) => (
            <div key={i} className="bar-col" title={`${count} trace${count !== 1 ? "s" : ""}`}>
              <div
                className="bar"
                style={{ height: `${(count / maxHour) * 100}%` }}
              />
            </div>
          ))}
        </div>
        <div className="bar-chart-labels">
          <span>24h ago</span>
          <span>12h ago</span>
          <span>now</span>
        </div>
      </div>

      {/* Severity breakdown */}
      <div className="health-section">
        <div className="health-section-label">By severity</div>
        <div className="severity-breakdown">
          {SEV_ORDER.map((sev) => {
            const count = stats.bySev[sev];
            const color = severityColor(sev);
            const pct = stats.allTime > 0 ? (count / stats.allTime) * 100 : 0;
            return (
              <div key={sev} className="sev-row">
                <div className="sev-dot" style={{ background: color }} />
                <span className="sev-row-label" style={{ color }}>
                  {sev}
                </span>
                <div className="sev-track">
                  <div className="sev-bar" style={{ width: `${pct}%`, background: color }} />
                </div>
                <span className="sev-count">{count}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* MITRE techniques */}
      {stats.topTech.length > 0 && (
        <div className="health-section">
          <div className="health-section-label">Top MITRE ATT&amp;CK techniques</div>
          <div className="technique-chart">
            {stats.topTech.map(([tech, count]) => (
              <div key={tech} className="technique-row">
                <span className="technique-id">{tech}</span>
                <div className="technique-track">
                  <div
                    className="technique-bar"
                    style={{ width: `${(count / maxTech) * 100}%` }}
                  />
                </div>
                <span className="technique-count">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Simulation mode */}
      <div className="health-section">
        <div className="health-section-label">Response mode</div>
        <div className="sim-row">
          <div className="sim-info">
            <div className="sim-title">Simulation mode</div>
            <div className="sim-desc">
              When enabled, threats are detected and logged but no automatic actions are taken.
            </div>
          </div>
          <button
            className={`toggle-switch ${agentStatus?.simulation_mode ? "toggle-switch--on" : "toggle-switch--off"}`}
            onClick={handleSimToggle}
            disabled={simToggling}
            aria-label="Toggle simulation mode"
          >
            <span className="toggle-knob" />
          </button>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value.toLocaleString()}</div>
    </div>
  );
}
