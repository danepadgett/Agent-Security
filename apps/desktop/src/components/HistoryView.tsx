import { useMemo, useState } from "react";
import type { HoundTrace } from "../types";
import { formatRelativeTime } from "../utils";
import { SearchIcon } from "./icons";

type Props = {
  houndTraces: HoundTrace[];
  onSelect: (trace: HoundTrace) => void;
};

const VERDICT_OPTS = ["All verdicts", "Blocked", "Simulated block", "Monitoring"];

export function HistoryView({ houndTraces, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("All verdicts");

  const filtered = useMemo(() => {
    return houndTraces.filter((trace) => {
      if (verdictFilter !== "All verdicts" && trace.verdict !== verdictFilter) return false;
      if (query.trim()) {
        const q = query.toLowerCase();
        return (
          trace.headline.toLowerCase().includes(q) ||
          trace.what_happened.toLowerCase().includes(q) ||
          trace.what_was_targeted.toLowerCase().includes(q) ||
          trace.mitre_summary.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [houndTraces, query, verdictFilter]);

  function verdictClass(verdict: string) {
    if (verdict === "Blocked") return "history-verdict--blocked";
    if (verdict === "Simulated block") return "history-verdict--simulated";
    return "history-verdict--monitoring";
  }

  return (
    <div className="history-view">
      <div className="history-toolbar">
        <div className="history-search">
          <SearchIcon size={13} />
          <input
            type="text"
            placeholder="Search traces..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <select
          className="history-filter-select"
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value)}
        >
          {VERDICT_OPTS.map((o) => <option key={o}>{o}</option>)}
        </select>
      </div>

      <div className="history-list">
        {filtered.length === 0 ? (
          <div className="history-empty">
            {houndTraces.length === 0
              ? "No traces yet. Hound Traces are created when you mark incidents as resolved."
              : "No results — try adjusting your search or filters."}
          </div>
        ) : (
          filtered.map((trace) => (
            <div
              key={trace.incident_id}
              className="history-row"
              onClick={() => onSelect(trace)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && onSelect(trace)}
            >
              <div className="incident-row-sev" style={{ background: riskColor(trace.risk_level) }} />
              <div className="history-row-body">
                <div className="history-row-headline">{trace.headline}</div>
                <div className="history-row-sub">
                  {trace.what_happened.slice(0, 90)}{trace.what_happened.length > 90 ? "..." : ""}
                </div>
              </div>
              <span className={`history-verdict ${verdictClass(trace.verdict)}`}>
                {trace.verdict}
              </span>
              <div className="incident-row-time">{formatRelativeTime(trace.timestamp)}</div>
            </div>
          ))
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
