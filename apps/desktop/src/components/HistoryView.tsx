import { useMemo, useState } from "react";
import type { StoryLine } from "../types";
import { formatRelativeTime } from "../utils";
import { SearchIcon } from "./icons";

type Props = {
  storylines: StoryLine[];
  onSelect: (storyline: StoryLine) => void;
};

const VERDICT_OPTS = ["All verdicts", "Blocked", "Simulated block", "Monitoring"];
const RISK_OPTS = ["All risks", "Critical", "High", "Medium", "Low"];

export function HistoryView({ storylines, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("All verdicts");
  const [riskFilter, setRiskFilter] = useState("All risks");

  const filtered = useMemo(() => {
    return storylines.filter((sl) => {
      if (verdictFilter !== "All verdicts" && sl.verdict !== verdictFilter) return false;
      if (riskFilter !== "All risks" && sl.risk_level !== riskFilter) return false;
      if (query.trim()) {
        const q = query.toLowerCase();
        return (
          sl.headline.toLowerCase().includes(q) ||
          sl.what_happened.toLowerCase().includes(q) ||
          sl.what_was_targeted.toLowerCase().includes(q) ||
          sl.mitre_summary.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [storylines, query, verdictFilter, riskFilter]);

  return (
    <div className="history-view">
      {/* Header */}
      <div className="history-header">
        <div className="history-title">Security History</div>
        <div className="history-subtitle">
          {storylines.length} incident{storylines.length !== 1 ? "s" : ""} on record
        </div>
      </div>

      {/* Search + filters */}
      <div className="history-controls">
        <div className="history-search-wrap">
          <SearchIcon size={13} className="history-search-icon" />
          <input
            className="history-search"
            type="text"
            placeholder="Search incidents…"
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
        <select
          className="history-filter-select"
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
        >
          {RISK_OPTS.map((o) => <option key={o}>{o}</option>)}
        </select>
      </div>

      {/* Storyline list */}
      <div className="history-list">
        {filtered.length === 0 && (
          <div className="history-empty">
            {storylines.length === 0 ? (
              <>
                <div className="history-empty-title">No incidents resolved yet</div>
                <div className="history-empty-sub">
                  StoryLines are created when you mark incidents as resolved.
                  They form a permanent record of your security history.
                </div>
              </>
            ) : (
              <>
                <div className="history-empty-title">No results</div>
                <div className="history-empty-sub">Try adjusting your search or filters.</div>
              </>
            )}
          </div>
        )}
        {filtered.map((sl) => (
          <StoryLineCard key={sl.incident_id} storyline={sl} onSelect={onSelect} />
        ))}
      </div>
    </div>
  );
}

function StoryLineCard({
  storyline,
  onSelect,
}: {
  storyline: StoryLine;
  onSelect: (sl: StoryLine) => void;
}) {
  const verdictClass = storyline.verdict === "Blocked"
    ? "blocked"
    : storyline.verdict === "Simulated block"
    ? "simulated"
    : "monitoring";

  const riskClass = storyline.risk_level.toLowerCase();

  return (
    <button className="history-card" onClick={() => onSelect(storyline)}>
      <div className="history-card-top">
        <span className={`verdict-badge verdict-badge--${verdictClass} verdict-badge--sm`}>
          {storyline.verdict}
        </span>
        <span className={`risk-badge risk-badge--${riskClass} risk-badge--sm`}>
          {storyline.risk_level}
        </span>
        {storyline.ai_enhanced && (
          <span className="history-ai-dot" title="AI Enhanced" />
        )}
        <span className="history-card-time">{formatRelativeTime(storyline.timestamp)}</span>
      </div>
      <div className="history-card-headline">{storyline.headline}</div>
      <div className="history-card-preview">{storyline.what_happened.slice(0, 120)}…</div>
    </button>
  );
}
