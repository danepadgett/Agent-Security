import { useState } from "react";
import type { AcknowledgedRecord, BehavioralIncident, FeedTab, HoundTrace, TelemetryEvent } from "../types";
import { formatRelativeTime } from "../utils";
import { severityColor } from "../utils";

const REASON_LABELS: Record<string, string> = {
  user_acknowledged: "Marked safe",
  file_removed:      "File removed",
  process_ended:     "Process ended",
  quarantined:       "Quarantined",
  whitelisted:       "Whitelisted",
};

type Props = {
  incidents: BehavioralIncident[];
  atomicAlerts: TelemetryEvent[];
  acknowledgedIds: Set<string>;
  acknowledgedRecords: Map<string, AcknowledgedRecord>;
  houndTraces: Map<string, HoundTrace>;
  viewedIds: Set<string>;
  newArrivalIds: Set<string>;
  selectedId: string | null;
  totalEvents: number;
  burstMode: boolean;
  burstSignalCount: number;
  onSelect: (incident: BehavioralIncident) => void;
};

export function IncidentFeed({
  incidents,
  acknowledgedIds,
  acknowledgedRecords,
  viewedIds,
  newArrivalIds,
  selectedId,
  totalEvents,
  burstMode,
  burstSignalCount,
  onSelect,
}: Props) {
  const [tab, setTab] = useState<FeedTab>("inbox");

  const inboxIncidents    = incidents.filter((i) => !acknowledgedIds.has(i.id));
  const resolvedIncidents = incidents.filter((i) =>  acknowledgedIds.has(i.id));

  const displayedIncidents =
    tab === "inbox"    ? inboxIncidents :
    tab === "resolved" ? resolvedIncidents :
    incidents;

  const handleAckAll = () => {
    // Placeholder — full ack-all handled by App.tsx via separate prop if needed
    // For now, individual ack is done from the detail panel
  };

  return (
    <div className="incident-feed">
      {/* Burst banner */}
      {burstMode && (
        <div className="burst-banner">
          <span className="burst-dot" />
          Attack activity detected — analyzing {burstSignalCount} signals
        </div>
      )}

      {/* Tabs */}
      <div className="feed-tabs">
        <button
          className={`feed-tab ${tab === "inbox" ? "feed-tab--active" : ""}`}
          onClick={() => setTab("inbox")}
        >
          Inbox
          <span className="feed-tab-count">
            {inboxIncidents.length > 0 ? inboxIncidents.length : ""}
          </span>
        </button>
        <button
          className={`feed-tab ${tab === "resolved" ? "feed-tab--active" : ""}`}
          onClick={() => setTab("resolved")}
        >
          Resolved
          <span className="feed-tab-count">
            {resolvedIncidents.length > 0 ? resolvedIncidents.length : ""}
          </span>
        </button>
        <button
          className={`feed-tab ${tab === "all" ? "feed-tab--active" : ""}`}
          onClick={() => setTab("all")}
        >
          All
          <span className="feed-tab-count">
            {incidents.length > 0 ? incidents.length : ""}
          </span>
        </button>
      </div>

      {/* Toolbar */}
      <div className="feed-toolbar">
        <div className="feed-toolbar-left">
          {tab === "inbox" && inboxIncidents.length > 0 && (
            <button className="feed-ack-all-btn" onClick={handleAckAll} disabled>
              Acknowledge all
            </button>
          )}
        </div>
        <span className="feed-count">
          {displayedIncidents.length} trace{displayedIncidents.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Body */}
      <div className="feed-body">
        {displayedIncidents.length === 0 ? (
          <div className="feed-empty">
            {tab === "inbox" ? (
              <>
                <div className="feed-empty-icon">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
                    <path d="M12 2L3.5 6v5.5C3.5 16.9 7.2 21.4 12 23c4.8-1.6 8.5-6.1 8.5-11.5V6L12 2z"
                      stroke="var(--border-strong)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    <polyline points="9 12 11 14 15 10"
                      stroke="var(--border-strong)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
                All clear — {totalEvents.toLocaleString()} events analyzed, nothing outside scope.
              </>
            ) : tab === "resolved" ? (
              "No resolved traces yet."
            ) : (
              "No traces recorded yet."
            )}
          </div>
        ) : (
          <div className="incident-list">
            {displayedIncidents.map((inc) => {
              const isAcked  = acknowledgedIds.has(inc.id);
              const isUnread = !viewedIds.has(inc.id) && !isAcked;
              const isNew    = newArrivalIds.has(inc.id);
              const rec      = acknowledgedRecords.get(inc.id);
              const meta     = inc.process_name ?? inc.primary_path ?? inc.reason;

              return (
                <div
                  key={inc.id}
                  className={[
                    "incident-row",
                    selectedId === inc.id ? "incident-row--selected" : "",
                    isUnread ? "incident-row--unread" : "",
                  ].filter(Boolean).join(" ")}
                  onClick={() => onSelect(inc)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => e.key === "Enter" && onSelect(inc)}
                >
                  <div
                    className="incident-row-sev"
                    style={{ background: severityColor(inc.severity) }}
                    aria-label={inc.severity}
                  />
                  <div className="incident-row-body">
                    <div className="incident-row-label">
                      {inc.attack_chain_label}
                    </div>
                    {meta && (
                      <div className="incident-row-meta">{meta}</div>
                    )}
                  </div>
                  {isAcked && rec && (
                    <span className="resolved-badge">
                      {REASON_LABELS[rec.resolved_reason] ?? rec.resolved_reason}
                    </span>
                  )}
                  {isNew && <span className="incident-new-dot" aria-label="New" />}
                  <div className="incident-row-time">
                    {formatRelativeTime(inc.timestamp)}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
