import { useState } from "react";
import type { AcknowledgedRecord, BehavioralIncident, FeedTab, StoryLine, TelemetryEvent } from "../types";
import { formatRelativeTime, getTimestampMs, mitreName } from "../utils";
import { SevIcon } from "./icons";

const ALERT_LABELS: Record<string, string> = {
  alert_downloaded_file_executed:          "Downloaded file executed",
  alert_interpreter_launch_from_downloads: "Interpreter from Downloads",
  alert_suspicious_shell_chain:            "Suspicious shell chain",
  alert_file_became_executable:            "File became executable",
  alert_quarantined_file_activity:         "Quarantined file activity",
  alert_persistence_artifact_touched:      "Persistence artifact modified",
  alert_burst_file_activity:               "Burst file activity",
  alert_lolbin_execution:                  "LOLBin execution",
  alert_command_injection_pattern:         "Command injection",
  alert_curl_pipe_bash:                    "curl-pipe-bash",
  alert_c2_beaconing_pattern:              "C2 beaconing",
  alert_keychain_access_attempt:           "Keychain access attempt",
  alert_browser_credential_access:         "Browser credential access",
  alert_ssh_key_access:                    "SSH key access",
  alert_process_masquerading:              "Process masquerading",
  response_blocked_by_whitelist:           "Whitelisted — blocked",
};

function alertLabel(t: string) {
  return ALERT_LABELS[t] ?? t.replace(/^alert_/, "").replace(/_/g, " ");
}

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
  storylines: Map<string, StoryLine>;
  viewedIds: Set<string>;
  newArrivalIds: Set<string>;
  selectedId: string | null;
  totalEvents: number;
  burstMode: boolean;
  burstSignalCount: number;
  onSelect: (incident: BehavioralIncident) => void;
  onSelectHistoryStoryLine?: (sl: StoryLine) => void;
};

export function IncidentFeed({
  incidents,
  atomicAlerts,
  acknowledgedIds,
  acknowledgedRecords,
  storylines,
  viewedIds,
  newArrivalIds,
  selectedId,
  totalEvents,
  burstMode,
  burstSignalCount,
  onSelect,
}: Props) {
  const [tab, setTab] = useState<FeedTab>("inbox");

  const inboxIncidents  = incidents.filter((i) => !acknowledgedIds.has(i.id));
  const resolvedIncidents = incidents.filter((i) => acknowledgedIds.has(i.id));

  // Orphan atomic alerts — those not subsumed by any incident
  // Simple heuristic: alerts that share an event_type with an incident's supporting_events
  // within 90 seconds of that incident are considered subsumed. Others are orphans.
  const incidentEventTypes = new Set(
    incidents.flatMap((i) => i.supporting_events)
  );
  const orphanAlerts = atomicAlerts.filter((e) => !incidentEventTypes.has(e.event_type));

  // Group orphan alerts by path-or-process within 60-second windows
  const orphanGroups = groupOrphanAlerts(orphanAlerts);

  const lastEventTime = incidents.length > 0 || atomicAlerts.length > 0
    ? (() => {
        const allTs = [...incidents.map(i => getTimestampMs(i.timestamp)), ...atomicAlerts.map(a => getTimestampMs(a.timestamp))];
        return Math.max(...allTs);
      })()
    : 0;

  return (
    <div className="feed">
      {/* Burst mode banner */}
      {burstMode && (
        <div className="burst-banner">
          <span className="burst-banner-dot" />
          <span className="burst-banner-text">
            Attack activity detected — analyzing {burstSignalCount} signals…
          </span>
        </div>
      )}

      {/* Tab bar */}
      <div className="feed-tabs">
        <button
          className={`feed-tab ${tab === "inbox" ? "feed-tab--active" : ""}`}
          onClick={() => setTab("inbox")}
        >
          Inbox
          {inboxIncidents.length > 0 && (
            <span className="feed-tab-count">{inboxIncidents.length}</span>
          )}
        </button>
        <button
          className={`feed-tab ${tab === "resolved" ? "feed-tab--active" : ""}`}
          onClick={() => setTab("resolved")}
        >
          Resolved
          {resolvedIncidents.length > 0 && (
            <span className="feed-tab-count feed-tab-count--muted">{resolvedIncidents.length}</span>
          )}
        </button>
        <button
          className={`feed-tab ${tab === "all" ? "feed-tab--active" : ""}`}
          onClick={() => setTab("all")}
        >
          All Activity
        </button>
      </div>

      {/* ── INBOX TAB ── */}
      {tab === "inbox" && (
        <div className="feed-body">
          {inboxIncidents.length === 0 ? (
            <InboxEmpty totalEvents={totalEvents} lastEventTime={lastEventTime} />
          ) : (
            <section className="feed-section">
              {inboxIncidents.map((inc) => (
                <IncidentCard
                  key={inc.id}
                  incident={inc}
                  acknowledged={false}
                  isNew={newArrivalIds.has(inc.id)}
                  unread={!viewedIds.has(inc.id)}
                  selected={selectedId === inc.id}
                  onClick={() => onSelect(inc)}
                />
              ))}
            </section>
          )}
        </div>
      )}

      {/* ── RESOLVED TAB ── */}
      {tab === "resolved" && (
        <div className="feed-body">
          {resolvedIncidents.length === 0 ? (
            <div className="feed-resolved-empty">
              <div className="feed-resolved-empty-text">No resolved incidents yet.</div>
              <div className="feed-resolved-empty-sub">
                Mark inbox incidents as resolved to build your security history.
              </div>
            </div>
          ) : (
            <section className="feed-section">
              {resolvedIncidents.map((inc) => {
                const rec = acknowledgedRecords.get(inc.id);
                const sl = storylines.get(inc.id);
                return (
                  <IncidentCard
                    key={inc.id}
                    incident={inc}
                    acknowledged={true}
                    resolvedReason={rec?.resolved_reason}
                    hasStoryLine={!!sl}
                    isNew={false}
                    unread={false}
                    selected={selectedId === inc.id}
                    onClick={() => onSelect(inc)}
                  />
                );
              })}
            </section>
          )}
        </div>
      )}

      {/* ── ALL ACTIVITY TAB ── */}
      {tab === "all" && (
        <div className="feed-body">
          {incidents.length === 0 && atomicAlerts.length === 0 ? (
            <div className="feed-resolved-empty">
              <div className="feed-resolved-empty-text">No activity recorded yet.</div>
            </div>
          ) : (
            <>
              {incidents.length > 0 && (
                <section className="feed-section">
                  <div className="feed-section-label">Incidents — {incidents.length}</div>
                  {incidents.map((inc) => (
                    <IncidentCard
                      key={inc.id}
                      incident={inc}
                      acknowledged={acknowledgedIds.has(inc.id)}
                      resolvedReason={acknowledgedRecords.get(inc.id)?.resolved_reason}
                      isNew={newArrivalIds.has(inc.id)}
                      unread={!viewedIds.has(inc.id)}
                      selected={selectedId === inc.id}
                      onClick={() => onSelect(inc)}
                    />
                  ))}
                </section>
              )}
              {orphanGroups.length > 0 && (
                <section className="feed-section">
                  <div className="feed-section-label feed-section-label--muted">
                    Signals — {orphanAlerts.length}
                  </div>
                  {orphanGroups.map((group) => (
                    <AlertGroupCard key={group.key} group={group} />
                  ))}
                </section>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Incident card ──────────────────────────────────────────────────────────────

function IncidentCard({
  incident,
  acknowledged,
  resolvedReason,
  hasStoryLine,
  isNew,
  unread,
  selected,
  onClick,
}: {
  incident: BehavioralIncident;
  acknowledged: boolean;
  resolvedReason?: string;
  hasStoryLine?: boolean;
  isNew: boolean;
  unread: boolean;
  selected: boolean;
  onClick: () => void;
}) {
  const topTechniques = incident.mitre_techniques.slice(0, 2);
  const signalCount = incident.supporting_events.length;

  return (
    <button
      className={[
        "incident-card",
        acknowledged ? "incident-card--acked" : "",
        isNew ? "incident-card--new" : "",
        selected ? "incident-card--selected" : "",
      ].filter(Boolean).join(" ")}
      data-sev={incident.severity}
      onClick={onClick}
    >
      <div className="incident-card-stripe" />
      <div className="incident-card-body">
        <div className="incident-card-top">
          <div className="incident-card-left">
            <span className="incident-card-sev-icon">
              <SevIcon severity={incident.severity} size={13} />
            </span>
            <span className="incident-card-title">{incident.attack_chain_label}</span>
          </div>
          <div className="incident-card-right">
            {unread && <span className="incident-unread-dot" aria-label="Unread" />}
            {signalCount > 0 && (
              <span className="incident-signal-badge" title={`${signalCount} signals`}>
                {signalCount} signals
              </span>
            )}
            <span className="incident-card-time">{formatRelativeTime(incident.timestamp)}</span>
          </div>
        </div>

        <div className="incident-card-reason">{incident.reason}</div>

        <div className="incident-card-footer">
          {topTechniques.map((t) => (
            <span key={t} className="technique-chip">
              {t} · {mitreName(t)}
            </span>
          ))}
          {acknowledged && resolvedReason && (
            <span className="resolved-reason-chip">
              {REASON_LABELS[resolvedReason] ?? resolvedReason}
            </span>
          )}
          {acknowledged && hasStoryLine && (
            <span className="storyline-chip">StoryLine</span>
          )}
        </div>
      </div>
    </button>
  );
}

// ── Alert group card ───────────────────────────────────────────────────────────

type AlertGroup = {
  key: string;
  label: string;
  count: number;
  events: TelemetryEvent[];
  expanded: boolean;
};

function groupOrphanAlerts(alerts: TelemetryEvent[]): AlertGroup[] {
  const groups = new Map<string, TelemetryEvent[]>();

  for (const alert of alerts) {
    const p = alert.payload as Record<string, unknown>;
    const details = (typeof p.details === "object" && p.details !== null ? p.details : p) as Record<string, unknown>;
    const rawPath =
      typeof details.path === "string" ? details.path :
      typeof details.command === "string" ? details.command :
      typeof p.path === "string" ? p.path : null;

    const groupKey = rawPath
      ? rawPath.split("/").slice(-2).join("/")
      : alert.event_type;

    const existing = groups.get(groupKey) ?? [];
    existing.push(alert);
    groups.set(groupKey, existing);
  }

  return Array.from(groups.entries()).map(([key, events]) => ({
    key,
    label: key,
    count: events.length,
    events,
    expanded: false,
  }));
}

function AlertGroupCard({ group }: { group: AlertGroup }) {
  const [expanded, setExpanded] = useState(false);
  const newest = group.events[group.events.length - 1];

  return (
    <div className="alert-group-card">
      <button className="alert-group-header" onClick={() => setExpanded((v) => !v)}>
        <span className="alert-group-label">{group.label}</span>
        <span className="alert-group-count">{group.count} signal{group.count !== 1 ? "s" : ""}</span>
        <span className="alert-group-time">{formatRelativeTime(newest.timestamp)}</span>
        <span className="alert-group-chevron">{expanded ? "▼" : "▶"}</span>
      </button>
      {expanded && (
        <div className="alert-group-body">
          {group.events.map((evt) => (
            <div key={evt.id} className="alert-group-row">
              <span className="alert-group-row-type">{alertLabel(evt.event_type)}</span>
              <span className="alert-group-row-time">{formatRelativeTime(evt.timestamp)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Empty inbox state ──────────────────────────────────────────────────────────

function InboxEmpty({ totalEvents, lastEventTime }: { totalEvents: number; lastEventTime: number }) {
  return (
    <div className="feed-empty feed-empty--inbox">
      <div className="inbox-empty-shield">
        <svg width="44" height="44" viewBox="0 0 24 24" fill="none">
          <path
            d="M12 2L3.5 6v5.5C3.5 16.9 7.2 21.4 12 23c4.8-1.6 8.5-6.1 8.5-11.5V6L12 2z"
            fill="var(--status-glow-clean)"
            stroke="var(--status-clean)"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <polyline
            points="9 12 11 14 15 10"
            stroke="var(--status-clean)"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
      <div className="feed-empty-title">All clear</div>
      <div className="feed-empty-sub">
        Hound has analyzed{" "}
        <strong style={{ color: "var(--text-primary)" }}>{totalEvents.toLocaleString()}</strong>{" "}
        events with no threats detected.
      </div>
      {lastEventTime > 0 && (
        <div className="inbox-empty-last-scan">
          Last scan: {formatRelativeTime(lastEventTime)}
        </div>
      )}
    </div>
  );
}
