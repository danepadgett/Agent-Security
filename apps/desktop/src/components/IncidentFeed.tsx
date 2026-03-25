import type { BehavioralIncident } from "../types";
import { formatRelativeTime, mitreName } from "../utils";
import { SevIcon } from "./icons";

type Props = {
  incidents: BehavioralIncident[];
  acknowledgedIds: Set<string>;
  viewedIds: Set<string>;
  newArrivalIds: Set<string>;
  selectedId: string | null;
  onSelect: (incident: BehavioralIncident) => void;
};

export function IncidentFeed({
  incidents,
  acknowledgedIds,
  viewedIds,
  newArrivalIds,
  selectedId,
  onSelect,
}: Props) {
  const active = incidents.filter((i) => !acknowledgedIds.has(i.id));
  const acked = incidents.filter((i) => acknowledgedIds.has(i.id));

  if (incidents.length === 0) {
    return <FeedEmpty />;
  }

  return (
    <div className="feed">
      {active.length > 0 && (
        <section className="feed-section">
          <div className="feed-section-label">
            Active — {active.length} incident{active.length !== 1 ? "s" : ""}
          </div>
          {active.map((inc) => (
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

      {acked.length > 0 && (
        <section className="feed-section">
          <div className="feed-section-label feed-section-label--muted">
            Acknowledged — {acked.length}
          </div>
          {acked.map((inc) => (
            <IncidentCard
              key={inc.id}
              incident={inc}
              acknowledged={true}
              isNew={false}
              unread={false}
              selected={selectedId === inc.id}
              onClick={() => onSelect(inc)}
            />
          ))}
        </section>
      )}
    </div>
  );
}

function IncidentCard({
  incident,
  acknowledged,
  isNew,
  unread,
  selected,
  onClick,
}: {
  incident: BehavioralIncident;
  acknowledged: boolean;
  isNew: boolean;
  unread: boolean;
  selected: boolean;
  onClick: () => void;
}) {
  const topTechniques = incident.mitre_techniques.slice(0, 2);

  return (
    <button
      className={[
        "incident-card",
        acknowledged ? "incident-card--acked" : "",
        isNew ? "incident-card--new" : "",
        selected ? "incident-card--selected" : "",
      ]
        .filter(Boolean)
        .join(" ")}
      data-sev={incident.severity}
      onClick={onClick}
    >
      {/* 3px severity accent bar */}
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
            <span className="incident-card-time">{formatRelativeTime(incident.timestamp)}</span>
          </div>
        </div>

        <div className="incident-card-reason">{incident.reason}</div>

        {topTechniques.length > 0 && (
          <div className="incident-card-footer">
            {topTechniques.map((t) => (
              <span key={t} className="technique-chip">
                {t} · {mitreName(t)}
              </span>
            ))}
          </div>
        )}
      </div>
    </button>
  );
}

function FeedEmpty() {
  return (
    <div className="feed-empty">
      <div className="feed-empty-radar">
        <div className="feed-empty-radar-sweep" />
        <div className="feed-empty-radar-dot" />
      </div>
      <div className="feed-empty-title">Your Mac is clean</div>
      <div className="feed-empty-sub">
        Agent Security is monitoring in the background. No incidents detected.
      </div>
    </div>
  );
}
